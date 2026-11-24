#!/usr/bin/env bash
#
# mayhem/build.sh — build avrdude's libFuzzer harnesses, their -standalone reproducers, and a
# normal (unsanitized) avrdude for mayhem/test.sh. Runs in /mayhem as `mayhem`; re-runnable and
# offline (CMake + the in-image flex/bison/libelf only).
set -euo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${SRC:=/mayhem}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

# UBSan's -fsanitize=function is relaxed (only it): libavrdude's list code calls typed destructors
# through void (*)(void *) everywhere (ldestroy_cb(list, avr_free_mem), lists.c), which trips on
# every part/programmer free. ASan and the rest of UBSan stay on and halting.
[ -n "$SANITIZER_FLAGS" ] && SANITIZER_FLAGS="$SANITIZER_FLAGS -fno-sanitize=function"

cd "$SRC"
# build_* directories are gitignored by upstream's .gitignore
FUZZ_BUILD="$SRC/mayhem/build_fuzz"
TEST_BUILD="$SRC/mayhem/build_test"
OUT="$SRC/mayhem/out"
mkdir -p "$OUT"

# 1) libavrdude, sanitized + SanCov-instrumented (the fuzzed code), DWARF 3
cmake -S . -B "$FUZZ_BUILD" -DCMAKE_BUILD_TYPE=Debug -DFORCE_DISABLE_PYTHON_SUPPORT=ON \
  -DBUILD_DOC=OFF -DBUILD_SHARED_LIBS=OFF \
  -DCMAKE_C_FLAGS="$SANITIZER_FLAGS -fsanitize=fuzzer-no-link $DEBUG_FLAGS" \
  -DCMAKE_C_FLAGS_DEBUG="-O1"
cmake --build "$FUZZ_BUILD" -j"$MAYHEM_JOBS" --target libavrdude conf
LIB="$FUZZ_BUILD/src/libavrdude.a"
# avrdude.conf is generated from src/avrdude.conf.in (target conf); harnesses read it beside them
cp "$FUZZ_BUILD/src/avrdude.conf" "$OUT/avrdude.conf"

# 2) harnesses: each linked twice (libFuzzer + standalone reproducer), with LSan off
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.c" -o "$FUZZ_BUILD/lsan_off.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$FUZZ_BUILD/standalone_main.o"
INC=(-I"$SRC/src" -I"$FUZZ_BUILD/src" -I"$FUZZ_BUILD")
# The libraries CMake found for libavrdude (libelf, hidapi, libusb, libm), as it links avrdude
read -r -a LIBS < <(sed -n 's/.*libavrdude\.a //p' "$FUZZ_BUILD/src/CMakeFiles/avrdude.dir/link.txt")
LIBS=("$LIB" "${LIBS[@]}")

harness() {                     # harness <name> <source> [extra cflags...]
  local name="$1" src="$2"; shift 2
  local wrap=()                 # fuzz_proto.c/fuzz_jtag3.c define __wrap_usleep (a no-op libc usleep)
  case "$(basename "$src")" in fuzz_proto.c|fuzz_jtag3.c) wrap=(-Wl,--wrap=usleep) ;; esac
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS -O1 "${INC[@]}" "$@" -c "$src" -o "$FUZZ_BUILD/$name.o"
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "${wrap[@]}" "$FUZZ_BUILD/$name.o" \
    "$FUZZ_BUILD/lsan_off.o" "${LIBS[@]}" -o "$OUT/$name"
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS "${wrap[@]}" "$FUZZ_BUILD/$name.o" "$FUZZ_BUILD/standalone_main.o" \
    "$FUZZ_BUILD/lsan_off.o" "${LIBS[@]}" -o "$OUT/$name-standalone"
}
H="$SRC/mayhem/harnesses"
harness fuzz_fileio     "$H/fuzz_fileio.c"
harness fuzz_fileio_elf "$H/fuzz_fileio.c" -DFUZZ_FORMAT=FMT_ELF
harness fuzz_config     "$H/fuzz_config.c"
harness fuzz_terminal   "$H/fuzz_terminal.c"
harness fuzz_update     "$H/fuzz_update.c"
harness fuzz_strtodata  "$H/fuzz_strtodata.c"
harness fuzz_stk500v2   "$H/fuzz_proto.c" -DPGM_ID='"stk500v2"'   -DPART_ID='"m328p"'
harness fuzz_arduino    "$H/fuzz_proto.c" -DPGM_ID='"arduino"'    -DPART_ID='"m328p"'
harness fuzz_urclock    "$H/fuzz_proto.c" -DPGM_ID='"urclock"'    -DPART_ID='"m328p"'
harness fuzz_jtagmkii   "$H/fuzz_proto.c" -DPGM_ID='"jtag2"'      -DPART_ID='"m128"'
harness fuzz_serialupdi "$H/fuzz_proto.c" -DPGM_ID='"serialupdi"' -DPART_ID='"m4809"' -DFUZZ_ECHO
harness fuzz_avr910     "$H/fuzz_proto.c" -DPGM_ID='"avr910"'     -DPART_ID='"m16"'
harness fuzz_butterfly  "$H/fuzz_proto.c" -DPGM_ID='"butterfly"'  -DPART_ID='"m169"'
# buspirate in its default binary mode is not a target: when the device stops answering, disable()
# -> buspirate_reset_from_binmode() calls buspirate_is_prompt() on an empty reply, which reads
# buf[-1] (stack-buffer-underflow, buspirate.c), so every input that runs out early, the empty one
# included, crashes there. Its text mode (-x ascii) parses the BusPirate's console lines instead.
harness fuzz_buspirate_ascii "$H/fuzz_proto.c" -DPGM_ID='"buspirate"' -DPART_ID='"m328p"' -DPGM_XPARM='"ascii"'
harness fuzz_jtagmki    "$H/fuzz_proto.c" -DPGM_ID='"jtag1"'      -DPART_ID='"m128"'
harness fuzz_jtag3      "$H/fuzz_jtag3.c"   # fake hidapi device; its hid_*() override libhidapi

# 3) avrdude itself with the project's normal flags, for mayhem/test.sh (tools/test-avrdude)
env -u CFLAGS -u LDFLAGS cmake -S . -B "$TEST_BUILD" -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DFORCE_DISABLE_PYTHON_SUPPORT=ON -DBUILD_DOC=OFF \
  -DCMAKE_C_FLAGS="$COVERAGE_FLAGS" -DCMAKE_EXE_LINKER_FLAGS="$COVERAGE_FLAGS"
cmake --build "$TEST_BUILD" -j"$MAYHEM_JOBS" --target avrdude conf
