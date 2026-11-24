#!/usr/bin/env bash
#
# mayhem/test.sh — RUN this repo's OWN functional test suite (already built by mayhem/build.sh).
# exit 0 = pass. EDIT per repo. PATCH-grade oracle: after an agent patches the source, the grader
# rebuilds (build.sh) then runs this. DELETE this file if the repo has no meaningful tests.
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

# Upstream's own functional suite, tools/test-avrdude: it drives the avrdude CLI (built by build.sh
# with normal flags) against the dryrun/dryboot emulated parts, writing and reading back flash,
# eeprom, fuses and usersig via -U and -T and diffing the results against tools/test_files. Each
# check prints ✅ (pass) or ❌ (fail).
AVRDUDE="$SRC/mayhem/build_test/src/avrdude"
CONF="$SRC/mayhem/build_test/src/avrdude.conf"
if [ ! -x "$AVRDUDE" ] || [ ! -f "$CONF" ]; then
  echo "test.sh: $AVRDUDE / $CONF missing — mayhem/build.sh did not build the test avrdude" >&2
  emit_ctrf "test-avrdude" 0 1 0
  exit 1
fi
tmp=$(mktemp -d "${TMPDIR:-/tmp}/avrdude-test.XXXXXX")
log="$tmp/test-avrdude.log"
"$SRC/tools/test-avrdude" -e "$AVRDUDE" -c "-C $CONF" -d 0 -t "$tmp" \
  -p "-c dryrun -p m328p" -p "-c dryrun -p m2560" -p "-c dryrun -p m4809" \
  -p "-c dryrun -p x128a1" -p "-c dryrun -p t13" </dev/null >"$log" 2>&1
rc=$?
cat "$log"
passed=$(grep -c '✅' "$log")
failed=$(grep -c '❌' "$log")
# A suite that ran nothing, or exited non-zero without a ❌ line, is a failure too
if [ "$passed" -eq 0 ] || { [ "$rc" -ne 0 ] && [ "$failed" -eq 0 ]; }; then
  failed=$((failed + 1))
fi
rm -rf "$tmp"
emit_ctrf "test-avrdude" "$passed" "$failed" 0
