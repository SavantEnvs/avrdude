/*
 * -U command-line operations: parse_op() of a "<memlist>:<op>:<file>[:<fmt>]" argument, then
 * update_dryrun() and do_op() against the dryrun programmer (an emulated ATmega328P), as
 * main.c runs them. Covers memory-list expansion (memory_list), immediate-mode data
 * (m:w:0x12,0x34:m -> fileio_imm/str_todata), the file readers for w/v ops, and verify.
 * The input is one -U argument (NUL-terminated).
 *
 * Read ops (r) write their output to the named file; only the stdout name "-" is let through so
 * the harness never creates files. The scratch cwd keeps relative names inside $TMPDIR.
 */
#include "fuzz_common.h"

static AVRPART *part;

int LLVMFuzzerInitialize(int *argc, char ***argv) {
  (void) argc; (void) argv;
  fuzz_init();
  part = fuzz_part("m328p");
  fuzz_scratch_cwd();
  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if(size > 4096)
    return -1;
  char *arg = malloc(size + 1);
  memcpy(arg, data, size);
  arg[size] = 0;
  UPDATE *upd = parse_op(arg);
  free(arg);
  if(!upd)
    return 0;
  // Read ops write the named file and w/v ops of "-" read stdin: neither is input from the fuzzer
  int is_stdio = upd->filename && strcmp(upd->filename, "-") == 0;
  if(upd->marker || (upd->op == DEVICE_READ) != is_stdio) {
    free_update(upd);
    return -1;
  }
  Fuzz_session s;
  if(fuzz_session_open(&s, "dryrun", part, "usb") >= 0) {
    if(!upd->memstr)            // As main.c: -U without memory defaults to flash
      upd->memstr = mmt_strdup(is_pdi(s.p)? "application": "flash");
    int rc = update_dryrun(s.p, upd);
    if(!rc || rc == LIBAVRDUDE_SOFTFAIL) {
      s.pgm->flush_cache(s.pgm, s.p);
      do_op(s.pgm, s.p, upd, UF_AUTO_ERASE | UF_VERIFY | UF_NOHEADING);
    }
    s.pgm->flush_cache(s.pgm, s.p);
  }
  fuzz_session_close(&s);
  free_update(upd);
  return 0;
}
