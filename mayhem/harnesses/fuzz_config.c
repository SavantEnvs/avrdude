/*
 * avrdude.conf / -C reader: read_config() (flex lexer.l + bison config_gram.y + config.c).
 * Each input is a complete configuration file. The config lists and the defaults a config file
 * can set are reset before every input, so one input's definitions never affect the next.
 */
#include "fuzz_common.h"

int LLVMFuzzerInitialize(int *argc, char ***argv) {
  (void) argc; (void) argv;
  fuzz_print = getenv("AVRDUDE_FUZZ_VERBOSE")? atoi(getenv("AVRDUDE_FUZZ_VERBOSE")): 0;
  verbose = fuzz_print? fuzz_print: -1;
  quell_progress = 2;
  init_cx(NULL);
  init_config();
  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  char path[PATH_MAX];

  cleanup_config();
  init_cx(NULL);
  init_config();
  default_programmer = default_parallel = default_serial = default_spi = NULL;
  default_linuxgpio = NULL;
  default_baudrate = 0;
  default_bitclock = 0.0;
  allow_subshells = 0;
  if(fuzz_tmpfile(data, size, path, sizeof path, ".conf") == 0) {
    read_config(path);
    unlink(path);
  }
  return 0;
}
