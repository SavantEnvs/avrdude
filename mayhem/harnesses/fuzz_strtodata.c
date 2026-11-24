/*
 * Literal parser str_todata() (strutil.c): the integer/float/char/string literals with size
 * suffixes that the terminal's write command and -U immediate mode (m:w:<data>:m) accept.
 * The first byte selects the memory the literal is meant for (affects endianness and default
 * sizes); the rest is the literal, NUL-terminated. STR_FILE is excluded: it names a file to
 * read, which is the fileio targets' surface.
 */
#include "fuzz_common.h"

static AVRPART *part;
static const char *mems[] = {"flash", "eeprom", "lfuse", "signature"};

int LLVMFuzzerInitialize(int *argc, char ***argv) {
  (void) argc; (void) argv;
  fuzz_init();
  part = fuzz_part("m328p");
  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if(size < 1)
    return -1;
  char *s = malloc(size);
  memcpy(s, data + 1, size - 1);
  s[size - 1] = 0;
  Str2data *sd = str_todata(s, STR_ANY & ~STR_FILE, part, mems[data[0] & 3]);
  str_freedata(sd);
  free(s);
  return 0;
}
