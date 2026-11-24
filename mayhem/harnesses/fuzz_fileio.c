/*
 * Firmware-file reader: fileio_mem(FIO_READ, file, format, part, mem, -1) as used by -U
 * <mem>:w:<file>[:<fmt>]. Built twice: FUZZ_FORMAT=FMT_AUTO (format auto-detection: Intel HEX,
 * S-record, ELF, raw, number lists) and FUZZ_FORMAT=FMT_ELF (the libelf reader elf2b()).
 *
 * The first input byte selects the part and memory (bits 0-2: memory, bits 3-4: part); the rest
 * is the file content. Each input gets a fresh copy of the part so memory contents read by one
 * input never leak into the next.
 */
#include "fuzz_common.h"

#ifndef FUZZ_FORMAT
#define FUZZ_FORMAT FMT_AUTO
#endif

static const char *part_ids[] = {"m328p", "m2560", "x128a1", "m4809"};
static const char *mems[] = {"flash", "eeprom", "lfuse", "fuses", "usersig", "lock", "boot", "flash"};
static AVRPART *base[4];

int LLVMFuzzerInitialize(int *argc, char ***argv) {
  (void) argc; (void) argv;
  fuzz_init();
  for(int i = 0; i < 4; i++)
    base[i] = fuzz_part(part_ids[i]);
  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  char path[PATH_MAX];

  if(size < 1)
    return -1;
  unsigned sel = data[0];
  AVRPART *p = avr_dup_part(base[(sel >> 3) & 3]);
  // avr_dup_part() copies the memory buffers avr_initmem() gave the base part
  const AVRMEM *mem = avr_locate_mem(p, mems[sel & 7]);
  if(!mem)
    mem = avr_locate_flash(p);
  if(fuzz_tmpfile(data + 1, size - 1, path, sizeof path, FUZZ_FORMAT == FMT_ELF? ".elf": ".bin") == 0) {
    fileio_mem(FIO_READ, path, FUZZ_FORMAT, p, mem, -1);
    unlink(path);
  }
  avr_free_part(p);
  return 0;
}
