/*
 * Terminal command language (-t / -T): terminal_line() -> tokenizer + cmd_*() in term.c, the
 * literal parser in strutil.c, the page cache in avrcache.c, disasm.c, and the dryrun
 * programmer that emulates an ATmega328P in memory. Each input line is one terminal line.
 *
 * Commands are ALLOW-LISTED, not filtered: every token that can start a command (the first of
 * a line, and any token after one containing ';') must be exactly one of the names below.
 * Excluded on purpose: save/backup/restore/verify (write or read named files), include (reads
 * and runs a file), ! (subshell), verbose/quell (change process-wide log levels), quit/pgm and
 * the hardware-only vtarg/varef/fosc/sck/spi. The programmer and part are fresh for each input.
 */
#include <ctype.h>
#include "fuzz_common.h"

static AVRPART *part;

static const char *allowed[] = {
  "dump", "d", "read", "r", "disasm", "write", "w", "flush", "abort", "erase", "pgerase",
  "config", "factory", "regfile", "sig", "part", "send", "parms", "help", "?", NULL
};

static int is_ws(char c) {
  return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f';
}

static int allowed_cmd(const char *tok, size_t len) {
  for(int i = 0; allowed[i]; i++)
    if(strlen(allowed[i]) == len && strncasecmp(allowed[i], tok, len) == 0)
      return 1;
  return 0;
}

// 1 if every possible command start in line is an allow-listed command name
static int line_ok(const char *s) {
  int start = 1;

  for(;;) {
    while(*s && is_ws(*s))
      s++;
    if(!*s)
      return 1;
    const char *t = s;
    while(*s && !is_ws(*s))
      s++;
    size_t len = s - t;
    if(start) {
      if(*t == '#')             // Comment: rest of line is ignored by the tokenizer
        return 1;
      size_t n = len;
      while(n && t[n-1] == ';')
        n--;
      if(n && !allowed_cmd(t, n))
        return 0;
    }
    start = memchr(t, ';', len) != NULL;
  }
}

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
  char *buf = malloc(size + 1);
  memcpy(buf, data, size);
  buf[size] = 0;
  if(strlen(buf) != size) {     // Lines are C strings
    free(buf);
    return -1;
  }
  for(char *line = buf, *next; line; line = next) {
    next = strchr(line, '\n');
    if(next)
      *next++ = 0;
    if(!line_ok(line)) {
      free(buf);
      return -1;
    }
  }
  memcpy(buf, data, size);
  buf[size] = 0;

  Fuzz_session s;
  if(fuzz_session_open(&s, "dryrun", part, "usb") >= 0) {
    for(char *line = buf, *next; line; line = next) {
      next = strchr(line, '\n');
      if(next)
        *next++ = 0;
      terminal_line(s.pgm, s.p, line);
    }
    s.pgm->flush_cache(s.pgm, s.p);
  }
  fuzz_session_close(&s);
  free(buf);
  return 0;
}
