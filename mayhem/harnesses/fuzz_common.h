/*
 * Shared scaffolding for the avrdude libFuzzer harnesses (mayhem/harnesses/fuzz_*.c).
 *
 * libavrdude expects the application (src/main.c) to define a handful of globals and the
 * message sink avrdude_message2(); this header provides harness versions of them. Messages are
 * still formatted (vsnprintf) so format/argument bugs in the library stay visible, but nothing
 * is printed unless AVRDUDE_FUZZ_VERBOSE is set.
 *
 * fuzz_init() mirrors main.c's start-up: init_cx(), init_config(), read_config(avrdude.conf).
 * avrdude.conf is looked up beside the harness binary (build.sh installs it there), or at
 * $AVRDUDE_CONF.
 */
#ifndef AVRDUDE_FUZZ_COMMON_H
#define AVRDUDE_FUZZ_COMMON_H

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <errno.h>

#include "ac_cfg.h"
#include "avrdude.h"
#include "libavrdude.h"

char *progname = "avrdude";
libavrdude_context *cx;
int verbose;
int quell_progress;
int ovsigck;
const char *partdesc;
const char *pgmid;

static int fuzz_print;

int avrdude_message2(FILE *fp, int lno, const char *file, const char *func,
  int msgmode, int msglvl, const char *format, ...) {
  (void) lno; (void) file; (void) func; (void) msgmode;
  char buf[4096];
  va_list ap;

  va_start(ap, format);
  int rc = vsnprintf(buf, sizeof buf, format, ap);
  va_end(ap);
  if(fuzz_print && msglvl <= MSG_INFO + fuzz_print)
    fputs(buf, fp);
  return rc < 0? 0: rc;
}

// Directory of the running binary, so avrdude.conf can be found beside it
static const char *fuzz_conf_path(void) {
  static char path[PATH_MAX];
  const char *env = getenv("AVRDUDE_CONF");

  if(env && *env)
    return env;
  ssize_t n = readlink("/proc/self/exe", path, sizeof path - 32);
  if(n <= 0)
    return "avrdude.conf";
  path[n] = 0;
  char *slash = strrchr(path, '/');
  if(!slash)
    return "avrdude.conf";
  strcpy(slash + 1, "avrdude.conf");
  return path;
}

static void fuzz_init(void) {
  fuzz_print = getenv("AVRDUDE_FUZZ_VERBOSE")? atoi(getenv("AVRDUDE_FUZZ_VERBOSE")): 0;
  verbose = fuzz_print? fuzz_print: -1;
  quell_progress = 2;
  update_progress = NULL;
  init_cx(NULL);
  init_config();
  const char *conf = fuzz_conf_path();
  if(read_config(conf)) {
    fprintf(stderr, "fuzz harness: cannot read config %s\n", conf);
    abort();
  }
}

// A part from avrdude.conf, with its memories allocated (main.c: locate_part + avr_initmem)
static AVRPART *fuzz_part(const char *id) {
  AVRPART *p = locate_part(part_list, id);

  if(!p) {
    fprintf(stderr, "fuzz harness: part %s not in avrdude.conf\n", id);
    abort();
  }
  if(avr_initmem(p)) {
    fprintf(stderr, "fuzz harness: avr_initmem(%s) failed\n", id);
    abort();
  }
  return p;
}

// Write the input to a scratch file under $TMPDIR; the caller unlinks it
static int fuzz_tmpfile(const uint8_t *data, size_t size, char *path, size_t pathlen, const char *suffix) {
  const char *tmp = getenv("TMPDIR");

  snprintf(path, pathlen, "%s/avrdude-fuzz-XXXXXX%s", tmp && *tmp? tmp: "/tmp", suffix);
  int fd = mkstemps(path, (int) strlen(suffix));
  if(fd < 0)
    return -1;
  size_t off = 0;
  while(off < size) {
    ssize_t w = write(fd, data + off, size - off);
    if(w <= 0) {
      close(fd);
      unlink(path);
      return -1;
    }
    off += (size_t) w;
  }
  close(fd);
  return 0;
}

// Make a scratch working directory under $TMPDIR and chdir into it, so any relative file
// access the library does stays inside it
static void fuzz_scratch_cwd(void) {
  const char *tmp = getenv("TMPDIR");
  char dir[PATH_MAX];

  snprintf(dir, sizeof dir, "%s/avrdude-fuzz-cwd-XXXXXX", tmp && *tmp? tmp: "/tmp");
  if(mkdtemp(dir) && chdir(dir) == 0)
    return;
}

// A programmer session as main.c opens one: initpgm, setup, open, enable, initialize. Each
// input gets a fresh programmer and part copy, torn down afterwards (disable, close, teardown).
typedef struct {
  PROGRAMMER *pgm;
  AVRPART *p;
  int opened;
} Fuzz_session;

static int fuzz_session_open(Fuzz_session *s, const char *pgm_id, const AVRPART *base, const char *port) {
  const PROGRAMMER *tmpl = locate_programmer(programmers, pgm_id);

  if(!tmpl || !tmpl->initpgm) {
    fprintf(stderr, "fuzz harness: programmer %s not in avrdude.conf\n", pgm_id);
    abort();
  }
  pgmid = pgm_id;
  partdesc = base->id;
  s->opened = 0;
  s->p = avr_dup_part(base);   // Copies the base part's memory buffers too
  s->pgm = pgm_dup(tmpl);
  init_cx(s->pgm);
  s->pgm->initpgm(s->pgm);
  if(s->pgm->setup)
    s->pgm->setup(s->pgm);
#ifdef PGM_XPARM
  // An -x extended parameter, applied after setup() and before open() as main.c does
  {
    LISTID xp = lcreat(NULL, 0);
    ladd(xp, (void *) PGM_XPARM);
    int rc = s->pgm->parseextparams? s->pgm->parseextparams(s->pgm, xp): -1;
    ldestroy(xp);
    if(rc < 0) {
      fprintf(stderr, "fuzz harness: -x %s rejected by %s\n", PGM_XPARM, pgm_id);
      abort();
    }
  }
#endif
  if(s->pgm->open(s->pgm, port) < 0)
    return -1;
  s->opened = 1;
  s->pgm->enable(s->pgm, s->p);
  return s->pgm->initialize(s->pgm, s->p);
}

static void fuzz_session_close(Fuzz_session *s) {
  if(s->opened) {
    s->pgm->disable(s->pgm);
    s->pgm->close(s->pgm);
  }
  if(s->pgm->teardown)
    s->pgm->teardown(s->pgm);
  pgm_free(s->pgm);
  avr_free_part(s->p);
  s->pgm = NULL;
  s->p = NULL;
}

#endif
