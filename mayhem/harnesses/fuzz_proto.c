/*
 * Programmer/bootloader protocol replies. The fuzz input is the byte stream the device sends
 * back over the serial line: a fake struct serial_device (libavrdude's own serial abstraction,
 * the global `serdev` every serial programmer talks through) serves the input to recv() and
 * reports a read failure once it is exhausted; send() is accepted and discarded. With
 * FUZZ_ECHO (SerialUPDI) the line echoes every sent byte first, as the UPDI one-wire bus does.
 *
 * The session is what main.c does for `avrdude -c PGM_ID -p PART_ID -P <serial port>`: open,
 * enable, initialize, read the signature, then read flash and eeprom (paged_load). Built once
 * per programmer (PGM_ID/PART_ID are set by build.sh). usleep() is replaced by a no-op at link
 * time (-Wl,--wrap=usleep, libc only) so programmer reset/settle delays don't stall each input.
 * PGM_XPARM, if set, is one -x extended parameter (e.g. buspirate's "ascii" text mode).
 */
#include "fuzz_common.h"

#ifndef PGM_ID
#error "build with -DPGM_ID=\"<programmer id>\" -DPART_ID=\"<part id>\""
#endif

static const uint8_t *in_data;
static size_t in_size, in_pos;
static uint8_t echo_buf[1 << 16];
static size_t echo_len, echo_pos;

int __wrap_usleep(useconds_t us) {
  (void) us;
  return 0;
}

static int fz_open(const char *port, union pinfo pinfo, union filedescriptor *fd) {
  (void) port; (void) pinfo;
  fd->ifd = 1000;
  return 0;
}

static int fz_setparams(const union filedescriptor *fd, long baud, unsigned long cflags) {
  (void) fd; (void) baud; (void) cflags;
  return 0;
}

static void fz_close(union filedescriptor *fd) {
  (void) fd;
}

static int fz_send(const union filedescriptor *fd, const unsigned char *buf, size_t len) {
  (void) fd;
#ifdef FUZZ_ECHO
  if(echo_pos == echo_len)
    echo_pos = echo_len = 0;
  for(size_t i = 0; i < len && echo_len < sizeof echo_buf; i++)
    echo_buf[echo_len++] = buf[i];
#else
  (void) buf; (void) len;
#endif
  return 0;
}

static int fz_recv(const union filedescriptor *fd, unsigned char *buf, size_t len) {
  (void) fd;
  for(size_t i = 0; i < len; i++) {
    if(echo_pos < echo_len)
      buf[i] = echo_buf[echo_pos++];
    else if(in_pos < in_size)
      buf[i] = in_data[in_pos++];
    else
      return -1;                // Timeout: the device sent nothing more
  }
  return 0;
}

static int fz_drain(const union filedescriptor *fd, int display) {
  (void) fd; (void) display;
  echo_pos = echo_len = 0;
  return 0;
}

static int fz_set_dtr_rts(const union filedescriptor *fd, int is_on) {
  (void) fd; (void) is_on;
  return 0;
}

static struct serial_device fuzz_serdev = {
  .open = fz_open, .setparams = fz_setparams, .close = fz_close, .rawclose = fz_close,
  .send = fz_send, .recv = fz_recv, .drain = fz_drain, .set_dtr_rts = fz_set_dtr_rts,
  .flags = SERDEV_FL_CANSETSPEED,
};

static AVRPART *part;

int LLVMFuzzerInitialize(int *argc, char ***argv) {
  (void) argc; (void) argv;
  fuzz_init();
  part = fuzz_part(PART_ID);
  serial_recv_timeout = 1;
  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  in_data = data;
  in_size = size;
  in_pos = 0;
  echo_len = echo_pos = 0;
  serdev = &fuzz_serdev;
  serial_recv_timeout = 1;

  Fuzz_session s;
  if(fuzz_session_open(&s, PGM_ID, part, "/dev/ttyFUZZ0") >= 0) {
    if(avr_signature(s.pgm, s.p) >= 0) {
      const AVRMEM *m;
      if((m = avr_locate_flash(s.p)))
        avr_read_mem(s.pgm, s.p, m, NULL);
      if((m = avr_locate_eeprom(s.p)))
        avr_read_mem(s.pgm, s.p, m, NULL);
    }
  }
  fuzz_session_close(&s);
  return 0;
}
