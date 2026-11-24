/*
 * JTAGICE3 / EDBG (Atmel-ICE, Xplained Mini) protocol replies over USB HID: jtag3.c's
 * jtag3_recv_frame / jtag3_edbg_recv_frame, jtag3_command, jtag3_paged_load(_tpi), through
 * libavrdude's real usbhid_serdev (usb_hidapi.c). The device is a fake hidapi: the hid_*()
 * functions below stand in for libhidapi (the USB device layer, not avrdude code) and serve the
 * fuzz input as the HID report descriptor and the HID reports the probe sends back; writes are
 * accepted and discarded.
 *
 * Input: byte 0 selects the programmer/part (low 2 bits); then a sequence of reports, each a
 * length byte n followed by n bytes (n = 0 or more than requested -> a full-size report).
 * The session is avrdude -c <pgm> -p <part> -P usb: open, enable, initialize, signature, read
 * flash and eeprom.
 */
#include <wchar.h>
#include <hidapi/hidapi.h>
#include "fuzz_common.h"

static const struct {
  const char *pgm, *part, *product;
} combos[] = {
  {"jtag3", "m128", "JTAGICE3"},
  {"atmelice", "m128", "Atmel-ICE CMSIS-DAP"},
  {"xplainedmini_updi", "m4809", "mEDBG CMSIS-DAP"},
  {"atmelice_tpi", "t10", "Atmel-ICE CMSIS-DAP"},
};
static AVRPART *parts_base[4];
static const char *product;

static const uint8_t *in_data;
static size_t in_size, in_pos;
static int fake_dev;

hid_device *hid_open(unsigned short vid, unsigned short pid, const wchar_t *serial) {
  (void) vid; (void) pid; (void) serial;
  return (hid_device *) &fake_dev;
}

hid_device *hid_open_path(const char *path) {
  (void) path;
  return (hid_device *) &fake_dev;
}

struct hid_device_info *hid_enumerate(unsigned short vid, unsigned short pid) {
  (void) vid; (void) pid;
  return NULL;
}

void hid_free_enumeration(struct hid_device_info *devs) {
  (void) devs;
}

void hid_close(hid_device *dev) {
  (void) dev;
}

const wchar_t *hid_error(hid_device *dev) {
  (void) dev;
  return L"fuzz";
}

int hid_get_serial_number_string(hid_device *dev, wchar_t *string, size_t maxlen) {
  (void) dev;
  if(maxlen < 8)
    return -1;
  wcscpy(string, L"FUZZ001");
  return 0;
}

int hid_get_product_string(hid_device *dev, wchar_t *string, size_t maxlen) {
  (void) dev;
  if(maxlen < 64)
    return -1;
  mbstowcs(string, product, maxlen);
  return 0;
}

int hid_write(hid_device *dev, const unsigned char *data, size_t length) {
  (void) dev; (void) data;
  return (int) length;
}

int hid_read_timeout(hid_device *dev, unsigned char *data, size_t length, int ms) {
  (void) dev; (void) ms;
  if(in_pos >= in_size)
    return -1;                  // The device went away
  size_t n = in_data[in_pos++];
  if(n == 0 || n > length)
    n = length;
  if(n > in_size - in_pos)
    n = in_size - in_pos;
  memcpy(data, in_data + in_pos, n);
  in_pos += n;
  return (int) n;
}

int hid_read(hid_device *dev, unsigned char *data, size_t length) {
  return hid_read_timeout(dev, data, length, -1);
}

int hid_get_feature_report(hid_device *dev, unsigned char *data, size_t length) {
  (void) dev; (void) data; (void) length;
  return -1;
}

int hid_send_feature_report(hid_device *dev, const unsigned char *data, size_t length) {
  (void) dev; (void) data;
  return (int) length;
}

// The HID report descriptor is device data too (usb_hidapi.c parses it for the packet size)
int hid_get_report_descriptor(hid_device *dev, unsigned char *buf, size_t buf_size) {
  return hid_read_timeout(dev, buf, buf_size, 0);
}

int __wrap_usleep(useconds_t us) {
  (void) us;
  return 0;
}

int LLVMFuzzerInitialize(int *argc, char ***argv) {
  (void) argc; (void) argv;
  fuzz_init();
  for(int i = 0; i < 4; i++)
    parts_base[i] = fuzz_part(combos[i].part);
  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if(size < 1)
    return -1;
  int c = data[0] & 3;
  in_data = data + 1;
  in_size = size - 1;
  in_pos = 0;
  product = combos[c].product;

  Fuzz_session s;
  if(fuzz_session_open(&s, combos[c].pgm, parts_base[c], "usb") >= 0) {
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
