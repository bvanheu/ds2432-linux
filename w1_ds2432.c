/*
 *	w1_ds2432.c - w1 family B3 (DS2432) driver
 *
 * Copyright (c) 2017 Benjamin Vanheuverzwijn <bvanheu@gmail.com>
 *
 * This source code is licensed under the GNU General Public License,
 * Version 2. See the file COPYING for more details.
 */

#include <linux/crypto.h>
#include <linux/cryptohash.h>
#include <linux/delay.h>
#include <linux/device.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/w1.h>

#ifdef CONFIG_W1_SLAVE_DS2432_CRC
#include <linux/crc16.h>

#define CRC16_INIT      0
#define CRC16_VALID     0xb001

#endif

#define W1_EEPROM_DS2432                0xB3

#define DS2432_WRITE_SCRATCHPAD         0x0F
#define DS2432_READ_SCRATCHPAD          0xAA
#define DS2432_COPY_SCRATCHPAD          0x55
#define DS2432_LOAD_FIRST_SECRET        0x5A
#define DS2432_READ_AUTHENTICATED       0xA5
#define DS2432_READ_MEMORY              0xF0

// Memory map
#define W1_DS2432_PAGE_0_ADDR           0x00
#define W1_DS2432_PAGE_1_ADDR           0x20
#define W1_DS2432_PAGE_2_ADDR           0x40
#define W1_DS2432_PAGE_3_ADDR           0x60
#define W1_DS2432_PAGE_SIZE             0x20

#define W1_DS2432_SECRET_ADDR           0x80
#define W1_DS2432_SECRET_SIZE           0x10

#define W1_DS2432_REGISTER_PAGE_ADDR    0x88
#define W1_DS2432_REGISTER_PAGE_SIZE    0x10

#define W1_DS2432_DATA_MEMORY_SIZE      0x80

struct w1_b3_data {
  u8 secret[8];
  u8 registration_number[8];
};

// Compute the 160-bit MAC
//
// Note: This algorithm is the SHA-1 algorithm as specified in the
// datasheet for the DS1961S, where the last step of the official
// FIPS-180 SHA routine is omitted (which only involves the addition of
// constant values).

struct sha1 {
  u32 a;
  u32 b;
  u32 c;
  u32 d;
  u32 e;
};

#define f1(x, y, z) (z ^ (x & (y ^ z)))       /* x ? y : z */
#define f2(x, y, z) (x ^ y ^ z)               /* XOR */
#define f3(x, y, z) ((x & y) + (z & (x ^ y))) /* majority */

#define K1 0x5A827999L /* Rounds  0-19: sqrt(2) * 2^30 */
#define K2 0x6ED9EBA1L /* Rounds 20-39: sqrt(3) * 2^30 */
#define K3 0x8F1BBCDCL /* Rounds 40-59: sqrt(5) * 2^30 */
#define K4 0xCA62C1D6L /* Rounds 60-79: sqrt(10) * 2^30 */

void maxim_sha_transform(struct sha1 *sha1, const char *in) {
  u32 a, b, c, d, e, t, i;
  u32 workspace[80];

  for (i = 0; i < 16; i++) {
    workspace[i] = be32_to_cpu(((const __be32 *)in)[i]);
  }

  for (i = 0; i < 64; i++) {
    workspace[i + 16] = rol32(workspace[i + 13] ^ workspace[i + 8] ^
                                  workspace[i + 2] ^ workspace[i],
                              1);
  }

  a = 0x67452301;
  b = 0xefcdab89;
  c = 0x98badcfe;
  d = 0x10325476;
  e = 0xc3d2e1f0;

  for (i = 0; i < 20; i++) {
    t = f1(b, c, d) + K1 + rol32(a, 5) + e + workspace[i];
    e = d;
    d = c;
    c = rol32(b, 30);
    b = a;
    a = t;
  }

  for (; i < 40; i++) {
    t = f2(b, c, d) + K2 + rol32(a, 5) + e + workspace[i];
    e = d;
    d = c;
    c = rol32(b, 30);
    b = a;
    a = t;
  }

  for (; i < 60; i++) {
    t = f3(b, c, d) + K3 + rol32(a, 5) + e + workspace[i];
    e = d;
    d = c;
    c = rol32(b, 30);
    b = a;
    a = t;
  }

  for (; i < 80; i++) {
    t = f2(b, c, d) + K4 + rol32(a, 5) + e + workspace[i];
    e = d;
    d = c;
    c = rol32(b, 30);
    b = a;
    a = t;
  }

  sha1->a = a;
  sha1->b = b;
  sha1->c = c;
  sha1->d = d;
  sha1->e = e;
}

/**
 * Check the file size bounds and adjusts count as needed.
 * This would not be needed if the file size didn't reset to 0 after a write.
 */
static inline size_t w1_b3_fix_count(loff_t off, size_t count, size_t size) {
  if (off > size) {
    return 0;
  }

  if ((off + count) > size) {
    return (size - off);
  }

  return count;
}

static int w1_ds2432_read_memory(struct w1_slave *sl, int address, u8 *memory,
                                 size_t count) {
  u8 wrbuf[3];

  if (w1_reset_select_slave(sl)) {
    return -EIO;
  }

  // Command
  wrbuf[0] = DS2432_READ_MEMORY;
  // Target address
  wrbuf[1] = (u8)(address & 0xff);
  wrbuf[2] = (u8)(address >> 8);

  w1_write_block(sl->master, wrbuf, sizeof(wrbuf));
  w1_read_block(sl->master, memory, count);

  return 0;
}

static int w1_ds2432_write_scratchpad(struct w1_slave *sl, int address,
                                      const u8 *data) {
  u8 wrbuf[11] = {0};
  u16 ds2432_scratchpad_crc = 0;
  u16 my_scratchpad_crc = 0;

  if (w1_reset_select_slave(sl)) {
    return -EIO;
  }

  wrbuf[0] = DS2432_WRITE_SCRATCHPAD;
  wrbuf[1] = (u8)(address & 0xff);
  wrbuf[2] = (u8)(address >> 8);

  wrbuf[3] = data[0];
  wrbuf[4] = data[1];
  wrbuf[5] = data[2];
  wrbuf[6] = data[3];
  wrbuf[7] = data[4];
  wrbuf[8] = data[5];
  wrbuf[9] = data[6];
  wrbuf[10] = data[7];

  w1_write_block(sl->master, wrbuf, sizeof(wrbuf));

  // Read inverted CRC16
  w1_read_block(sl->master, (u8 *)&ds2432_scratchpad_crc, 2);

#ifdef CONFIG_W1_SLAVE_DS2432_CRC
  my_scratchpad_crc = crc16(0, wrbuf, sizeof(wrbuf));

  // Under certain conditions (see Write Scratchpad command) the master will
  // receive an inverted CRC16 of the command,
  ds2432_scratchpad_crc = ~ds2432_scratchpad_crc;

  if (my_scratchpad_crc != ds2432_scratchpad_crc) {
    dev_err(
        &sl->dev,
        "write_scratchpad: invalid checksum: received %04x but expected %04x\n",
        ds2432_scratchpad_crc, my_scratchpad_crc);
    return -EIO;
  }
#endif

  return 0;
}

static int w1_ds2432_read_scratchpad(struct w1_slave *sl, u16 *address, u8 *es,
                                     u8 *data) {
  u8 wrbuf[1] = {0};
  u8 rdbuf[3] = {0};
  u16 ds2432_scratchpad_crc = 0;
  u16 my_scratchpad_crc = 0;

  if (w1_reset_select_slave(sl)) {
    return -EIO;
  }

  // Command
  wrbuf[0] = DS2432_READ_SCRATCHPAD;

  // Write command
  w1_write_block(sl->master, wrbuf, 1);

  // Read TA1,TA2,ES
  w1_read_block(sl->master, rdbuf, 3);

  *address = ((u16)(rdbuf[1] << 8) | rdbuf[0]);
  *es = rdbuf[2];

  // Read the content of the scratchpad (8 bytes)
  w1_read_block(sl->master, data, 8);

  // Read inverted CRC16
  w1_read_block(sl->master, (u8 *)&ds2432_scratchpad_crc, 2);

#ifdef CONFIG_W1_SLAVE_DS2432_CRC
  my_scratchpad_crc = crc16(0, wrbuf, 1);
  my_scratchpad_crc = crc16(my_scratchpad_crc, rdbuf, 3);
  my_scratchpad_crc = crc16(my_scratchpad_crc, data, 8);

  // Under certain conditions (see Read Scratchpad command) the master will
  // receive an inverted CRC16 of the command,
  ds2432_scratchpad_crc = ~ds2432_scratchpad_crc;

  if (my_scratchpad_crc != ds2432_scratchpad_crc) {
    dev_err(
        &sl->dev,
        "read_scratchpad: invalid checksum: received %04x but expected %04x\n",
        ds2432_scratchpad_crc, my_scratchpad_crc);
    return -EIO;
  }
#endif

  return 0;
}

static int w1_ds2432_load_first_secret(struct w1_slave *sl, u16 address,
                                       u8 es) {
  u8 load_first_secret[4] = {0};
  u8 success;

  if (w1_reset_select_slave(sl)) {
    return -EIO;
  }

  load_first_secret[0] = DS2432_LOAD_FIRST_SECRET;
  load_first_secret[1] = address & 0xff;
  load_first_secret[2] = address >> 8;
  load_first_secret[3] = es;

  w1_write_block(sl->master, load_first_secret, sizeof(load_first_secret));

  // The device-internal data transfer takes 10 ms maximum during which the
  // voltage on the 1-Wire bus must not fall below 2.8V
  msleep(10);

  // A pattern of alternating 1s and 0s will be transmitted after the data has
  // been copied until the master issues a reset pulse.
  success = w1_read_8(sl->master);

  if (success != 0xAA && success != 0x55) {
    dev_err(&sl->dev, "unable to load_first_secret, code %02x\n", success);
    return -EIO;
  }

  return 0;
}

/**
 * Generate MAC for copy scratchpad operation
 *
 * secret: 8 bytes, actual secret
 * scratchpad: 8 bytes, scratchpad data
 * memory_page: page number (1 to 3 inclusive) or 0 for scratchpad
 * data_memory_page: the first 28 bytes of the addressed memory page
 * serial_number: device serial_number
 * sha1: generated MAC
 */
static void generate_mac(const u8 *secret, const u8 *scratchpad,
                         u16 memory_page, const u8 *data_memory_page,
                         const u8 *serial_number, struct sha1 *sha1,
                         struct w1_slave *sl) {
  u8 message[64] = {0};
  u8 i = 0;

  // First half of the secret.
  for (i = 0; i < 4; i++) {
    message[i] = secret[i];
  }

  // Data in the memory page.
  for (i = 4; i < 32; i++) {
    message[i] = data_memory_page[i - 4];
  }

  // Scratchpad content.
  for (i = 32; i < 40; i++) {
    message[i] = scratchpad[i - 32];
  }

  // Memory page number.
  // 	message[40] bit 7:4 = 0000 for Copy Scratchpad
  // 	message[40] bit 3:0 = T8:T5 (we only keep the upper part of the memory
  // page address)
  // message[40] = ((memory_page & 0x01e0) >> 5) & 0x0f;
  message[40] = ((memory_page & 0xf0) >> 5);

  // message[41] is family_code, which is conveniently the first byte of the
  // serial_number.
  for (i = 41; i < 48; i++) {
    message[i] = serial_number[i - 41];
  }

  // Second half of the secret.
  for (i = 48; i < 52; i++) {
    message[i] = secret[i - 44];
  }

  // Magic numbers taken from the datasheet.
  message[52] = 0xff;
  message[53] = 0xff;
  message[54] = 0xff;
  message[55] = 0x80;

  message[56] = 0x00;
  message[57] = 0x00;
  message[58] = 0x00;
  message[59] = 0x00;

  message[60] = 0x00;
  message[61] = 0x00;
  message[62] = 0x01;
  message[63] = 0xb8;

  maxim_sha_transform(sha1, message);
}

static int w1_ds2432_copy_scratchpad(struct w1_slave *sl, u16 address, u8 es,
                                     const struct sha1 *mac) {
  u8 copy_scratchpad[4] = {0};
  u8 copy_scratchpad_mac[20] = {0};
  u32 value = 0;
  u32 i = 0;
  u8 success = 0;

  if (w1_reset_select_slave(sl)) {
    return -EIO;
  }

  // Copy scratchpad command
  copy_scratchpad[0] = DS2432_COPY_SCRATCHPAD;
  copy_scratchpad[1] = (u8)(address & 0xff);
  copy_scratchpad[2] = (u8)((address >> 8) & 0xff);
  copy_scratchpad[3] = es;

  w1_write_block(sl->master, copy_scratchpad, 4);

  // Let enough time to the DS2432 to compute the SHA1.
  msleep(2);

  value = mac->e;
  for (i = 0; i < 4; i++) {
    copy_scratchpad_mac[i] = (u8)(value & 0xff);
    value = value >> 8;
  }

  value = mac->d;
  for (i = 0; i < 4; i++) {
    copy_scratchpad_mac[4 + i] = (u8)(value & 0xff);
    value = value >> 8;
  }

  value = mac->c;
  for (i = 0; i < 4; i++) {
    copy_scratchpad_mac[8 + i] = (u8)(value & 0xff);
    value = value >> 8;
  }

  value = mac->b;
  for (i = 0; i < 4; i++) {
    copy_scratchpad_mac[12 + i] = (u8)(value & 0xff);
    value = value >> 8;
  }

  value = mac->a;
  for (i = 0; i < 4; i++) {
    copy_scratchpad_mac[16 + i] = (u8)(value & 0xff);
    value = value >> 8;
  }

  w1_write_block(sl->master, copy_scratchpad_mac, 20);

  // Now the master waits for 10 ms during which the
  // voltage on the 1-Wire bus must not fall below 2.8V. If the MAC generated by
  // the DS2432 matches the MAC that the master computed, the DS2432 will set
  // its AA (Authorization Accepted) flag, and copy the entire scratchpad
  // contents to the data EEPROM. As indication for a successful copy the master
  // will be able to read a pattern of alternating 1's and 0's until it issues a
  // Reset Pulse. A pattern of all zeros tells the master that the copy did not
  // take place.

  msleep(10);

  // As indication for a successful copy the master will be
  // able to read a pattern of alternating 1s ands until it issues a Reset
  // Pulse.
  success = w1_read_8(sl->master);

  if (success == 0x00) {
    dev_err(&sl->dev, "unable to copy_scratchpad: invalid mac (code %02x)",
            success);
    // EACCES: mac is invalid, probably due to a bad key.
    return -EACCES;
  }

  if (success == 0xff) {
    dev_err(&sl->dev, "unable to copy_scratchpad: write protected (code %02x)",
            success);
    // EPERM: mac is valid but the chip is write protected.
    return -EPERM;
  }

  if (success != 0xAA && success != 0x55) {
    dev_err(&sl->dev, "unable to copy_scratchpad: unknown error (code %02x)",
            success);
    // EIO: unknown error, potentially i/o related.
    return -EIO;
  }

  return 0;
}

static int w1_ds2432_write_secret(struct w1_slave *sl, u8 *secret) {
  int error = 0;
  u16 address = 0;
  u8 es = 0;
  u8 data[8] = {0};

  if (w1_reset_select_slave(sl)) {
    // EIO: unable to select device.
    return -EIO;
  }

  // 1. Send a WRITE_SCRATCHPAD command to the buffer where the secret is
  // stored.
  error = w1_ds2432_write_scratchpad(sl, W1_DS2432_SECRET_ADDR, secret);
  if (error < 0) {
    return error;
  }

  // 2. Get the authorization pattern
  error = w1_ds2432_read_scratchpad(sl, &address, &es, data);
  if (error < 0) {
    return error;
  }

  if (address != W1_DS2432_SECRET_ADDR) {
    dev_err(&sl->dev, "unexpected address: %04x (expected %04x)\n", address,
            W1_DS2432_SECRET_ADDR);
    // EIO: invalid address, probably due to i/o.
    return -EIO;
  }

  if ((es >> 5) & 1) {
    dev_err(&sl->dev, "ES partial byte is 1\n");
    // EIO: invalid ES byte, probably due to i/o.
    return -EIO;
  }

  // 3. Transmit the Load First Secret
  error = w1_ds2432_load_first_secret(sl, address, es);
  if (error < 0) {
    return error;
  }

  w1_reset_bus(sl->master);

  return error;
}

//
// eeprom (page 0 to 3)
//

static ssize_t eeprom_read(struct file *filp, struct kobject *kobj,
                           struct bin_attribute *bin_attr, char *buf,
                           loff_t off, size_t count) {
  struct w1_slave *sl = kobj_to_w1_slave(kobj);

  if ((count = w1_b3_fix_count(off, count, W1_DS2432_DATA_MEMORY_SIZE)) == 0) {
    return 0;
  }

  mutex_lock(&sl->master->bus_mutex);

  if (w1_reset_select_slave(sl)) {
    count = -EIO;
    goto out_up;
  }

  w1_ds2432_read_memory(sl, off, buf, count);
out_up:
  mutex_unlock(&sl->master->bus_mutex);

  return count;
}

// Block-size are 8 bytes.
static int eeprom_write_block(struct w1_slave *sl, u16 address,
                              const u8 *data) {
  int error = 0;
  u16 sp_address = 0;
  u8 es = 0;
  u8 scratchpad[8] = {0};
  u8 data_memory_page[32] = {0};
  struct w1_b3_data *b3_data = sl->family_data;
  struct sha1 mac;

  // 1. Read the first 28 bytes of the target address to generate the MAC.
  error = w1_ds2432_read_memory(sl, (address / 32) * 32, data_memory_page,
                                sizeof(data_memory_page));
  if (error < 0) {
    return error;
  }

  // 2. Write data to the scratchpad.
  error = w1_ds2432_write_scratchpad(sl, address, data);
  if (error < 0) {
    return error;
  }

  // 3. Read back the scratchpad, making sure the data made it.
  error = w1_ds2432_read_scratchpad(sl, &sp_address, &es, scratchpad);
  if (error < 0) {
    return error;
  }

  if (sp_address != address) {
    dev_err(&sl->dev, "unexpected address: %04x (expected: %04x)\n", sp_address,
            address);
    // EIO: invalid address, probably due to i/o.
    return -EIO;
  }

  if ((es >> 5) & 1) {
    dev_err(&sl->dev, "ES partial byte is 1\n");
    // EIO: invalid ES byte, probably due to i/o issue.
    return -EIO;
  }

  if (memcmp(scratchpad, data, 8)) {
    dev_err(&sl->dev, "scratchpad data does not match\n");
    // EIO: data read is not equal to what was sent, probably due to i/o.
    return -EIO;
  }

  // 4. Generate MAC
  generate_mac(b3_data->secret, scratchpad, address, data_memory_page,
               b3_data->registration_number, &mac, sl);

  // 5. Issue copy scratchpad.
  error = w1_ds2432_copy_scratchpad(sl, sp_address, es, &mac);

  return error;
}

static ssize_t eeprom_write(struct file *filp, struct kobject *kobj,
                            struct bin_attribute *bin_attr, char *buf,
                            loff_t off, size_t count) {
  struct w1_slave *sl = kobj_to_w1_slave(kobj);
  int result = 0;
  u8 address = 0;

  mutex_lock(&sl->master->bus_mutex);

  if (w1_reset_select_slave(sl)) {
    count = -EIO;
    goto out_up;
  }

  // We can only write 8 bytes at a time
  while (address < count) {
    result = eeprom_write_block(sl, address, &buf[address]);
    if (result < 0) {
      count = result;
      goto out_up;
    }

    address += 8;
  }

out_up:
  mutex_unlock(&sl->master->bus_mutex);

  return count;
}

static BIN_ATTR_RW(eeprom, W1_DS2432_DATA_MEMORY_SIZE);

//
// SECRET MEMORY
//
// 0080h to 0087h - No read access; secret not required for write access
//

static ssize_t secret_read(struct file *filp, struct kobject *kobj,
                           struct bin_attribute *bin_attr, char *buf,
                           loff_t off, size_t count) {
  struct w1_slave *sl = kobj_to_w1_slave(kobj);
  struct w1_b3_data *b3_data = sl->family_data;

  memcpy(buf, b3_data->secret, 8);

  return 8;
}

static ssize_t secret_write(struct file *filp, struct kobject *kobj,
                            struct bin_attribute *bin_attr, char *buf,
                            loff_t off, size_t count) {
  struct w1_slave *sl = kobj_to_w1_slave(kobj);
  struct w1_b3_data *b3_data = sl->family_data;

  memcpy(b3_data->secret, buf, 8);

  return count;
}

static BIN_ATTR_RW(secret, 8);

static ssize_t secret_sync_read(struct file *filp, struct kobject *kobj,
                                struct bin_attribute *bin_attr, char *buf,
                                loff_t off, size_t count) {
  // secret_sync is not readable.
  return 0;
}

static ssize_t secret_sync_write(struct file *filp, struct kobject *kobj,
                                 struct bin_attribute *bin_attr, char *buf,
                                 loff_t off, size_t count) {
  struct w1_slave *sl = kobj_to_w1_slave(kobj);
  struct w1_b3_data *b3_data = sl->family_data;

  mutex_lock(&sl->master->bus_mutex);

  if (w1_reset_select_slave(sl)) {
    count = -EIO;
    goto out_up;
  }

  w1_ds2432_write_secret(sl, b3_data->secret);

out_up:
  mutex_unlock(&sl->master->bus_mutex);

  return count;
}

static BIN_ATTR_RW(secret_sync, 1);

//
// REGISTER PAGE
//
// 0088h Write-protect secret, 008Ch to 008Fh - Protection activated by code AAh
// or 55h 0089h Write-protect pages 0 to 3 - Protection activated by code AAh or
// 55h 008Ah User byte, self-protecting - Protection activated by code AAh or
// 55h 008Bh Factory byte (read only) - Reads either AAh or 55h 008Ch User
// byte/EPROM mode control for page 1Mode - activated by code AAh or 55h 008Dh
// User byte/Write-protect page 0 only - Protection activated by code AAh or 55h
// 008Eh to 008Fh User Bytes/Manufacturer ID - Function depends on factory byte
// 0090h to 0097h 64-Bit Registration Number (Alternate readout)
//

static ssize_t register_page_read(struct file *filp, struct kobject *kobj,
                                  struct bin_attribute *bin_attr, char *buf,
                                  loff_t off, size_t count) {
  struct w1_slave *sl = kobj_to_w1_slave(kobj);

  mutex_lock(&sl->master->bus_mutex);

  if (w1_ds2432_read_memory(sl, W1_DS2432_REGISTER_PAGE_ADDR + off, buf,
                            W1_DS2432_REGISTER_PAGE_SIZE)) {
    dev_err(&sl->dev, "unable to read register page\n");
    count = -EIO;
    goto out_up;
  }

  // Reset the bus to wake up the EEPROM (this may not be needed)
  w1_reset_bus(sl->master);

out_up:
  mutex_unlock(&sl->master->bus_mutex);

  return count;
}

static BIN_ATTR_RO(register_page, W1_DS2432_REGISTER_PAGE_SIZE);

//
// Register page - write protect secret
// 0088h Write-protect secret - Protection activated by code AAh or 55h
//

static ssize_t write_protect_secret_read(struct file *filp,
                                         struct kobject *kobj,
                                         struct bin_attribute *bin_attr,
                                         char *buf, loff_t off, size_t count) {
  struct w1_slave *sl = kobj_to_w1_slave(kobj);

  mutex_lock(&sl->master->bus_mutex);

  if (w1_reset_select_slave(sl)) {
    count = -EIO;
    goto out_up;
  }

  w1_ds2432_read_memory(sl, W1_DS2432_REGISTER_PAGE_ADDR + 0 + off, buf, count);
out_up:
  mutex_unlock(&sl->master->bus_mutex);

  return count;
}

static ssize_t write_protect_secret_write(struct file *filp,
                                          struct kobject *kobj,
                                          struct bin_attribute *bin_attr,
                                          char *buf, loff_t off, size_t count) {
  return 0;
}

static BIN_ATTR_RW(write_protect_secret, 1);

//
// Register page - write protect page 0-3
// 0089h Write-protect pages 0 to 3 - Protection activated by code AAh or 55h
//

static ssize_t write_protect_pages_03_read(struct file *filp,
                                           struct kobject *kobj,
                                           struct bin_attribute *bin_attr,
                                           char *buf, loff_t off,
                                           size_t count) {
  struct w1_slave *sl = kobj_to_w1_slave(kobj);

  u8 write_protected[1];

  mutex_lock(&sl->master->bus_mutex);

  if (w1_ds2432_read_memory(sl, W1_DS2432_REGISTER_PAGE_ADDR + 1 + off,
                            write_protected, sizeof(write_protected))) {
    dev_err(&sl->dev, "unable to read memory\n");
    count = -EIO;
    goto out_up;
  }

  // This field is only 1byte
  count = 1;

  // '0': disabled
  buf[0] = '0';
  if (write_protected[0] == 0x55 || write_protected[0] == 0xAA) {
    // '1': enabled
    buf[0] = '1';
  }

  // Reset the bus to wake up the EEPROM (this may not be needed)
  w1_reset_bus(sl->master);

out_up:
  mutex_unlock(&sl->master->bus_mutex);

  return count;
}

static ssize_t write_protect_pages_03_write(struct file *filp,
                                            struct kobject *kobj,
                                            struct bin_attribute *bin_attr,
                                            char *buf, loff_t off,
                                            size_t count) {
  return 0;
}

static BIN_ATTR_RW(write_protect_pages_03, 1);

//
// Register page - user byte
// 008Ah User byte, self-protecting - Protection activated by code AAh or 55h
//

static ssize_t user_byte_read(struct file *filp, struct kobject *kobj,
                              struct bin_attribute *bin_attr, char *buf,
                              loff_t off, size_t count) {
  struct w1_slave *sl = kobj_to_w1_slave(kobj);

  mutex_lock(&sl->master->bus_mutex);

  if (w1_reset_select_slave(sl)) {
    count = -EIO;
    goto out_up;
  }

  w1_ds2432_read_memory(sl, W1_DS2432_REGISTER_PAGE_ADDR + 2 + off, buf, count);
out_up:
  mutex_unlock(&sl->master->bus_mutex);

  return count;
}

static ssize_t user_byte_write(struct file *filp, struct kobject *kobj,
                               struct bin_attribute *bin_attr, char *buf,
                               loff_t off, size_t count) {
  return 0;
}

static BIN_ATTR_RW(user_byte, 1);

//
// Register page - factory byte (read only)
// 008Bh Factory byte (read only) - Reads either AAh or 55h
//

static ssize_t factory_byte_read(struct file *filp, struct kobject *kobj,
                                 struct bin_attribute *bin_attr, char *buf,
                                 loff_t off, size_t count) {
  struct w1_slave *sl = kobj_to_w1_slave(kobj);

  mutex_lock(&sl->master->bus_mutex);

  if (w1_reset_select_slave(sl)) {
    count = -EIO;
    goto out_up;
  }

  w1_ds2432_read_memory(sl, W1_DS2432_REGISTER_PAGE_ADDR + 3 + off, buf, count);
out_up:
  mutex_unlock(&sl->master->bus_mutex);

  return count;
}

static BIN_ATTR_RO(factory_byte, 1);

//
// Register page - EPROM mode for page 1
// 008Ch User byte/EPROM mode control for page 1 - Mode activated by code AAh or
// 55h
//

static ssize_t eprom_mode_page_1_read(struct file *filp, struct kobject *kobj,
                                      struct bin_attribute *bin_attr, char *buf,
                                      loff_t off, size_t count) {
  return 0;
}

static ssize_t eprom_mode_page_1_write(struct file *filp, struct kobject *kobj,
                                       struct bin_attribute *bin_attr,
                                       char *buf, loff_t off, size_t count) {
  return 0;
}

static BIN_ATTR_RW(eprom_mode_page_1, 1);

//
// Register page - write protect page 0
// 008Dh User byte/Write-protect page 0 only - Protection activated by code AAh
// or 55h
//

static ssize_t write_protect_page_0_read(struct file *filp,
                                         struct kobject *kobj,
                                         struct bin_attribute *bin_attr,
                                         char *buf, loff_t off, size_t count) {
  return 0;
}

static ssize_t write_protect_page_0_write(struct file *filp,
                                          struct kobject *kobj,
                                          struct bin_attribute *bin_attr,
                                          char *buf, loff_t off, size_t count) {
  return 0;
}

static BIN_ATTR_RW(write_protect_page_0, 1);

//
// Register page - manufacturer id
// 008Eh to 008Fh User Bytes/Manufacturer ID - Function depends on factory byte
//

static ssize_t manufacturer_id_read(struct file *filp, struct kobject *kobj,
                                    struct bin_attribute *bin_attr, char *buf,
                                    loff_t off, size_t count) {
  struct w1_slave *sl = kobj_to_w1_slave(kobj);

  mutex_lock(&sl->master->bus_mutex);

  if (w1_reset_select_slave(sl)) {
    count = -EIO;
    goto out_up;
  }

  w1_ds2432_read_memory(sl, W1_DS2432_REGISTER_PAGE_ADDR + 6 + off, buf, count);
out_up:
  mutex_unlock(&sl->master->bus_mutex);

  return count;
}

static ssize_t manufacturer_id_write(struct file *filp, struct kobject *kobj,
                                     struct bin_attribute *bin_attr, char *buf,
                                     loff_t off, size_t count) {
  return 0;
}

static BIN_ATTR_RW(manufacturer_id, 2);

//
// Register page - registration number
// 0090h to 0097h 64-Bit Registration Number (Alternate readout)
//

static ssize_t registration_number_read(struct file *filp, struct kobject *kobj,
                                        struct bin_attribute *bin_attr,
                                        char *buf, loff_t off, size_t count) {
  struct w1_slave *sl = kobj_to_w1_slave(kobj);

  mutex_lock(&sl->master->bus_mutex);

  if (w1_reset_select_slave(sl)) {
    count = -EIO;
    goto out_up;
  }

  w1_ds2432_read_memory(sl, W1_DS2432_REGISTER_PAGE_ADDR + 8 + off, buf, count);
out_up:
  mutex_unlock(&sl->master->bus_mutex);

  return count;
}

static BIN_ATTR_RO(registration_number, 8);

static struct bin_attribute *w1_ds2432_bin_attributes[] = {
    &bin_attr_eeprom,
    &bin_attr_secret,
    &bin_attr_secret_sync,
    &bin_attr_register_page,
    // Register page break-down
    &bin_attr_write_protect_secret,
    &bin_attr_write_protect_pages_03,
    &bin_attr_user_byte,
    &bin_attr_factory_byte,
    &bin_attr_eprom_mode_page_1,
    &bin_attr_write_protect_page_0,
    &bin_attr_manufacturer_id,
    &bin_attr_registration_number,
    NULL,
};

static const struct attribute_group w1_ds2432_group = {
    .bin_attrs = w1_ds2432_bin_attributes,
};

static const struct attribute_group *w1_b3_groups[] = {
    &w1_ds2432_group,
    NULL,
};

static int w1_b3_add_slave(struct w1_slave *sl) {
  struct w1_b3_data *data;

  data = kzalloc(sizeof(struct w1_b3_data), GFP_KERNEL);
  if (!data) {
    return -ENOMEM;
  }

  sl->family_data = data;

  memcpy(data->registration_number, &sl->reg_num, 8);

  return 0;
}

static void w1_b3_remove_slave(struct w1_slave *sl) {
  kfree(sl->family_data);
  sl->family_data = NULL;
}

static struct w1_family_ops w1_b3_fops = {
    .add_slave      = w1_b3_add_slave,
    .remove_slave   = w1_b3_remove_slave,
    .groups         = w1_b3_groups,
};

static struct w1_family w1_family_b3 = {
    .fid    = W1_EEPROM_DS2432,
    .fops   = &w1_b3_fops,
};

module_w1_family(w1_family_b3);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Benjamin Vanheuverzwijn <bvanheu@gmail.com>");
MODULE_DESCRIPTION("w1 family b3 driver for DS2432, 1kb EEPROM");
MODULE_ALIAS("w1-family-" __stringify(W1_EEPROM_DS2432));
