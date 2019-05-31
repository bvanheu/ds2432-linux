# ds2432-linux

Linux driver to interface with a DS2432 (family B3) over 1-wire.

## Requirements

### Archlinux

`pacman -S linux-headers`

### Raspbian

`apt-get install raspberrypi-kernel-headers`

## Building

Simple type `make`.

## Interacting with a DS2432

`insmod` the driver:

```
insmod ./w1_ds2432.ko
```

Then when connecting a DS2432 device, a new device will appear in the following
path: `/sys/bus/w1/devices/b3-xxxxxxxxxxxx`.

The following list of files will be created:

* `eeprom` : read/write data on the chip
* `secret` : 8 bytes, this key will be used when writing to write-protected device
* `secret_sync` : 1 byte, force the chip to use this key
* `write_protect_secret` : put the secret in write-protected mode
* `write_protect_pages_03` : put the eeprom in write-protected mode
* `user_byte` : read the user byte
* `factory_byte` : read the factory byte
* `eprom_mode_page1` :
* `write_protect_page0` :
* `manufacturer_id` :
* `registration_number` :


## Typical Usage

Reading the EEPROM:
```
# hexdump -C /sys/bus/w1/devices/b3-xxxxxxxxxxxx/eeprom
```

Writing to EEPROM:
```
# cp eeprom.bin /sys/bus/w1/devices/b3-xxxxxxxxxxxx/eeprom
```

Use the key `00112233445577` to write on the EEPROM:
```
# echo -e -n "\x00\x11\x22\x33\x44\x55\x66\x77" > /sys/bus/w1/devices/b3-xxxxxxxxxxxx/secret
# cp eeprom.bin /sys/bus/w1/devices/b3-xxxxxxxxxxxx/eeprom
```

Ask the chip to use the secret `aabbccddeeff1122`:
```
# echo -e -n "\xaa\xbb\xcc\xdd\xee\xff\x11\x22" > /sys/bus/w1/devices/b3-xxxxxxxxxxxx/secret
# echo -n 1 > /sys/bus/w1/devices/b3-xxxxxxxxxxxx/secret_sync
```
