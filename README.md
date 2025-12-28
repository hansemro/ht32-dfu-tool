ht32-dfu-tool
=============

A host-side DFU tool for Holtek HT32 devices in In-System Programming (ISP)
mode over USB.

## Host Setup (Linux/BSD, macOS, Windows)

### Dependencies

- libusb-1 (with headers)
- rust toolchain with cargo

### Windows Development Setup (MSYS2/MINGW64)

1. Install MSYS2 from https://www.msys2.org/

2. Update MSYS2 environment (from `MSYS2 MINGW64` console):

```bash
pacman -Syu
```

3. Install build tools and dependencies:

```bash
pacman -S base-devel \
        mingw-w64-x86_64-toolchain \
        mingw-w64-x86_64-rust \
        mingw-w64-x86_64-libusb
```

### Linux Udev Rule

To permit HT32 device access to regular users, create a udev rule file
`/etc/udev/rules.d/50-ht32.rules` containing the following:

```
# Holtek HT32 ISP USB Interface
ACTION!="remove", SUBSYSTEMS=="usb", ATTRS{idVendor}=="04d9", ATTRS{idProduct}=="8010", MODE="0660", TAG+="uaccess"
```

Restart your computer or reload udev rules by running the following commands:

```
sudo udevadm control --reload
sudo udevadm trigger
```

## Installation

Run the following to install directly from git repo:

```
cargo install --git https://github.com/hansemro/ht32-dfu-tool
```

To build and install from source directory, run instead:

```
cd ht32-dfu-tool
cargo install --path .
```

## Usage Help

```
ht32-dfu-tool [OPTIONS] <COMMAND> [COMMAND_OPTIONS]

Commands:
  list                  List detected devices

  info                  Print device info including model, ISP version, page
                        size, flash size, flash security status, option byte
                        protection status, and PP0:PP3 page protection bits.

  read [-c <LENGTH_IN_BYTES>] <ADDR> <FILE>
                        Read flash starting at ADDR to FILE.

                        Unless the -c option is specified to read a specific
                        length of flash in bytes, flash will be read until the
                        end of flash.

  write [-m] [-v] <ADDR> <FILE> [FS_EN] [OBP_EN] [PP0] [PP1] [PP2] [PP3]
                        Program binary FILE to flash starting at ADDR by first
                        erasing pages of flash that will be written, writing to
                        flash, and, optionally, verify flash contents and/or
                        set flash security, option byte protection, and page
                        protection.

                        By default, a page erase is performed over any pages
                        that will be written. However, if the -m or
                        --mass-erase option is specified, then all flash pages
                        including the option byte page will be erased and then
                        followed by a reset to apply flash security changes.

                        If -v or --verify option is specified, then the written
                        region of flash will be validated after writing.

                        Set FS_EN to true/false to enable/disable Flash
                        Security.

                        Set OBP_EN to true/false to enable/disable Option Byte
                        Protection.

                        The arguments PP0-PP3 are 32-bit values where each bit
                        corresponds to a page, with PP0 setting page protection
                        for pages 0-31, PP1 for pages 32-63, and so on. Setting
                        the n-th bit in the respective argument to 1/0
                        disables/enables page protection for the corresponding
                        page. By default, no pages are protected with PP0-PP3
                        each set to 0xffffffff.

  reset                 Reset to application firmware

  reset-iap             Reset to IAP (or ISP depending on how HT32 device is
                        configured to boot)

  help                  Print this message or the help of the given subcommand(s)

Options:
  -d, --device <VID:PID>  Specify vendor_id:product_id in hexadecimal [default: 04d9:8010]
  -n, --devnum <DEV_NUM>  Match given device number in list
  -w, --wait              Wait for device to appear
  -r, --reset             Reset after performing command
  -h, --help              Print help
  -V, --version           Print version
```

## Supported Targets

Tested with HT32F165x and HT32F523xx. Should work with other HT32 MCUs over USB with similar ISP
command interface. Refer to user manual on booting configuration to learn more about how to boot
into ISP mode.

## License

Distributed under the [GPL-2.0-or-later License](LICENSE).

- [crc-rs](https://github.com/mrhooray/crc-rs): MIT
- [clap](https://github.com/clap-rs/clap): MIT
- [indicatif](https://github.com/console-rs/indicatif): MIT
- [rusb](https://github.com/a1ien/rusb): MIT
