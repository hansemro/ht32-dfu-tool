ht32-dfu-tool
=============

A host-side DFU tool for Holtek HT32 devices in In-System Programming (ISP)
mode over USB.

Holtek HT32 processors feature a ROM ISP bootloader used for reprogramming
flash, setting flash security, and verifying integrity of flash via USB or
UART interface. By shorting the designated BOOT pin(s) and resetting, the
device will start in ISP bootloader and can be detected over USB. Refer to
the VMCR register in the Flash Memory Controller section in the User Manuals
to see which pins need to be shorted high/low to start in `Boot Loader` mode.

## Setup

### Dependencies

- libusb-1 (with headers)
- cargo/rustup

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

To permit HT32 device access by non-root users in the `plugdev` group, create
a udev rule file `/etc/udev/rules.d/99-ht32.rules` containing the following:

```
# Holtek HT32 ISP USB Interface
SUBSYSTEMS=="usb", ATTRS{idVendor}=="04d9", ATTRS{idProduct}=="8010", MODE="0660", GROUP="plugdev", TAG+="uaccess"
```

Restart your computer or reload udev rules by running the following commands:
```
sudo udevadm control --reload
sudo udevadm trigger
```

## Build from Source

Build the utility with cargo:
```
cd ht32-dfu-tool
cargo build -r
```

Target binary is located at `./target/release/ht32-dfu-tool[.exe]`.

## Usage Help

```
ht32-dfu-tool [OPTIONS] <COMMAND>

Commands:
  list                  List detected devices

  read <ADDR> <FILE>    Read flash starting at <ADDR> to <FILE>

  write <ADDR> <FILE> [FS_EN] [OBP_EN] [PP0] [PP1] [PP2] [PP3]
                        Write <FILE> to flash starting at <ADDR>, and
                        optionally set flash security, option byte protection,
                        and page protection.

  info                  Check device info
  reset                 Reset to application firmware
  reset-iap             Reset to IAP (or ISP depending on BOOT pin(s))

  help                  Print this message or the help of the given subcommand(s)

Options:
  -d, --device <VID:PID>  <vendor_id>:<product_id> [default: 04d9:8010]
  -n, --devnum <DEV_NUM>  Match given device number in list
  -w, --wait              Wait for device to appear
  -r, --reset             Reset after we're finished
  -m, --mass-erase        Mass-erase device before writing flash
  -v, --verify            Verify flash contents after writing flash
  -c <LENGTH>             Number of bytes to read [default: rest of flash]
  -h, --help              Print help
  -V, --version           Print version
```

## Notes about ISP

- Mass-erase wipes entire flash and disables security/protection, but is necessary for reprogramming locked devices.
- A reset occurs after a mass-erase, so keep the pins shorted until after the write finishes.
- Flash security prevents reading data from flash.

## License

Distributed under the [GPL-2.0 License](LICENSE).

- [crc-rs](https://github.com/mrhooray/crc-rs): MIT
- [clap](https://github.com/clap-rs/clap): MIT
- [indicatif](https://github.com/console-rs/indicatif): MIT
- [rusb](https://github.com/a1ien/rusb): MIT
