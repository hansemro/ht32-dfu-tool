ht32-dfu-tool
=============

A host-side DFU tool for Holtek HT32 devices in ISP mode over USB.

Holtek HT32 processors feature a ROM ISP bootloader used for reprogramming
flash, setting flash security, and verifying integrity of flash via USB or
UART interface. By shorting the designated BOOT pin(s) and resetting, the
device will start in ISP bootloader and can be detected over USB. Refer to
the VMCR register in the Flash Memory Controller section in the User Manuals,
to see which pins need to be shorted high/low to start in `Boot Loader` mode.

## Build

Build utility with cargo:
```
cargo build -r
```

## Usage Help

```
ht32-dfu-tool [OPTIONS] <COMMAND>

Commands:
  list                          List detected devices

  read <ADDR> <FILE>            Read flash starting at <ADDR> to <FILE>

  write <ADDR> <FILE>           Write <FILE> to flash starting at <ADDR>

  info                          Check device info

  help                          Print this message or the help of the given subcommand(s)

Options:
  -d, --device <VID:PID>  <vendor_id>:<product_id> [default: 04d9:8010]
  -n, --devnum <DEV_NUM>  Match given device number in list
  -r, --reset             Reset after we're finished
  -m, --mass-erase        Mass-erase device before writing flash
  -v, --verify            Verify flash contents after writing flash
  -c <LENGTH>             Number of bytes to read [default: entire flash]
  -h, --help              Print help
  -V, --version           Print version
```

## Notes about ISP

- Mass-erase wipes entire flash and disables security/protection, but is necessary for reprogramming locked devices.
- Device does not reboot to ISP if resetting while the pins are not shorted correctly.
    - A reset occurs after a mass-erase, so keep the pins shorted until after the write finishes.
- Flash security prevents reading data from flash.
