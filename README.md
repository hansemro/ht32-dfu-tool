ht32-dfu-tool: Holtek HT32 ISP Device Firmware Upgrade Tool
===========================================================

Compatability:
- HT32F1xxx
- HT32F52xxx

## Build

Build utility with cargo:
```
cargo build -r
```

## Usage

```
ht32-dfu-tool [OPTIONS] <COMMAND>

Commands:
  list                          List detected devices

  read <ADDR> <LENGTH> <FILE>   Read <LENGTH> bytes of flash starting at <ADDR> to
                                <FILE>

  write <ADDR> <FILE>           Write <FILE> to flash starting at <ADDR>

  info                          Check device info

  help                          Print this message or the help of the given subcommand(s)

Options:
  -d, --device <VID:PID>  <vendor_id>:<product_id> [default: 04d9:8010]
  -n, --devnum <DEV_NUM>  Match given device number in list
  -r, --reset             Reset after we're finished
  -m, --mass-erase        Mass-erase device before writing flash
  -v, --verify            Verify flash contents after writing flash
  -h, --help              Print help
  -V, --version           Print version
```
