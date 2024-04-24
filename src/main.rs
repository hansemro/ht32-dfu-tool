// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2023 Hansem Ro <hansemro@outlook.com>

mod command;
mod device;

use crate::device::HT32DeviceList;
use clap::{Parser, Subcommand, Args};
use std::path::PathBuf;

/// Attempt to parse the string `src` containing two hexadecimal numbers
/// separated by a colon.
fn parse_vidpid(src: &str) -> Result<(u16, u16), std::num::ParseIntError> {
    let lower = src.to_lowercase();
    let mut split = lower.split(':').map(|x| x.trim_start_matches("0x"));
    let vid = u16::from_str_radix(split.next().unwrap(), 16)?;
    let pid = u16::from_str_radix(split.next().unwrap(), 16)?;
    Ok((vid, pid))
}

/// Attempt to parse the string `src` as hexadecimal if it begins with "0x",
/// or as decimal otherwise.
fn parse_hex_or_dec(src: &str) -> Result<u32, std::num::ParseIntError> {
    let lower = src.to_lowercase();
    if lower.starts_with("0x") {
        let (_, num) = lower.split_at(2);
        Ok(u32::from_str_radix(num, 16)?)
    } else {
        Ok(lower.parse::<u32>()?)
    }
}

#[derive(Parser, Debug)]
#[command(author, version, about = "HT32 ISP DFU Tool", long_about = None)]
struct Cli {
    /// Specify vendor_id:product_id in hexadecimal
    #[arg(
        short,
        long,
        value_parser(parse_vidpid),
        id = "VID:PID",
        default_value = "04d9:8010"
    )]
    device: (u16, u16),
    /// Match given device number in list
    #[arg(short = 'n', long, id = "DEV_NUM")]
    devnum: Option<u32>,
    /// Wait for device to appear
    #[arg(short, long, action = clap::ArgAction::SetTrue)]
    wait: bool,

    /// Reset after performing command
    #[arg(short, long, action = clap::ArgAction::SetTrue)]
    reset: bool,

    #[command(subcommand)]
    action: Action,
}

#[derive(Subcommand, Debug, PartialEq)]
enum Action {
    /// List detected devices
    List,
    /// Check device info
    Info,
    /// Read flash starting at ADDR to FILE
    Read(ReadArgs),
    /// Write FILE to flash starting at ADDR
    Write(WriteArgs),
    /// Reset to application firmware
    Reset,
    /// Reset to IAP (or ISP depending on BOOT pin(s))
    ResetIAP,
}

#[derive(Args, Debug, PartialEq)]
struct ReadArgs {
    /// Start address (use 0x prefix if hexadecimal)
    #[arg(value_parser(parse_hex_or_dec))]
    addr: u32,
    /// Output file path
    file: PathBuf,
    /// Number of bytes to read [default: rest of flash]
    #[arg(short = 'c', value_parser(parse_hex_or_dec))]
    length: Option<u32>,
}

#[derive(Args, Debug, PartialEq)]
struct WriteArgs {
    /// Start address (use 0x prefix if hexadecimal)
    #[arg(value_parser(parse_hex_or_dec))]
    addr: u32,
    /// Input file path
    file: PathBuf,
    /// Enable flash security
    fs_en: Option<bool>,
    /// Enable option byte protection
    obp_en: Option<bool>,
    /// 32-bit page protection disable bitmask for pages 0-31
    #[arg(value_parser(parse_hex_or_dec))]
    pp0: Option<u32>,
    /// 32-bit page protection disable bitmask for pages 32-63
    #[arg(value_parser(parse_hex_or_dec))]
    pp1: Option<u32>,
    /// 32-bit page protection disable bitmask for pages 64-95
    #[arg(value_parser(parse_hex_or_dec))]
    pp2: Option<u32>,
    /// 32-bit page protection disable bitmask for pages 96-127
    #[arg(value_parser(parse_hex_or_dec))]
    pp3: Option<u32>,
    /// Mass erase
    #[arg(short, long = "mass_erase", action = clap::ArgAction::SetTrue)]
    mass_erase: bool,
    /// Verify flash contents after writing flash
    #[arg(short, long, action = clap::ArgAction::SetTrue)]
    verify: bool,

}

fn main() {
    let args = Cli::parse();

    let (vid, pid) = args.device;

    let mut ht32_devs = HT32DeviceList::new(vid, pid).expect("Failed to get device list");

    if args.action == Action::List {
        ht32_devs.print_list();
        return;
    }

    if args.wait {
        println!("Waiting for device...");
        while ht32_devs.len() == 0 {
            std::thread::sleep(std::time::Duration::from_millis(100));
            ht32_devs = HT32DeviceList::new(vid, pid).expect("Failed to get device list");
        }
    }

    if (ht32_devs.len() > 1) && args.devnum.is_none() {
        panic!("Multiple targets detected but no devnum is specified.");
    }

    let devnum = args.devnum.unwrap_or(0) as usize;
    if devnum >= ht32_devs.len() {
        panic!("Cannot find device {}. Check device list.", devnum);
    }

    let mut dev = ht32_devs.get_dev(devnum).unwrap();
    match dev.claim() {
        Ok(_) => println!("Claimed interface"),
        Err(e) => println!("{:?}", e),
    }

    match args.action {
        Action::List => (),
        Action::Read(read_args) => {
            let security_info = dev
                .get_security_info()
                .expect("Unable to get device security status");
            assert!(!security_info.flash_security());
            let info = dev.get_info().expect("Unable to get device information");
            let length = if read_args.length.is_none() {
                info.flash_size() - read_args.addr
            } else {
                read_args.length.unwrap()
            };
            assert!(info.flash_size() >= read_args.addr + length);
            assert!(length >= 64);
            dev.read(&read_args.file, read_args.addr, length).expect("Read failed");
        }
        Action::Write(write_args) => {
            match dev.write(&write_args.file, write_args.addr, write_args.mass_erase) {
                Ok(_) => (),
                Err(e) => match e {
                    device::Error::PageProtected(page_num) => {
                        panic!("Cannot erase or write to protected page: {}", page_num);
                    }
                    _ => panic!("Write failed"),
                },
            }
            if write_args.verify {
                dev.verify(&write_args.file, write_args.addr).expect("Flash verification failed");
            }
            if write_args.fs_en.is_some() {
                // default to no security or page protection
                let fs_en = write_args.fs_en.unwrap_or(false);
                let obp_en = write_args.obp_en.unwrap_or(false);
                let pp0 = write_args.pp0.unwrap_or(0xffffffff);
                let pp1 = write_args.pp1.unwrap_or(0xffffffff);
                let pp2 = write_args.pp2.unwrap_or(0xffffffff);
                let pp3 = write_args.pp3.unwrap_or(0xffffffff);
                dev.erase_write_option_bytes([pp0, pp1, pp2, pp3], fs_en, obp_en)
                    .expect("Failed to write option bytes");
            }
        }
        Action::Info => {
            println!("Getting device info...");
            dev.print_info().expect("Unable to get device information");
        }
        Action::Reset => {
            println!("Resetting...");
            dev.reset_app().ok();
            return;
        }
        Action::ResetIAP => {
            println!("Resetting to IAP/ISP...");
            dev.reset_iap().ok();
            return;
        }
    }

    if args.reset {
        // reset device
        match dev.reset_app() {
            Ok(_) => (),
            Err(_) => println!("Failed to reset device"),
        }
    }

    dev.release().ok();
}
