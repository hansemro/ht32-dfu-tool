// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2023 Hansem Ro <hansemro@outlook.com>

mod device;
mod command;

use crate::device::HT32DeviceList;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

fn parse_vidpid(src: &str) -> Result<(u16, u16), std::num::ParseIntError> {
    let lower = src.to_lowercase();
    let mut split = lower.split(':')
        .map(|x| x.trim_start_matches("0x"));
    let vid = u16::from_str_radix(split.next().unwrap(), 16)?;
    let pid = u16::from_str_radix(split.next().unwrap(), 16)?;
    Ok((vid, pid))
}

fn parse_hex_or_dec(src: &str) -> Result<u32, std::num::ParseIntError> {
    let lower = src.to_lowercase();
    if lower.starts_with("0x") {
        let (_,num) = lower.split_at(2);
        Ok(u32::from_str_radix(num, 16)?)
    } else {
        Ok(lower.parse::<u32>()?)
    }
}

#[derive(Parser, Debug)]
#[command(author, version, about = "HT32 ISP DFU Tool", long_about = None)]
struct Args {
    /// <vendor_id>:<product_id>
    #[arg(short, long, value_parser(parse_vidpid), id = "VID:PID", default_value = "04d9:8010")]
    device: (u16, u16),
    /// Match given device number in list
    #[arg(short = 'n', long, id = "DEV_NUM")]
    devnum: Option<u32>,
    /// Wait for device to appear
    #[arg(short, long, action = clap::ArgAction::SetTrue)]
    wait: bool,

    /// Reset after we're finished
    #[arg(short, long, action = clap::ArgAction::SetTrue)]
    reset: bool,
    /// Mass-erase device before writing flash
    #[arg(short, long = "mass-erase", action = clap::ArgAction::SetTrue)]
    mass_erase: bool,
    /// Verify flash contents after writing flash
    #[arg(short, long, action = clap::ArgAction::SetTrue)]
    verify: bool,

    /// Number of bytes to read [default: rest of flash]"
    #[arg(short = 'c', value_parser(parse_hex_or_dec))]
    length: Option<u32>,

    #[command(subcommand)]
    action: Action
}

#[derive(Subcommand, Debug, PartialEq)]
enum Action {
    /// List detected devices
    List,
    /// Read flash starting at <ADDR> to <FILE>
    Read {
        /// Start address (use 0x prefix if hexadecimal)
        #[arg(value_parser(parse_hex_or_dec))]
        addr: u32,
        /// Output file path
        file: PathBuf,
    },
    /// Write <FILE> to flash starting at <ADDR>
    Write {
        /// Start address (use 0x prefix if hexadecimal)
        #[arg(value_parser(parse_hex_or_dec))]
        addr: u32,
        /// Input file path
        file: PathBuf,
    },
    /// Check device info
    Info,
    /// Reset to application firmware
    Reset,
    /// Reset to IAP (or ISP depending on BOOT pin(s))
    ResetIAP,
}

fn main() {
    let args = Args::parse();

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
        Action::Read { addr, file } => {
            let security_info = dev.get_security_info().expect("Unable to get device security status");
            assert!(!security_info.flash_security());
            let info = dev.get_info().expect("Unable to get device information");
            let length = if args.length.is_none() {
                info.flash_size() - addr
            } else {
                args.length.unwrap()
            };
            assert!(info.flash_size() >= addr + length);
            assert!(length >= 64);
            println!("Reading 0x{:04x}:0x{:04x} to {:?}...", addr, addr + length - 1, file);
            dev.read(&file, addr, length).expect("Read failed");
        }
        Action::Write { addr, file } => {
            let security_info = dev.get_security_info().expect("Unable to get device security status");
            if !args.mass_erase && security_info.flash_security() {
                panic!("Flash is secured. Mass-erase is required to write to flash.");
            }
            dev.write(&file, addr, args.mass_erase).expect("Write failed");
            if args.verify {
                dev.verify(&file, addr).expect("Flash verification failed");
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
