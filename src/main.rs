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

#[derive(Parser, Debug)]
#[command(author, version, about = "HT32 ISP DFU Tool", long_about = None)]
struct Args {
    /// <vendor_id>:<product_id>
    #[arg(short, long, value_parser(parse_vidpid), id = "VID:PID", default_value = "04d9:8010")]
    device: (u16, u16),
    /// Match given device number in list
    #[arg(short = 'n', long, id = "DEV_NUM")]
    devnum: Option<u32>,

    /// Reset after we're finished
    #[arg(short, long, action = clap::ArgAction::SetTrue)]
    reset: bool,
    /// Mass-erase device before writing flash
    #[arg(short, long = "mass-erase", action = clap::ArgAction::SetTrue)]
    mass_erase: bool,
    /// Verify flash contents after writing flash
    #[arg(short, long, action = clap::ArgAction::SetTrue)]
    verify: bool,

    #[command(subcommand)]
    action: Action
}

#[derive(Subcommand, Debug, PartialEq)]
enum Action {
    /// List detected devices
    List,
    /// Read <LENGTH> bytes of flash starting at <ADDR> to <FILE>
    Read {
        /// Address
        #[arg(help = "Start address")]
        addr: u32,
        #[arg(help = "Number of bytes to read")]
        length: u32,
        #[arg(help = "Output file path")]
        file: PathBuf,
    },
    /// Write <FILE> to flash starting at <ADDR>
    Write {
        #[arg(help = "Start address")]
        addr: u32,
        #[arg(help = "Input File path")]
        file: PathBuf,
    },
    /// Check device info
    Info,
}

fn main() {
    let args = Args::parse();

    let (vid, pid) = args.device;

    let mut ht32_devs = HT32DeviceList::new(vid, pid).expect("No HT32 ISP devices detected");

    if args.action == Action::List {
        ht32_devs.print_list();
        return;
    }

    if (ht32_devs.len() > 1) && args.devnum.is_none() {
        panic!("Multiple targets detected but no devnum is specified.");
    }

    let devnum = args.devnum.unwrap_or(0) as usize;
    if devnum >= ht32_devs.len() {
        panic!("Cannot find device devnum. Check device list.");
    }

    let mut dev = ht32_devs.get_dev(devnum).unwrap();
    match dev.claim() {
        Ok(_) => println!("Claimed interface"),
        Err(e) => println!("{:?}", e),
    }

    match args.action {
        Action::List => (),
        Action::Read { addr, length, file } => {
            let security_info = dev.get_security_info().expect("Unable to get device security status");
            assert!(!security_info.flash_security());
            let info = dev.get_info().expect("Unable to get device information");
            assert!(info.flash_size() >= addr + length);
            assert!(length > 0);
            println!("Reading 0x{:04x}:0x{:04x} to {:?}...", addr, addr + length - 1, file);
            dev.read(&file, addr, length).expect("Read failed");
        }
        Action::Write { addr, file } => {
            let security_info = dev.get_security_info().expect("Unable to get device security status");
            if !args.mass_erase && security_info.flash_security() {
                panic!("Flash is secured. Mass-erase is required to write to flash.");
            }
            if args.mass_erase {
                println!("Performing mass-erase...");
                dev.mass_erase().expect("Failed to perform mass-erase");
                println!("Resetting device...");
                dev.reset_reconnect().expect("Device failed to reconnect");
            }
            println!("Writing {:?} to 0x{:04x}...", file, addr);
            dev.write(&file, addr).expect("Write failed");
            println!("Writing finished");
            if args.verify {
                println!("Verifying flash...");
                dev.verify(&file, addr).expect("Flash verification failed");
                println!("Validated");
            }
        }
        Action::Info => {
            println!("Getting Device Info...");
            dev.print_info().expect("Unable to get device information");
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
