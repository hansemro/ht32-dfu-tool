// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2023 Hansem Ro <hansemro@outlook.com>

use crate::command::HT32ISPCommand;
use std::time::Duration;
use std::fs::File;
use std::io::{Read, Write};
use std::path::PathBuf;
use crc16::{State, XMODEM};
use indicatif::{ProgressBar, ProgressState, ProgressStyle};

#[derive(Debug)]
pub enum Error {
    UsbError(rusb::Error),
    DeviceNotFound,
    EndpointNotFound,
    ReconnectFailed,
    FileError(std::io::Error),
    InvalidFilePath,
    WriteFailed,
    CheckFailed,
    OptionBytePageProtected,
    PageProtected(u8),
}

pub struct HT32ISPInfo {
    model: u32,
    version: u16,
    page_size: u16,
    flash_size: u32,
}

impl HT32ISPInfo {
    pub fn model(&self) -> u32 {
        self.model
    }

    pub fn version(&self) -> u16 {
        self.version
    }

    pub fn page_size(&self) -> u16 {
        self.page_size
    }

    pub fn flash_size(&self) -> u32 {
        self.flash_size
    }
}

pub const OB_ADDR: u32 = 0x1ff00000;

pub struct HT32Security {
    flash_security: bool,
    option_byte_protection: bool,
    page_protection: [u32; 4],
}

impl HT32Security {
    /// Flash read and JTAG protection
    pub fn flash_security(&self) -> bool {
        self.flash_security
    }

    /// Option byte page protection
    pub fn option_byte_protection(&self) -> bool {
        self.option_byte_protection
    }

    /// Page protection
    pub fn page_protection(&self) -> [u32; 4] {
        self.page_protection
    }
}

pub struct HT32ISPDevice {
    handle: Option<rusb::DeviceHandle<rusb::GlobalContext>>,
    vid: u16,
    pid: u16,
    bus_number: u8,
    port_number: u8,
    interface: u8,
    ep_in: u8,
    ep_out: u8,

    info: Option<HT32ISPInfo>,
    security_info: Option<HT32Security>,
}

/// HT32 device in ISP mode
impl HT32ISPDevice {
    pub fn new(device: rusb::Device<rusb::GlobalContext>, vid: u16, pid: u16) -> Result<Self, Error> {
        // Find endpoints
        let mut ep_in: Option<u8> = None;
        let mut ep_out: Option<u8> = None;
        let mut interface: Option<u8> = None;
        let device_desc = device.device_descriptor() 
            .map_err(Error::UsbError)?;
        'outer: for n in 0..device_desc.num_configurations() {
            let config_desc = device.config_descriptor(n)
                .map_err(Error::UsbError)?;
            for iface in config_desc.interfaces() {
                for iface_desc in iface.descriptors() {
                    for ep_desc in iface_desc.endpoint_descriptors() {
                        if ep_in.is_none()
                            && ep_desc.direction() == rusb::Direction::In
                            && ep_desc.transfer_type() == rusb::TransferType::Interrupt
                            && ep_desc.max_packet_size() == 64
                        {
                            if interface.is_none() {
                                interface = Some(iface.number());
                            }
                            ep_in = Some(ep_desc.address());
                        } else if ep_out.is_none()
                            && ep_desc.direction() == rusb::Direction::Out
                            && ep_desc.transfer_type() == rusb::TransferType::Interrupt
                            && ep_desc.max_packet_size() == 64
                        {
                            if interface.is_none() {
                                interface = Some(iface.number());
                            }
                            ep_out = Some(ep_desc.address());
                        }
                        if ep_in.is_some() && ep_out.is_some() {
                            break 'outer;
                        }
                    }
                }
            }
        }
        if interface.is_none() || ep_in.is_none() || ep_out.is_none() {
            return Err(Error::EndpointNotFound);
        }
        Ok(Self {
            handle: Some(device.open().map_err(Error::UsbError)?),
            vid,
            pid,
            bus_number: device.bus_number(),
            port_number: device.port_number(),
            interface: interface.unwrap(),
            ep_in: ep_in.unwrap(),
            ep_out: ep_out.unwrap(),
            info: None,
            security_info: None,
        })
    }

    /// Attempt to claim device
    pub fn claim(&mut self) -> Result<(), Error> {
        self.handle.as_mut().ok_or(Error::DeviceNotFound)?
            .set_auto_detach_kernel_driver(true).ok();
        self.handle.as_mut().ok_or(Error::DeviceNotFound)?
            .claim_interface(self.interface)
            .map_err(Error::UsbError)?;
        Ok(())
    }

    /// Attempt to release device
    pub fn release(&mut self) -> Result<(), Error> {
        self.handle.as_mut().ok_or(Error::DeviceNotFound)?
            .set_auto_detach_kernel_driver(false).ok();
        self.handle.as_mut().ok_or(Error::DeviceNotFound)?.release_interface(self.interface)
            .map_err(Error::UsbError)?;
        Ok(())
    }

    /// Send `cmd` to ISP device at its output endpoint and returns the number
    /// of bytes successfully transmitted.
    fn send_cmd(&self, cmd: &[u8]) -> Result<usize, Error> {
        // update CRC region
        let mut _cmd = [0u8; 64];
        _cmd[..].copy_from_slice(cmd);
        _cmd[2] = 0;
        _cmd[3] = 0;
        let crc = State::<XMODEM>::calculate(&_cmd);
        _cmd[2] = crc as u8;
        _cmd[3] = (crc >> 8) as u8;
        self.handle.as_ref().ok_or(Error::DeviceNotFound)?
            .write_interrupt(self.ep_out, &_cmd, Duration::new(1, 0))
            .map_err(Error::UsbError)
    }

    /// Attempt to read data from device's input endpoint
    fn recv(&self, buf: &mut [u8]) -> Result<usize, Error> {
        self.handle.as_ref().ok_or(Error::DeviceNotFound)?
            .read_interrupt(self.ep_in, buf, Duration::new(1, 0))
            .map_err(Error::UsbError)
    }

    /// Send `cmd` to device and get its `response`
    fn send_recv_cmd(&self, cmd: &[u8], response: &mut [u8])
            -> Result<(usize, usize), Error> {
        Ok((self.send_cmd(cmd)?, self.recv(response)?))
    }

    /// Attempt GET_REPORT request
    pub fn get_report(&self, response: &mut [u8]) -> Result<(u32, u32), Error> {
        // Get_Report request (USB HID version v1.11 spec)
        self.handle.as_ref().ok_or(Error::DeviceNotFound)?
            .read_control(
            /* bmRequest */ rusb::request_type(
                                rusb::Direction::In,
                                rusb::RequestType::Class,
                                rusb::Recipient::Interface),
            /* bRequest */  0x01,
            /* wValue */    0x0100,
            /* wIndex */    self.interface as u16,
                            response,
                            Duration::new(1, 0))
            .map_err(Error::UsbError)?;
        let mut passed = 0;
        let mut failed = 0;
        for n in response {
            if *n == 0x4f {
                passed += 1;
            } else if *n == 0x46 {
                failed += 1;
            }
        }
        Ok((passed, failed))
    }

    /// Get device information including model, ISP version, page size, and
    /// flash size.
    pub fn get_info(&mut self) -> Result<&HT32ISPInfo, Error> {
        if self.info.is_none() {
            let cmd: [u8; 64] = HT32ISPCommand::info_cmd().into();
            let mut info = [0u8; 64];
            self.send_recv_cmd(&cmd[..], &mut info[..])?;
            let version: u16 = (info[2] as u16) | ((info[3] as u16) << 8);
            let model: u32 = match version {
                0x100 => {
                    (info[0] as u32) | ((info[1] as u32) << 8)
                }
                0x101 => {
                    (info[16] as u32) |
                        ((info[17] as u32) << 8) |
                        ((info[18] as u32) << 16) |
                        ((info[19] as u32) << 24)
                }
                _ => 0
            };
            let page_size: u16 = (info[6] as u16) | ((info[7] as u16) << 8);
            let flash_page_count: u16 = (info[8] as u16) | ((info[9] as u16) << 8);
            let flash_size: u32 = page_size as u32 * flash_page_count as u32;
            self.info = Some(HT32ISPInfo {
                model,
                version,
                page_size,
                flash_size
            });
        }
        Ok(self.info.as_ref().unwrap())
    }

    /// Get device flash security and option byte protection status.
    pub fn get_security_info(&mut self) -> Result<&HT32Security, Error> {
        if self.security_info.is_none() {
            let cmd: [u8; 64] = HT32ISPCommand::read_flash_cmd(OB_ADDR, 64).into();
            let mut buf = [0u8; 64];
            self.send_recv_cmd(&cmd[..], &mut buf[..])?;
            // security/protection is enabled when bit is 0
            let flash_security = (buf[16] & 1) == 0;
            let option_byte_protection = (buf[16] & 2) == 0;
            let page_protection_0: u32 = (buf[0] as u32) |
                    ((buf[1] as u32) << 8) |
                    ((buf[2] as u32) << 16) |
                    ((buf[3] as u32) << 24);
            let page_protection_1: u32 = (buf[4] as u32) |
                    ((buf[5] as u32) << 8) |
                    ((buf[6] as u32) << 16) |
                    ((buf[7] as u32) << 24);
            let page_protection_2: u32 = (buf[8] as u32) |
                    ((buf[9] as u32) << 8) |
                    ((buf[10] as u32) << 16) |
                    ((buf[11] as u32) << 24);
            let page_protection_3: u32 = (buf[12] as u32) |
                    ((buf[13] as u32) << 8) |
                    ((buf[14] as u32) << 16) |
                    ((buf[15] as u32) << 24);
            self.security_info = Some(HT32Security {
                flash_security, 
                option_byte_protection,
                page_protection: [
                    page_protection_0,
                    page_protection_1,
                    page_protection_2,
                    page_protection_3
                ]
            });
        }
        Ok(self.security_info.as_ref().unwrap())
    }

    /// Print device information
    pub fn print_info(&mut self) -> Result<(), Error> {
        let info = self.get_info()?;
        if info.model() != 0 {
            println!("Model: HT32F{:x}", info.model());
        } else {
            println!("Model: unknown");
        }
        println!("Version: v{:x}", info.version());
        println!("Page size: {} B", info.page_size());
        println!("Flash size: {} B", info.flash_size());
        let info = self.get_security_info()?;
        println!("Flash security: {}", info.flash_security());
        println!("Option byte protection: {}", info.option_byte_protection());
        let page_protection = info.page_protection();
        println!("Page protection: 0x{:08x} 0x{:08x} 0x{:08x} 0x{:08x}",
                 page_protection[0],
                 page_protection[1],
                 page_protection[2],
                 page_protection[3]);
        Ok(())
    }

    /// Reset device and attempt to reconnect device
    pub fn reset_reconnect(&mut self) -> Result<(), Error> {
        self.reset_iap()?;
        println!("Waiting for device to reconnect...");

        std::thread::sleep(Duration::new(3, 0));
        // Attempt to reconnect by locating new device handle based on previous
        // bus and port numbers. This works only if BOOT pin(s) are configured
        // to boot into ISP.
        let mut dev_list = rusb::DeviceList::new()
            .map_err(Error::UsbError)?
            .iter()
            .filter(|dev| {
                if (dev.bus_number() == self.bus_number)
                    && (dev.port_number() == self.port_number)
                {
                    match dev.device_descriptor() {
                        Ok(d) => {
                            (d.vendor_id() == self.vid)
                                && (d.product_id() == self.pid)
                        }
                        Err(_) => false,
                    }
                } else {
                    false
                }
            }).collect::<Vec<_>>();
        if dev_list.is_empty() {
            Err(Error::ReconnectFailed)
        } else {
            self.handle = Some(dev_list.remove(0).open()
                               .map_err(|_| Error::ReconnectFailed)?);
            self.claim()?;
            Ok(())
        }
    }

    /// Reset to application firmware. Works even if BOOT pins are configured
    /// to boot into ISP.
    pub fn reset_app(&mut self) -> Result<(), Error> {
        let cmd: [u8; 64] = HT32ISPCommand::reset_ap_cmd().into();
        self.send_cmd(&cmd[..])?;
        // invalidate handle
        self.release().ok();
        self.handle = None;
        self.info = None;
        self.security_info = None;
        Ok(())
    }

    /// Reset to IAP/ISP firmware depending on how BOOT pins are configured.
    pub fn reset_iap(&mut self) -> Result<(), Error> {
        let cmd: [u8; 64] = HT32ISPCommand::reset_iap_cmd().into();
        self.send_cmd(&cmd[..])?;
        // invalidate handle
        self.release().ok();
        self.handle = None;
        self.info = None;
        self.security_info = None;
        Ok(())
    }

    /// If `write` is true, erase then write binary file to flash starting at
    /// `addr`. If `mass_erase` is true, then wipe entire flash. Otherwise,
    /// erase pages of flash used by the file.
    ///
    /// Otherwise, if `write` is false, then check the region of flash against
    /// the binary file.
    fn write_verify(&mut self, filepath: &PathBuf, addr: u32, write: bool, mass_erase: bool) -> Result<(), Error> {
        let mut file = File::open(filepath).map_err(Error::FileError)?;
        let metadata = file.metadata().map_err(Error::FileError)?;
        if !metadata.is_file() {
            return Err(Error::InvalidFilePath);
        }
        let info = self.get_info()?;
        let end: usize = addr as usize + metadata.len() as usize;
        assert!(info.flash_size() as usize >= end);

        if write & !mass_erase {
            let start_page = addr / (info.page_size() as u32);
            let end_page = (addr + metadata.len() as u32 - 1) / (info.page_size() as u32);
            // check if range of pages overlap page protected bits
            let security_info = self.get_security_info()?;
            for page in start_page..=end_page {
                let index = page / 32;
                let offset = page % 32;
                if (security_info.page_protection[index as usize] & (1 << offset)) == 0 {
                    return Err(Error::PageProtected(page as u8));
                }
            }
        }

        if write {
            if mass_erase {
                // Mass-erase
                println!("Mass-erasing flash...");
                self.mass_erase()?;
                // reset to apply changes to security bits
                println!("Resetting device...");
                self.reset_reconnect()?;
            } else {
                // Page-erase
                println!("Erasing flash page(s)...");
                self.page_erase(addr, metadata.len() as u32)?;
            }
            println!("Writing {:?} to flash region [0x{:04x}:0x{:04x}]...",
                     filepath, addr, end - 1);
        } else {
            println!("Verifying flash region [0x{:04x}:0x{:04x}] against {:?}",
                     addr, end - 1, filepath);
        }

        // clear status
        let mut status = [0u8; 64];
        self.get_report(&mut status[..]).ok();

        let pb = ProgressBar::new(metadata.len() as u64);
        pb.set_style(ProgressStyle::with_template("{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {bytes}/{total_bytes} ({eta})")
            .unwrap()
            .with_key("eta", |state: &ProgressState, w: &mut dyn std::fmt::Write| {
                write!(w, "{:.1}s", state.eta().as_secs_f64()).unwrap()
            })
            .progress_chars("#>-"));

        let mut count = 0;
        for offset in ((addr as usize)..end).step_by(52) {
            let left = end as u32 - offset as u32;
            let length = if left <= 52 {
                left
            } else {
                52
            };
            let mut data = [0u8; 52]; 
            file.read(&mut data[..]).map_err(Error::FileError)?;
            let cmd: [u8; 64] = if write {
                HT32ISPCommand::write_flash_cmd(offset as u32, length, data).into()
            } else {
                HT32ISPCommand::check_flash_cmd(offset as u32, length, data).into()
            };
            self.send_cmd(&cmd[..])?;
            count += 1;
            // check status every 30 write/verify requests
            if left <= 52 || count >= 30 {
                std::thread::sleep(Duration::from_millis(100));
                let (passed, failed) = self.get_report(&mut status[..])?;
                if count == 30 {
                    assert!(passed + failed == 30);
                }
                if failed > 0 {
                    if write {
                        pb.abandon_with_message("Write failed");
                        return Err(Error::WriteFailed);
                    } else {
                        pb.abandon_with_message("Verification failed");
                        return Err(Error::CheckFailed);
                    }
                }
                count -= passed;
            }
            pb.set_position(offset as u64 + length as u64 - addr as u64);
        }
        if write {
            pb.finish_with_message("Verified flash region");
        } else {
            pb.finish_with_message("Flashed flash region");
        }
        Ok(())
    }

    /// Write binary file to flash starting at `addr`.
    pub fn write(&mut self, filepath: &PathBuf, addr: u32, mass_erase: bool) -> Result<(), Error> {
        self.write_verify(filepath, addr, true, mass_erase)
    }

    /// Compare contents of flash to file starting at `addr`.
    pub fn verify(&mut self, filepath: &PathBuf, addr: u32) -> Result<(), Error> {
        self.write_verify(filepath, addr, false, false)
    }

    /// Set flash security, option byte protection, and page protection bits.
    /// Changes get applied on the next reset.
    ///
    /// Cannot set option bytes page if option byte protection is already
    /// enabled.
    pub fn erase_write_option_bytes(&mut self, pp: [u32; 4], flash_security: bool, ob_protection: bool) -> Result<(), Error> {
        let security_info = self.get_security_info()?;
        if security_info.option_byte_protection() {
            return Err(Error::OptionBytePageProtected);
        }
        let cp: u32 = !((flash_security as u32) | ((ob_protection as u32) << 1));
        // checksum
        let ck = pp[0] + pp[1] + pp[2] + pp[3] + cp;

        let mut ob = [0u8; 52];
        // 0x0 : pp0
        ob[0] = pp[0] as u8;
        ob[1] = (pp[0] >> 8) as u8;
        ob[2] = (pp[0] >> 16) as u8;
        ob[3] = (pp[0] >> 24) as u8;
        // 0x4 : pp1
        ob[4] = pp[1] as u8;
        ob[5] = (pp[1] >> 8) as u8;
        ob[6] = (pp[1] >> 16) as u8;
        ob[7] = (pp[1] >> 24) as u8;
        // 0x8 : pp2
        ob[8] = pp[2] as u8;
        ob[9] = (pp[2] >> 8) as u8;
        ob[10] = (pp[2] >> 16) as u8;
        ob[11] = (pp[2] >> 24) as u8;
        // 0xc : pp3
        ob[12] = pp[3] as u8;
        ob[13] = (pp[3] >> 8) as u8;
        ob[14] = (pp[3] >> 16) as u8;
        ob[15] = (pp[3] >> 24) as u8;
        // 0x10 : cp
        ob[16] = cp as u8;
        ob[17] = (cp >> 8) as u8;
        ob[18] = (cp >> 16) as u8;
        ob[19] = (cp >> 24) as u8;
        // 0x20 : ck
        ob[32] = ck as u8;
        ob[33] = (ck >> 8) as u8;
        ob[34] = (ck >> 16) as u8;
        ob[35] = (ck >> 24) as u8;

        // clear status
        let mut status = [0u8; 64];
        self.get_report(&mut status[..]).ok();

        // erase
        println!("Erasing option bytes page...");
        self.page_erase(OB_ADDR, 1)?;

        // write
        println!("Writing option bytes...");
        let cmd: [u8; 64] = HT32ISPCommand::write_flash_cmd(OB_ADDR, 52, ob).into();
        self.send_cmd(&cmd[..])?;
        Ok(())
    }

    /// Read `n`-bytes of flash starting at `addr` and write to file.
    pub fn read(&mut self, filepath: &PathBuf, addr: u32, n: u32) -> Result<(), Error> {
        let mut file = File::create(filepath).map_err(Error::FileError)?;
        let end = addr + n;

        let pb = ProgressBar::new(end as u64);
        pb.set_style(ProgressStyle::with_template("{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {bytes}/{total_bytes} ({eta})")
            .unwrap()
            .with_key("eta", |state: &ProgressState, w: &mut dyn std::fmt::Write| {
                write!(w, "{:.1}s", state.eta().as_secs_f64()).unwrap()
            })
            .progress_chars("#>-"));

        // read command seems to only accept lengths that are multiples of 64 bytes
        for offset in (addr..end).step_by(64) {
            let left = end - offset;
            let length = if left <= 64 {
                left
            } else {
                64
            };
            let cmd: [u8; 64] = HT32ISPCommand::read_flash_cmd(offset, 64).into();
            let mut buf = [0u8; 64];
            self.send_recv_cmd(&cmd[..], &mut buf[..])?;
            file.write_all(&buf[..(length as usize)]).map_err(Error::FileError)?;
            pb.set_position((offset + length) as u64);
        }
        pb.finish();
        Ok(())
    }

    /// Wipe flash contents, flash security, and page protections.
    pub fn mass_erase(&self) -> Result<(), Error> {
        let cmd: [u8; 64] = HT32ISPCommand::mass_erase_cmd().into();
        self.send_cmd(&cmd[..])?;
        std::thread::sleep(Duration::new(5, 0));
        Ok(())
    }

    /// Erase pages of flash used by given region `addr` to `addr + n - 1`.
    pub fn page_erase(&self, addr: u32, n: u32) -> Result<(), Error> {
        let cmd: [u8; 64] = HT32ISPCommand::page_erase_cmd(addr, n).into();
        self.send_cmd(&cmd[..])?;
        std::thread::sleep(Duration::new(5, 0));
        Ok(())
    }
}

/// List of (HT32) devices found with the same VID and PID.
pub struct HT32DeviceList {
    dev_list: Vec<rusb::Device<rusb::GlobalContext>>,
    vid: u16,
    pid: u16,
}

impl HT32DeviceList {
    pub fn new(vid: u16, pid: u16) -> Result<Self, Error> {
        Ok(Self {
            dev_list: rusb::DeviceList::new()
                .map_err(Error::UsbError)?
                .iter()
                .filter(|dev| {
                    match dev.device_descriptor() {
                        Ok(d) => (d.vendor_id() == vid) && (d.product_id() == pid),
                        Err(_) => false,
                    }
                }).collect::<Vec<_>>(),
            vid,
            pid,
        })
    }

    /// Get number of devices in the list
    pub fn len(&self) -> usize {
        self.dev_list.len()
    }

    /// Get `n`-th HT32ISPDevice in the list
    pub fn get_dev(&mut self, n: usize) -> Result<HT32ISPDevice, Error> {
        if n >= self.len() {
            Err(Error::DeviceNotFound)
        } else {
            Ok(HT32ISPDevice::new(self.dev_list.remove(n), self.vid, self.pid)?)
        }
    }

    /// Print device list
    pub fn print_list(&self) {
        let mut count = 0;
        for dev in self.dev_list.iter() {
            let device_desc = match dev.device_descriptor() {
                Ok(d) => d,
                Err(_) => continue,
            };

            println!(
                "Device {}: [{:04x}:{:04x}] Bus={} Port={} Addr={}",
                count,
                device_desc.vendor_id(),
                device_desc.product_id(),
                dev.bus_number(),
                dev.port_number(),
                dev.address());
            count += 1;
        }
    }
}
