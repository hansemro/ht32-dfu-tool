// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2023 Hansem Ro <hansemro@outlook.com>

use crate::command::HT32ISPCommand;
use std::time::Duration;
use std::fs::File;
use std::io::{Read, Write};
use std::path::PathBuf;
use crc16::{State, XMODEM};

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
}

impl HT32Security {
    pub fn flash_security(&self) -> bool {
        self.flash_security
    }

    pub fn option_byte_protection(&self) -> bool {
        self.option_byte_protection
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

impl HT32ISPDevice {
    pub fn new(device: rusb::Device<rusb::GlobalContext>, vid: u16, pid: u16) -> Result<Self, Error> {
        // Find endpoints
        let mut ep_in: Option<u8> = None;
        let mut ep_out: Option<u8> = None;
        let mut interface: Option<u8> = None;
        let device_desc = device.device_descriptor() 
            .map_err(|e| Error::UsbError(e))?;
        'outer: for n in 0..device_desc.num_configurations() {
            let config_desc = device.config_descriptor(n)
                .map_err(|e| Error::UsbError(e))?;
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
            Err(Error::EndpointNotFound)
        } else {
            Ok(Self {
                handle: Some(device.open().map_err(|e| Error::UsbError(e))?),
                vid: vid,
                pid: pid,
                bus_number: device.bus_number(),
                port_number: device.port_number(),
                interface: interface.unwrap(),
                ep_in: ep_in.unwrap(),
                ep_out: ep_out.unwrap(),
                info: None,
                security_info: None,
            })
        }
    }

    /// Attempt to claim device
    pub fn claim(&mut self) -> Result<(), Error> {
        match self.handle.as_mut().ok_or(Error::DeviceNotFound)?
            .set_auto_detach_kernel_driver(true)
        {
            Ok(_) => (),
            Err(_) => (),
        }
        self.handle.as_mut().ok_or(Error::DeviceNotFound)?
            .claim_interface(self.interface)
            .map_err(|e| Error::UsbError(e))?;
        Ok(())
    }

    /// Attempt to release device
    pub fn release(&mut self) -> Result<(), Error> {
        match self.handle.as_mut().ok_or(Error::DeviceNotFound)?
            .set_auto_detach_kernel_driver(false)
        {
            Ok(_) => (),
            Err(_) => (),
        }
        self.handle.as_mut().ok_or(Error::DeviceNotFound)?.release_interface(self.interface)
            .map_err(|e| Error::UsbError(e))?;
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
        Ok(self.handle.as_ref().ok_or(Error::DeviceNotFound)?
            .write_interrupt(self.ep_out, &_cmd, Duration::new(1, 0))
            .map_err(|e| Error::UsbError(e))?)
    }

    /// Attempt to read data from device's input endpoint
    fn recv(&self, buf: &mut [u8]) -> Result<usize, Error> {
        Ok(self.handle.as_ref().ok_or(Error::DeviceNotFound)?
            .read_interrupt(self.ep_in, buf, Duration::new(1, 0))
            .map_err(|e| Error::UsbError(e))?)
    }

    /// Send `cmd` to device and get its `response`
    fn send_recv_cmd(&self, cmd: &[u8], response: &mut [u8])
            -> Result<(usize, usize), Error> {
        Ok((self.send_cmd(&cmd)?, self.recv(response)?))
    }

    /// Attempt GET_REPORT request
    pub fn get_report(&self, response: &mut [u8]) -> Result<(), Error> {
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
            .map_err(|e| Error::UsbError(e))?;
        Ok(())
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
        Ok(&self.info.as_ref().unwrap())
    }

    /// Get device flash security and option byte protection status.
    pub fn get_security_info(&mut self) -> Result<&HT32Security, Error> {
        if self.security_info.is_none() {
            let cmd: [u8; 64] = HT32ISPCommand::read_flash_cmd(OB_ADDR, 64).into();
            let mut buf = [0u8; 64];
            self.send_recv_cmd(&cmd[..], &mut buf[..])?;
            let flash_security = (buf[16] & 1) == 0;
            let option_byte_protection = (buf[16] & 2) == 0;
            // TODO: check which pages are protected
            self.security_info = Some(HT32Security {
                flash_security, 
                option_byte_protection
            });
        }
        Ok(&self.security_info.as_ref().unwrap())
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
        Ok(())
    }

    /// Reset device and attempt to reconnect device
    pub fn reset_reconnect(&mut self) -> Result<(), Error> {
        let cmd: [u8; 64] = HT32ISPCommand::reset_iap_cmd().into();
        self.send_cmd(&cmd[..])?;
        std::thread::sleep(Duration::new(3, 0));
        // invalidate handle
        self.handle = None;
        self.info = None;
        self.security_info = None;

        // Attempt to reconnect by locating new device handle based on previous
        // bus and port numbers. This works only if BOOT pin(s) are configured
        // to boot into ISP.
        let mut dev_list = rusb::DeviceList::new()
            .map_err(|e| Error::UsbError(e))?
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
        self.handle = Some(dev_list.remove(0).open()
                           .map_err(|_| Error::ReconnectFailed)?);
        self.claim()?;
        Ok(())
    }

    /// Reset to application firmware. Works even if BOOT pins are configured
    /// to boot into ISP.
    pub fn reset_app(&mut self) -> Result<(), Error> {
        let cmd: [u8; 64] = HT32ISPCommand::reset_ap_cmd().into();
        self.send_cmd(&cmd[..])?;
        // invalidate handle
        self.handle = None;
        self.info = None;
        self.security_info = None;
        Ok(())
    }

    fn write_verify(&mut self, filepath: &PathBuf, addr: u32, write: bool) -> Result<(), Error> {
        let mut file = File::open(filepath).map_err(|e| Error::FileError(e))?;
        let metadata = file.metadata().map_err(|e| Error::FileError(e))?;
        if !metadata.is_file() {
            return Err(Error::InvalidFilePath);
        }
        let info = self.get_info()?;
        let end: usize = addr as usize + metadata.len() as usize;
        assert!(info.flash_size() as usize > end);

        // clear status
        let mut status = [0u8; 64];
        self.get_report(&mut status[..]).ok();

        let mut count = 0;
        for offset in ((addr as usize)..end).step_by(52) {
            let left = end as u32 - offset as u32;
            let length = if left <= 52 {
                left
            } else {
                52
            };
            let mut data = [0u8; 52]; 
            file.read(&mut data[..]).map_err(|e| Error::FileError(e))?;
            let cmd: [u8; 64] = if write {
                HT32ISPCommand::write_flash_cmd(offset as u32, length, data).into()
            } else {
                HT32ISPCommand::check_flash_cmd(offset as u32, length, data).into()
            };
            self.send_cmd(&cmd[..])?;
            count += 1;
            // check status every 30 write requests
            if left <= 52 || count >= 30 {
                std::thread::sleep(Duration::new(1, 0));
                self.get_report(&mut status[..])?;
                let mut passed = 0;
                for n in status.iter() {
                    if *n == 0x4f {
                        passed += 1;
                    }
                }
                count -= passed;
            }
        }
        if count > 0 {
            if write {
                Err(Error::WriteFailed)
            } else {
                Err(Error::CheckFailed)
            }
        } else {
            Ok(())
        }
    }

    pub fn write(&mut self, filepath: &PathBuf, addr: u32) -> Result<(), Error> {
        self.write_verify(filepath, addr, true)
    }

    pub fn verify(&mut self, filepath: &PathBuf, addr: u32) -> Result<(), Error> {
        self.write_verify(filepath, addr, false)
    }

    pub fn read(&mut self, filepath: &PathBuf, addr: u32, n: u32) -> Result<(), Error> {
        let mut file = File::create(filepath).map_err(|e| Error::FileError(e))?;
        let end = addr + n;
        for offset in (addr..end).step_by(64) {
            let cmd: [u8; 64] = HT32ISPCommand::read_flash_cmd(offset, 64).into();
            let mut buf = [0u8; 64];
            self.send_recv_cmd(&cmd[..], &mut buf[..])?;
            file.write_all(&buf).map_err(|e| Error::FileError(e))?;
        }
        Ok(())
    }

    pub fn mass_erase(&self) -> Result<(), Error> {
        let cmd: [u8; 64] = HT32ISPCommand::mass_erase_cmd().into();
        self.send_cmd(&cmd[..])?;
        std::thread::sleep(Duration::new(5, 0));
        Ok(())
    }
}

pub struct HT32DeviceList {
    dev_list: Vec<rusb::Device<rusb::GlobalContext>>,
    vid: u16,
    pid: u16,
}

impl HT32DeviceList {
    pub fn new(vid: u16, pid: u16) -> Result<Self, Error> {
        Ok(Self {
            dev_list: rusb::DeviceList::new()
                .map_err(|e| Error::UsbError(e))?
                .iter()
                .filter(|dev| {
                    match dev.device_descriptor() {
                        Ok(d) => (d.vendor_id() == vid) && (d.product_id() == pid),
                        Err(_) => false,
                    }
                }).collect::<Vec<_>>(),
            vid: vid,
            pid: pid,
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