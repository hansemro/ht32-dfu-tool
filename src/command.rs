// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2023 Hansem Ro <hansemro@outlook.com>

#[derive(Debug)]
pub struct HT32ISPCommand {
    pub command: u8,
    pub subcommand: u8,
    pub arg1: u32,
    pub arg2: u32,
    pub data: [u8; 52],
}

impl From<HT32ISPCommand> for [u8; 64] {
    fn from(item: HT32ISPCommand) -> [u8; 64] {
        let mut cmd = [0u8; 64];
        cmd[0] = item.command;
        cmd[1] = item.subcommand;
        //cmd[2..4] reserved for CRC16
        cmd[4] = item.arg1 as u8;
        cmd[5] = (item.arg1 >> 8) as u8;
        cmd[6] = (item.arg1 >> 16) as u8;
        cmd[7] = (item.arg1 >> 24) as u8;
        cmd[8] = item.arg2 as u8;
        cmd[9] = (item.arg2 >> 8) as u8;
        cmd[10] = (item.arg2 >> 16) as u8;
        cmd[11] = (item.arg2 >> 24) as u8;
        cmd[12..].copy_from_slice(&item.data);
        cmd
    }
}

impl HT32ISPCommand {
    /// HT32ISPCommand to get ISP Info Block from the Input Endpoint
    pub fn info_cmd() -> Self {
        Self {
            command: 0x3,
            subcommand: 0x0,
            arg1: 0x0,
            arg2: 0x0,
            data: [0u8; 52],
        }
    }

    /// HT32ISPCommand to get CRC of `n`-bytes of flash starting at `addr`.
    /// Status result and CRC are stored in the Status Report.
    pub fn crc_flash_cmd(addr: u32, n: u32) -> Self {
        //assert!(n >= 4);
        Self {
            command: 0x2,
            subcommand: 0x0,
            arg1: addr,
            arg2: n,
            data: [0u8; 52],
        }
    }

    /// HT32ISPCommand to check if `n`-bytes of flash starting at `addr` match
    /// `buf`. Result is stored in the Status Report.
    ///
    /// Pad `buf` with 0s if less than 52 bytes long.
    pub fn check_flash_cmd(addr: u32, n: u32, buf: [u8; 52]) -> Self {
        Self {
            command: 0x1,
            subcommand: 0x0,
            arg1: addr,
            arg2: addr + n - 1,
            data: buf,
        }
    }

    /// HT32ISPCommand to read `n`-bytes of flash starting at `addr` from the
    /// Input Endpoint. If target device is flash secured, then no data will be
    /// obtained.
    pub fn read_flash_cmd(addr: u32, n: u32) -> Self {
        Self {
            command: 0x1,
            subcommand: 0x2,
            arg1: addr,
            arg2: addr + n - 1,
            data: [0u8; 52],
        }
    }

    /// HT32ISPCommand to write `n`-bytes of flash starting at `addr` from
    /// `buf`.
    ///
    /// Pad `buf` with 0s if less than 52 bytes long.
    pub fn write_flash_cmd(addr: u32, n: u32, buf: [u8; 52]) -> Self {
        Self {
            command: 0x1,
            subcommand: 0x1,
            arg1: addr,
            arg2: addr + n - 1,
            data: buf,
        }
    }

    /// HT32ISPCommand to mass-erase flash (and wipe security bits).
    pub fn mass_erase_cmd() -> Self {
        Self {
            command: 0x0,
            subcommand: 0xA,
            arg1: 0x0,
            arg2: 0x0,
            data: [0u8; 52],
        }
    }

    /// HT32ISPCommand to erase pages of flash used by given region `addr` to
    /// `addr + n - 1`.
    ///
    /// Page size varies by model and can be obtained with the info command.
    pub fn page_erase_cmd(addr: u32, n: u32) -> Self {
        Self {
            command: 0x0,
            subcommand: 0x8,
            arg1: addr,
            arg2: addr + n - 1,
            data: [0u8; 52],
        }
    }

    /// HT32ISPCommand to reset device to application (AP) firmware.
    pub fn reset_ap_cmd() -> Self {
        Self {
            command: 0x4,
            subcommand: 0x0,
            arg1: 0x0,
            arg2: 0x0,
            data: [0u8; 52],
        }
    }

    /// HT32ISPCommand to reset device to IAP bootloader.
    pub fn reset_iap_cmd() -> Self {
        Self {
            command: 0x4,
            subcommand: 0x1,
            arg1: 0x0,
            arg2: 0x0,
            data: [0u8; 52],
        }
    }
}
