//! XFS Message Structures
//!
//! This module defines the core structures for XFS messages, used to communicate
//! with ATM peripherals. Note: Structures use #[repr(C)] for FFI/protocol compatibility.

use std::ffi::c_void;
use std::mem;
use std::ptr;
use std::os::raw::{c_long, c_ulong, c_ushort, c_char};
use serde::{Deserialize, Serialize};

// --- WFSVersion: Defines the version structure common across XFS ---
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct WFSVersion {
    pub us_version: c_ushort,
    pub us_low_version: c_ushort,
    pub us_high_version: c_ushort,
    pub sz_description: [c_char; 256],
    pub sz_system_status: [c_char; 256],
}

// --- WFSHDR: The header present on almost every XFS command/response ---
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct WFSHDR {
    pub h_service: c_ulong,
    pub h_async_service: c_ulong,
    // Typically a pointer to the command/response specific structure
    pub lp_buffer: *mut c_void,
    pub dw_size: c_ulong,
    // For requests, this is the command ID. For responses, often the result code.
    pub dw_command: c_ulong,
}

// --- WFS_CDM_CASHUNIT: Defines a physical cash cassette ---
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct WFS_CDM_CASHUNIT {
    pub us_number: c_ushort,
    pub ul_total_items: c_ulong,
    pub ul_reject_items: c_ulong,
    pub ul_unit_id: c_long,
    pub ul_status: c_long,
    // Good spot for padding, bad spot for stack smashers.
    pub reserved: [c_char; 16],
}

// --- WFS_CDM_DENOMINATION: Core structure for Cash Dispenser commands ---
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct WFS_CDM_DENOMINATION {
    pub sz_currency_id: [c_char; 4],
    pub ul_amount: c_ulong,
    // Pointer to an array of cash units. High-value target for heap manipulation.
    pub lpp_list: *mut *mut WFS_CDM_CASHUNIT,
}

// --- WFS_IDC_TRACKDATA: Structure for card track data ---
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct WFS_IDC_TRACKDATA {
    pub track_number: c_ushort,
    pub track_length: c_ushort,
    // Potential buffer overflow here if not handled carefully!
    pub track_data: [c_char; 256],
}

// --- XFS Command Codes ---
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u16)]
pub enum XFSCommand {
    // Service Manager Commands (1 - 99)
    Open = 1,
    Close = 2,
    Register = 3,
    Deregister = 4,
    Lock = 5,
    Unlock = 6,

    // Command/Info Requests (100 - 199)
    GetInfo = 101,
    Execute = 102,
    GetStatus = 103,
    GetCapabilities = 104,

    // IDC (Card Reader) Commands (1000 - 1099)
    IDC_ReadTrack = 1005,
    IDC_WriteTrack = 1008,
    IDC_Eject = 1009,
    IDC_Retain = 1010,
    IDC_Reset = 1011,

    // PIN (PIN Pad) Commands (1100 - 1199)
    PIN_GetPIN = 1101,
    PIN_Reset = 1103,

    // CDM (Cash Dispenser) Commands (1200 - 1299)
    CDM_Dispense = 1201,
    CDM_GetInfo = 1202,
    CDM_Reset = 1203,

    // PTR (Receipt Printer) Commands (1500 - 1599)
    PTR_PrintForm = 1501,
    PTR_GetInfo = 1502,
    PTR_Reset = 1503,
}

impl XFSCommand {
    pub fn from_u32(value: u32) -> Option<Self> {
        // Use mem::transmute for a clean enum conversion from C data
        if value > u16::MAX as u32 { return None; }
        unsafe {
            let cmd_val = value as u16;
            if (cmd_val >= XFSCommand::Open as u16 && cmd_val <= XFSCommand::Unlock as u16) ||
               (cmd_val >= XFSCommand::GetInfo as u16 && cmd_val <= XFSCommand::GetCapabilities as u16) ||
               (cmd_val >= XFSCommand::IDC_ReadTrack as u16 && cmd_val <= XFSCommand::IDC_Reset as u16) ||
               (cmd_val >= XFSCommand::PIN_GetPIN as u16 && cmd_val <= XFSCommand::PIN_Reset as u16) ||
               (cmd_val >= XFSCommand::CDM_Dispense as u16 && cmd_val <= XFSCommand::CDM_Reset as u16) ||
               (cmd_val >= XFSCommand::PTR_PrintForm as u16 && cmd_val <= XFSCommand::PTR_Reset as u16) {
                Some(mem::transmute::<u16, Self>(cmd_val))
            } else {
                None
            }
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            XFSCommand::Open => "WFS_OPEN",
            XFSCommand::Close => "WFS_CLOSE",
            XFSCommand::Register => "WFS_REGISTER",
            XFSCommand::Deregister => "WFS_DEREGISTER",
            XFSCommand::Lock => "WFS_LOCK",
            XFSCommand::Unlock => "WFS_UNLOCK",
            XFSCommand::GetInfo => "WFS_CMD_GET_INFO",
            XFSCommand::Execute => "WFS_CMD_EXECUTE",
            XFSCommand::GetStatus => "WFS_INF_GET_STATUS",
            XFSCommand::GetCapabilities => "WFS_INF_GET_CAPABILITIES",
            XFSCommand::IDC_ReadTrack => "WFS_IDC_READ_TRACK",
            XFSCommand::IDC_WriteTrack => "WFS_IDC_WRITE_TRACK",
            XFSCommand::IDC_Eject => "WFS_IDC_EJECT",
            XFSCommand::IDC_Retain => "WFS_IDC_RETAIN",
            XFSCommand::IDC_Reset => "WFS_IDC_RESET",
            XFSCommand::PIN_GetPIN => "WFS_PIN_GET_PIN",
            XFSCommand::PIN_Reset => "WFS_PIN_RESET",
            XFSCommand::CDM_Dispense => "WFS_CDM_DISPENSE",
            XFSCommand::CDM_GetInfo => "WFS_CDM_GET_INFO",
            XFSCommand::CDM_Reset => "WFS_CDM_RESET",
            XFSCommand::PTR_PrintForm => "WFS_PTR_PRINT_FORM",
            XFSCommand::PTR_GetInfo => "WFS_PTR_GET_INFO",
            XFSCommand::PTR_Reset => "WFS_PTR_RESET",
        }
    }
}

// --- XFS Message Structures ---
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XFSMessage {
    pub header: WFSHDR,
    pub command: XFSCommand,
    pub payload: Vec<u8>,
}

impl XFSMessage {
    pub fn new(header: WFSHDR, command: XFSCommand, payload: Vec<u8>) -> Self {
        Self { header, command, payload }
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, String> {
        if data.len() < mem::size_of::<WFSHDR>() {
            return Err("Packet too short for WFSHDR".to_string());
        }

        let header: WFSHDR = unsafe { ptr::read_unaligned(data.as_ptr() as *const WFSHDR) };

        let command = XFSCommand::from_u32(header.dw_command)
            .ok_or_else(|| format!("Unknown command: 0x{:X}", header.dw_command))?;

        let payload = if data.len() > mem::size_of::<WFSHDR>() {
            data[mem::size_of::<WFSHDR>()..].to_vec()
        } else {
            Vec::new()
        };

        Ok(XFSMessage::new(header, command, payload))
    }

    // to_bytes implementation remains the same for simplicity
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::new();

        let mut header_with_command = self.header;
        header_with_command.dw_command = self.command as u32 as c_ulong;
        header_with_command.dw_size = self.payload.len() as c_ulong;

        // Add header
        let header_bytes = unsafe {
            std::slice::from_raw_parts(
                &header_with_command as *const WFSHDR as *const u8,
                mem::size_of::<WFSHDR>(),
            )
        };
        result.extend_from_slice(header_bytes);

        // Add payload
        result.extend_from_slice(&self.payload);

        result
    }

    pub fn get_command_name(&self) -> &'static str {
        self.command.as_str()
    }
}

// --- XFS Error Codes (Concise and Realistic Subset) ---
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u32)]
pub enum XFSError {
    Success = 0,
    InternalError = 1,
    Timeout = 2,
    Cancelled = 3,
    DeviceBusy = 4,
    NoHardware = 5,
    NotSupported = 6,
    InvalidData = 7,
    InvalidPointer = 8,
    InvalidHandle = 9,
    InvalidParameter = 10,
    InvalidState = 11,
    NotEnoughMemory = 12,
    // Standard XFS specific errors start here
    WFS_ERR_DEV_NOT_READY = 100,
    WFS_ERR_HARDWARE_ERROR = 101,
    WFS_ERR_COMM_ERROR = 102,
    WFS_ERR_NO_DISPENSE_SUPPLY = 103,
    WFS_ERR_PTR_FORMNOTFOUND = 104,
    WFS_ERR_IDC_INVALID_MEDIA = 105,
}

impl XFSError {
    pub fn from_u32(value: u32) -> Option<Self> {
        unsafe {
            // A concise range check for the realistic core errors
            if (value >= 0 && value <= 12) || (value >= 100 && value <= 105) {
                Some(mem::transmute::<u32, Self>(value))
            } else {
                None
            }
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            XFSError::Success => "SUCCESS",
            XFSError::InternalError => "WFS_ERR_INTERNAL_ERROR",
            XFSError::Timeout => "WFS_ERR_TIMEOUT",
            XFSError::Cancelled => "WFS_ERR_CANCELED",
            XFSError::DeviceBusy => "WFS_ERR_DEV_BUSY",
            XFSError::NoHardware => "WFS_ERR_NO_HARDWARE",
            XFSError::NotSupported => "WFS_ERR_NOT_SUPPORTED",
            XFSError::InvalidData => "WFS_ERR_INVALID_DATA",
            XFSError::InvalidPointer => "WFS_ERR_INVALID_POINTER",
            XFSError::InvalidHandle => "WFS_ERR_INVALID_HSERVICE",
            XFSError::InvalidParameter => "WFS_ERR_INVALID_COMMAND",
            XFSError::InvalidState => "WFS_ERR_INVALID_STATE",
            XFSError::NotEnoughMemory => "WFS_ERR_NOT_ENOUGH_MEMORY",
            XFSError::WFS_ERR_DEV_NOT_READY => "WFS_ERR_DEV_NOT_READY",
            XFSError::WFS_ERR_HARDWARE_ERROR => "WFS_ERR_HARDWARE_ERROR",
            XFSError::WFS_ERR_COMM_ERROR => "WFS_ERR_COMM_ERROR",
            XFSError::WFS_ERR_NO_DISPENSE_SUPPLY => "WFS_ERR_NO_DISPENSE_SUPPLY",
            XFSError::WFS_ERR_PTR_FORMNOTFOUND => "WFS_ERR_PTR_FORMNOTFOUND",
            XFSError::WFS_ERR_IDC_INVALID_MEDIA => "WFS_ERR_IDC_INVALID_MEDIA",
        }
    }
}
