//! XFS (CEN/XFS) Protocol Handler
//! 
//! This module provides a parser and analyzer for the CEN/XFS protocol,
//! which is commonly used in ATM peripherals.

use std::collections::HashMap;
use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use byteorder::{LittleEndian, ReadBytesExt};
use std::io::Cursor;

pub mod xfs_messages;
pub mod xfs_engine;
pub mod state_v3;

use xfs_messages::{XFSMessage, XFSCommand, XFSResponse};
use xfs_engine::XFSSessionEngine;
use state_v3::XFSStateMachine;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XFSMessageHeader {
    pub length: u32,
    pub command: u16,
    pub source: u16,
    pub destination: u16,
    pub hresult: u32,
    pub category: u16,
    pub request_id: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XFSMessageInfo {
    pub header: XFSMessageHeader,
    pub command_name: String,
    pub is_request: bool,
    pub is_response: bool,
    pub is_error: bool,
    pub fields: HashMap<String, serde_json::Value>,
}

pub struct XFSHandler {
    state_machine: XFSStateMachine,
}

impl XFSHandler {
    pub fn new() -> Self {
        Self {
            state_machine: XFSStateMachine::new(),
        }
    }
    
    pub fn parse_header(&self, data: &[u8]) -> Result<XFSMessageHeader> {
        if data.len() < 16 {
            return Err(anyhow!("XFS message too short for header"));
        }
        
        let mut cursor = Cursor::new(data);
        
        let length = cursor.read_u32::<LittleEndian>()?;
        let command = cursor.read_u16::<LittleEndian>()?;
        let source = cursor.read_u16::<LittleEndian>()?;
        let destination = cursor.read_u16::<LittleEndian>()?;
        let hresult = cursor.read_u32::<LittleEndian>()?;
        let category = cursor.read_u16::<LittleEndian>()?;
        let request_id = cursor.read_u32::<LittleEndian>()?;
        
        Ok(XFSMessageHeader {
            length,
            command,
            source,
            destination,
            hresult,
            category,
            request_id,
        })
    }
    
    pub fn parse_message(&self, data: &[u8]) -> Result<XFSMessageInfo> {
        let header = self.parse_header(data)?;
        
        let command_name = self.get_command_name(header.command);
        let is_request = self.is_request_command(header.command);
        let is_response = !is_request;
        let is_error = header.hresult != 0;
        
        let mut fields = HashMap::new();
        fields.insert("command".to_string(), serde_json::Value::Number(header.command.into()));
        fields.insert("command_name".to_string(), serde_json::Value::String(command_name.clone()));
        fields.insert("source".to_string(), serde_json::Value::Number(header.source.into()));
        fields.insert("destination".to_string(), serde_json::Value::Number(header.destination.into()));
        fields.insert("hresult".to_string(), serde_json::Value::Number(header.hresult.into()));
        fields.insert("category".to_string(), serde_json::Value::Number(header.category.into()));
        fields.insert("request_id".to_string(), serde_json::Value::Number(header.request_id.into()));
        
        // Parse command-specific data
        if data.len() > 16 {
            let payload = &data[16..];
            let command_fields = self.parse_command_payload(header.command, payload)?;
            for (key, value) in command_fields {
                fields.insert(key, value);
            }
        }
        
        Ok(XFSMessageInfo {
            header,
            command_name,
            is_request,
            is_response,
            is_error,
            fields,
        })
    }
    
    fn get_command_name(&self, command: u16) -> String {
        match command {
            1 => "WFS_OPEN".to_string(),
            2 => "WFS_CLOSE".to_string(),
            3 => "WFS_REGISTER".to_string(),
            4 => "WFS_DEREGISTER".to_string(),
            5 => "WFS_LOCK".to_string(),
            6 => "WFS_UNLOCK".to_string(),
            101 => "WFS_CMD_GET_INFO".to_string(),
            102 => "WFS_CMD_EXECUTE".to_string(),
            201 => "WFS_INF_GET_STATUS".to_string(),
            202 => "WFS_INF_GET_CAPABILITIES".to_string(),
            301 => "WFS_SRV_GET_INFO".to_string(),
            302 => "WFS_SRV_LOCK".to_string(),
            303 => "WFS_SRV_UNLOCK".to_string(),
            1001 => "WFS_IDC_CASH_IN".to_string(),
            1002 => "WFS_IDC_CASH_OUT".to_string(),
            1003 => "WFS_IDC_EJECT".to_string(),
            1004 => "WFS_IDC_RETAIN".to_string(),
            1005 => "WFS_IDC_READ_TRACK".to_string(),
            1006 => "WFS_IDC_READ_RAW".to_string(),
            1007 => "WFS_IDC_RESET".to_string(),
            1008 => "WFS_IDC_WRITE_TRACK".to_string(),
            1101 => "WFS_PIN_GET_PIN".to_string(),
            1102 => "WFS_PIN_DISPLAY_PIN".to_string(),
            1103 => "WFS_PIN_RESET".to_string(),
            1201 => "WFS_DISP_DISPENSE".to_string(),
            1202 => "WFS_DISP_GET_INFO".to_string(),
            1203 => "WFS_DISP_RESET".to_string(),
            _ => format!("UNKNOWN_{}", command),
        }
    }
    
    fn is_request_command(&self, command: u16) -> bool {
        // Even commands are typically requests, odd are responses
        command % 2 == 0
    }
    
    fn parse_command_payload(&self, command: u16, data: &[u8]) -> Result<HashMap<String, serde_json::Value>> {
        let mut fields = HashMap::new();
        
        match command {
            1 => { // WFS_OPEN
                if data.len() >= 4 {
                    let mut cursor = Cursor::new(data);
                    let timeout = cursor.read_u32::<LittleEndian>()?;
                    fields.insert("timeout".to_string(), serde_json::Value::Number(timeout.into()));
                }
            },
            101 => { // WFS_CMD_GET_INFO
                if data.len() >= 4 {
                    let mut cursor = Cursor::new(data);
                    let command_class = cursor.read_u32::<LittleEndian>()?;
                    fields.insert("command_class".to_string(), serde_json::Value::Number(command_class.into()));
                }
            },
            1005 => { // WFS_IDC_READ_TRACK
                if data.len() >= 8 {
                    let mut cursor = Cursor::new(data);
                    let track = cursor.read_u32::<LittleEndian>()?;
                    let timeout = cursor.read_u32::<LittleEndian>()?;
                    fields.insert("track".to_string(), serde_json::Value::Number(track.into()));
                    fields.insert("timeout".to_string(), serde_json::Value::Number(timeout.into()));
                }
            },
            1201 => { // WFS_DISP_DISPENSE
                if data.len() >= 8 {
                    let mut cursor = Cursor::new(data);
                    let amount = cursor.read_u32::<LittleEndian>()?;
                    let currency = cursor.read_u32::<LittleEndian>()?;
                    fields.insert("amount".to_string(), serde_json::Value::Number(amount.into()));
                    fields.insert("currency".to_string(), serde_json::Value::Number(currency.into()));
                }
            },
            _ => {
                // For unknown commands, just include raw data as hex
                fields.insert("raw_payload".to_string(), serde_json::Value::String(
                    data.iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(" ")
                ));
            }
        }
        
        Ok(fields)
    }
    
    pub fn update_state_machine(&mut self, message: &XFSMessageInfo) -> Result<()> {
        let event = if message.is_request {
            format!("REQ_{}", message.command_name)
        } else {
            format!("RES_{}", message.command_name)
        };
        
        self.state_machine.process_event(&event)
    }
    
    pub fn get_current_state(&self) -> &str {
        self.state_machine.get_current_state()
    }
    
    pub fn is_in_error_state(&self) -> bool {
        self.state_machine.is_in_error_state()
    }
}

impl Default for XFSHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl crate::protocols::ProtocolHandler for XFSHandler {
    fn parse(&self, data: &[u8]) -> Result<HashMap<String, serde_json::Value>> {
        let message = self.parse_message(data)?;
        
        let mut fields = message.fields;
        fields.insert("protocol".to_string(), serde_json::Value::String("XFS".to_string()));
        fields.insert("message_type".to_string(), serde_json::Value::String(message.command_name));
        fields.insert("is_request".to_string(), serde_json::Value::Bool(message.is_request));
        fields.insert("is_response".to_string(), serde_json::Value::Bool(message.is_response));
        fields.insert("is_error".to_string(), serde_json::Value::Bool(message.is_error));
        
        Ok(fields)
    }
    
    fn get_message_type(&self, data: &[u8]) -> Result<String> {
        let header = self.parse_header(data)?;
        Ok(self.get_command_name(header.command))
    }
    
    fn is_request(&self, data: &[u8]) -> Result<bool> {
        let header = self.parse_header(data)?;
        Ok(self.is_request_command(header.command))
    }
    
    fn is_response(&self, data: &[u8]) -> Result<bool> {
        Ok(!self.is_request(data)?)
    }
    
    fn get_fields(&self) -> Vec<String> {
        vec![
            "command".to_string(),
            "source".to_string(),
            "destination".to_string(),
            "hresult".to_string(),
            "category".to_string(),
            "request_id".to_string(),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_parse_header() {
        let handler = XFSHandler::new();
        let data = [
            0x10, 0x00, 0x00, 0x00,  // length = 16
            0x01, 0x00,              // command = 1 (WFS_OPEN)
            0x01, 0x00,              // source = 1
            0x00, 0x00,              // destination = 0
            0x00, 0x00, 0x00, 0x00, // hresult = 0
            0x00, 0x00,              // category = 0
            0x01, 0x00, 0x00, 0x00, // request_id = 1
        ];
        
        let header = handler.parse_header(&data).unwrap();
        assert_eq!(header.length, 16);
        assert_eq!(header.command, 1);
        assert_eq!(header.source, 1);
        assert_eq!(header.destination, 0);
        assert_eq!(header.hresult, 0);
        assert_eq!(header.category, 0);
        assert_eq!(header.request_id, 1);
    }
    
    #[test]
    fn test_parse_message() {
        let handler = XFSHandler::new();
        let data = [
            0x14, 0x00, 0x00, 0x00,  // length = 20
            0x65, 0x03,              // command = 877 (WFS_IDC_READ_TRACK)
            0x01, 0x00,              // source = 1
            0x00, 0x00,              // destination = 0
            0x00, 0x00, 0x00, 0x00, // hresult = 0
            0x00, 0x00,              // category = 0
            0x01, 0x00, 0x00, 0x00, // request_id = 1
            0x01, 0x00, 0x00, 0x00, // track = 1
            0x1E, 0x00, 0x00, 0x00, // timeout = 30
        ];
        
        let message = handler.parse_message(&data).unwrap();
        assert_eq!(message.command_name, "WFS_IDC_READ_TRACK");
        assert!(message.is_request);
        assert!(!message.is_response);
        assert!(!message.is_error);
        assert_eq!(message.fields["track"], serde_json::Value::Number(1.into()));
        assert_eq!(message.fields["timeout"], serde_json::Value::Number(30.into()));
    }
    
    #[test]
    fn test_command_names() {
        let handler = XFSHandler::new();
        assert_eq!(handler.get_command_name(1), "WFS_OPEN");
        assert_eq!(handler.get_command_name(2), "WFS_CLOSE");
        assert_eq!(handler.get_command_name(101), "WFS_CMD_GET_INFO");
        assert_eq!(handler.get_command_name(1001), "WFS_IDC_CASH_IN");
        assert_eq!(handler.get_command_name(1101), "WFS_PIN_GET_PIN");
        assert_eq!(handler.get_command_name(1201), "WFS_DISP_DISPENSE");
        assert_eq!(handler.get_command_name(9999), "UNKNOWN_9999");
    }
    
    #[test]
    fn test_request_response() {
        let handler = XFSHandler::new();
        assert!(handler.is_request_command(1));   // WFS_OPEN
        assert!(!handler.is_request_command(2));  // WFS_CLOSE response
        assert!(handler.is_request_command(101)); // WFS_CMD_GET_INFO
        assert!(!handler.is_request_command(102)); // WFS_CMD_GET_INFO response
    }
}
