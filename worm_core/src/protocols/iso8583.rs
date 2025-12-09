//! ISO 8583 Protocol Handler
//! 
//! This module provides a parser and analyzer for the ISO 8583 protocol,
//! which is commonly used for financial transaction messages.

use std::collections::HashMap;
use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use byteorder::{BigEndian, ReadBytesExt};
use std::io::Cursor;

use crate::protocols::ProtocolHandler;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ISO8583MessageType {
    AuthorizationRequest = 0x0100,
    AuthorizationResponse = 0x0110,
    ReversalRequest = 0x0400,
    ReversalResponse = 0x0410,
    SettlementRequest = 0x0500,
    SettlementResponse = 0x0510,
    NetworkManagementRequest = 0x0800,
    NetworkManagementResponse = 0x0810,
}

impl ISO8583MessageType {
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            0x0100 => Some(ISO8583MessageType::AuthorizationRequest),
            0x0110 => Some(ISO8583MessageType::AuthorizationResponse),
            0x0400 => Some(ISO8583MessageType::ReversalRequest),
            0x0410 => Some(ISO8583MessageType::ReversalResponse),
            0x0500 => Some(ISO8583MessageType::SettlementRequest),
            0x0510 => Some(ISO8583MessageType::SettlementResponse),
            0x0800 => Some(ISO8583MessageType::NetworkManagementRequest),
            0x0810 => Some(ISO8583MessageType::NetworkManagementResponse),
            _ => None,
        }
    }
    
    pub fn as_str(&self) -> &'static str {
        match self {
            ISO8583MessageType::AuthorizationRequest => "AUTHORIZATION_REQUEST",
            ISO8583MessageType::AuthorizationResponse => "AUTHORIZATION_RESPONSE",
            ISO8583MessageType::ReversalRequest => "REVERSAL_REQUEST",
            ISO8583MessageType::ReversalResponse => "REVERSAL_RESPONSE",
            ISO8583MessageType::SettlementRequest => "SETTLEMENT_REQUEST",
            ISO8583MessageType::SettlementResponse => "SETTLEMENT_RESPONSE",
            ISO8583MessageType::NetworkManagementRequest => "NETWORK_MANAGEMENT_REQUEST",
            ISO8583MessageType::NetworkManagementResponse => "NETWORK_MANAGEMENT_RESPONSE",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ISO8583Message {
    pub mti: String,
    pub bitmap: Vec<u8>,
    pub fields: HashMap<u8, Vec<u8>>,
    pub is_request: bool,
    pub is_response: bool,
}

pub struct ISO8583Handler;

impl ISO8583Handler {
    pub fn new() -> Self {
        Self
    }
    
    pub fn parse_message(&self, data: &[u8]) -> Result<ISO8583Message> {
        if data.len() < 4 {
            return Err(anyhow!("ISO8583 message too short for MTI"));
        }
        
        let mut cursor = Cursor::new(data);
        
        // Parse MTI (Message Type Indicator)
        let mti_bytes = [
            cursor.read_u8()?,
            cursor.read_u8()?,
            cursor.read_u8()?,
            cursor.read_u8()?,
        ];
        let mti = String::from_utf8_lossy(&mti_bytes);
        
        // Parse bitmap
        let mut bitmap = Vec::new();
        if data.len() >= 8 {
            bitmap.push(cursor.read_u8()?);
            bitmap.push(cursor.read_u8()?);
            bitmap.push(cursor.read_u8()?);
            bitmap.push(cursor.read_u8()?);
            bitmap.push(cursor.read_u8()?);
            bitmap.push(cursor.read_u8()?);
            bitmap.push(cursor.read_u8()?);
            
            // Check if secondary bitmap is present
            if (bitmap[0] & 0x80) != 0 {
                bitmap.push(cursor.read_u8()?);
                bitmap.push(cursor.read_u8()?);
                bitmap.push(cursor.read_u8()?);
                bitmap.push(cursor.read_u8()?);
                bitmap.push(cursor.read_u8()?);
                bitmap.push(cursor.read_u8()?);
                bitmap.push(cursor.read_u8()?);
            }
        }
        
        // Parse fields based on bitmap
        let mut fields = HashMap::new();
        let mut field_number = 1;
        
        for &byte in &bitmap {
            for bit in 0..8 {
                if (byte & (1 << (7 - bit))) != 0 {
                    // Field is present
                    if field_number == 1 {
                        // Fixed length field (4 bytes)
                        if cursor.position() + 4 <= data.len() as u64 {
                            let mut field_data = Vec::new();
                            for _ in 0..4 {
                                field_data.push(cursor.read_u8()?);
                            }
                            fields.insert(field_number, field_data);
                        }
                    } else if field_number == 2 {
                        // Variable length field (LLVAR)
                        if cursor.position() + 1 <= data.len() as u64 {
                            let length = cursor.read_u8()? as usize;
                            if cursor.position() + length as u64 <= data.len() as u64 {
                                let mut field_data = Vec::new();
                                for _ in 0..length {
                                    field_data.push(cursor.read_u8()?);
                                }
                                fields.insert(field_number, field_data);
                            }
                        }
                    } else if field_number == 3 {
                        // Variable length field (LLLVAR)
                        if cursor.position() + 2 <= data.len() as u64 {
                            let length = cursor.read_u16::<BigEndian>()? as usize;
                            if cursor.position() + length as u64 <= data.len() as u64 {
                                let mut field_data = Vec::new();
                                for _ in 0..length {
                                    field_data.push(cursor.read_u8()?);
                                }
                                fields.insert(field_number, field_data);
                            }
                        }
                    } else {
                        // Other fields - simplified parsing
                        if cursor.position() < data.len() as u64 {
                            let mut field_data = Vec::new();
                            // Read until next field or end of message
                            while cursor.position() < data.len() as u64 {
                                field_data.push(cursor.read_u8()?);
                            }
                            fields.insert(field_number, field_data);
                        }
                    }
                }
                field_number += 1;
            }
        }
        
        // Determine if this is a request or response based on MTI
        let mti_value = u16::from_str_radix(&mti, 10).unwrap_or(0);
        let message_type = ISO8583MessageType::from_u16(mti_value);
        let (is_request, is_response) = match message_type {
            Some(ISO8583MessageType::AuthorizationRequest) |
            Some(ISO8583MessageType::ReversalRequest) |
            Some(ISO8583MessageType::SettlementRequest) |
            Some(ISO8583MessageType::NetworkManagementRequest) => (true, false),
            Some(ISO8583MessageType::AuthorizationResponse) |
            Some(ISO8583MessageType::ReversalResponse) |
            Some(ISO8583MessageType::SettlementResponse) |
            Some(ISO8583MessageType::NetworkManagementResponse) => (false, true),
            None => (false, false),
        };
        
        Ok(ISO8583Message {
            mti: mti.to_string(),
            bitmap,
            fields,
            is_request,
            is_response,
        })
    }
    
    pub fn get_message_type_name(&self, mti: &str) -> String {
        let mti_value = u16::from_str_radix(mti, 10).unwrap_or(0);
        match ISO8583MessageType::from_u16(mti_value) {
            Some(msg_type) => msg_type.as_str().to_string(),
            None => format!("UNKNOWN_MTI_{}", mti),
        }
    }
    
    pub fn parse_field_2(&self, data: &[u8]) -> Result<Vec<u8>> {
        if data.is_empty() {
            return Err(anyhow!("Field 2 data is empty"));
        }
        
        let length = data[0] as usize;
        if data.len() < length + 1 {
            return Err(anyhow!("Field 2 data too short"));
        }
        
        Ok(data[1..=length].to_vec())
    }
    
    pub fn parse_field_3(&self, data: &[u8]) -> Result<Vec<u8>> {
        if data.len() < 2 {
            return Err(anyhow!("Field 3 data too short for length"));
        }
        
        let mut cursor = Cursor::new(data);
        let length = cursor.read_u16::<BigEndian>()? as usize;
        if data.len() < length + 2 {
            return Err(anyhow!("Field 3 data too short"));
        }
        
        Ok(data[2..=length+1].to_vec())
    }
    
    pub fn parse_field_4(&self, data: &[u8]) -> Result<Vec<u8>> {
        if data.len() < 12 {
            return Err(anyhow!("Field 4 data too short"));
        }
        
        Ok(data[..12].to_vec())
    }
}

impl Default for ISO8583Handler {
    fn default() -> Self {
        Self::new()
    }
}

impl ProtocolHandler for ISO8583Handler {
    fn parse(&self, data: &[u8]) -> Result<HashMap<String, serde_json::Value>> {
        let message = self.parse_message(data)?;
        
        let mut fields = HashMap::new();
        fields.insert("protocol".to_string(), serde_json::Value::String("ISO8583".to_string()));
        fields.insert("mti".to_string(), serde_json::Value::String(message.mti.clone()));
        fields.insert("message_type".to_string(), serde_json::Value::String(self.get_message_type_name(&message.mti)));
        fields.insert("is_request".to_string(), serde_json::Value::Bool(message.is_request));
        fields.insert("is_response".to_string(), serde_json::Value::Bool(message.is_response));
        
        // Add bitmap as hex
        fields.insert("bitmap".to_string(), serde_json::Value::String(
            message.bitmap.iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(" ")
        ));
        
        // Add fields
        let mut field_map = serde_json::Map::new();
        for (field_number, field_data) in &message.fields {
            let field_data_hex = field_data.iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(" ");
            field_map.insert(field_number.to_string(), serde_json::Value::String(field_data_hex));
        }
        fields.insert("fields".to_string(), serde_json::Value::Object(field_map));
        
        Ok(fields)
    }
    
    fn get_message_type(&self, data: &[u8]) -> Result<String> {
        let message = self.parse_message(data)?;
        Ok(self.get_message_type_name(&message.mti))
    }
    
    fn is_request(&self, data: &[u8]) -> Result<bool> {
        let message = self.parse_message(data)?;
        Ok(message.is_request)
    }
    
    fn is_response(&self, data: &[u8]) -> Result<bool> {
        let message = self.parse_message(data)?;
        Ok(message.is_response)
    }
    
    fn get_fields(&self) -> Vec<String> {
        vec![
            "mti".to_string(),
            "bitmap".to_string(),
            "fields".to_string(),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_parse_authorization_request() {
        let handler = ISO8583Handler::new();
        let data = [
            0x30, 0x31, 0x30, 0x30,  // MTI = 0100
            0x70, 0x00, 0x00, 0x00,  // Bitmap (fields 1, 2, 3, 5, 6, 7 present)
            0x02,                    // Field 2 length
            0x41, 0x42,              // Field 2 data
            0x00, 0x0C,              // Field 3 length
            0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, // Field 3 data
            0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, // Field 4 data (fixed 12 bytes)
        ];
        
        let message = handler.parse_message(&data).unwrap();
        assert_eq!(message.mti, "0100");
        assert_eq!(self.get_message_type_name(&message.mti), "AUTHORIZATION_REQUEST");
        assert!(message.is_request);
        assert!(!message.is_response);
        
        // Check bitmap
        assert_eq!(message.bitmap, vec![0x70, 0x00, 0x00, 0x00]);
        
        // Check fields
        assert!(message.fields.contains_key(&2));
        assert_eq!(message.fields[&2], vec![0x41, 0x42]);
        
        assert!(message.fields.contains_key(&3));
        assert_eq!(message.fields[&3], vec![
            0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33,
            0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33
        ]);
        
        assert!(message.fields.contains_key(&4));
        assert_eq!(message.fields[&4], vec![
            0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33
        ]);
    }
    
    #[test]
    fn test_parse_field_2() {
        let handler = ISO8583Handler::new();
        let data = [0x02, 0x41, 0x42];
        
        let field_data = handler.parse_field_2(&data).unwrap();
        assert_eq!(field_data, vec![0x41, 0x42]);
    }
    
    #[test]
    fn test_parse_field_3() {
        let handler = ISO8583Handler::new();
        let data = [0x00, 0x0C, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33];
        
        let field_data = handler.parse_field_3(&data).unwrap();
        assert_eq!(field_data, vec![
            0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33
        ]);
    }
    
    #[test]
    fn test_parse_field_4() {
        let handler = ISO8583Handler::new();
        let data = [0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33];
        
        let field_data = handler.parse_field_4(&data).unwrap();
        assert_eq!(field_data, vec![
            0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33
        ]);
    }
}
