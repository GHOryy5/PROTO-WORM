//! Industrial Control Systems Protocol Handlers
//! 
//! This module provides protocol handlers for various industrial control protocols
//! used in critical infrastructure systems.

use std::collections::HashMap;
use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};

pub mod modbus;
pub mod s7comm_plus;

use modbus::ModbusHandler;
use s7comm_plus::S7CommPlusHandler;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OTProtocolType {
    Modbus,
    S7CommPlus,
}

impl OTProtocolType {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "modbus" => Some(OTProtocolType::Modbus),
            "s7commplus" => Some(OTProtocolType::S7CommPlus),
            "s7comm_plus" => Some(OTProtocolType::S7CommPlus),
            _ => None,
        }
    }
    
    pub fn as_str(&self) -> &'static str {
        match self {
            OTProtocolType::Modbus => "modbus",
            OTProtocolType::S7CommPlus => "s7commplus",
        }
    }
    
    pub fn description(&self) -> &'static str {
        match self {
            OTProtocolType::Modbus => "Modbus RTU/TCP - Industrial automation protocol",
            OTProtocolType::S7CommPlus => "Siemens S7CommPlus - Industrial PLC protocol",
        }
    }
}

pub trait OTProtocolHandler {
    fn parse(&self, data: &[u8]) -> Result<HashMap<String, serde_json::Value>>;
    fn get_message_type(&self, data: &[u8]) -> Result<String>;
    fn is_request(&self, data: &[u8]) -> Result<bool>;
    fn is_response(&self, data: &[u8]) -> Result<bool>;
    fn get_fields(&self) -> Vec<String>;
}

pub struct OTProtocolHandlerFactory;

impl OTProtocolHandlerFactory {
    pub fn create_handler(protocol_type: OTProtocolType) -> Box<dyn OTProtocolHandler> {
        match protocol_type {
            OTProtocolType::Modbus => Box::new(ModbusHandler::new()),
            OTProtocolType::S7CommPlus => Box::new(S7CommPlusHandler::new()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OTProtocolMessage {
    pub protocol: String,
    pub message_type: String,
    pub is_request: bool,
    pub is_response: bool,
    pub fields: HashMap<String, serde_json::Value>,
    pub raw_data: Vec<u8>,
}

impl OTProtocolMessage {
    pub fn new(
        protocol: String,
        message_type: String,
        is_request: bool,
        is_response: bool,
        fields: HashMap<String, serde_json::Value>,
        raw_data: Vec<u8>,
    ) -> Self {
        Self {
            protocol,
            message_type,
            is_request,
            is_response,
            fields,
            raw_data,
        }
    }
    
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self).map_err(|e| anyhow!("Failed to serialize message: {}", e))
    }
    
    pub fn from_json(json: &str) -> Result<Self> {
        serde_json::from_str(json).map_err(|e| anyhow!("Failed to deserialize message: {}", e))
    }
}

pub fn detect_ot_protocol(data: &[u8]) -> Result<OTProtocolType> {
    if data.len() < 4 {
        return Err(anyhow!("Data too short to detect protocol"));
    }
    
    // Check for Modbus signature
    if data.len() >= 8 && data[0] == 0x00 && data[1] == 0x00 && 
       data[4] == 0x00 && data[5] == 0x00 {
        return Ok(OTProtocolType::Modbus);
    }
    
    // Check for S7CommPlus signature
    if data.len() >= 4 && data[0] == 0x72 && data[1] == 0x01 {
        return Ok(OTProtocolType::S7CommPlus);
    }
    
    Err(anyhow!("Unknown OT protocol"))
}

pub fn parse_ot_message(data: &[u8]) -> Result<OTProtocolMessage> {
    let protocol_type = detect_ot_protocol(data)?;
    let handler = OTProtocolHandlerFactory::create_handler(protocol_type);
    
    let fields = handler.parse(data)?;
    let message_type = handler.get_message_type(data)?;
    let is_request = handler.is_request(data)?;
    let is_response = handler.is_response(data)?;
    
    Ok(OTProtocolMessage::new(
        protocol_type.as_str().to_string(),
        message_type,
        is_request,
        is_response,
        fields,
        data.to_vec(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_protocol_type_from_str() {
        assert_eq!(OTProtocolType::from_str("modbus"), Some(OTProtocolType::Modbus));
        assert_eq!(OTProtocolType::from_str("MODBUS"), Some(OTProtocolType::Modbus));
        assert_eq!(OTProtocolType::from_str("s7commplus"), Some(OTProtocolType::S7CommPlus));
        assert_eq!(OTProtocolType::from_str("s7comm_plus"), Some(OTProtocolType::S7CommPlus));
        assert_eq!(OTProtocolType::from_str("unknown"), None);
    }
    
    #[test]
    fn test_protocol_type_as_str() {
        assert_eq!(OTProtocolType::Modbus.as_str(), "modbus");
        assert_eq!(OTProtocolType::S7CommPlus.as_str(), "s7commplus");
    }
    
    #[test]
    fn test_detect_modbus() {
        let modbus_data = vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03];
        assert_eq!(detect_ot_protocol(&modbus_data).unwrap(), OTProtocolType::Modbus);
    }
    
    #[test]
    fn test_detect_s7commplus() {
        let s7_data = vec![0x72, 0x01, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00];
        assert_eq!(detect_ot_protocol(&s7_data).unwrap(), OTProtocolType::S7CommPlus);
    }
}
