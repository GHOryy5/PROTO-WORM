//! Protocol Handlers
//! 
//! This module provides protocol-specific handlers for parsing and analyzing
//! various protocols used in ATMs and Industrial Control Systems.

use std::collections::HashMap;
use std::convert::TryInto;
use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};

pub mod xfs;
pub mod ot;
pub mod iso8583;

use xfs::XFSHandler;
use ot::{S7CommPlusHandler, ModbusHandler};
use iso8583::ISO8583Handler;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolType {
    XFS,
    S7CommPlus,
    Modbus,
    ISO8583,
    NDC,
    DNP3,
}

impl ProtocolType {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "xfs" => Some(ProtocolType::XFS),
            "s7commplus" => Some(ProtocolType::S7CommPlus),
            "s7comm_plus" => Some(ProtocolType::S7CommPlus),
            "modbus" => Some(ProtocolType::Modbus),
            "iso8583" => Some(ProtocolType::ISO8583),
            "ndc" => Some(ProtocolType::NDC),
            "dnp3" => Some(ProtocolType::DNP3),
            _ => None,
        }
    }
    
    pub fn as_str(&self) -> &'static str {
        match self {
            ProtocolType::XFS => "xfs",
            ProtocolType::S7CommPlus => "s7commplus",
            ProtocolType::Modbus => "modbus",
            ProtocolType::ISO8583 => "iso8583",
            ProtocolType::NDC => "ndc",
            ProtocolType::DNP3 => "dnp3",
        }
    }
    
    pub fn description(&self) -> &'static str {
        match self {
            ProtocolType::XFS => "CEN/XFS (eXtensions for Financial Services) - ATM protocol",
            ProtocolType::S7CommPlus => "Siemens S7CommPlus - Industrial PLC protocol",
            ProtocolType::Modbus => "Modbus RTU/TCP - Industrial automation protocol",
            ProtocolType::ISO8583 => "ISO 8583 - Financial transaction message format",
            ProtocolType::NDC => "Network Direct Connect - Legacy ATM protocol",
            ProtocolType::DNP3 => "Distributed Network Protocol 3 - Power systems protocol",
        }
    }
    
    pub fn get_fields(&self) -> Vec<String> {
        match self {
            ProtocolType::XFS => vec![
                "command".to_string(),
                "source".to_string(),
                "destination".to_string(),
                "hresult".to_string(),
                "category".to_string(),
                "request_id".to_string(),
            ],
            ProtocolType::S7CommPlus => vec![
                "magic".to_string(),
                "version".to_string(),
                "reserved".to_string(),
                "message_type".to_string(),
                "length".to_string(),
                "sequence_number".to_string(),
            ],
            ProtocolType::Modbus => vec![
                "transaction_id".to_string(),
                "protocol_id".to_string(),
                "length".to_string(),
                "unit_id".to_string(),
                "function_code".to_string(),
                "data".to_string(),
            ],
            ProtocolType::ISO8583 => vec![
                "mti".to_string(),
                "bitmap".to_string(),
                "fields".to_string(),
            ],
            ProtocolType::NDC => vec![
                "header".to_string(),
                "message_type".to_string(),
                "data".to_string(),
            ],
            ProtocolType::DNP3 => vec![
                "start".to_string(),
                "length".to_string(),
                "control".to_string(),
                "destination".to_string(),
                "source".to_string(),
                "function".to_string(),
                "data".to_string(),
            ],
        }
    }
    
    pub fn get_commands(&self) -> Vec<String> {
        match self {
            ProtocolType::XFS => vec![
                "WFS_OPEN".to_string(),
                "WFS_CLOSE".to_string(),
                "WFS_REGISTER".to_string(),
                "WFS_DEREGISTER".to_string(),
                "WFS_LOCK".to_string(),
                "WFS_UNLOCK".to_string(),
                "WFS_CMD_GET_INFO".to_string(),
                "WFS_CMD_EXECUTE".to_string(),
                "WFS_INF_GET_STATUS".to_string(),
                "WFS_INF_GET_CAPABILITIES".to_string(),
                "WFS_IDC_CASH_IN".to_string(),
                "WFS_IDC_CASH_OUT".to_string(),
                "WFS_IDC_EJECT".to_string(),
                "WFS_IDC_RETAIN".to_string(),
                "WFS_IDC_READ_TRACK".to_string(),
                "WFS_IDC_READ_RAW".to_string(),
                "WFS_IDC_RESET".to_string(),
                "WFS_IDC_WRITE_TRACK".to_string(),
                "WFS_PIN_GET_PIN".to_string(),
                "WFS_PIN_DISPLAY_PIN".to_string(),
                "WFS_PIN_RESET".to_string(),
                "WFS_DISP_DISPENSE".to_string(),
                "WFS_DISP_GET_INFO".to_string(),
                "WFS_DISP_RESET".to_string(),
            ],
            ProtocolType::S7CommPlus => vec![
                "JOB_REQUEST".to_string(),
                "JOB_RESPONSE".to_string(),
                "ACK".to_string(),
                "USER_DATA".to_string(),
                "ALARM_NOTIFICATION".to_string(),
                "SYSTEM_STATUS".to_string(),
            ],
            ProtocolType::Modbus => vec![
                "READ_COILS".to_string(),
                "READ_DISCRETE_INPUTS".to_string(),
                "READ_HOLDING_REGISTERS".to_string(),
                "READ_INPUT_REGISTERS".to_string(),
                "WRITE_SINGLE_COIL".to_string(),
                "WRITE_SINGLE_REGISTER".to_string(),
                "WRITE_MULTIPLE_COILS".to_string(),
                "WRITE_MULTIPLE_REGISTERS".to_string(),
            ],
            ProtocolType::ISO8583 => vec![
                "AUTHORIZATION_REQUEST".to_string(),
                "AUTHORIZATION_RESPONSE".to_string(),
                "REVERSAL_REQUEST".to_string(),
                "REVERSAL_RESPONSE".to_string(),
                "SETTLEMENT_REQUEST".to_string(),
                "SETTLEMENT_RESPONSE".to_string(),
                "NETWORK_MANAGEMENT_REQUEST".to_string(),
                "NETWORK_MANAGEMENT_RESPONSE".to_string(),
            ],
            ProtocolType::NDC => vec![
                "SIGN_ON".to_string(),
                "SIGN_OFF".to_string(),
                "STATUS_REQUEST".to_string(),
                "STATUS_RESPONSE".to_string(),
                "TRANSACTION_REQUEST".to_string(),
                "TRANSACTION_RESPONSE".to_string(),
                "KEY_EXCHANGE_REQUEST".to_string(),
                "KEY_EXCHANGE_RESPONSE".to_string(),
            ],
            ProtocolType::DNP3 => vec![
                "READ".to_string(),
                "WRITE".to_string(),
                "SELECT".to_string(),
                "OPERATE".to_string(),
                "DIRECT_OPERATE".to_string(),
                "RESPONSE".to_string(),
                "UNSOLICITED_RESPONSE".to_string(),
                "CONFIRM".to_string(),
            ],
        }
    }
    
    pub fn is_stateful(&self) -> bool {
        match self {
            ProtocolType::XFS => true,
            ProtocolType::S7CommPlus => true,
            ProtocolType::Modbus => false,
            ProtocolType::ISO8583 => true,
            ProtocolType::NDC => true,
            ProtocolType::DNP3 => true,
        }
    }
    
    pub fn detect(data: &[u8]) -> Option<Self> {
        if data.len() < 4 {
            return None;
        }
        
        // Check for XFS signature
        if data.len() >= 10 && data[0] == 0x02 && data[1] == 0x00 {
            return Some(ProtocolType::XFS);
        }
        
        // Check for S7CommPlus signature
        if data.len() >= 4 && data[0] == 0x72 && data[1] == 0x01 {
            return Some(ProtocolType::S7CommPlus);
        }
        
        // Check for Modbus signature
        if data.len() >= 8 && data[0] == 0x00 && data[1] == 0x00 && 
           data[4] == 0x00 && data[5] == 0x00 {
            return Some(ProtocolType::Modbus);
        }
        
        // Check for ISO8583 signature
        if data.len() >= 4 && data[0] == 0x30 && data[1] == 0x30 {
            return Some(ProtocolType::ISO8583);
        }
        
        // Check for NDC signature
        if data.len() >= 4 && data[0] == 0x01 && data[1] == 0x00 {
            return Some(ProtocolType::NDC);
        }
        
        // Check for DNP3 signature
        if data.len() >= 4 && data[0] == 0x05 && data[1] == 0x64 {
            return Some(ProtocolType::DNP3);
        }
        
        None
    }
}

pub trait ProtocolHandler {
    fn parse(&self, data: &[u8]) -> Result<HashMap<String, serde_json::Value>>;
    fn get_message_type(&self, data: &[u8]) -> Result<String>;
    fn is_request(&self, data: &[u8]) -> Result<bool>;
    fn is_response(&self, data: &[u8]) -> Result<bool>;
    fn get_fields(&self) -> Vec<String>;
}

pub struct ProtocolHandlerFactory;

impl ProtocolHandlerFactory {
    pub fn create_handler(protocol_type: ProtocolType) -> Box<dyn ProtocolHandler> {
        match protocol_type {
            ProtocolType::XFS => Box::new(XFSHandler::new()),
            ProtocolType::S7CommPlus => Box::new(S7CommPlusHandler::new()),
            ProtocolType::Modbus => Box::new(ModbusHandler::new()),
            ProtocolType::ISO8583 => Box::new(ISO8583Handler::new()),
            ProtocolType::NDC => Box::new(NDCHandler::new()),
            ProtocolType::DNP3 => Box::new(DNP3Handler::new()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolMessage {
    pub protocol: String,
    pub message_type: String,
    pub is_request: bool,
    pub is_response: bool,
    pub fields: HashMap<String, serde_json::Value>,
    pub raw_data: Vec<u8>,
}

impl ProtocolMessage {
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

pub fn detect_protocol(data: &[u8]) -> Result<ProtocolType> {
    ProtocolType::detect(data).ok_or_else(|| anyhow!("Unknown protocol"))
}

pub fn parse_message(data: &[u8]) -> Result<ProtocolMessage> {
    let protocol_type = detect_protocol(data)?;
    let handler = ProtocolHandlerFactory::create_handler(protocol_type);
    
    let fields = handler.parse(data)?;
    let message_type = handler.get_message_type(data)?;
    let is_request = handler.is_request(data)?;
    let is_response = handler.is_response(data)?;
    
    Ok(ProtocolMessage::new(
        protocol_type.as_str().to_string(),
        message_type,
        is_request,
        is_response,
        fields,
        data.to_vec(),
    ))
}

// Placeholder handlers for protocols not yet implemented
struct NDCHandler;
struct DNP3Handler;

impl ProtocolHandler for NDCHandler {
    fn parse(&self, data: &[u8]) -> Result<HashMap<String, serde_json::Value>> {
        let mut fields = HashMap::new();
        fields.insert("protocol".to_string(), serde_json::Value::String("NDC".to_string()));
        fields.insert("raw_data".to_string(), serde_json::Value::String(
            data.iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(" ")
        ));
        Ok(fields)
    }
    
    fn get_message_type(&self, data: &[u8]) -> Result<String> {
        if data.len() < 4 {
            return Ok("UNKNOWN".to_string());
        }
        
        let msg_type = u16::from_le_bytes([data[2], data[3]]);
        match msg_type {
            0x01 => Ok("SIGN_ON".to_string()),
            0x02 => Ok("SIGN_OFF".to_string()),
            0x03 => Ok("STATUS_REQUEST".to_string()),
            0x04 => Ok("STATUS_RESPONSE".to_string()),
            0x05 => Ok("TRANSACTION_REQUEST".to_string()),
            0x06 => Ok("TRANSACTION_RESPONSE".to_string()),
            0x07 => Ok("KEY_EXCHANGE_REQUEST".to_string()),
            0x08 => Ok("KEY_EXCHANGE_RESPONSE".to_string()),
            _ => Ok(format!("UNKNOWN_0x{:04X}", msg_type)),
        }
    }
    
    fn is_request(&self, data: &[u8]) -> Result<bool> {
        if data.len() < 4 {
            return Ok(false);
        }
        
        let msg_type = u16::from_le_bytes([data[2], data[3]]);
        Ok(msg_type % 2 == 1) // Odd messages are requests
    }
    
    fn is_response(&self, data: &[u8]) -> Result<bool> {
        Ok(!self.is_request(data)?)
    }
    
    fn get_fields(&self) -> Vec<String> {
        vec![
            "header".to_string(),
            "message_type".to_string(),
            "data".to_string(),
        ]
    }
}

impl ProtocolHandler for DNP3Handler {
    fn parse(&self, data: &[u8]) -> Result<HashMap<String, serde_json::Value>> {
        let mut fields = HashMap::new();
        fields.insert("protocol".to_string(), serde_json::Value::String("DNP3".to_string()));
        fields.insert("raw_data".to_string(), serde_json::Value::String(
            data.iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(" ")
        ));
        Ok(fields)
    }
    
    fn get_message_type(&self, data: &[u8]) -> Result<String> {
        if data.len() < 10 {
            return Ok("UNKNOWN".to_string());
        }
        
        let function = data[9];
        match function {
            0x01 => Ok("READ".to_string()),
            0x02 => Ok("WRITE".to_string()),
            0x03 => Ok("SELECT".to_string()),
            0x04 => Ok("OPERATE".to_string()),
            0x05 => Ok("DIRECT_OPERATE".to_string()),
            0x81 => Ok("RESPONSE".to_string()),
            0x82 => Ok("UNSOLICITED_RESPONSE".to_string()),
            0x83 => Ok("CONFIRM".to_string()),
            _ => Ok(format!("UNKNOWN_0x{:02X}", function)),
        }
    }
    
    fn is_request(&self, data: &[u8]) -> Result<bool> {
        if data.len() < 10 {
            return Ok(false);
        }
        
        let function = data[9];
        Ok(function < 0x80) // Functions < 0x80 are requests
    }
    
    fn is_response(&self, data: &[u8]) -> Result<bool> {
        Ok(!self.is_request(data)?)
    }
    
    fn get_fields(&self) -> Vec<String> {
        vec![
            "start".to_string(),
            "length".to_string(),
            "control".to_string(),
            "destination".to_string(),
            "source".to_string(),
            "function".to_string(),
            "data".to_string(),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_protocol_type_from_str() {
        assert_eq!(ProtocolType::from_str("xfs"), Some(ProtocolType::XFS));
        assert_eq!(ProtocolType::from_str("XFS"), Some(ProtocolType::XFS));
        assert_eq!(ProtocolType::from_str("s7commplus"), Some(ProtocolType::S7CommPlus));
        assert_eq!(ProtocolType::from_str("s7comm_plus"), Some(ProtocolType::S7CommPlus));
        assert_eq!(ProtocolType::from_str("modbus"), Some(ProtocolType::Modbus));
        assert_eq!(ProtocolType::from_str("iso8583"), Some(ProtocolType::ISO8583));
        assert_eq!(ProtocolType::from_str("ndc"), Some(ProtocolType::NDC));
        assert_eq!(ProtocolType::from_str("dnp3"), Some(ProtocolType::DNP3));
        assert_eq!(ProtocolType::from_str("unknown"), None);
    }
    
    #[test]
    fn test_protocol_type_as_str() {
        assert_eq!(ProtocolType::XFS.as_str(), "xfs");
        assert_eq!(ProtocolType::S7CommPlus.as_str(), "s7commplus");
        assert_eq!(ProtocolType::Modbus.as_str(), "modbus");
        assert_eq!(ProtocolType::ISO8583.as_str(), "iso8583");
        assert_eq!(ProtocolType::NDC.as_str(), "ndc");
        assert_eq!(ProtocolType::DNP3.as_str(), "dnp3");
    }
    
    #[test]
    fn test_detect_protocol() {
        let xfs_data = vec![0x02, 0x00, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00];
        assert_eq!(detect_protocol(&xfs_data).unwrap(), ProtocolType::XFS);
        
        let s7_data = vec![0x72, 0x01, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00];
        assert_eq!(detect_protocol(&s7_data).unwrap(), ProtocolType::S7CommPlus);
        
        let modbus_data = vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00];
        assert_eq!(detect_protocol(&modbus_data).unwrap(), ProtocolType::Modbus);
        
        let iso_data = vec![0x30, 0x30, 0x30, 0x30, 0x10, 0x00, 0x01, 0x00];
        assert_eq!(detect_protocol(&iso_data).unwrap(), ProtocolType::ISO8583);
        
        let ndc_data = vec![0x01, 0x00, 0x01, 0x00, 0x10, 0x00, 0x01, 0x00];
        assert_eq!(detect_protocol(&ndc_data).unwrap(), ProtocolType::NDC);
        
        let dnp3_data = vec![0x05, 0x64, 0x10, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00];
        assert_eq!(detect_protocol(&dnp3_data).unwrap(), ProtocolType::DNP3);
        
        let unknown_data = vec![0xFF, 0xFF, 0xFF, 0xFF];
        assert!(detect_protocol(&unknown_data).is_err());
    }
}
