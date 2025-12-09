//! S7CommPlus Protocol Handler and Engine
//! 
//! This module provides a complete implementation of the S7CommPlus protocol,
//! including parsing, state tracking, and fuzzing capabilities.

use std::collections::HashMap;
use anyhow::{Result, anyhow, bail, Context};
use serde::{Deserialize, Serialize};
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use std::io::{Cursor, Write};
use std::sync::{Arc, Mutex};

use crate::protocols::ot::modbus::OTProtocolHandler;
use crate::protocols::ProtocolHandler;
use crate::protocols::ProtocolType;
use crate::protocols::ProtocolMessage;
use crate::mutators::{Fuzzer, MutationStrategy};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S7CommPlusMessageType {
    JobRequest = 0x01,
    JobResponse = 0x02,
    Ack = 0x03,
    UserData = 0x07,
    AlarmNotification = 0x08,
    SystemStatus = 0x0C,
}

impl S7CommPlusMessageType {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x01 => Some(S7CommPlusMessageType::JobRequest),
            0x02 => Some(S7CommPlusMessageType::JobResponse),
            0x03 => Some(S7CommPlusMessageType::Ack),
            0x07 => Some(S7CommPlusMessageType::UserData),
            0x08 => Some(S7CommPlusMessageType::AlarmNotification),
            0x0C => Some(S7CommPlusMessageType::SystemStatus),
            _ => None,
        }
    }
    
    pub fn as_str(&self) -> &'static str {
        match self {
            S7CommPlusMessageType::JobRequest => "JOB_REQUEST",
            S7CommPlusMessageType::JobResponse => "JOB_RESPONSE",
            S7CommPlusMessageType::Ack => "ACK",
            S7CommPlusMessageType::UserData => "USER_DATA",
            S7CommPlusMessageType::AlarmNotification => "ALARM_NOTIFICATION",
            S7CommPlusMessageType::SystemStatus => "SYSTEM_STATUS",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct S7CommPlusHeader {
    pub magic: u16,
    pub version: u16,
    pub reserved: u32,
    pub message_type: u8,
    pub length: u16,
    pub sequence_number: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct S7CommPlusMessage {
    pub header: S7CommPlusHeader,
    pub message_type_name: String,
    pub data: Vec<u8>,
    pub is_request: bool,
    pub is_response: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum S7CommPlusState {
    Disconnected,
    Connected,
    Authenticated,
    Error,
}

impl S7CommPlusState {
    pub fn as_str(&self) -> &'static str {
        match self {
            S7CommPlusState::Disconnected => "DISCONNECTED",
            S7CommPlusState::Connected => "CONNECTED",
            S7CommPlusState::Authenticated => "AUTHENTICATED",
            S7CommPlusState::Error => "ERROR",
        }
    }
}

pub struct S7CommPlusStateMachine {
    current_state: S7CommPlusState,
    sequence_number: u16,
}

impl S7CommPlusStateMachine {
    pub fn new() -> Self {
        Self {
            current_state: S7CommPlusState::Disconnected,
            sequence_number: 0,
        }
    }
    
    pub fn get_current_state(&self) -> &str {
        self.current_state.as_str()
    }
    
    pub fn is_in_error_state(&self) -> bool {
        self.current_state == S7CommPlusState::Error
    }
    
    pub fn get_sequence_number(&self) -> u16 {
        self.sequence_number
    }
    
    pub fn increment_sequence_number(&mut self) {
        self.sequence_number = self.sequence_number.wrapping_add(1);
    }
    
    pub fn process_event(&mut self, event: &str) -> Result<()> {
        let old_state = self.current_state.clone();
        
        let next_state = match (&self.current_state, event) {
            // Connection events
            (S7CommPlusState::Disconnected, e) if e.contains("CONNECT") => {
                self.sequence_number = 0; // Reset sequence number on connect
                S7CommPlusState::Connected
            },
            
            // Authentication events
            (S7CommPlusState::Connected, e) if e.contains("AUTH_SUCCESS") => {
                S7CommPlusState::Authenticated
            },
            (S7CommPlusState::Connected, e) if e.contains("AUTH_FAILURE") => {
                S7CommPlusState::Error
            },
            
            // Disconnection events
            (S7CommPlusState::Connected, e) if e.contains("DISCONNECT") => {
                S7CommPlusState::Disconnected
            },
            (S7CommPlusState::Authenticated, e) if e.contains("DISCONNECT") => {
                S7CommPlusState::Disconnected
            },
            
            // Error events
            (_, e) if e.contains("ERROR") => {
                S7CommPlusState::Error
            },
            
            // Recovery from error
            (S7CommPlusState::Error, e) if e.contains("RESET") => {
                S7CommPlusState::Disconnected
            },
            
            // Default: stay in same state
            (s, _) => s.clone(),
        };
        
        self.current_state = next_state;
        
        // Increment sequence number for successful requests
        if event.contains("REQ_") && self.current_state != S7CommPlusState::Error {
            self.increment_sequence_number();
        }
        
        Ok(())
    }
}

pub struct S7CommPlusHandler {
    state_machine: S7CommPlusStateMachine,
}

impl S7CommPlusHandler {
    pub fn new() -> Self {
        Self {
            state_machine: S7CommPlusStateMachine::new(),
        }
    }
    
    pub fn parse_header(&self, data: &[u8]) -> Result<S7CommPlusHeader> {
        if data.len() < 12 {
            return Err(anyhow!("S7CommPlus message too short for header"));
        }
        
        let mut cursor = Cursor::new(data);
        
        let magic = cursor.read_u16::<BigEndian>()?;
        let version = cursor.read_u16::<BigEndian>()?;
        let reserved = cursor.read_u32::<BigEndian>()?;
        let message_type = cursor.read_u8()?;
        let length = cursor.read_u16::<BigEndian>()?;
        let sequence_number = cursor.read_u16::<BigEndian>()?;
        
        Ok(S7CommPlusHeader {
            magic,
            version,
            reserved,
            message_type,
            length,
            sequence_number,
        })
    }
    
    pub fn parse_message(&self, data: &[u8]) -> Result<S7CommPlusMessage> {
        let header = self.parse_header(data)?;
        
        if header.magic != 0x7201 {
            return Err(anyhow!("Invalid S7CommPlus magic number: 0x{:04X}", header.magic));
        }
        
        let message_type_name = match S7CommPlusMessageType::from_u8(header.message_type) {
            Some(msg_type) => msg_type.as_str().to_string(),
            None => format!("UNKNOWN_MESSAGE_TYPE_{:02X}", header.message_type),
        };
        
        let data_start = 12;
        let data = if data.len() > data_start {
            data[data_start..].to_vec()
        } else {
            Vec::new()
        };
        
        // Determine if this is a request or response based on the message type
        let (is_request, is_response) = match header.message_type {
            0x01 => (true, false),  // JobRequest
            0x02 => (false, true), // JobResponse
            0x03 => (false, true), // Ack
            0x07 => (true, false),  // UserData
            0x08 => (false, true), // AlarmNotification
            0x0C => (false, true), // SystemStatus
            _ => (false, false),    // Unknown
        };
        
        Ok(S7CommPlusMessage {
            header,
            message_type_name,
            data,
            is_request,
            is_response,
        })
    }
    
    pub fn parse_job_request(&self, data: &[u8]) -> Result<(u8, u32, Vec<u8>)> {
        if data.len() < 5 {
            return Err(anyhow!("Job request too short"));
        }
        
        let mut cursor = Cursor::new(data);
        let function_code = cursor.read_u8()?;
        let parameter_length = cursor.read_u32::<BigEndian>()?;
        
        let mut parameters = Vec::new();
        for _ in 0..parameter_length {
            if cursor.position() < data.len() as u64 {
                parameters.push(cursor.read_u8()?);
            }
        }
        
        Ok((function_code, parameter_length, parameters))
    }
    
    pub fn parse_job_response(&self, data: &[u8]) -> Result<(u8, u32, Vec<u8>)> {
        if data.len() < 5 {
            return Err(anyhow!("Job response too short"));
        }
        
        let mut cursor = Cursor::new(data);
        let function_code = cursor.read_u8()?;
        let parameter_length = cursor.read_u32::<BigEndian>()?;
        
        let mut parameters = Vec::new();
        for _ in 0..parameter_length {
            if cursor.position() < data.len() as u64 {
                parameters.push(cursor.read_u8()?);
            }
        }
        
        Ok((function_code, parameter_length, parameters))
    }
    
    pub fn update_state_machine(&mut self, message: &S7CommPlusMessage) -> Result<()> {
        let event = if message.is_request {
            format!("REQ_{}", message.message_type_name)
        } else {
            format!("RES_{}", message.message_type_name)
        };
        
        self.state_machine.process_event(&event)
    }
    
    pub fn get_current_state(&self) -> &str {
        self.state_machine.get_current_state()
    }
    
    pub fn is_in_error_state(&self) -> bool {
        self.state_machine.is_in_error_state()
    }
    
    pub fn get_sequence_number(&self) -> u16 {
        self.state_machine.get_sequence_number()
    }
}

impl Default for S7CommPlusHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl ProtocolHandler for S7CommPlusHandler {
    fn parse(&self, data: &[u8]) -> Result<HashMap<String, serde_json::Value>> {
        let message = self.parse_message(data)?;
        
        let mut fields = HashMap::new();
        fields.insert("protocol".to_string(), serde_json::Value::String("S7CommPlus".to_string()));
        fields.insert("magic".to_string(), serde_json::Value::Number(message.header.magic.into()));
        fields.insert("version".to_string(), serde_json::Value::Number(message.header.version.into()));
        fields.insert("reserved".to_string(), serde_json::Value::Number(message.header.reserved.into()));
        fields.insert("message_type".to_string(), serde_json::Value::Number(message.header.message_type.into()));
        fields.insert("message_type_name".to_string(), serde_json::Value::String(message.message_type_name.clone()));
        fields.insert("length".to_string(), serde_json::Value::Number(message.header.length.into()));
        fields.insert("sequence_number".to_string(), serde_json::Value::Number(message.header.sequence_number.into()));
        fields.insert("is_request".to_string(), serde_json::Value::Bool(message.is_request));
        fields.insert("is_response".to_string(), serde_json::Value::Bool(message.is_response));
        
        // Parse message-specific data
        match S7CommPlusMessageType::from_u8(message.header.message_type) {
            Some(S7CommPlusMessageType::JobRequest) => {
                if let Ok((function_code, parameter_length, parameters)) = self.parse_job_request(&message.data) {
                    fields.insert("function_code".to_string(), serde_json::Value::Number(function_code.into()));
                    fields.insert("parameter_length".to_string(), serde_json::Value::Number(parameter_length.into()));
                    let parameter_values: Vec<serde_json::Value> = parameters
                        .iter()
                        .map(|&v| serde_json::Value::Number(v.into()))
                        .collect();
                    fields.insert("parameters".to_string(), serde_json::Value::Array(parameter_values));
                }
            },
            Some(S7CommPlusMessageType::JobResponse) => {
                if let Ok((function_code, parameter_length, parameters)) = self.parse_job_response(&message.data) {
                    fields.insert("function_code".to_string(), serde_json::Value::Number(function_code.into()));
                    fields.insert("parameter_length".to_string(), serde_json::Value::Number(parameter_length.into()));
                    let parameter_values: Vec<serde_json::Value> = parameters
                        .iter()
                        .map(|&v| serde_json::Value::Number(v.into()))
                        .collect();
                    fields.insert("parameters".to_string(), serde_json::Value::Array(parameter_values));
                }
            },
            _ => {
                // For unknown message types, include raw data as hex
                fields.insert("raw_data".to_string(), serde_json::Value::String(
                    message.data.iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(" ")
                ));
            }
        }
        
        Ok(fields)
    }
    
    fn get_message_type(&self, data: &[u8]) -> Result<String> {
        let message = self.parse_message(data)?;
        Ok(message.message_type_name)
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
            "magic".to_string(),
            "version".to_string(),
            "reserved".to_string(),
            "message_type".to_string(),
            "message_type_name".to_string(),
            "length".to_string(),
            "sequence_number".to_string(),
            "function_code".to_string(),
            "parameter_length".to_string(),
            "parameters".to_string(),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_parse_header() {
        let handler = S7CommPlusHandler::new();
        let data = [
            0x72, 0x01,              // magic = 0x7201
            0x00, 0x01,              // version = 1
            0x00, 0x00, 0x00, 0x00, // reserved = 0
            0x01,                    // message_type = 1 (JobRequest)
            0x00, 0x05,              // length = 5
            0x00, 0x01,              // sequence_number = 1
        ];
        
        let header = handler.parse_header(&data).unwrap();
        assert_eq!(header.magic, 0x7201);
        assert_eq!(header.version, 1);
        assert_eq!(header.reserved, 0);
        assert_eq!(header.message_type, 1);
        assert_eq!(header.length, 5);
        assert_eq!(header.sequence_number, 1);
    }
    
    #[test]
    fn test_parse_job_request() {
        let handler = S7CommPlusHandler::new();
        let data = [
            0x72, 0x01,              // magic = 0x7201
            0x00, 0x01,              // version = 1
            0x00, 0x00, 0x00, 0x00, // reserved = 0
            0x01,                    // message_type = 1 (JobRequest)
            0x00, 0x05,              // length = 5
            0x00, 0x01,              // sequence_number = 1
            0x04,                    // function_code = 4
            0x00, 0x00, 0x00, 0x01, // parameter_length = 1
            0x42,                    // parameter = 0x42
        ];
        
        let message = handler.parse_message(&data).unwrap();
        assert_eq!(message.message_type_name, "JOB_REQUEST");
        assert!(message.is_request);
        assert!(!message.is_response);
        
        let (function_code, parameter_length, parameters) = handler.parse_job_request(&message.data).unwrap();
        assert_eq!(function_code, 4);
        assert_eq!(parameter_length, 1);
        assert_eq!(parameters, vec![0x42]);
    }
    
    #[test]
    fn test_parse_job_response() {
        let handler = S7CommPlusHandler::new();
        let data = [
            0x72, 0x01,              // magic = 0x7201
            0x00, 0x01,              // version = 1
            0x00, 0x00, 0x00, 0x00, // reserved = 0
            0x02,                    // message_type = 2 (JobResponse)
            0x00, 0x05,              // length = 5
            0x00, 0x01,              // sequence_number = 1
            0x04,                    // function_code = 4
            0x00, 0x00, 0x00, 0x01, // parameter_length = 1
            0x43,                    // parameter = 0x43
        ];
        
        let message = handler.parse_message(&data).unwrap();
        assert_eq!(message.message_type_name, "JOB_RESPONSE");
        assert!(!message.is_request);
        assert!(message.is_response);
        
        let (function_code, parameter_length, parameters) = handler.parse_job_response(&message.data).unwrap();
        assert_eq!(function_code, 4);
        assert_eq!(parameter_length, 1);
        assert_eq!(parameters, vec![0x43]);
    }
    
    #[test]
    fn test_state_machine() {
        let mut sm = S7CommPlusStateMachine::new();
        assert_eq!(sm.get_current_state(), "DISCONNECTED");
        assert_eq!(sm.get_sequence_number(), 0);
        
        // Connect
        sm.process_event("CONNECT").unwrap();
        assert_eq!(sm.get_current_state(), "CONNECTED");
        assert_eq!(sm.get_sequence_number(), 0);
        
        // Authenticate successfully
        sm.process_event("AUTH_SUCCESS").unwrap();
        assert_eq!(sm.get_current_state(), "AUTHENTICATED");
        assert_eq!(sm.get_sequence_number(), 0);
        
        // Send a request
        sm.process_event("REQ_JOB_REQUEST").unwrap();
        assert_eq!(sm.get_current_state(), "AUTHENTICATED");
        assert_eq!(sm.get_sequence_number(), 1);
        
        // Send another request
        sm.process_event("REQ_JOB_REQUEST").unwrap();
        assert_eq!(sm.get_current_state(), "AUTHENTICATED");
        assert_eq!(sm.get_sequence_number(), 2);
        
        // Disconnect
        sm.process_event("DISCONNECT").unwrap();
        assert_eq!(sm.get_current_state(), "DISCONNECTED");
        assert_eq!(sm.get_sequence_number(), 2); // Sequence number preserved
        
        // Reconnect
        sm.process_event("CONNECT").unwrap();
        assert_eq!(sm.get_current_state(), "CONNECTED");
        assert_eq!(sm.get_sequence_number(), 0); // Sequence number reset on connect
    }
}
