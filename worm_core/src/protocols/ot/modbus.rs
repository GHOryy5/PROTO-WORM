//! Modbus/TCP Protocol Core
//!
//! Implements message structures and parsing logic for Modbus TCP, a
//! widely used, unauthenticated industrial control protocol.

use anyhow::{Result, Context};
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use std::io::{Cursor, Read, Write};

// --- 1. Modbus TCP Header (MBAP) Structure ---
// Modbus Application Protocol (MBAP) header is 7 bytes
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct ModbusHeader {
    // Transaction Identifier (2 bytes): Used for client/server request/response matching
    pub transaction_id: u16,
    // Protocol Identifier (2 bytes): Should always be 0 for Modbus/TCP
    pub protocol_id: u16,
    // Length (2 bytes): Number of bytes in the PDU that follow the MBAP header
    pub length: u16,
    // Unit Identifier (1 byte): Used for routing to specific slaves on a serial line
    pub unit_id: u8,
}

// --- 2. Function Codes (The core operation) ---
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum ModbusFunction {
    // Standard Read Operations
    READ_COILS = 0x01,
    READ_DISCRETE_INPUTS = 0x02,
    READ_HOLDING_REGISTERS = 0x03,
    READ_INPUT_REGISTERS = 0x04,
    // Standard Write Operations
    WRITE_SINGLE_COIL = 0x05,
    WRITE_SINGLE_REGISTER = 0x06,
    WRITE_MULTIPLE_COILS = 0x0F,
    WRITE_MULTIPLE_REGISTERS = 0x10,
    // Exceptions use Function Code + 0x80
    EXCEPTION_MASK = 0x80,
}

// --- 3. Modbus Message Container ---
pub struct ModbusMessage {
    pub header: ModbusHeader,
    pub function_code: u8,
    // The rest of the message data (function-specific payload)
    pub data: Vec<u8>,
}

impl ModbusMessage {
    /// Creates a request for a standard function, like reading registers.
    pub fn new_request(func: ModbusFunction, unit_id: u8, address: u16, quantity: u16) -> Result<Self> {
        let mut data = Vec::new();
        // Address (2 bytes)
        data.write_u16::<BigEndian>(address).context("Failed to write address")?;
        // Quantity (2 bytes)
        data.write_u16::<BigEndian>(quantity).context("Failed to write quantity")?;

        let length = (data.len() + 1) as u16; // +1 for the function code
        
        let header = ModbusHeader {
            // Transaction IDs should be unique, but 1 is fine for a single fuzzer iteration
            transaction_id: rand::random(), 
            protocol_id: 0,
            length,
            unit_id,
        };

        Ok(Self {
            header,
            function_code: func as u8,
            data,
        })
    }
    
    /// Serializes the ModbusMessage struct into raw bytes for network transmission.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();

        // 1. Write MBAP Header (Big Endian)
        buf.write_u16::<BigEndian>(self.header.transaction_id)?;
        buf.write_u16::<BigEndian>(self.header.protocol_id)?;
        buf.write_u16::<BigEndian>(self.header.length)?;
        buf.write_u8(self.header.unit_id)?;

        // 2. Write Function Code
        buf.write_u8(self.function_code)?;

        // 3. Write PDU Data (Payload)
        buf.write_all(&self.data)?;

        Ok(buf)
    }

    /// Deserializes raw bytes received from the network into a ModbusMessage struct.
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let mut cursor = Cursor::new(data);

        // 1. Read MBAP Header
        let transaction_id = cursor.read_u16::<BigEndian>().context("Failed to read transaction ID")?;
        let protocol_id = cursor.read_u16::<BigEndian>().context("Failed to read protocol ID")?;
        let length = cursor.read_u16::<BigEndian>().context("Failed to read length")?;
        let unit_id = cursor.read_u8().context("Failed to read unit ID")?;

        let header = ModbusHeader { transaction_id, protocol_id, length, unit_id };
        
        // Basic sanity check: is the length field plausible?
        if length as usize != data.len() - 6 { // PDU length (Function Code + Data)
            return Err(anyhow::anyhow!("MBAP Length field mismatch. Possible packet corruption or truncation."));
        }

        // 2. Read Function Code
        let function_code = cursor.read_u8().context("Failed to read function code")?;

        // 3. Read Remaining PDU Data (Payload)
        let mut data_buf = Vec::new();
        cursor.read_to_end(&mut data_buf).context("Failed to read PDU data")?;

        Ok(ModbusMessage { header, function_code, data: data_buf })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_modbus_read_request_creation() -> Result<()> {
        let message = ModbusMessage::new_request(
            ModbusFunction::READ_HOLDING_REGISTERS,
            1,    // Unit ID
            0x1000, // Starting Address
            10,   // Quantity
        )?;

        // Check Header Values
        assert_eq!(message.header.protocol_id, 0);
        // Length = 1 (Function Code) + 4 (Address/Quantity) = 5
        assert_eq!(message.header.length, 5);
        assert_eq!(message.header.unit_id, 1);
        
        // Check Function Code
        assert_eq!(message.function_code, ModbusFunction::READ_HOLDING_REGISTERS as u8);

        // Check PDU Payload (Address: 0x1000, Quantity: 10)
        let expected_data = vec![
            0x10, 0x00, // Address
            0x00, 0x0A, // Quantity (10)
        ];
        assert_eq!(message.data, expected_data);

        Ok(())
    }

    #[test]
    fn test_modbus_serialization_deserialization() -> Result<()> {
        let original_msg = ModbusMessage::new_request(
            ModbusFunction::WRITE_SINGLE_REGISTER,
            42, 
            0x00FF, 
            1, // Quantity doesn't apply to single write but is required by the constructor
        )?;

        let bytes = original_msg.to_bytes()?;
        // MBAP (7) + Function Code (1) + Address/Quantity (4) = 12 bytes
        assert_eq!(bytes.len(), 12); 

        let decoded_msg = ModbusMessage::from_bytes(&bytes)?;

        // Verify that the decoded message matches the original
        assert_eq!(decoded_msg.header.unit_id, original_msg.header.unit_id);
        assert_eq!(decoded_msg.function_code, original_msg.function_code);
        assert_eq!(decoded_msg.data, original_msg.data);

        Ok(())
    }
}
