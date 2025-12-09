//! XFS Protocol Engine Core
//!
//! Handles serialization/deserialization of XFS messages and manages the
//! session state machine. This is central logic for protocol analysis
//! and stateful packet generation.

use anyhow::{Result, bail, Context};
use crate::protocols::xfs::xfs_messages::{WFSHDR, XFSMessage, XFSCommand, XFSError};
use crate::protocols::xfs::state_v3::XFSStateMachine;
use std::mem;
use std::ptr;

// A simple structure to hold the entire context of a single XFS session
pub struct XFSSessionEngine {
    state_machine: XFSStateMachine,
    // We'll use session ID tracked by state machine
    service_handle: u32,
}

impl XFSSessionEngine {
    pub fn new() -> Self {
        Self {
            state_machine: XFSStateMachine::new(),
            service_handle: 0,
        }
    }

    pub fn get_current_state(&self) -> &str {
        self.state_machine.get_current_state()
    }

    /// Converts raw bytes into an XFSMessage struct and updates state.
    /// This is the core "Protocol Parser" and "Stateful Monitor."
    pub fn parse_and_process(&mut self, data: &[u8]) -> Result<XFSMessage> {
        // 1. Deserialization: Convert bytes to structured message.
        let msg = XFSMessage::from_bytes(data)
            .context("Failed to deserialize raw bytes into XFSMessage structure")?;

        // 2. State Event Creation: Generate a verbose event string for the state machine.
        let command_name = msg.get_command_name();
        let is_response = msg.header.h_service != 0 && msg.header.h_async_service == 0;
        let prefix = if is_response { "RES_" } else { "REQ_" };
        
        let mut event_string = format!("{}{}", prefix, command_name);

        // 3. Error/Success Annotation (Crucial for state transitions)
        if is_response {
            // Check the command field in the response header for an error code (WFS_ERR_*)
            let result_code = msg.header.dw_command as u32;
            if result_code != XFSError::Success as u32 {
                let err_name = XFSError::from_u32(result_code)
                    .map(|e| format!("{:?}", e))
                    .unwrap_or_else(|| format!("UNKNOWN_ERROR_0x{:X}", result_code));
                
                event_string = format!("{}_ERROR:{}", event_string, err_name);
            }
        }
        
        // 4. State Transition
        self.state_machine.process_event(&event_string)
            .context(format!("State machine transition failed on event: {}", event_string))?;

        // 5. Update Session Handle (Example for WFS_OPEN success)
        if command_name == XFSCommand::Open.as_str() && !event_string.contains("ERROR") {
             // A real implementation would parse the WFSOpen structure from payload
             // For now, we simulate success by using the h_service from the header
             self.service_handle = msg.header.h_service as u32;
        }

        Ok(msg)
    }

    /// Generates a binary request for a given command, ready to be sent.
    /// This is the "Fuzzing Packet Generator" component.
    pub fn create_request(&mut self, command: XFSCommand, payload: Vec<u8>) -> Result<Vec<u8>> {
        // Enforce state validity before creating a request
        if self.state_machine.is_in_error_state() {
             bail!("Cannot send request: Current state is in an unrecoverable ERROR state.");
        }

        let mut header = WFSHDR::default();
        header.h_service = self.service_handle as c_ulong; // Use current service handle
        header.dw_command = command as u32 as c_ulong;
        header.dw_size = payload.len() as c_ulong;
        
        // In a real fuzzer, you'd put fuzzed/controlled data pointer here
        // For simplicity, we just use null_mut as the data is in 'payload'
        header.lp_buffer = ptr::null_mut(); 

        let msg = XFSMessage::new(header, command, payload);
        
        // Before returning bytes, check the state transition (assuming request succeeds for now)
        let event_string = format!("REQ_{}", msg.get_command_name());
        self.state_machine.process_event(&event_string)
            .context(format!("Pre-send state check failed for event: {}", event_string))?;

        Ok(msg.to_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocols::xfs::xfs_messages::XFSCommand;

    #[test]
    fn test_engine_happy_path() -> Result<()> {
        let mut engine = XFSSessionEngine::new();
        
        // 1. Simulate WFS_OPEN Request (Creates request, updates state to BUSY)
        let open_req_bytes = engine.create_request(XFSCommand::Open, vec![0xDE, 0xAD, 0xBE, 0xEF])?;
        assert_eq!(engine.get_current_state(), "BUSY_PROCESSING");

        // 2. Simulate WFS_OPEN Response (Must include a service handle for success)
        let mut response_header = WFSHDR::default();
        response_header.dw_command = XFSError::Success as u32 as c_ulong; // Success code
        response_header.h_service = 0xAAAA_BBBB; // The service handle
        let response_msg = XFSMessage::new(response_header, XFSCommand::Open, vec![]);
        let open_res_bytes = response_msg.to_bytes();
        
        engine.parse_and_process(&open_res_bytes)?;
        assert_eq!(engine.get_current_state(), "IDLE");
        assert_eq!(engine.service_handle, 0xAAAA_BBBB);

        // 3. Simulate WFS_CDM_DISPENSE Request
        let dispense_req_bytes = engine.create_request(XFSCommand::CDM_Dispense, vec![0x10, 0x00])?;
        assert_eq!(engine.get_current_state(), "BUSY_PROCESSING");

        // 4. Simulate WFS_CDM_DISPENSE Success Response
        let mut dispense_res_header = WFSHDR::default();
        dispense_res_header.dw_command = XFSError::Success as u32 as c_ulong;
        let dispense_res_msg = XFSMessage::new(dispense_res_header, XFSCommand::CDM_Dispense, vec![]);
        let dispense_res_bytes = dispense_res_msg.to_bytes();

        engine.parse_and_process(&dispense_res_bytes)?;
        assert_eq!(engine.get_current_state(), "IDLE");

        Ok(())
    }

    #[test]
    fn test_engine_error_handling() -> Result<()> {
        let mut engine = XFSSessionEngine::new();
        engine.state_machine.process_event("RES_WFS_OPEN")?; // Manually transition to IDLE for error test

        // 1. Send a command, wait for error
        engine.create_request(XFSCommand::CDM_Dispense, vec![])?;
        assert_eq!(engine.get_current_state(), "BUSY_PROCESSING");

        // 2. Simulate Error Response (e.g., WFS_ERR_NO_DISPENSE_SUPPLY = 103)
        let mut err_res_header = WFSHDR::default();
        err_res_header.dw_command = 103 as c_ulong; 
        let err_res_msg = XFSMessage::new(err_res_header, XFSCommand::CDM_Dispense, vec![]);
        let err_res_bytes = err_res_msg.to_bytes();

        let result = engine.parse_and_process(&err_res_bytes);
        assert!(result.is_err());
        // The error response should have triggered an "ERROR" state transition
        assert_eq!(engine.get_current_state(), "ERROR");
        
        // 3. Attempt to send a request while in error state (should fail)
        let fail_request = engine.create_request(XFSCommand::CDM_Dispense, vec![]);
        assert!(fail_request.is_err());
        assert!(fail_request.unwrap_err().to_string().contains("Cannot send request: Current state is in an unrecoverable ERROR state."));

        // 4. Test recovery via reset command
        engine.create_request(XFSCommand::CDM_Reset, vec![])?; // This should update state from ERROR to BUSY
        assert_eq!(engine.get_current_state(), "BUSY_PROCESSING");

        // 5. Successful reset response
        let mut reset_res_header = WFSHDR::default();
        reset_res_header.dw_command = XFSError::Success as u32 as c_ulong;
        let reset_res_msg = XFSMessage::new(reset_res_header, XFSCommand::CDM_Reset, vec![]);
        engine.parse_and_process(&reset_res_msg.to_bytes())?;
        assert_eq!(engine.get_current_state(), "IDLE");

        Ok(())
    }
}
