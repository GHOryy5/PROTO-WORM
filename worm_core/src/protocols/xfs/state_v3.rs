//! XFS State Machine (Version 3)
//! 
//! Implements a simple deterministic finite automaton (DFA) to track the
//! session state of an XFS peripheral (e.g., a Card Dispenser). This is 
//! essential for sequential/stateful fuzzing.

use anyhow::{Result, anyhow};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum XFSState {
    Uninitialized,
    Idle,           // WFS_OPEN successful
    BusyProcessing, // WFS_CMD_EXECUTE (e.g., DISPENSE) sent, waiting for response
    ServiceReady,   // Locked and Ready for specific operation
    Error,          // Last command resulted in an error
    Fatal,          // Unrecoverable error, requires reset
}

impl XFSState {
    pub fn as_str(&self) -> &'static str {
        match self {
            XFSState::Uninitialized => "UNINITIALIZED",
            XFSState::Idle => "IDLE",
            XFSState::BusyProcessing => "BUSY_PROCESSING",
            XFSState::ServiceReady => "SERVICE_READY",
            XFSState::Error => "ERROR",
            XFSState::Fatal => "FATAL_ERROR",
        }
    }
}

pub struct XFSStateMachine {
    current_state: XFSState,
    session_id: u32,
}

impl XFSStateMachine {
    pub fn new() -> Self {
        Self {
            current_state: XFSState::Uninitialized,
            session_id: 0,
        }
    }

    pub fn get_current_state(&self) -> &str {
        self.current_state.as_str()
    }
    
    pub fn is_in_error_state(&self) -> bool {
        self.current_state == XFSState::Error || self.current_state == XFSState::Fatal
    }

    /// Processes an incoming event (a command or response) and updates state.
    /// This is where core protocol logic resides.
    pub fn process_event(&mut self, event: &str) -> Result<()> {
        let old_state = self.current_state.clone();
        
        // This is a simplified transition table. A full RE project would have 100s of these.
        let next_state = match (&old_state, event) {
            // --- Initialization/Session Management ---
            (XFSState::Uninitialized, e) if e.starts_with("REQ_WFS_OPEN") => XFSState::BusyProcessing,
            (XFSState::BusyProcessing, e) if e.starts_with("RES_WFS_OPEN") && !e.contains("ERROR") => {
                self.session_id = rand::random(); // Assign a dummy ID for testing
                XFSState::Idle
            },
            (XFSState::Idle, e) if e.starts_with("REQ_WFS_CLOSE") => XFSState::BusyProcessing,
            (XFSState::BusyProcessing, e) if e.starts_with("RES_WFS_CLOSE") => XFSState::Uninitialized,

            // --- Command Execution (Dispenser/Pinpad) ---
            (XFSState::Idle, e) if e.starts_with("REQ_WFS_DISP_DISPENSE") => XFSState::BusyProcessing,
            (XFSState::Idle, e) if e.starts_with("REQ_WFS_PIN_GET_PIN") => XFSState::BusyProcessing,
            
            // Success response transitions back to Idle
            (XFSState::BusyProcessing, e) if e.starts_with("RES_") && !e.contains("ERROR") => XFSState::Idle,

            // --- Error Handling ---
            (_, e) if e.contains("ERROR") => XFSState::Error,
            (XFSState::Error, e) if e.starts_with("REQ_WFS_RESET") => XFSState::BusyProcessing,
            (XFSState::BusyProcessing, e) if e.starts_with("RES_WFS_RESET") && !e.contains("ERROR") => XFSState::Idle,
            
            // Sequence violation detection (fuzzer's target)
            (XFSState::Uninitialized, e) if e.starts_with("REQ_WFS_DISP_DISPENSE") => {
                return Err(anyhow!("State Violation: DISPENSE requested before OPEN. Fuzzing target hit?"));
            }

            // Default transition: stay in same state if event is unknown or irrelevant
            (s, _) => s.clone(), 
        };

        self.current_state = next_state;
        
        // Log the change for audit/fuzzing coverage
        println!("[STATE] {} -> {} triggered by event: {}", old_state.as_str(), self.current_state.as_str(), event);

        if self.current_state == XFSState::Error {
            Err(anyhow!("Protocol error state entered by event: {}", event))
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initial_state() {
        let sm = XFSStateMachine::new();
        assert_eq!(sm.get_current_state(), "UNINITIALIZED");
    }

    #[test]
    fn test_happy_path() -> Result<()> {
        let mut sm = XFSStateMachine::new();
        
        sm.process_event("REQ_WFS_OPEN")?;
        assert_eq!(sm.get_current_state(), "BUSY_PROCESSING");

        sm.process_event("RES_WFS_OPEN")?;
        assert_eq!(sm.get_current_state(), "IDLE");

        sm.process_event("REQ_WFS_DISP_DISPENSE")?;
        assert_eq!(sm.get_current_state(), "BUSY_PROCESSING");
        
        sm.process_event("RES_WFS_DISP_DISPENSE")?;
        assert_eq!(sm.get_current_state(), "IDLE");
        
        Ok(())
    }

    #[test]
    fn test_error_transition() -> Result<()> {
        let mut sm = XFSStateMachine::new();
        sm.process_event("REQ_WFS_OPEN")?;
        
        // Simulate an error response
        sm.process_event("RES_WFS_OPEN_ERROR")?;
        assert_eq!(sm.get_current_state(), "ERROR");
        assert!(sm.is_in_error_state());

        // Test recovery
        sm.process_event("REQ_WFS_RESET")?;
        sm.process_event("RES_WFS_RESET")?;
        assert_eq!(sm.get_current_state(), "IDLE");
        
        Ok(())
    }

    #[test]
    fn test_state_violation_detection() {
        let mut sm = XFSStateMachine::new();
        // Try to dispense before opening session (classic security flaw)
        let result = sm.process_event("REQ_WFS_DISP_DISPENSE");
        
        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("State Violation: DISPENSE requested before OPEN"));
    }
}
