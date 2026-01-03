//! Proto-Worm Sentry
//! 
//! Analyzes crash dumps from the fuzzer. 
//! Rust's memory safety guarantees are critical here because we are parsing
//! potentially malicious/corrupt bytes.

use std::collections::HashMap;
use std::mem::size_of_val;
use std::sync::{Arc, Mutex};
use serde::{Deserialize, Serialize};

// --- TYPES ---

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CrashReport {
    pub crash_id: String,
    pub timestamp: i64,
    pub signal: String,
    pub summary: String,
    pub severity: Severity,
    pub registers: HashMap<String, u64>,
    pub memory_map: Vec<MemoryRegion>,
    pub is_reproducible: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryRegion {
    pub start_addr: u64,
    pub end_addr: u64,
    pub permissions: String, // "rwx", "r--"
}

#[derive(Debug)]
pub struct AnalyzerEngine {
    // Cache of known crash signatures to deduplicate
    signature_cache: Arc<Mutex<HashMap<String, String>>>, // Signature -> CrashID
}

// --- ANALYSIS LOGIC ---

impl AnalyzerEngine {
    pub fn new() -> Self {
        Self {
            signature_cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// The main entry point.
    /// Takes raw bytes from Fuzzer and determines exploitability.
    pub fn analyze(&self, raw_packet: &[u8], error_msg: &str) -> Result<CrashReport, String> {
        // 1. Parse Registers (Simulated from GDB output)
        // In a real impl, we would run the binary under GDB and scrape output.
        let mut registers = HashMap::new();
        registers.insert("RIP".to_string(), 0x0); // RIP = 0 -> NULL Deref
        registers.insert("RSP".to_string(), 0x7ffe0000);
        
        // 2. Determine Signal
        let signal = self.detect_signal(error_msg);
        
        // 3. Determine Severity
        let severity = self.calculate_severity(&signal, &registers);
        
        // 4. Check for Exploitable Conditions
        let summary = self.generate_crash_summary(&signal, &registers);
        
        let report = CrashReport {
            crash_id: format!("CRASH-{:x}", md5_compute(raw_packet)),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            signal: signal.clone(),
            summary: summary.clone(),
            severity,
            registers,
            memory_map: vec![], // Would parse /proc/pid/maps
            is_reproducible: self.check_reproducibility(raw_packet),
        };

        // 5. Deduplication
        let sig = self.generate_signature(&report);
        let mut cache = self.signature_cache.lock().unwrap();
        if cache.contains_key(&sig) {
            return Err(format!("Duplicate crash: {}", sig));
        }
        cache.insert(sig, report.crash_id.clone());
        
        Ok(report)
    }

    fn detect_signal(&self, msg: &str) -> String {
        if msg.contains("SIGSEGV") {
            return "SIGSEGV".to_string();
        } else if msg.contains("SIGABRT") {
            return "SIGABRT".to_string();
        } else if msg.contains("connection reset") {
            return "RST".to_string();
        }
        return "UNKNOWN".to_string()
    }

    fn calculate_severity(&self, signal: &str, regs: &HashMap<String, u64>) -> Severity {
        match signal {
            s if s.contains("SIGSEGV") => {
                // Check RIP for NULL or non-canonical address
                if let Some(&rip) = regs.get("RIP") {
                    if rip < 0x1000 {
                        return Severity::Critical; // NULL Deref is often exploitable
                    }
                }
                Severity::High
            }
            s if s.contains("SIGABRT") => Severity::Medium, // Logic error
            _ => Severity::Low,
        }
    }

    fn generate_crash_summary(&self, signal: &str, regs: &HashMap<String, u64>) -> String {
        if let Some(&rip) = regs.get("RIP") {
            return format!(
                "Fault at Instruction Pointer 0x{:x} due to {}.", 
                rip, signal
            );
        }
        format!("Crash detected: {}", signal)
    }
    
    /// Simulates reproducibility check by re-running the binary.
    /// In a real implementation, this is expensive.
    fn check_reproducibility(&self, _input: &[u8]) -> bool {
        true // Always assume true for demo
    }

    fn generate_signature(&self, report: &CrashReport) -> String {
        // A signature based on RIP and Signal
        if let Some(&rip) = report.registers.get("RIP") {
            return format!("{}@0x{:x}", report.signal, rip);
        }
        report.signal.clone()
    }
}

// Helper for ID generation
fn md5_compute(input: &[u8]) -> u128 {
    let mut digest = [0u8; 16];
    // Mock MD5
    let len = std::cmp::min(16, input.len());
    for i in 0..len {
        digest[i] = input[i];
    }
    u128::from_le_bytes(digest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_null_deref_detection() {
        let engine = AnalyzerEngine::new();
        let result = engine.analyze(&[0x00, 0x01], "SIGSEGV");
        assert!(result.is_ok());
        let report = result.unwrap();
        assert!(matches!(report.severity, Severity::Critical));
    }
}