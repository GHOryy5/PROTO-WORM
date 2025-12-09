//! Grammar-Based Fuzzer
//! 
//! Implements context-aware grammar-based fuzzing that mutates protocol
//! messages based on their syntactic structure rather than random bit flips.

use std::collections::HashMap;
use anyhow::{Result, anyhow};
use serde::{Serialize, Deserialize};
use rand::{Rng, SeedableRng};
use rand::rngs::StdRng;
use std::collections::HashSet;

use super::FuzzResult;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrammarRule {
    pub name: String,
    pub pattern: String,
    pub constraints: Vec<String>,
    pub examples: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrammarContext {
    pub protocol: String,
    pub state: String,
    pub field_constraints: HashMap<String, Vec<String>>,
    pub valid_transitions: Vec<String>,
}

pub struct GrammarFuzzer {
    rng: StdRng,
    grammar_rules: HashMap<String, Vec<GrammarRule>>,
    context: GrammarContext,
    mutation_history: HashSet<Vec<u8>>,
    coverage_map: HashMap<String, u32>,
}

impl GrammarFuzzer {
    pub fn new() -> Self {
        Self {
            rng: StdRng::from_entropy(),
            grammar_rules: HashMap::new(),
            context: GrammarContext {
                protocol: "unknown".to_string(),
                state: "initial".to_string(),
                field_constraints: HashMap::new(),
                valid_transitions: Vec::new(),
            },
            mutation_history: HashSet::new(),
            coverage_map: HashMap::new(),
        }
    }
    
    pub fn with_seed(seed: u64) -> Self {
        Self {
            rng: StdRng::seed_from_u64(seed),
            grammar_rules: HashMap::new(),
            context: GrammarContext {
                protocol: "unknown".to_string(),
                state: "initial".to_string(),
                field_constraints: HashMap::new(),
                valid_transitions: Vec::new(),
            },
            mutation_history: HashSet::new(),
            coverage_map: HashMap::new(),
        }
    }
    
    pub fn load_grammar(&mut self, protocol: &str, grammar_json: &str) -> Result<()> {
        // Parse JSON grammar definition
        let grammar: serde_json::Value = serde_json::from_str(grammar_json)
            .map_err(|e| anyhow!("Failed to parse grammar JSON: {}", e))?;
        
        // Extract rules
        if let Some(rules) = grammar.get("rules").and_then(|v| v.as_array()) {
            for rule_value in rules {
                if let Some(rule_obj) = rule_value.as_object() {
                    let name = rule_obj.get("name")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown")
                        .to_string();
                    
                    let pattern = rule_obj.get("pattern")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    
                    let mut constraints = Vec::new();
                    if let Some(constraints_array) = rule_obj.get("constraints").and_then(|v| v.as_array()) {
                        for constraint in constraints_array {
                            if let Some(constraint_str) = constraint.as_str() {
                                constraints.push(constraint_str.to_string());
                            }
                        }
                    }
                    
                    let mut examples = Vec::new();
                    if let Some(examples_array) = rule_obj.get("examples").and_then(|v| v.as_array()) {
                        for example in examples_array {
                            if let Some(example_str) = example.as_str() {
                                examples.push(example_str.as_bytes().to_vec());
                            }
                        }
                    }
                    
                    let rule = GrammarRule {
                        name,
                        pattern,
                        constraints,
                        examples,
                    };
                    
                    self.grammar_rules.entry(protocol.to_string()).or_insert_with(Vec::new).push(rule);
                }
            }
        }
        
        // Update context
        self.context.protocol = protocol.to_string();
        
        // Extract state transitions
        if let Some(transitions) = grammar.get("transitions").and_then(|v| v.as_array()) {
            for transition in transitions {
                if let Some(transition_str) = transition.as_str() {
                    self.context.valid_transitions.push(transition_str.to_string());
                }
            }
        }
        
        Ok(())
    }
    
    pub fn fuzz(&mut self, data: &[u8]) -> FuzzResult {
        // Try to identify the protocol and extract structure
        let protocol = self.detect_protocol(data);
        let structure = self.analyze_structure(data, &protocol);
        
        // Generate mutations based on grammar rules
        let mut attempts = 0;
        let max_attempts = 100;
        
        while attempts < max_attempts {
            let mutated = self.mutate_based_on_grammar(&structure, &protocol);
            
            // Check if we've already generated this mutation
            if !self.mutation_history.contains(&mutated) {
                self.mutation_history.insert(mutated.clone());
                
                // Update coverage map
                let mutation_key = format!("{}:{}", protocol, self.get_mutation_type(&mutated, data));
                *self.coverage_map.entry(mutation_key).or_insert(0) += 1;
                
                return FuzzResult {
                    mutated_data: mutated,
                    mutation_type: "grammar_based".to_string(),
                    mutation_description: format!("Grammar-based mutation for {}", protocol),
                    original_data_hash: self.calculate_hash(data),
                    mutated_data_hash: self.calculate_hash(&mutated),
                };
            }
            
            attempts += 1;
        }
        
        // Fallback to a simple mutation if grammar-based fails
        self.simple_mutation(data)
    }
    
    fn detect_protocol(&self, data: &[u8]) -> String {
        // Simple protocol detection based on byte patterns
        if data.len() >= 4 {
            // Check for XFS signature
            if data[0] == 0x02 && data[1] == 0x00 {
                return "xfs".to_string();
            }
            
            // Check for Modbus signature
            if data[0] == 0x00 && data[1] == 0x00 && 
               data.len() >= 8 && data[4] == 0x00 && data[5] == 0x00 {
                return "modbus".to_string();
            }
            
            // Check for S7CommPlus signature
            if data[0] == 0x72 && data[1] == 0x01 {
                return "s7commplus".to_string();
            }
            
            // Check for ISO8583 signature
            if data[0] >= 0x30 && data[0] <= 0x39 && 
               data[1] >= 0x30 && data[1] <= 0x39 &&
               data[2] >= 0x30 && data[2] <= 0x39 &&
               data[3] >= 0x30 && data[3] <= 0x39 {
                return "iso8583".to_string();
            }
        }
        
        "unknown".to_string()
    }
    
    fn analyze_structure(&self, data: &[u8], protocol: &str) -> HashMap<String, Vec<u8>> {
        let mut structure = HashMap::new();
        
        match protocol {
            "xfs" => {
                if data.len() >= 16 {
                    // XFS header structure
                    structure.insert("header".to_string(), data[..16].to_vec());
                    
                    // Extract command
                    let command = u16::from_le_bytes([data[4], data[5]]);
                    structure.insert("command".to_string(), command.to_le_bytes().to_vec());
                    
                    // Extract payload if present
                    if data.len() > 16 {
                        structure.insert("payload".to_string(), data[16..].to_vec());
                    }
                }
            },
            "modbus" => {
                if data.len() >= 8 {
                    // Modbus header structure
                    structure.insert("header".to_string(), data[..8].to_vec());
                    
                    // Extract function code
                    if data.len() > 8 {
                        structure.insert("function_code".to_string(), vec![data[8]]);
                        
                        // Extract data if present
                        if data.len() > 9 {
                            structure.insert("data".to_string(), data[9..].to_vec());
                        }
                    }
                }
            },
            "s7commplus" => {
                if data.len() >= 12 {
                    // S7CommPlus header structure
                    structure.insert("header".to_string(), data[..12].to_vec());
                    
                    // Extract message type
                    structure.insert("message_type".to_string(), vec![data[11]]);
                    
                    // Extract data if present
                    if data.len() > 12 {
                        structure.insert("data".to_string(), data[12..].to_vec());
                    }
                }
            },
            "iso8583" => {
                if data.len() >= 4 {
                    // ISO8583 MTI
                    structure.insert("mti".to_string(), data[..4].to_vec());
                    
                    // Extract bitmap if present
                    if data.len() >= 12 {
                        structure.insert("bitmap".to_string(), data[4..12].to_vec());
                        
                        // Extract fields if present
                        if data.len() > 12 {
                            structure.insert("fields".to_string(), data[12..].to_vec());
                        }
                    }
                }
            },
            _ => {
                // Unknown protocol, treat as raw bytes
                structure.insert("raw".to_string(), data.to_vec());
            }
        }
        
        structure
    }
    
    fn mutate_based_on_grammar(&mut self, structure: &HashMap<String, Vec<u8>>, protocol: &str) -> Vec<u8> {
        let rules = self.grammar_rules.get(protocol).cloned().unwrap_or_default();
        
        if rules.is_empty() {
            return self.simple_mutation(&structure.get("raw").cloned().unwrap_or_default());
        }
        
        // Select a random rule
        let rule = &rules[self.rng.gen_range(0..rules.len())];
        
        // Apply the rule mutation
        self.apply_rule_mutation(structure, rule)
    }
    
    fn apply_rule_mutation(&mut self, structure: &HashMap<String, Vec<u8>>, rule: &GrammarRule) -> Vec<u8> {
        // Create a copy of the structure to mutate
        let mut mutated_structure = structure.clone();
        
        // Apply different mutation strategies based on rule type
        match rule.name.as_str() {
            "field_substitution" => {
                // Substitute a field with a value from examples
                if let Some(field_name) = rule.pattern.split(':').nth(1) {
                    if let Some(field_data) = mutated_structure.get(field_name) {
                        if !rule.examples.is_empty() {
                            let example = &rule.examples[self.rng.gen_range(0..rule.examples.len())];
                            mutated_structure.insert(field_name.to_string(), example.clone());
                        }
                    }
                }
            },
            "length_modification" => {
                // Modify the length of a variable-length field
                if let Some(field_name) = rule.pattern.split(':').nth(1) {
                    if let Some(field_data) = mutated_structure.get_mut(field_name) {
                        let new_length = match self.rng.gen_range(0..4) {
                            0 => field_data.len() / 2,     // Halve
                            1 => field_data.len() * 2,     // Double
                            2 => field_data.len() + 10,    // Add 10
                            _ => field_data.len() - 5,     // Subtract 5
                        };
                        
                        // Truncate or extend the field
                        if new_length < field_data.len() {
                            field_data.truncate(new_length);
                        } else {
                            field_data.resize(new_length, 0);
                        }
                    }
                }
            },
            "boundary_value" => {
                // Set a field to a boundary value
                if let Some(field_name) = rule.pattern.split(':').nth(1) {
                    if let Some(field_data) = mutated_structure.get_mut(field_name) {
                        let boundary_value = match self.rng.gen_range(0..4) {
                            0 => vec![0x00],            // Zero
                            1 => vec![0xFF],            // Max byte
                            2 => vec![0x7F],            // Max signed byte
                            _ => vec![0x80],            // Min signed byte
                        };
                        
                        field_data.clear();
                        field_data.extend_from_slice(&boundary_value);
                    }
                }
            },
            "sequence_violation" => {
                // Create a protocol sequence violation
                if let Some(field_name) = rule.pattern.split(':').nth(1) {
                    if let Some(field_data) = mutated_structure.get_mut(field_name) {
                        // Corrupt the field in a way that violates protocol sequence
                        for byte in field_data.iter_mut() {
                            *byte = self.rng.gen_range(0x80..0xFF);
                        }
                    }
                }
            },
            _ => {
                // Unknown rule, apply random mutation
                return self.simple_mutation(&structure.get("raw").cloned().unwrap_or_default());
            }
        }
        
        // Reconstruct the mutated data
        self.reconstruct_from_structure(&mutated_structure)
    }
    
    fn reconstruct_from_structure(&self, structure: &HashMap<String, Vec<u8>>) -> Vec<u8> {
        let mut result = Vec::new();
        
        // Add header if present
        if let Some(header) = structure.get("header") {
            result.extend_from_slice(header);
        }
        
        // Add MTI if present
        if let Some(mti) = structure.get("mti") {
            result.extend_from_slice(mti);
        }
        
        // Add bitmap if present
        if let Some(bitmap) = structure.get("bitmap") {
            result.extend_from_slice(bitmap);
        }
        
        // Add fields if present
        if let Some(fields) = structure.get("fields") {
            result.extend_from_slice(fields);
        }
        
        // Add command if present
        if let Some(command) = structure.get("command") {
            result.extend_from_slice(command);
        }
        
        // Add message_type if present
        if let Some(message_type) = structure.get("message_type") {
            result.extend_from_slice(message_type);
        }
        
        // Add function_code if present
        if let Some(function_code) = structure.get("function_code") {
            result.extend_from_slice(function_code);
        }
        
        // Add data if present
        if let Some(data) = structure.get("data") {
            result.extend_from_slice(data);
        }
        
        // Add payload if present
        if let Some(payload) = structure.get("payload") {
            result.extend_from_slice(payload);
        }
        
        result
    }
    
    fn simple_mutation(&mut self, data: &[u8]) -> Vec<u8> {
        if data.is_empty() {
            return vec![0x41]; // Single byte if input is empty
        }
        
        let mut result = data.to_vec();
        
        // Apply a simple mutation strategy
        match self.rng.gen_range(0..5) {
            0 => {
                // Bit flip
                let byte_index = self.rng.gen_range(0..result.len());
                let bit_index = self.rng.gen_range(0..8);
                result[byte_index] ^= 1 << bit_index;
            },
            1 => {
                // Byte change
                let byte_index = self.rng.gen_range(0..result.len());
                result[byte_index] = self.rng.gen();
            },
            2 => {
                // Byte insertion
                let insert_index = self.rng.gen_range(0..=result.len());
                let byte_to_insert = self.rng.gen();
                result.insert(insert_index, byte_to_insert);
            },
            3 => {
                // Byte deletion
                if !result.is_empty() {
                    let delete_index = self.rng.gen_range(0..result.len());
                    result.remove(delete_index);
                }
            },
            _ => {
                // Byte swap
                if result.len() >= 2 {
                    let index1 = self.rng.gen_range(0..result.len());
                    let index2 = self.rng.gen_range(0..result.len());
                    result.swap(index1, index2);
                }
            }
        }
        
        result
    }
    
    fn get_mutation_type(&self, mutated: &[u8], original: &[u8]) -> String {
        if mutated.len() != original.len() {
            return "length_change".to_string();
        }
        
        let mut changed_bytes = 0;
        for i in 0..mutated.len().min(original.len()) {
            if mutated[i] != original[i] {
                changed_bytes += 1;
            }
        }
        
        if changed_bytes == 0 {
            return "no_change".to_string();
        }
        
        if changed_bytes == 1 {
            return "single_byte".to_string();
        }
        
        format!("multi_byte_{}", changed_bytes)
    }
    
    fn calculate_hash(&self, data: &[u8]) -> String {
        use std::hash::{Hash, Hasher};
        use std::collections::hash_map::DefaultHasher;
        
        let mut hasher = DefaultHasher::new();
        data.hash(&mut hasher);
        format!("{:x}", hasher.finish())
    }
    
    pub fn get_coverage(&self) -> HashMap<String, u32> {
        self.coverage_map.clone()
    }
    
    pub fn reset_coverage(&mut self) {
        self.coverage_map.clear();
    }
}

impl Default for GrammarFuzzer {
    fn default() -> Self {
        Self::new()
    }
}
