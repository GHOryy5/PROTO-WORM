//! Structure-Aware Fuzzer with ML Guidance
//! 
//! Implements intelligent structure-aware fuzzing that targets protocol boundaries,
//! field lengths, and other structural elements using machine learning
//! to guide mutation selection for maximum vulnerability discovery.

use std::collections::{HashMap, HashSet};
use anyhow::{Result, anyhow};
use serde::{Serialize, Deserialize};
use rand::{Rng, SeedableRng};
use rand::rngs::StdRng;

use super::FuzzResult;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StructureRule {
    pub name: String,
    pub field_name: String,
    pub mutation_type: String,
    pub min_value: Option<u32>,
    pub max_value: Option<u32>,
    pub valid_values: Option<Vec<u32>>,
    pub weight: f32,
    pub success_rate: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldBoundary {
    pub name: String,
    pub offset: usize,
    pub length: usize,
    pub field_type: String,
    pub is_length_field: bool,
    pub points_to: Vec<String>,
    pub criticality: f32, // How critical this field is for protocol security
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityPattern {
    pub name: String,
    pub description: String,
    pub field_mutations: Vec<String>,
    pub sequence_violations: Vec<String>,
    pub cvss_score: f32,
}

pub struct StructureFuzzer {
    rng: StdRng,
    structure_rules: HashMap<String, Vec<StructureRule>>,
    field_boundaries: HashMap<String, Vec<FieldBoundary>>,
    vulnerability_patterns: HashMap<String, Vec<VulnerabilityPattern>>,
    coverage_map: HashMap<String, u32>,
    mutation_history: Vec<(String, bool)>, // (mutation_name, success)
    ml_model: HashMap<String, f32>, // ML model for predicting success
}

impl StructureFuzzer {
    pub fn new() -> Self {
        let mut fuzzer = Self {
            rng: StdRng::from_entropy(),
            structure_rules: HashMap::new(),
            field_boundaries: HashMap::new(),
            vulnerability_patterns: HashMap::new(),
            coverage_map: HashMap::new(),
            mutation_history: Vec::new(),
            ml_model: HashMap::new(),
        };
        
        // Initialize with common vulnerability patterns
        fuzzer.initialize_vulnerability_patterns();
        fuzzer
    }
    
    pub fn with_seed(seed: u64) -> Self {
        let mut fuzzer = Self {
            rng: StdRng::seed_from_u64(seed),
            structure_rules: HashMap::new(),
            field_boundaries: HashMap::new(),
            vulnerability_patterns: HashMap::new(),
            coverage_map: HashMap::new(),
            mutation_history: Vec::new(),
            ml_model: HashMap::new(),
        };
        
        // Initialize with common vulnerability patterns
        fuzzer.initialize_vulnerability_patterns();
        fuzzer
    }
    
    fn initialize_vulnerability_patterns(&mut self) {
        // Add common vulnerability patterns
        let buffer_overflow = VulnerabilityPattern {
            name: "buffer_overflow".to_string(),
            description: "Buffer overflow by exceeding field length".to_string(),
            field_mutations: vec![
                "length_overflow".to_string(),
                "boundary_overflow".to_string(),
                "integer_overflow".to_string(),
            ],
            sequence_violations: vec![],
            cvss_score: 7.5,
        };
        
        let format_string = VulnerabilityPattern {
            name: "format_string".to_string(),
            description: "Format string vulnerability in field values".to_string(),
            field_mutations: vec![
                "format_string".to_string(),
                "null_byte_injection".to_string(),
            ],
            sequence_violations: vec![],
            cvss_score: 6.8,
        };
        
        let state_confusion = VulnerabilityPattern {
            name: "state_confusion".to_string(),
            description: "Protocol state confusion through invalid sequences".to_string(),
            field_mutations: vec![],
            sequence_violations: vec![
                "invalid_state_transition".to_string(),
                "privileged_operation".to_string(),
            ],
            cvss_score: 7.2,
        };
        
        let auth_bypass = VulnerabilityPattern {
            name: "auth_bypass".to_string(),
            description: "Authentication bypass through field manipulation".to_string(),
            field_mutations: vec![
                "auth_flag_manipulation".to_string(),
                "session_id_hijack".to_string(),
            ],
            sequence_violations: vec![
                "unauthenticated_operation".to_string(),
            ],
            cvss_score: 8.5,
        };
        
        // Add patterns to all protocols
        let protocols = vec!["xfs", "modbus", "s7commplus", "iso8583"];
        for protocol in protocols {
            self.vulnerability_patterns.entry(protocol.to_string()).or_insert_with(Vec::new).push(buffer_overflow.clone());
            self.vulnerability_patterns.entry(protocol.to_string()).or_insert_with(Vec::new).push(format_string.clone());
            self.vulnerability_patterns.entry(protocol.to_string()).or_insert_with(Vec::new).push(state_confusion.clone());
            self.vulnerability_patterns.entry(protocol.to_string()).or_insert_with(Vec::new).push(auth_bypass.clone());
            
            // Initialize ML model with equal weights
            for pattern in &["buffer_overflow", "format_string", "state_confusion", "auth_bypass"] {
                self.ml_model.insert(pattern.to_string(), 0.25);
            }
        }
    }
    
    pub fn load_structure_definition(&mut self, protocol: &str, definition_json: &str) -> Result<()> {
        // Parse JSON structure definition
        let definition: serde_json::Value = serde_json::from_str(definition_json)
            .map_err(|e| anyhow!("Failed to parse structure definition JSON: {}", e))?;
        
        // Extract field boundaries
        if let Some(boundaries) = definition.get("field_boundaries").and_then(|v| v.as_array()) {
            for boundary_value in boundaries {
                if let Some(boundary_obj) = boundary_value.as_object() {
                    let name = boundary_obj.get("name")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown")
                        .to_string();
                    
                    let offset = boundary_obj.get("offset")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0) as usize;
                    
                    let length = boundary_obj.get("length")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0) as usize;
                    
                    let field_type = boundary_obj.get("field_type")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown")
                        .to_string();
                    
                    let is_length_field = boundary_obj.get("is_length_field")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    
                    let mut points_to = Vec::new();
                    if let Some(points) = boundary_obj.get("points_to").and_then(|v| v.as_array()) {
                        for point in points {
                            if let Some(point_str) = point.as_str() {
                                points_to.push(point_str.to_string());
                            }
                        }
                    }
                    
                    let criticality = boundary_obj.get("criticality")
                        .and_then(|v| v.as_f64())
                        .unwrap_or(0.5) as f32;
                    
                    let boundary = FieldBoundary {
                        name,
                        offset,
                        length,
                        field_type,
                        is_length_field,
                        points_to,
                        criticality,
                    };
                    
                    self.field_boundaries.entry(protocol.to_string()).or_insert_with(Vec::new).push(boundary);
                }
            }
        }
        
        // Extract structure rules
        if let Some(rules) = definition.get("structure_rules").and_then(|v| v.as_array()) {
            for rule_value in rules {
                if let Some(rule_obj) = rule_value.as_object() {
                    let name = rule_obj.get("name")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown")
                        .to_string();
                    
                    let field_name = rule_obj.get("field_name")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    
                    let mutation_type = rule_obj.get("mutation_type")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    
                    let min_value = rule_obj.get("min_value")
                        .and_then(|v| v.as_u64())
                        .map(|v| v as u32);
                    
                    let max_value = rule_obj.get("max_value")
                        .and_then(|v| v.as_u64())
                        .map(|v| v as u32);
                    
                    let mut valid_values = None;
                    if let Some(values) = rule_obj.get("valid_values").and_then(|v| v.as_array()) {
                        let mut vals = Vec::new();
                        for value in values {
                            if let Some(val) = value.as_u64() {
                                vals.push(val as u32);
                            }
                        }
                        valid_values = Some(vals);
                    }
                    
                    let weight = rule_obj.get("weight")
                        .and_then(|v| v.as_f64())
                        .unwrap_or(0.5) as f32;
                    
                    let success_rate = rule_obj.get("success_rate")
                        .and_then(|v| v.as_f64())
                        .unwrap_or(0.5) as f32;
                    
                    let rule = StructureRule {
                        name,
                        field_name,
                        mutation_type,
                        min_value,
                        max_value,
                        valid_values,
                        weight,
                        success_rate,
                    };
                    
                    self.structure_rules.entry(protocol.to_string()).or_insert_with(Vec::new).push(rule);
                }
            }
        }
        
        Ok(())
    }
    
    pub fn fuzz(&mut self, data: &[u8]) -> FuzzResult {
        // Detect protocol
        let protocol = self.detect_protocol(data);
        
        // Get field boundaries for this protocol
        let boundaries = self.field_boundaries.get(protocol).cloned().unwrap_or_default();
        
        if boundaries.is_empty() {
            return FuzzResult {
                mutated_data: self.simple_mutation(data),
                mutation_type: "structure_simple".to_string(),
                mutation_description: "Simple structure mutation for unknown protocol".to_string(),
                original_data_hash: self.calculate_hash(data),
                mutated_data_hash: self.calculate_hash(&self.simple_mutation(data)),
            };
        }
        
        // Select a vulnerability pattern to target
        let vulnerability_pattern = self.select_vulnerability_pattern(&protocol);
        
        // Select a mutation based on the vulnerability pattern and ML model
        let mutation = self.select_ml_guided_mutation(&protocol, &vulnerability_pattern);
        
        // Apply the mutation
        let mutated = self.apply_structure_mutation(data, &boundaries, &mutation, &vulnerability_pattern);
        
        // Update coverage map
        let mutation_key = format!("structure:{}:{}", protocol, mutation.name);
        *self.coverage_map.entry(mutation_key).or_insert(0) += 1;
        
        FuzzResult {
            mutated_data: mutated,
            mutation_type: "structure_based".to_string(),
            mutation_description: format!("Structure-based mutation targeting {}: {}", vulnerability_pattern.name, mutation.name),
            original_data_hash: self.calculate_hash(data),
            mutated_data_hash: self.calculate_hash(&mutated),
        }
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
    
    fn select_vulnerability_pattern(&mut self, protocol: &str) -> &VulnerabilityPattern {
        let patterns = self.vulnerability_patterns.get(protocol).cloned().unwrap_or_default();
        
        if patterns.is_empty() {
            // Return a default pattern
            return &VulnerabilityPattern {
                name: "generic".to_string(),
                description: "Generic vulnerability pattern".to_string(),
                field_mutations: vec!["boundary_test".to_string()],
                sequence_violations: vec![],
                cvss_score: 5.0,
            };
        }
        
        // Select pattern based on ML model weights
        let total_weight: f32 = patterns.iter().map(|p| self.ml_model.get(&p.name).copied().unwrap_or(0.25)).sum();
        let mut random_value = self.rng.gen::<f32>() * total_weight;
        
        let mut current_weight = 0.0;
        for pattern in &patterns {
            current_weight += self.ml_model.get(&pattern.name).copied().unwrap_or(0.25);
            if random_value <= current_weight {
                return pattern;
            }
        }
        
        // Fallback to the first pattern
        &patterns[0]
    }
    
    fn select_ml_guided_mutation(&mut self, protocol: &str, vulnerability_pattern: &VulnerabilityPattern) -> StructureRule {
        let rules = self.structure_rules.get(protocol).cloned().unwrap_or_default();
        
        // Filter rules based on vulnerability pattern
        let matching_rules: Vec<&StructureRule> = rules.iter()
            .filter(|r| vulnerability_pattern.field_mutations.contains(&r.mutation_type))
            .collect();
        
        if matching_rules.is_empty() {
            // Create a default rule
            return StructureRule {
                name: "boundary_test".to_string(),
                field_name: "unknown".to_string(),
                mutation_type: "boundary".to_string(),
                min_value: None,
                max_value: None,
                valid_values: None,
                weight: 0.5,
                success_rate: 0.5,
            };
        }
        
        // Select rule based on ML model and success rate
        let total_weight: f32 = matching_rules.iter().map(|r| r.weight * r.success_rate).sum();
        let mut random_value = self.rng.gen::<f32>() * total_weight;
        
        let mut current_weight = 0.0;
        for rule in &matching_rules {
            current_weight += rule.weight * rule.success_rate;
            if random_value <= current_weight {
                return rule.clone();
            }
        }
        
        // Fallback to the first matching rule
        matching_rules[0].clone()
    }
    
    fn apply_structure_mutation(&mut self, data: &[u8], boundaries: &[FieldBoundary], rule: &StructureRule, vulnerability_pattern: &VulnerabilityPattern) -> Vec<u8> {
        let mut result = data.to_vec();
        
        match rule.mutation_type.as_str() {
            "length_overflow" => {
                // Apply a length overflow mutation
                if let Some(boundary) = self.find_boundary_by_name(boundaries, &rule.field_name) {
                    if boundary.is_length_field {
                        self.apply_length_overflow_mutation(&mut result, boundary);
                    }
                }
            },
            "boundary_overflow" => {
                // Apply a boundary overflow mutation
                if let Some(boundary) = self.find_boundary_by_name(boundaries, &rule.field_name) {
                    self.apply_boundary_overflow_mutation(&mut result, boundary);
                }
            },
            "integer_overflow" => {
                // Apply an integer overflow mutation
                if let Some(boundary) = self.find_boundary_by_name(boundaries, &rule.field_name) {
                    self.apply_integer_overflow_mutation(&mut result, boundary);
                }
            },
            "format_string" => {
                // Apply a format string mutation
                if let Some(boundary) = self.find_boundary_by_name(boundaries, &rule.field_name) {
                    self.apply_format_string_mutation(&mut result, boundary);
                }
            },
            "null_byte_injection" => {
                // Apply a null byte injection mutation
                if let Some(boundary) = self.find_boundary_by_name(boundaries, &rule.field_name) {
                    self.apply_null_byte_injection_mutation(&mut result, boundary);
                }
            },
            "auth_flag_manipulation" => {
                // Apply an authentication flag manipulation mutation
                if let Some(boundary) = self.find_boundary_by_name(boundaries, &rule.field_name) {
                    self.apply_auth_flag_manipulation_mutation(&mut result, boundary);
                }
            },
            "session_id_hijack" => {
                // Apply a session ID hijack mutation
                if let Some(boundary) = self.find_boundary_by_name(boundaries, &rule.field_name) {
                    self.apply_session_id_hijack_mutation(&mut result, boundary);
                }
            },
            "boundary" => {
                // Apply a boundary value mutation
                if let Some(boundary) = self.find_boundary_by_name(boundaries, &rule.field_name) {
                    self.apply_boundary_mutation(&mut result, boundary, rule);
                }
            },
            _ => {
                // Unknown mutation type, apply a simple mutation
                return self.simple_mutation(data);
            }
        }
        
        result
    }
    
    fn find_boundary_by_name(&self, boundaries: &[FieldBoundary], name: &str) -> Option<&FieldBoundary> {
        boundaries.iter().find(|b| b.name == name)
    }
    
    fn apply_boundary_mutation(&mut self, data: &mut Vec<u8>, boundary: &FieldBoundary, rule: &StructureRule) {
        if boundary.offset + boundary.length > data.len() {
            return;
        }
        
        // Apply a boundary value based on the field type and rule
        match boundary.field_type.as_str() {
            "u8" => {
                let value = if let Some(ref valid_values) = rule.valid_values {
                    // Use a valid value from the rule
                    let index = self.rng.gen_range(0..valid_values.len());
                    valid_values[index] as u8
                } else if let Some(max_value) = rule.max_value {
                    // Use the max value from the rule
                    max_value as u8
                } else {
                    // Use a boundary value
                    match self.rng.gen_range(0..4) {
                        0 => 0x00,      // Zero
                        1 => 0xFF,      // Max
                        2 => 0x7F,      // Max signed
                        _ => 0x80,      // Min signed
                    }
                };
                
                data[boundary.offset] = value;
            },
            "u16" => {
                if boundary.offset + 1 < data.len() {
                    let value = if let Some(ref valid_values) = rule.valid_values {
                        // Use a valid value from the rule
                        let index = self.rng.gen_range(0..valid_values.len());
                        valid_values[index] as u16
                    } else if let Some(max_value) = rule.max_value {
                        // Use the max value from the rule
                        max_value as u16
                    } else {
                        // Use a boundary value
                        match self.rng.gen_range(0..4) {
                            0 => 0x0000,    // Zero
                            1 => 0xFFFF,    // Max
                            2 => 0x7FFF,    // Max signed
                            _ => 0x8000,    // Min signed
                        }
                    };
                    
                    data[boundary.offset] = (value & 0xFF) as u8;
                    data[boundary.offset + 1] = ((value >> 8) & 0xFF) as u8;
                }
            },
            "u32" => {
                if boundary.offset + 3 < data.len() {
                    let value = if let Some(ref valid_values) = rule.valid_values {
                        // Use a valid value from the rule
                        let index = self.rng.gen_range(0..valid_values.len());
                        valid_values[index]
                    } else if let Some(max_value) = rule.max_value {
                        // Use the max value from the rule
                        max_value
                    } else {
                        // Use a boundary value
                        match self.rng.gen_range(0..4) {
                            0 => 0x00000000,     // Zero
                            1 => 0xFFFFFFFF,     // Max
                            2 => 0x7FFFFFFF,     // Max signed
                            _ => 0x80000000,     // Min signed
                        }
                    };
                    
                    data[boundary.offset] = (value & 0xFF) as u8;
                    data[boundary.offset + 1] = ((value >> 8) & 0xFF) as u8;
                    data[boundary.offset + 2] = ((value >> 16) & 0xFF) as u8;
                    data[boundary.offset + 3] = ((value >> 24) & 0xFF) as u8;
                }
            },
            _ => {
                // Unknown field type, set to a random value
                for i in 0..boundary.length.min(data.len() - boundary.offset) {
                    data[boundary.offset + i] = self.rng.gen();
                }
            }
        }
    }
    
    fn apply_length_overflow_mutation(&mut self, data: &mut Vec<u8>, boundary: &FieldBoundary) {
        if boundary.offset + boundary.length > data.len() {
            return;
        }
        
        // Set the length field to a maximum value
        let max_value = match boundary.length {
            1 => 0xFF,
            2 => 0xFFFF,
            4 => 0xFFFFFFFF,
            _ => 0xFF, // Default to 1 byte max
        };
        
        for i in 0..boundary.length.min(data.len() - boundary.offset) {
            data[boundary.offset + i] = ((max_value >> (i * 8)) & 0xFF) as u8;
        }
        
        // Also update the fields this length field points to
        for field_name in &boundary.points_to {
            if let Some(pointed_boundary) = self.find_boundary_by_name(
                &self.field_boundaries.get("xfs").cloned().unwrap_or_default(), // Assuming XFS for simplicity
                field_name
            ) {
                // Fill the pointed-to field with random data
                if pointed_boundary.offset + pointed_boundary.length <= data.len() {
                    for i in 0..pointed_boundary.length.min(data.len() - pointed_boundary.offset) {
                        data[pointed_boundary.offset + i] = self.rng.gen();
                    }
                }
            }
        }
    }
    
    fn apply_boundary_overflow_mutation(&mut self, data: &mut Vec<u8>, boundary: &FieldBoundary) {
        if boundary.offset + boundary.length > data.len() {
            return;
        }
        
        // Write past the boundary
        let overflow_size = self.rng.gen_range(1..10); // Overflow by 1-10 bytes
        
        for i in 0..boundary.length.min(data.len() - boundary.offset) {
            data[boundary.offset + i] = self.rng.gen();
        }
        
        // Write overflow bytes
        let start = boundary.offset + boundary.length;
        for i in 0..overflow_size {
            if start + i < data.len() {
                data[start + i] = self.rng.gen();
            } else {
                data.push(self.rng.gen());
            }
        }
    }
    
    fn apply_integer_overflow_mutation(&mut self, data: &mut Vec<u8>, boundary: &FieldBoundary) {
        if boundary.offset + boundary.length > data.len() {
            return;
        }
        
        // Set the field to a value that will cause an overflow
        let overflow_value = match boundary.field_type.as_str() {
            "u8" => 0xFF,
            "u16" => 0xFFFF,
            "u32" => 0xFFFFFFFF,
            _ => 0xFF, // Default to 1 byte max
        };
        
        for i in 0..boundary.length.min(data.len() - boundary.offset) {
            data[boundary.offset + i] = ((overflow_value >> (i * 8)) & 0xFF) as u8;
        }
    }
    
    fn apply_format_string_mutation(&mut self, data: &mut Vec<u8>, boundary: &FieldBoundary) {
        if boundary.offset + boundary.length > data.len() {
            return;
        }
        
        // Inject format string characters
        let format_strings = vec![
            b"%s", b"%x", b"%n", b"%d",
            b"%08x", b"%p", b"\x", b"\n",
        ];
        
        let format_string = &format_strings[self.rng.gen_range(0..format_strings.len())];
        
        // Replace the field with the format string
        for i in 0..boundary.length.min(data.len() - boundary.offset).min(format_string.len()) {
            data[boundary.offset + i] = format_string[i];
        }
    }
    
    fn apply_null_byte_injection_mutation(&mut self, data: &mut Vec<u8>, boundary: &FieldBoundary) {
        if boundary.offset + boundary.length > data.len() {
            return;
        }
        
        // Inject null bytes into the field
        for i in 0..boundary.length.min(data.len() - boundary.offset) {
            // 50% chance to inject a null byte
            if self.rng.gen::<f32>() < 0.5 {
                data[boundary.offset + i] = 0x00;
            }
        }
    }
    
    fn apply_auth_flag_manipulation_mutation(&mut self, data: &mut Vec<u8>, boundary: &FieldBoundary) {
        if boundary.offset + boundary.length > data.len() {
            return;
        }
        
        // Set authentication flag to true (bypass)
        match boundary.field_type.as_str() {
            "u8" => {
                data[boundary.offset] = 0x01; // Set to true
            },
            "u16" => {
                if boundary.offset + 1 < data.len() {
                    data[boundary.offset] = 0x01; // Set to true
                    data[boundary.offset + 1] = 0x00; // Set to false
                }
            },
            "u32" => {
                if boundary.offset + 3 < data.len() {
                    data[boundary.offset] = 0x01; // Set to true
                    data[boundary.offset + 1] = 0x00; // Set to false
                    data[boundary.offset + 2] = 0x00; // Set to false
                    data[boundary.offset + 3] = 0x00; // Set to false
                }
            },
            _ => {
                // Unknown field type, set to a random value
                for i in 0..boundary.length.min(data.len() - boundary.offset) {
                    data[boundary.offset + i] = self.rng.gen();
                }
            }
        }
    }
    
    fn apply_session_id_hijack_mutation(&mut self, data: &mut Vec<u8>, boundary: &FieldBoundary) {
        if boundary.offset + boundary.length > data.len() {
            return;
        }
        
        // Set session ID to a privileged value
        let privileged_ids = vec![0x00000000, 0xFFFFFFFF, 0x80000000, 0x7FFFFFFF];
        let privileged_id = privileged_ids[self.rng.gen_range(0..privileged_ids.len())];
        
        for i in 0..boundary.length.min(data.len() - boundary.offset) {
            data[boundary.offset + i] = ((privileged_id >> (i * 8)) & 0xFF) as u8;
        }
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
    
    pub fn update_ml_model(&mut self, mutation_name: &str, success: bool) {
        // Update the ML model based on success/failure
        let current_weight = self.ml_model.get(mutation_name).copied().unwrap_or(0.25);
        
        let new_weight = if success {
            // Increase weight for successful mutations
            (current_weight * 1.1).min(1.0)
        } else {
            // Decrease weight for unsuccessful mutations
            (current_weight * 0.9).max(0.1)
        };
        
        self.ml_model.insert(mutation_name.to_string(), new_weight);
        
        // Store in history
        self.mutation_history.push((mutation_name.to_string(), success));
        
        // Limit history size
        if self.mutation_history.len() > 1000 {
            self.mutation_history.remove(0);
        }
    }
    
    pub fn get_coverage(&self) -> HashMap<String, u32> {
        self.coverage_map.clone()
    }
    
    pub fn reset_coverage(&mut self) {
        self.coverage_map.clear();
    }
    
    pub fn get_ml_model(&self) -> &HashMap<String, f32> {
        &self.ml_model
    }
    
    fn calculate_hash(&self, data: &[u8]) -> String {
        use std::hash::{Hash, Hasher};
        use std::collections::hash_map::DefaultHasher;
        
        let mut hasher = DefaultHasher::new();
        data.hash(&mut hasher);
        format!("{:x}", hasher.finish())
    }
}

impl Default for StructureFuzzer {
    fn default() -> Self {
        Self::new()
    }
}
