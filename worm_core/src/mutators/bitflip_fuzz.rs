//! Bit-Flip Fuzzer with Machine Learning
//! 
//! Implements intelligent bit-flipping fuzzing with ML-guided
//! mutation selection to maximize vulnerability discovery.

use std::collections::HashMap;
use anyhow::{Result, anyhow};
use serde::{Serialize, Deserialize};
use rand::{Rng, SeedableRng};
use rand::rngs::StdRng;

use super::FuzzResult;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitFlipPattern {
    pub name: String,
    pub pattern: Vec<usize>,
    pub description: String,
    pub effectiveness: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitFlipModel {
    pub weights: HashMap<String, f32>,
    pub patterns: Vec<BitFlipPattern>,
    pub learning_rate: f32,
}

pub struct BitFlipFuzzer {
    rng: StdRng,
    model: BitFlipModel,
    mutation_history: Vec<(Vec<u8>, bool)>, // (mutation, success)
    coverage_map: HashMap<String, u32>,
}

impl BitFlipFuzzer {
    pub fn new() -> Self {
        let mut fuzzer = Self {
            rng: StdRng::from_entropy(),
            model: BitFlipModel {
                weights: HashMap::new(),
                patterns: Vec::new(),
                learning_rate: 0.1,
            },
            mutation_history: Vec::new(),
            coverage_map: HashMap::new(),
        };
        
        // Initialize with default patterns
        fuzzer.initialize_default_patterns();
        fuzzer
    }
    
    pub fn with_seed(seed: u64) -> Self {
        let mut fuzzer = Self {
            rng: StdRng::seed_from_u64(seed),
            model: BitFlipModel {
                weights: HashMap::new(),
                patterns: Vec::new(),
                learning_rate: 0.1,
            },
            mutation_history: Vec::new(),
            coverage_map: HashMap::new(),
        };
        
        // Initialize with default patterns
        fuzzer.initialize_default_patterns();
        fuzzer
    }
    
    fn initialize_default_patterns(&mut self) {
        // Add common bit-flip patterns
        self.model.patterns.push(BitFlipPattern {
            name: "single_bit".to_string(),
            pattern: vec![0], // Flip bit 0
            description: "Flip a single bit".to_string(),
            effectiveness: 0.5,
        });
        
        self.model.patterns.push(BitFlipPattern {
            name: "single_bit_random".to_string(),
            pattern: vec![1], // Flip bit 1
            description: "Flip a single random bit".to_string(),
            effectiveness: 0.6,
        });
        
        self.model.patterns.push(BitFlipPattern {
            name: "two_adjacent".to_string(),
            pattern: vec![0, 1], // Flip bits 0 and 1
            description: "Flip two adjacent bits".to_string(),
            effectiveness: 0.7,
        });
        
        self.model.patterns.push(BitFlipPattern {
            name: "four_corners".to_string(),
            pattern: vec![0, 2, 4, 6], // Flip bits 0, 2, 4, 6
            description: "Flip four corner bits".to_string(),
            effectiveness: 0.8,
        });
        
        self.model.patterns.push(BitFlipPattern {
            name: "byte_boundary".to_string(),
            pattern: vec![7], // Flip bit 7 (MSB)
            description: "Flip the most significant bit".to_string(),
            effectiveness: 0.9,
        });
        
        // Initialize weights based on effectiveness
        for pattern in &self.model.patterns {
            self.model.weights.insert(pattern.name.clone(), pattern.effectiveness);
        }
    }
    
    pub fn fuzz(&mut self, data: &[u8]) -> FuzzResult {
        if data.is_empty() {
            return FuzzResult {
                mutated_data: vec![0x41], // Single byte if input is empty
                mutation_type: "bitflip".to_string(),
                mutation_description: "Single byte mutation for empty input".to_string(),
                original_data_hash: self.calculate_hash(data),
                mutated_data_hash: self.calculate_hash(&[0x41]),
            };
        }
        
        // Select a pattern based on learned weights
        let pattern = self.select_pattern();
        
        // Apply the pattern
        let mutated = self.apply_pattern(data, &pattern);
        
        // Update coverage map
        let pattern_key = format!("bitflip:{}", pattern.name);
        *self.coverage_map.entry(pattern_key).or_insert(0) += 1;
        
        FuzzResult {
            mutated_data: mutated,
            mutation_type: "bitflip".to_string(),
            mutation_description: format!("Bit-flip mutation using pattern: {}", pattern.name),
            original_data_hash: self.calculate_hash(data),
            mutated_data_hash: self.calculate_hash(&mutated),
        }
    }
    
    fn select_pattern(&mut self) -> BitFlipPattern {
        // Calculate total weight
        let total_weight: f32 = self.model.weights.values().sum();
        
        // Generate a random number between 0 and total_weight
        let mut random_value = self.rng.gen::<f32>() * total_weight;
        
        // Find the pattern corresponding to the random value
        let mut current_weight = 0.0;
        for pattern in &self.model.patterns {
            current_weight += self.model.weights.get(&pattern.name).copied().unwrap_or(0.0);
            if random_value <= current_weight {
                return pattern.clone();
            }
        }
        
        // Fallback to the first pattern
        self.model.patterns[0].clone()
    }
    
    fn apply_pattern(&mut self, data: &[u8], pattern: &BitFlipPattern) -> Vec<u8> {
        let mut result = data.to_vec();
        
        // Apply the pattern to a random byte
        let byte_index = self.rng.gen_range(0..result.len());
        
        for &bit_index in &pattern.pattern {
            if bit_index < 8 {
                result[byte_index] ^= 1 << bit_index;
            }
        }
        
        result
    }
    
    pub fn update_model(&mut self, mutation: &[u8], success: bool) {
        // Find the pattern that was used
        let pattern_name = self.identify_pattern(mutation);
        
        // Update the weight based on success/failure
        let current_weight = self.model.weights.get(&pattern_name).copied().unwrap_or(0.5);
        let new_weight = if success {
            // Increase weight for successful mutations
            (current_weight * (1.0 + self.model.learning_rate)).min(1.0)
        } else {
            // Decrease weight for unsuccessful mutations
            (current_weight * (1.0 - self.model.learning_rate)).max(0.1)
        };
        
        self.model.weights.insert(pattern_name, new_weight);
        
        // Store in history
        self.mutation_history.push((mutation.to_vec(), success));
        
        // Limit history size
        if self.mutation_history.len() > 1000 {
            self.mutation_history.remove(0);
        }
    }
    
    fn identify_pattern(&self, mutation: &[u8]) -> String {
        // This is a simplified implementation
        // In a real ML system, this would be more sophisticated
        
        // Count bit flips
        let mut bit_flips = 0;
        let mut byte_flips = 0;
        
        for i in 0..mutation.len().min(256) {
            let original_byte = i as u8;
            let mutated_byte = mutation[i];
            
            if original_byte != mutated_byte {
                byte_flips += 1;
                bit_flips += (original_byte ^ mutated_byte).count_ones();
            }
        }
        
        // Identify pattern based on the flips
        if byte_flips == 1 && bit_flips == 1 {
            return "single_bit".to_string();
        } else if byte_flips == 1 && bit_flips <= 2 {
            return "single_bit_random".to_string();
        } else if byte_flips == 1 && bit_flips == 2 {
            return "two_adjacent".to_string();
        } else if byte_flips == 1 && bit_flips >= 4 {
            return "four_corners".to_string();
        } else if byte_flips >= 1 {
            // Check if MSB was flipped
            for i in 0..mutation.len().min(256) {
                let original_byte = i as u8;
                let mutated_byte = mutation[i];
                
                if (original_byte ^ mutated_byte) & 0x80 != 0 {
                    return "byte_boundary".to_string();
                }
            }
        }
        
        "unknown".to_string()
    }
    
    pub fn train_model(&mut self, generations: usize) {
        for _ in 0..generations {
            // Generate a random mutation
            let random_data = vec![self.rng.gen::<u8>(); self.rng.gen_range(10..100)];
            let pattern = self.select_pattern();
            let mutated = self.apply_pattern(&random_data, &pattern);
            
            // Simulate success/failure (in a real system, this would be determined by actual testing)
            let success = self.rng.gen::<f32>() > 0.5;
            
            // Update the model
            self.update_model(&mutated, success);
        }
    }
    
    pub fn get_model(&self) -> &BitFlipModel {
        &self.model
    }
    
    pub fn get_coverage(&self) -> HashMap<String, u32> {
        self.coverage_map.clone()
    }
    
    pub fn reset_coverage(&mut self) {
        self.coverage_map.clear();
    }
    
    fn calculate_hash(&self, data: &[u8]) -> String {
        use std::hash::{Hash, Hasher};
        use std::collections::hash_map::DefaultHasher;
        
        let mut hasher = DefaultHasher::new();
        data.hash(&mut hasher);
        format!("{:x}", hasher.finish())
    }
}

impl Default for BitFlipFuzzer {
    fn default() -> Self {
        Self::new()
    }
}
