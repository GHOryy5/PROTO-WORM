//! Protocol Fuzzing Mutators
//! 
//! This module provides various mutation strategies for fuzzing
//! protocol implementations to discover vulnerabilities.

use std::collections::HashMap;
use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use rand::{Rng, SeedableRng};
use rand::rngs::StdRng;

pub mod grammar_fuzz;
pub mod sequence_fuzz;
pub mod bitflip_fuzz;
pub mod structure_fuzz;

use grammar_fuzz::GrammarFuzzer;
use sequence_fuzz::SequenceFuzzer;
use bitflip_fuzz::BitFlipFuzzer;
use structure_fuzz::StructureFuzzer;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MutationStrategy {
    Grammar,
    Sequence,
    BitFlip,
    Structure,
    Smart,
    Coverage,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzResult {
    pub mutated_data: Vec<u8>,
    pub mutation_type: String,
    pub mutation_description: String,
    pub original_data_hash: String,
    pub mutated_data_hash: String,
}

pub struct Fuzzer {
    strategy: MutationStrategy,
    rng: StdRng,
}

impl Fuzzer {
    pub fn new() -> Self {
        Self {
            strategy: MutationStrategy::BitFlip,
            rng: StdRng::from_entropy(),
        }
    }
    
    pub fn with_seed(seed: u64) -> Self {
        Self {
            strategy: MutationStrategy::BitFlip,
            rng: StdRng::seed_from_u64(seed),
        }
    }
    
    pub fn set_strategy(&mut self, strategy: MutationStrategy) {
        self.strategy = strategy;
    }
    
    pub fn fuzz(&mut self, data: &[u8], count: usize) -> Vec<FuzzResult> {
        let mut results = Vec::new();
        
        for _ in 0..count {
            let result = match self.strategy {
                MutationStrategy::Grammar => {
                    let mut fuzzer = GrammarFuzzer::new();
                    fuzzer.fuzz(data)
                },
                MutationStrategy::Sequence => {
                    let mut fuzzer = SequenceFuzzer::new();
                    fuzzer.fuzz(data)
                },
                MutationStrategy::BitFlip => {
                    let mut fuzzer = BitFlipFuzzer::new();
                    fuzzer.fuzz(data)
                },
                MutationStrategy::Structure => {
                    let mut fuzzer = StructureFuzzer::new();
                    fuzzer.fuzz(data)
                },
                MutationStrategy::Smart => {
                    // Smart fuzzing combines multiple strategies
                    let strategy_index = self.rng.gen_range(0..3);
                    let sub_strategy = match strategy_index {
                        0 => MutationStrategy::Grammar,
                        1 => MutationStrategy::Sequence,
                        2 => MutationStrategy::BitFlip,
                        _ => MutationStrategy::Structure,
                    };
                    
                    let mut fuzzer = Fuzzer {
                        strategy: sub_strategy,
                        rng: StdRng::from_entropy(),
                    };
                    fuzzer.fuzz(data).pop().unwrap()
                },
                MutationStrategy::Coverage => {
                    // Coverage-guided fuzzing focuses on unexplored paths
                    // For now, we'll use a random strategy
                    let strategy_index = self.rng.gen_range(0..3);
                    let sub_strategy = match strategy_index {
                        0 => MutationStrategy::Grammar,
                        1 => MutationStrategy::Sequence,
                        2 => MutationStrategy::BitFlip,
                        _ => MutationStrategy::Structure,
                    };
                    
                    let mut fuzzer = Fuzzer {
                        strategy: sub_strategy,
                        rng: StdRng::from_entropy(),
                    };
                    fuzzer.fuzz(data).pop().unwrap()
                },
            };
            
            results.push(result);
        }
        
        results
    }
    
    pub fn calculate_coverage(&self, original_data: &[u8], mutated_data: &[u8]) -> f32 {
        // Simple coverage calculation based on byte differences
        let mut differences = 0;
        let min_len = std::cmp::min(original_data.len(), mutated_data.len());
        
        for i in 0..min_len {
            if original_data[i] != mutated_data[i] {
                differences += 1;
            }
        }
        
        // Add length differences
        differences += (original_data.len() as i32 - mutated_data.len() as i32).abs() as usize;
        
        // Calculate coverage as a percentage of bytes changed
        if original_data.is_empty() {
            0.0
        } else {
            differences as f32 / original_data.len() as f32
        }
    }
}

impl Default for Fuzzer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_fuzzer_creation() {
        let fuzzer = Fuzzer::new();
        assert_eq!(fuzzer.strategy, MutationStrategy::BitFlip);
        
        let mut fuzzer = Fuzzer::new();
        fuzzer.set_strategy(MutationStrategy::Grammar);
        assert_eq!(fuzzer.strategy, MutationStrategy::Grammar);
    }
    
    #[test]
    fn test_fuzzer_with_seed() {
        let fuzzer1 = Fuzzer::with_seed(12345);
        let fuzzer2 = Fuzzer::with_seed(12345);
        
        // With the same seed, both fuzzers should produce the same results
        let data = vec![0x01, 0x02, 0x03, 0x04];
        let results1 = fuzzer1.fuzz(&data, 1);
        let results2 = fuzzer2.fuzz(&data, 1);
        
        assert_eq!(results1.len(), results2.len());
        assert_eq!(results1[0].mutated_data, results2[0].mutated_data);
    }
    
    #[test]
    fn test_coverage_calculation() {
        let fuzzer = Fuzzer::new();
        let original = vec![0x01, 0x02, 0x03, 0x04];
        let mutated = vec![0x01, 0x03, 0x03, 0x04];
        
        let coverage = fuzzer.calculate_coverage(&original, &mutated);
        assert_eq!(coverage, 0.25); // 1 byte changed out of 4
    }
}
