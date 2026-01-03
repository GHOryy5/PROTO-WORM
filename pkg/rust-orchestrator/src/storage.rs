//! Proto-Worm Orchestrator Storage Layer
//! 
//! Responsible for:
//! - Persisting Corpus (Interesting inputs)
//! - Storing Crash Dumps
//! - Managing Worker Status
//! - Metadata Indexing
//!
//! Uses Sled for high-performance, embedded key-value storage.

use sled::{Db, Tree, IVec};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Arc;

// --- SCHEMAS ---

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CorpusEntry {
    pub id: String,
    pub payload: Vec<u8>,
    pub timestamp: i64,
    pub score: f32, // From Python Brain
    pub target: String, // Which service triggered this
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CrashRecord {
    pub crash_id: String,
    pub payload: Vec<u8>,
    pub signal: String,
    pub stack_trace: Option<String>,
    pub status: ReviewStatus,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum ReviewStatus {
    New,
    Analyzing,
    ConfirmedBug,
    Duplicate,
}

// --- DATABASE HANDLE ---

pub struct StorageEngine {
    db: Db,
    // Specific trees for specific data types
    corpus_tree: Tree,
    crash_tree: Tree,
}

impl StorageEngine {
    /// Opens or creates the database at the specified path.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, sled::Error> {
        let db = sled::open(path)?;
        
        // Open specific trees (column families)
        let corpus = db.open_tree("corpus")?;
        let crashes = db.open_tree("crashes")?;
        
        Ok(Self {
            db,
            corpus_tree: corpus,
            crash_tree: crashes,
        })
    }

    // --- CORPUS MANAGEMENT ---

    /// Adds a new input to the corpus.
    /// Returns `true` if this is a *new* input (not duplicate).
    pub fn add_corpus_entry(&self, entry: &CorpusEntry) -> Result<bool, sled::Error> {
        let key = entry.id.as_bytes();
        
        // Check for duplicate first
        if self.corpus_tree.get(key)?.is_some() {
            return Ok(false);
        }
        
        let val = bincode::serialize(entry).expect("Failed to serialize corpus entry");
        self.corpus_tree.insert(key, val)?;
        self.db.flush_async(); // Optimize for speed
        Ok(true)
    }

    /// Gets a random entry from the corpus for mutation.
    pub fn get_random_corpus_entry(&self) -> Option<CorpusEntry> {
        // In a real scenario, we'd scan randomly.
        // For Sled, we iterate keys.
        self.corpus_tree
            .iter()
            .values()
            .next()
            .and_then(|ivec| bincode::deserialize::<CorpusEntry>(&ivec).ok())
    }

    // --- CRASH MANAGEMENT ---

    /// Stores a crash report.
    pub fn save_crash(&self, crash: &CrashRecord) -> Result<(), sled::Error> {
        let key = crash.crash_id.as_bytes();
        let val = bincode::serialize(crash).expect("Failed to serialize crash");
        self.crash_tree.insert(key, val)?;
        Ok(())
    }

    /// Marks a crash as reviewed/confirmed.
    pub fn update_crash_status(&self, id: &str, status: ReviewStatus) -> Result<bool, sled::Error> {
        let key = id.as_bytes();
        if let Some(mut val) = self.crash_tree.get(key)? {
            let mut crash: CrashRecord = bincode::deserialize(&val).unwrap();
            crash.status = status;
            let new_val = bincode::serialize(&crash).unwrap();
            self.crash_tree.insert(key, new_val)?;
            return Ok(true);
        }
        Ok(false)
    }
}

// --- INDEXING (For Querying) ---

pub struct QueryEngine {
    storage: Arc<StorageEngine>,
}

impl QueryEngine {
    pub fn new(storage: Arc<StorageEngine>) -> Self {
        Self { storage }
    }

    /// Finds all crashes with a specific signal (e.g., SIGSEGV).
    pub fn find_crashes_by_signal(&self, signal: &str) -> Vec<CrashRecord> {
        let mut results = Vec::new();
        for item in self.storage.crash_tree.iter() {
            if let Ok(val) = item {
                if let Ok(crash) = bincode::deserialize::<CrashRecord>(&val) {
                    if crash.signal == signal {
                        results.push(crash);
                    }
                }
            }
        }
        results
    }

    /// Returns the top N highest scoring corpus entries.
    pub fn top_scoring_corpus(&self, n: usize) -> Vec<CorpusEntry> {
        let mut entries: Vec<CorpusEntry> = self.storage
            .corpus_tree
            .iter()
            .values()
            .filter_map(|v| v.ok())
            .filter_map(|v| bincode::deserialize::<CorpusEntry>(&v).ok())
            .collect();
            
        // Sort by score descending
        entries.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap());
        entries.truncate(n);
        entries
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_corpus_storage() {
        let dir = tempdir().unwrap();
        let store = StorageEngine::open(dir.path()).unwrap();
        
        let entry = CorpusEntry {
            id: "test-1".to_string(),
            payload: vec![1, 2, 3],
            timestamp: 0,
            score: 0.9,
            target: "dummy".to_string(),
        };
        
        let is_new = store.add_corpus_entry(&entry).unwrap();
        assert!(is_new);
        
        let retrieved = store.get_random_corpus_entry().unwrap();
        assert_eq!(retrieved.id, "test-1");
    }
}