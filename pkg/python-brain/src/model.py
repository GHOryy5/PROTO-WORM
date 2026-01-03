"""
Proto-Worm Intelligence Engine.

Uses Machine Learning to score the "interestingness" of a packet.
This optimizes the fuzzing loop by prioritizing inputs that
actually trigger logic, rather than just smashing random bytes.

Stack:
- NumPy: Vectorization
- Scikit-Learn: Classification/Regression
"""
import numpy as np
import pickle
import os
from typing import List, Tuple
from dataclasses import dataclass
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

# --- CONFIGURATION ---
MODEL_PATH = "models/scorer.pkl"
SCALER_PATH = "models/scaler.pkl"
FEATURE_DIM = 6 # How many features we extract

@dataclass
class ScoringResult:
    """
    Result of the ML Model.
    """
    anomaly_score: float   # 0.0 (Normal) to 1.0 (Highly Anomalous/Interesting)
    features: np.ndarray # For debugging
    is_critical: bool     # If score > 0.9

class FeatureExtractor:
    """
    Turns raw bytes into mathematical vectors.
    This is the most important part for ML.
    """
    
    @staticmethod
    def calculate_entropy(data: bytes) -> float:
        """Calculates Shannon Entropy."""
        if not data: return 0.0
        
        counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
        p = counts / np.sum(counts)
        p = p[p > 0]
        return -np.sum(p * np.log2(p))

    @staticmethod
    def calculate_byte_frequency_variance(data: bytes) -> float:
        """Checks for repeating patterns."""
        if len(data) < 4: return 0.0
        counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
        return np.var(counts)

    @staticmethod
    def structural_score(data: bytes, expected_len: int) -> float:
        """Punishes huge deviations from expected packet length."""
        actual = len(data)
        if expected_len == 0: return 0.0
        return abs(actual - expected_len) / actual

    @staticmethod
    def opcode_consistency(data: bytes, valid_opcodes: List[int]) -> float:
        """1.0 if packet starts with valid opcode, 0.0 if not."""
        if len(data) == 0: return 0.0
        return 1.0 if data[0] in valid_opcodes else 0.0

    @staticmethod
    def extract(data: bytes, metadata: dict) -> np.ndarray:
        """
        Extracts all features into a vector of length FEATURE_DIM.
        """
        # 1. Entropy
        ent = FeatureExtractor.calculate_entropy(data)
        
        # 2. Length Normalization
        norm_len = len(data) / 1024.0
        
        # 3. Variance
        var = FeatureExtractor.calculate_byte_frequency_variance(data)
        
        # 4. Structural
        opcode_valid = FeatureExtractor.opcode_consistency(data, metadata.get('valid_ops', []))
        struct_score = FeatureExtractor.structural_score(data, metadata.get('expected_len', 100))
        
        # 5. High-Bit Ratio
        bits = np.unpackbits(np.frombuffer(data, dtype=np.uint8))
        high_bits = np.sum(bits > 0) / len(bits)
        
        return np.array([ent, norm_len, var, opcode_valid, struct_score, high_bits])

class WormBrain:
    """
    The Main Controller for ML Scoring.
    """
    
    def __init__(self, load_if_exists: bool = True):
        self.model = None
        self.scaler = StandardScaler()
        
        if load_if_exists and os.path.exists(MODEL_PATH):
            self.load_model()
        else:
            self.init_model()

    def init_model(self):
        """Initialize a default Isolation Forest."""
        print("[BRAIN] Initializing Isolation Forest Model...")
        self.model = IsolationForest(
            n_estimators=100, 
            max_samples='auto', 
            contamination=0.05, # Expect 5% anomalies
            random_state=42
        )
        # Train on dummy data first to fit scaler
        dummy_data = np.random.rand(100, FEATURE_DIM)
        self.scaler.fit(dummy_data)
        self.model.fit(dummy_data)

    def save_model(self):
        """Persist the model to disk."""
        os.makedirs("models", exist_ok=True)
        with open(MODEL_PATH, 'wb') as f:
            pickle.dump(self.model, f)
        with open(SCALER_PATH, 'wb') as f:
            pickle.dump(self.scaler, f)
        print("[BRAIN] Model saved successfully.")

    def load_model(self):
        """Load persisted model."""
        with open(MODEL_PATH, 'rb') as f:
            self.model = pickle.load(f)
        with open(SCALER_PATH, 'rb') as f:
            self.scaler = pickle.load(f)
        print("[BRAIN] Model loaded from disk.")

    def score_packet(self, packet_bytes: bytes, metadata: dict) -> ScoringResult:
        """
        Main Entry Point.
        Returns a score indicating how 'Interesting' the packet is.
        """
        # 1. Extract Features
        features = FeatureExtractor.extract(packet_bytes, metadata)
        features = features.reshape(1, -1) # Reshape for sklearn
        
        # 2. Normalize
        try:
            normalized = self.scaler.transform(features)
        except:
            # Fallback if scaler isn't fitted
            normalized = features

        # 3. Predict
        # IsolationForest returns -1 for outlier, 1 for inlier.
        # We want 0.0 to 1.0 score.
        prediction = self.model.decision_function(normalized)[0]
        
        # Map to 0.0 - 1.0 range (Approximation)
        # Decision function is negative for outliers.
        score = max(0.0, min(1.0, -prediction / 0.5))

        return ScoringResult(
            anomaly_score=score,
            features=features[0],
            is_critical=score > 0.8
        )

    def train_online(self, feedback_data: List[Tuple[bytes, bool]]):
        """
        Retrain the model based on feedback (Reinforcement Learning Lite).
        feedback_data is list of (packet, was_interesting).
        """
        if len(feedback_data) < 100: return # Not enough data yet
        
        X = []
        y = [] # Not used for IsolationForest, but needed for other models
        
        for pkt, _interesting in feedback_data:
            feats = FeatureExtractor.extract(pkt, {})
            X.append(feats)
            
        X = np.array(X)
        X = self.scaler.fit_transform(X) # Refit scaler too
        
        print("[BRAIN] Retraining model with new corpus data...")
        self.model.fit(X)
        self.save_model()

# --- USAGE ---
if __name__ == "__main__":
    brain = WormBrain()
    
    # Simulate a weird packet
    weird_pkt = bytes([0xDE, 0xAD, 0xBE, 0xEF] + [0x00]*50) 
    result = brain.score_packet(weird_pkt, {'valid_ops': [0x01], 'expected_len': 100})
    
    print(f"Score: {result.anomaly_score:.4f}")
    print(f"Critical: {result.is_critical}")