import numpy as np
from typing import List, Dict
import json

class AnomalyScorer:
    """
    Uses a simple statistical model to determine if a packet is "Interesting".
    
    High entropy != High interest. 
    We want "Grammatically Correct but Logically Broken" packets.
    """
    
    def __init__(self):
        # Mocking a pre-trained model weights
        # In reality, this loads a .pkl file
        self.feature_weights = np.array([0.5, 1.2, 0.8]) 
        self.bias = -0.3

    def score(self, packet_bytes: bytes, metadata: Dict) -> float:
        """
        Returns a score 0.0 to 1.0.
        > 0.8 is considered "Critical" by the Fuzzer.
        """
        
        # Feature 1: Entropy (Randomness)
        # Too high = just garbage. Too low = empty.
        entropy = self._calculate_entropy(packet_bytes)
        
        # Feature 2: Length Deviation
        # Is the packet weirdly long or short for this state?
        length_score = self._calculate_length_score(len(packet_bytes), metadata.get('expected_len', 100))
        
        # Feature 3: Opcode Consistency
        # Does the packet header match the payload structure?
        op_score = metadata.get('opcode_valid', 0)
        
        features = np.array([entropy, length_score, op_score])
        
        # Dot product to get score
        z = np.dot(features, self.feature_weights) + self.bias
        sigmoid = 1 / (1 + np.exp(-z))
        
        return float(sigmoid)

    def _calculate_entropy(self, data: bytes) -> float:
        counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
        p = counts / np.sum(counts)
        # Filter zeros to avoid log(0)
        p = p[p > 0]
        return -np.sum(p * np.log2(p))

    def _calculate_length_score(self, actual_len: int, expected_len: int) -> float:
        if expected_len == 0: return 0.0
        diff = abs(actual_len - expected_len)
        # Penalize massive deviations slightly
        return 1.0 / (1.0 + diff * 0.01)

# --- Usage ---
if __name__ == "__main__":
    scorer = AnomalyScorer()
    
    # Example: A suspicious packet
    suspicious_pkt = bytes([0xAA, 0xBB, 0xCC] * 50) 
    score = scorer.score(suspicious_pkt, {'expected_len': 100, 'opcode_valid': 1})
    
    print(f"Anomaly Score: {score:.4f}")
    if score > 0.8:
        print(">> CRITICAL: Fuzzer should prioritize this input.")