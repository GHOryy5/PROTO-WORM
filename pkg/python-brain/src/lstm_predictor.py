"""
Proto-Worm Deep Learning Engine.

Implements an LSTM (Long Short-Term Memory) model using PyTorch.
This model learns the "Grammar" of the protocol to generate
highly-structured, syntactically-valid mutations.

This is significantly more complex than basic ML and provides
stateful prediction capabilities.
"""

import torch
import torch.nn as nn
import torch.optim as optim
import numpy as np
import os
from typing import List, Tuple
import json

# --- CONFIGURATION ---
MODEL_PATH = "models/lstm_worm.pt"
INPUT_SIZE = 256   # Byte frequency vector
HIDDEN_SIZE = 128
NUM_LAYERS = 2
OUTPUT_SIZE = 256 # Predict next byte distribution
LEARNING_RATE = 0.001
SEQUENCE_LEN = 32 # How many past bytes to look at

class WormLSTM(nn.Module):
    """
    Recurrent Neural Network for Byte Sequence Prediction.
    Architecture:
    Input -> Embedding -> LSTM -> Linear -> Softmax
    """
    def __init__(self):
        super(WormLSTM, self).__init__()
        
        # 1. Embedding Layer: Converts byte (0-255) to dense vector
        self.embedding = nn.Embedding(256, 64)
        
        # 2. LSTM Layer: Captures temporal dependencies in the protocol
        self.lstm = nn.LSTM(
            input_size=64,
            hidden_size=HIDDEN_SIZE,
            num_layers=NUM_LAYERS,
            batch_first=True,
            dropout=0.2
        )
        
        # 3. Fully Connected Layer
        self.fc = nn.Linear(HIDDEN_SIZE, OUTPUT_SIZE)
        
    def forward(self, x):
        # x shape: (batch_size, seq_len)
        embeds = self.embedding(x) # (batch, seq, 64)
        
        # LSTM returns (output, (h_n, c_n)
        lstm_out, _ = self.lstm(embeds)
        
        # We only care about the last time step for prediction
        last_out = lstm_out[:, -1, :]
        
        out = self.fc(last_out)
        return out

class DeepGrammarGenerator:
    """
    Manages the model, training loop, and prediction.
    """
    def __init__(self):
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.model = WormLSTM().to(self.device)
        self.optimizer = optim.Adam(self.model.parameters(), lr=LEARNING_RATE)
        self.criterion = nn.CrossEntropyLoss()
        
        if os.path.exists(MODEL_PATH):
            self.load_model()
        else:
            print("[BRAIN] No model found. Initializing fresh.")

    def train_step(self, batch_sequences: List[List[int]]) -> float:
        """
        Performs one step of backpropagation.
        batch_sequences: List of lists of integers (bytes)
        """
        self.model.train()
        self.optimizer.zero_grad()
        
        # Preprocess input/target
        # Input: bytes 0..N-1
        # Target: bytes 1..N
        inputs = []
        targets = []
        
        for seq in batch_sequences:
            if len(seq) < 2: continue
            inputs.append(torch.tensor(seq[:-1], dtype=torch.long))
            targets.append(torch.tensor(seq[1:], dtype=torch.long))
            
        if len(inputs) == 0: return 0.0
        
        # Pad sequences to max length in batch
        inputs = torch.nn.utils.rnn.pad_sequence(inputs, batch_first=True).to(self.device)
        
        # Flatten target for loss calc (or handle padding mask)
        # Simplified: Just concatenating targets for demo
        # In prod, we need a packed sequence.
        target_tensor = torch.cat(targets).to(self.device)
        
        # Forward
        predictions = self.model(inputs)
        
        # Reshape predictions to match target
        # Predictions: (Batch, Classes)
        
        loss = self.criterion(predictions, target_tensor)
        
        # Backward
        loss.backward()
        torch.nn.utils.clip_grad_norm_(self.model.parameters(), 1.0) # Prevent exploding gradients
        self.optimizer.step()
        
        return loss.item()

    def predict_next_byte(self, context: List[int], top_k: int = 5) -> List[int]:
        """
        Given a context (previous bytes), predict the most likely next bytes.
        Returns list of byte integers.
        """
        self.model.eval()
        
        with torch.no_grad():
            if len(context) < SEQUENCE_LEN:
                # Pad with zeros
                padded = context + [0]*(SEQUENCE_LEN - len(context))
            else:
                padded = context[-SEQUENCE_LEN:]
                
            input_tensor = torch.tensor([padded], dtype=torch.long).to(self.device)
            
            logits = self.model(input_tensor)
            probs = torch.softmax(logits, dim=1).squeeze()
            
            # Get top k indices
            top_k_vals, top_k_indices = torch.topk(probs, top_k)
            
            return top_k_indices.cpu().numpy().tolist()

    def generate_mutation(self, seed: bytes) -> bytes:
        """
        Generates a syntactically valid mutation by appending
        a predicted byte from the LSTM.
        """
        byte_list = list(seed)
        if len(byte_list) > SEQUENCE_LEN:
            byte_list = byte_list[-SEQUENCE_LEN:]
            
        preds = self.predict_next_byte(byte_list, top_k=3)
        
        # Pick one of the top predictions
        next_byte = np.random.choice(preds)
        
        return seed + bytes([next_byte])

    def save_model(self):
        torch.save(self.model.state_dict(), MODEL_PATH)
        print(f"[BRAIN] Model saved to {MODEL_PATH}")

    def load_model(self):
        self.model.load_state_dict(torch.load(MODEL_PATH))
        print(f"[BRAIN] Model loaded from {MODEL_PATH}")

# --- MAIN EXECUTION ---
if __name__ == "__main__":
    brain = DeepGrammarGenerator()
    
    # Simulate training on some protocol data
    # In real scenario, this comes from the CorpusManager
    dummy_corpus = [
        [0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02], # Header + Op
        [0x01, 0x00, 0x04, 0xFF, 0xAA, 0xBB], # Random Data
    ]
    
    print("[BRAIN] Training LSTM on initial corpus...")
    for epoch in range(10):
        loss = brain.train_step(dummy_corpus)
        print(f"Epoch {epoch}: Loss {loss:.4f}")
        
    # Generate a test packet
    seed = bytes([0xDE, 0xAD, 0xBE, 0xEF])
    mutated = brain.generate_mutation(seed)
    print(f"[BRAIN] Generated Packet: {mutated.hex()}")