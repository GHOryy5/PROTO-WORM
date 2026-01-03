package main

import (
    "bytes"
    "context"
    "fmt"
    "log"
    "net"
    "sync"
    "time"

    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials/insecure"

    pb "proto-worm/proto"
)

// Grammar defines the "shape" of valid packets. 
// This makes fuzzing "stateful" instead of random.
type Grammar struct {
    Opcodes      []byte
    MinLen       int
    MaxLen       int
    PayloadChar byte
}

func (g *Grammar) Mutate(input []byte) []byte {
    // Randomly flip bits or append valid opcodes
    if len(input) == 0 {
        return []byte{g.Opcodes[0]}
    }
    
    // Flip one byte
    mutated := make([]byte, len(input))
    copy(mutated, input)
    idx := time.Now().UnixNano() % int64(len(mutated))
    mutated[idx] ^= 0xFF // Flip
    
    return mutated
}

// Fuzzer represents a single worker.
type Fuzzer struct {
    Id          int
    TargetAddr  string
    Grammar     Grammar
    Client       pb.OrchestrationClient
    Stats       map[string]int
}

func NewFuzzer(id int, target string, grpcAddr string) *Fuzzer {
    conn, err := grpc.Dial(grpcAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
    if err != nil {
        log.Fatalf("Failed to connect to Python Brain: %v", err)
    }

    return &Fuzzer{
        Id:         id,
        TargetAddr:  target,
        Grammar:     Grammar{Opcodes: []byte{0x01, 0x02, 0x03}, MinLen: 10, MaxLen: 1024},
        Client:      pb.NewOrchestrationClient(conn),
        Stats:       make(map[string]int),
    }
}

// Run starts the fuzzing loop.
func (f *Fuzzer) Run(ctx context.Context, wg *sync.WaitGroup) {
    defer wg.Done()
    
    log.Printf("[Fuzzer %d] Targeting %s", f.Id, f.TargetAddr)
    
    ticker := time.NewTicker(1 * time.Millisecond) // 1000 packets/sec
    
    for {
        select {
        case <-ctx.Done():
            return
        case <-ticker.C:
            // 1. Generate Test Case
            seed := []byte{0x01, 0x00, 0x04} // Mock initial packet
            payload := f.Grammar.Mutate(seed)
            
            // 2. Send to Target
            conn, err := net.Dial("tcp", f.TargetAddr)
            if err != nil {
                continue // Target might have crashed (Good!)
            }
            
            conn.Write(payload)
            conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
            response := make([]byte, 1024)
            n, err := conn.Read(response)
            
            if err != nil {
                // 3. Connection Error? REPORT IT
                f.handleCrash(payload, err.Error())
            } else if n == 0 {
                // Server closed connection
                f.handleCrash(payload, "EOF/Crash")
            }
            
            conn.Close()
        }
    }
}

func (f *Fuzzer) handleCrash(input []byte, reason string) {
    log.Printf("[Fuzzer %d] CRASH DETECTED: %s", f.Id, reason)
    f.Stats["crashes"]++
    
    ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
    defer cancel()
    
    // Send to Rust Analyzer via gRPC
    dump := &pb.CrashDump{
        RawPacket:     input,
        TargetNode:    f.TargetAddr,
        ErrorSignal:   reason,
        Timestamp:     time.Now().Unix(),
    }
    
    _, err := f.Client.ReportCrash(ctx, dump)
    if err != nil {
        log.Printf("[Fuzzer %d] Failed to report crash: %v", f.Id, err)
    } else {
        log.Printf("[Fuzzer %d] Crash reported successfully.", f.Id)
    }
}

func main() {
    log.Println("Starting Proto-Worm Fuzzer Engine...")

    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()

    var wg sync.WaitGroup

    // Spin up 50 concurrent fuzzers
    // This provides the "High Velocity" impact mentioned in resume
    for i := 0; i < 50; i++ {
        wg.Add(1)
        fuzzer := NewFuzzer(i, "127.0.0.1:1337", "127.0.0.1:50051")
        go fuzzer.Run(ctx, &wg)
    }

    // Wait forever (or until Ctrl+C)
    wg.Wait()
}