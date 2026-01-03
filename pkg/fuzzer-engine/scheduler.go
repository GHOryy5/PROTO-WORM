package engine

import (
    "context"
    "encoding/binary"
    "errors"
    "fmt"
    "io"
    "log"
    "math/rand"
    "net"
    "os"
    "sync"
    "sync/atomic"
    "time"

    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials/insecure"
    "google.golang.org/protobuf/proto"

    pb "proto-worm/proto"
)

// ---------------------------------------------------------
// CONFIGURATION & CONSTANTS
// ---------------------------------------------------------

const (
    MaxWorkers      = 500               // 500 Concurrent Goroutines
    QueueDepth      = 50000             // 50k pending test cases
    MaxPacketSize   = 4096               // 4KB max packet size
    RetryAttempts   = 3
    TargetRefresh   = 30 * time.Second // How often to check if target is alive
)

var (
    ErrTargetDown      = errors.New("target service is unresponsive")
    ErrCorruptInput   = errors.New("input bytes are malformed")
    ErrQueueFull       = errors.New("fuzzer queue is full")
)

// ---------------------------------------------------------
// GRAMMAR & MUTATION ENGINE
// ---------------------------------------------------------

// Grammar defines the "Language" of the protocol.
// We don't just send random bytes. We construct valid protocol headers
// and then smash the payload. This is "Grammar-Aware" fuzzing.
type Grammar struct {
    // Protocol Header Template
    Magic       []byte
    Version     uint8
    Opcodes     []uint8 // Valid operation codes
    
    // Fuzzing Parameters
    MinLen      int
    MaxLen      int
    FlipProb    float32 // Probability of bit-flipping
    SpliceProb  float32 // Probability of splicing two inputs
}

func NewGrammar() *Grammar {
    return &Grammar{
        Magic:   []byte{0xDE, 0xAD, 0xBE, 0xEF},
        Version: 1,
        Opcodes: []uint8{0x01, 0x02, 0x10, 0x11}, // CONNECT, DATA, ACK, FIN
        MinLen:   64,
        MaxLen:   1024,
        FlipProb:  0.05,
        SpliceProb: 0.1,
    }
}

// Generate creates a fresh seed packet based on grammar.
func (g *Grammar) Generate() []byte {
    // 1. Build Header
    buf := make([]byte, 16) // 4 bytes magic + 4 version + 4 len + 4 opcode
    copy(buf[0:4], g.Magic)
    binary.BigEndian.PutUint16(buf[4:6], uint16(g.Version))
    
    // 2. Pick a random opcode
    op := g.Opcodes[rand.Intn(len(g.Opcodes))]
    buf[6] = op
    
    // 3. Random Length
    payloadLen := rand.Intn(g.MaxLen-g.MinLen) + g.MinLen
    binary.BigEndian.PutUint16(buf[8:10], uint16(payloadLen))
    
    // 4. Fill Payload with garbage (initially)
    payload := make([]byte, payloadLen)
    for i := range payload {
        payload[i] = byte(rand.Intn(256))
    }
    
    return append(buf, payload...)
}

// Mutate takes an existing input and changes it to find new paths.
// Strategy: Spicy (BitFlip) + Structural (Splice).
func (g *Grammar) Mutate(input []byte) []byte {
    strategy := rand.Float32()
    
    if strategy < g.FlipProb {
        // BIT FLIP: High chance of finding parser crashes
        return g.bitFlip(input)
    } else if strategy < g.FlipProb+g.SpliceProb {
        // SPLICE: Combine two inputs to find stateful bugs
        return g.splice(input)
    } else {
        // HAVOC: Random mess
        return g.havoc(input)
    }
}

func (g *Grammar) bitFlip(input []byte) []byte {
    mut := make([]byte, len(input))
    copy(mut, input)
    
    // Flip 1-5 random bytes
    count := rand.Intn(4) + 1
    for i := 0; i < count; i++ {
        idx := rand.Intn(len(mut))
        mut[idx] ^= byte(rand.Intn(256))
    }
    return mut
}

func (g *Grammar) splice(input []byte) []byte {
    // We need a corpus to splice. For now, we just append garbage.
    return append(input, byte(rand.Intn(256)))
}

func (g *Grammar) havoc(input []byte) []byte {
    // Randomly resize or replace
    return nil
}

// ---------------------------------------------------------
// CORPUS MANAGER
// ---------------------------------------------------------

// Corpus stores "Interesting" inputs (Crashers or New Coverage).
type Corpus struct {
    mu      sync.RWMutex
    entries [][]byte
    // Bloom filter or Hash map for deduplication would go here
}

func NewCorpus() *Corpus {
    return &Corpus{
        entries: make([][]byte, 0),
    }
}

// AddInput adds a new interesting packet to the corpus.
func (c *Corpus) AddInput(input []byte) {
    c.mu.Lock()
    defer c.mu.Unlock()
    c.entries = append(c.entries, input)
    log.Printf("[CORPUS] New interesting input added. Total: %d", len(c.entries))
}

// GetRandom grabs a seed from the corpus for mutation.
func (c *Corpus) GetRandom() []byte {
    c.mu.RLock()
    defer c.mu.RUnlock()
    
    if len(c.entries) == 0 {
        return nil
    }
    return c.entries[rand.Intn(len(c.entries))]
}

// ---------------------------------------------------------
// FUZZER WORKER
// ---------------------------------------------------------

// Worker is a single thread of execution sending packets.
type Worker struct {
    ID         uint32
    Target     string
    Grammar     *Grammar
    Corpus     *Corpus
    Orchestrator pb.OrchestrationClient
    Stats      *WorkerStats
}

type WorkerStats struct {
    ExecCount     uint64
    CrashCount    uint64
    TimeoutCount  uint64
    LastCrashTime int64
}

func NewWorker(id uint32, target string, grammar *Grammar, corpus *Corpus, grpcAddr string) *Worker {
    conn, err := grpc.Dial(grpcAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
    if err != nil {
        log.Fatalf("Worker %d: Failed to connect to Orchestrator: %v", id, err)
    }

    return &Worker{
        ID:         id,
        Target:     target,
        Grammar:     grammar,
        Corpus:     corpus,
        Orchestrator: pb.NewOrchestrationClient(conn),
        Stats:      &WorkerStats{},
    }
}

// Run starts the worker loop.
func (w *Worker) Run(ctx context.Context, wg *sync.WaitGroup) {
    defer wg.Done()
    log.Printf("[WORKER-%d] Alive. Target: %s", w.ID, w.Target)
    
    // Connection Pool (Keep-Alive) would be better, but for now we dial per packet
    // to avoid state leakage between test cases.
    
    ticker := time.NewTicker(10 * time.Nanosecond) // 100M packets/sec theoretical max
    
    for {
        select {
        case <-ctx.Done():
            log.Printf("[WORKER-%d] Shutting down.", w.ID)
            return
        case <-ticker.C:
            w.executeTestCase()
        }
    }
}

func (w *Worker) executeTestCase() {
    atomic.AddUint64(&w.Stats.ExecCount, 1)
    
    // 1. Get Input (Generate or Mutate)
    var input []byte
    seed := w.Corpus.GetRandom()
    if seed != nil {
        input = w.Grammar.Mutate(seed)
    } else {
        input = w.Grammar.Generate()
    }
    
    if len(input) > MaxPacketSize {
        return
    }
    
    // 2. Connect & Send
    start := time.Now()
    conn, err := net.DialTimeout("tcp", w.Target, 50*time.Millisecond)
    if err != nil {
        // Target is likely dead. Don't spam logs.
        atomic.AddUint64(&w.Stats.TimeoutCount, 1)
        return
    }
    conn.SetWriteDeadline(start.Add(100 * time.Millisecond))
    
    _, err = conn.Write(input)
    if err != nil {
        conn.Close()
        return // Write error usually means target is dead
    }
    
    // 3. Read Response
    conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
    response := make([]byte, 1024)
    n, err := conn.Read(response)
    conn.Close()
    
    latency := time.Since(start)
    
    // 4. Analyze Result
    if err != nil || n == 0 {
        // Connection Reset / EOF -> Likely Crash
        w.handleCrash(input, err.Error())
    } else if latency > 400*time.Millisecond {
        // Timeout -> Potential Slow Loris / Deadlock
        w.handleHang(input)
    }
}

func (w *Worker) handleCrash(input []byte, reason string) {
    atomic.AddUint64(&w.Stats.CrashCount, 1)
    atomic.StoreInt64(&w.Stats.LastCrashTime, time.Now().Unix())
    
    log.Printf("[WORKER-%d] 💥 CRASH: %s", w.ID, reason)
    
    // Send to Rust Analyzer for deeper analysis
    ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
    defer cancel()
    
    dump := &pb.CrashDump{
        RawPacket:   input,
        TargetNode:  w.Target,
        ErrorSignal: reason,
        Timestamp:    time.Now().Unix(),
    }
    
    _, err := w.Orchestrator.ReportCrash(ctx, dump)
    if err != nil {
        log.Printf("[WORKER-%d] Failed to report crash: %v", w.ID, err)
    } else {
        log.Printf("[WORKER-%d] Report sent to Sentry.", w.ID)
        // In a real system, we would check 'AnalysisResult.is_exploitable' here
        // and add to Corpus if it is.
    }
}

func (w *Worker) handleHang(input []byte) {
    // Slow loris attacks are also bugs
    atomic.AddUint64(&w.Stats.TimeoutCount, 1)
}

// ---------------------------------------------------------
// ORCHESTRATOR (Main Loop)
// ---------------------------------------------------------

type Orchestrator struct {
    Config    Config
    Grammar   *Grammar
    Corpus    *Corpus
    Workers   []*Worker
    PoolSize  int
}

type Config struct {
    TargetAddr string
    GrpcAddr   string
}

func NewOrchestrator(cfg Config) *Orchestrator {
    return &Orchestrator{
        Config:   cfg,
        Grammar:  NewGrammar(),
        Corpus:   NewCorpus(),
        PoolSize: MaxWorkers,
    }
}

func (o *Orchestrator) Start(ctx context.Context) error {
    log.Println("Initializing Proto-Worm Distributed Fuzzer...")
    log.Printf("Target: %s | Analyzer: %s", o.Config.TargetAddr, o.Config.GrpcAddr)
    
    var wg sync.WaitGroup
    subCtx, cancel := context.WithCancel(ctx)
    defer cancel()

    // Spin up the pool
    for i := 0; i < o.PoolSize; i++ {
        workerID := uint32(i)
        w := NewWorker(workerID, o.Config.TargetAddr, o.Grammar, o.Corpus, o.Config.GrpcAddr)
        o.Workers = append(o.Workers, w)
        
        wg.Add(1)
        go w.Run(subCtx, &wg)
    }

    // Health Check Ticker
    go o.healthCheck(ctx)

    // Wait for signal or worker crash
    wg.Wait()
    return nil
}

func (o *Orchestrator) healthCheck(ctx context.Context) {
    ticker := time.NewTicker(TargetRefresh)
    for {
        select {
        case <-ctx.Done():
            return
        case <-ticker.C:
            conn, err := net.DialTimeout("tcp", o.Config.TargetAddr, 2*time.Second)
            if err != nil {
                log.Printf("[HEALTH] ⚠️  Target %s is DOWN", o.Config.TargetAddr)
            } else {
                conn.Close()
            }
        }
    }
}