package main

import (
    "flag"
    "fmt"
    "log"
    "net"
    "os"
    "sync"
    "time"

    "proto-worm/pkg/proto"
)

// ---------------------------------------------------------
// CONFIGURATION
// ---------------------------------------------------------

var (
    listenAddr = flag.String("addr", "0.0.0.0:1337", "Address to listen on")
    debugMode = flag.Bool("debug", false, "Enable verbose logging")
)

// ---------------------------------------------------------
// STORAGE ENGINE (SIMULATED DISTRIBUTED DB)
// ---------------------------------------------------------

// KVStore is the stateful component holding data.
// It simulates sharding and replication.
type KVStore struct {
    mu    sync.RWMutex
    shard map[int]*Shard
    shardCount int
}

type Shard struct {
    mu    sync.RWMutex
    data  map[string][]byte // Value can be large binary
    dirty bool
}

type Record struct {
    Key       string
    Value     []byte
    Timestamp int64
    ExpiresAt int64 // 0 = never
}

func NewKVStore(shards int) *KVStore {
    kv := &KVStore{
        shardCount: shards,
        shard:     make(map[int]*Shard),
    }
    for i := 0; i < shards; i++ {
        kv.shard[i] = &Shard{data: make(map[string][]byte)}
    }
    return kv
}

func (kv *KVStore) GetShard(key string) *Shard {
    // Simple hash based sharding
    hash := 0
    for _, c := range []byte(key) {
        hash += int(c)
    }
    return kv.shard[hash%kv.shardCount]
}

// SET stores a key-value pair.
// Vulnerability: Does not validate 'value' size limits per key.
func (kv *KVStore) Set(key string, value []byte, ttl int64) error {
    shard := kv.GetShard(key)
    shard.mu.Lock()
    defer shard.mu.Unlock()
    
    // Logic: Check for existing key
    // Logic: Check TTL
    rec := &Record{
        Key:       key,
        Value:     value,
        Timestamp: time.Now().Unix(),
        ExpiresAt: ttl,
    }
    
    shard.data[key] = value
    shard.dirty = true
    
    return nil
}

// GET retrieves a value.
// Vulnerability: Returns underlying buffer (unsafe concurrency).
func (kv *KVStore) Get(key string) ([]byte, bool) {
    shard := kv.GetShard(key)
    shard.mu.RLock()
    defer shard.mu.RUnlock()
    
    val, ok := shard.data[key]
    return val, ok
}

// DEL removes a key.
func (kv *KVStore) Delete(key string) error {
    shard := kv.GetShard(key)
    shard.mu.Lock()
    defer shard.mu.Unlock()
    
    delete(shard.data, key)
    return nil
}

// DUMP exports the entire shard (Admin command).
// Vulnerability: Allocates massive buffer without checking memory.
func (kv *KVStore) Dump(shardID int) ([]byte, error) {
    if shardID < 0 || shardID >= kv.shardCount {
        return nil, fmt.Errorf("invalid shard id")
    }
    
    shard := kv.shard[shardID]
    shard.mu.RLock()
    defer shard.mu.RUnlock()
    
    // Dangerous: Allocating full size of map in one go
    buf := make([]byte, 0, 1024*1024) // Pre-alloc 1MB
    
    for k, v := range shard.data {
        buf = append(buf, []byte(k)...)
        buf = append(buf, 0x00) // Null terminator
        buf = append(buf, v...)
    }
    
    return buf, nil
}

// ---------------------------------------------------------
// AUTH PROVIDER
// ---------------------------------------------------------

type MockAuthProvider struct {
    Token string
}

func (m *MockAuthProvider) Authenticate(t string) bool {
    return t == m.Token
}

// ---------------------------------------------------------
// SERVER HANDLER
// ---------------------------------------------------------

type Server struct {
    kv      *KVStore
    auth    *MockAuthProvider
    limiter *RateLimiter
}

type RateLimiter struct {
    tokens map[string]int
    mu     sync.Mutex
    rate   int
}

func NewRateLimiter(rate int) *RateLimiter {
    return &RateLimiter{
        tokens: make(map[string]int),
        rate:   rate,
    }
}

func (rl *RateLimiter) Allow(ip string) bool {
    rl.mu.Lock()
    defer rl.mu.Unlock()
    
    if rl.tokens[ip] > 0 {
        rl.tokens[ip]--
        return true
    }
    return false
}

func NewServer() *Server {
    return &Server{
        kv:      NewKVStore(16), // 16 shards
        auth:    &MockAuthProvider{Token: "ADMIN_TOKEN"},
        limiter: NewRateLimiter(100),
    }
}

// HandleConnection manages the full session for a client.
func (s *Server) HandleConnection(conn net.Conn) {
    defer conn.Close()
    
    // Rate Limit Check
    if !s.limiter.Allow(conn.RemoteAddr().String()) {
        log.Printf("[SERVER] Rate limited %s", conn.RemoteAddr())
        return
    }
    
    log.Printf("[SERVER] New connection from %s", conn.RemoteAddr())
    
    // Wrap in Proto Connection
    protoConn := proto.NewConnection(conn, s.auth)
    
    for {
        // 1. Read Frame
        frame, err := protoConn.ReadFrame()
        if err != nil {
            if *debugMode {
                log.Printf("[SERVER] Read error: %v", err)
            }
            // Simulate Crash on specific error types for fuzzer
            if err.Error() == "invalid magic bytes" {
                panic("CRITICAL PROTOCOL VIOLATION")
            }
            return
        }
        
        // 2. Switch on Frame Type
        switch f := frame.(type) {
        case *proto.HandshakeAck:
            // Client accepted handshake
            log.Printf("[SERVER] Handshake complete")
        case *proto.AuthAck:
            log.Printf("[SERVER] Auth success")
        case *proto.CommandResponse:
            // Client sending us a command?
            // (Usually server sends response, but protocol allows duplex)
        default:
            // Execute Logic
            s.executeCommand(conn, frame)
        }
    }
}

func (s *Server) executeCommand(conn net.Conn, frame interface{}) error {
    // This is where we parse the specific command (SET, GET, DELETE, DUMP)
    // For fuzzer's sake, we assume frame contains raw byte buffer we need to parse manually
    // because we want to test parser bugs.
    
    // In a strict implementation, we would type assert `frame`.
    // Here we assume the Fuzzer sends us garbage that we try to interpret.
    
    buf := make([]byte, 1024)
    n, _ := conn.Read(buf) // Read potential command payload
    
    if n > 0 {
        // Extremely unsafe parsing for fuzzing purposes
        // We treat the first byte as Opcode
        opcode := buf[0]
        
        // Extract Key (until space)
        keyEnd := 1
        for keyEnd < n && buf[keyEnd] != ' ' {
            keyEnd++
        }
        key := string(buf[1:keyEnd])
        
        switch opcode {
        case 0x01: // SET
            value := buf[keyEnd+1:]
            if err := s.kv.Set(key, value, 0); err != nil {
                log.Printf("[SERVER] SET error: %v", err)
            }
        case 0x02: // GET
            val, _ := s.kv.Get(key)
            conn.Write(val)
        case 0x03: // DUMP
            shardID := int(buf[1])
            data, err := s.kv.Dump(shardID)
            if err != nil {
                return err
            }
            conn.Write(data)
        default:
            log.Printf("[SERVER] Unknown opcode: %x", opcode)
        }
    }
    
    return nil
}

// ---------------------------------------------------------
// MAIN
// ---------------------------------------------------------

func main() {
    flag.Parse()
    
    log.Printf("[SERVER] Starting WORM-PROTO Target Server...")
    log.Printf("[SERVER] Listening on %s", *listenAddr)
    
    ln, err := net.Listen("tcp", *listenAddr)
    if err != nil {
        log.Fatalf("[SERVER] Failed to listen: %v", err)
    }
    
    srv := NewServer()
    
    for {
        conn, err := ln.Accept()
        if err != nil {
            log.Printf("[SERVER] Accept error: %v", err)
            continue
        }
        
        // Spawn goroutine per connection
        // This allows concurrency testing for the fuzzer
        go srv.HandleConnection(conn)
    }
}

func init() {
    if os.Getenv("WORM_DEBUG") == "1" {
        debugMode = new(bool)
        *debugMode = true
    }
}