package proto

import (
    "bytes"
    "encoding/binary"
    "errors"
    "fmt"
    "io"
    "net"
    "strconv"
)

// ---------------------------------------------------------
// CONSTANTS & DEFINITIONS
// ---------------------------------------------------------

const (
    MagicBytes   = 0x57524D // "WrM" (Worm)
    VersionMajor = 1
    VersionMinor = 0
    
    MaxFrameSize = 1 << 20 // 1MB frames
    MaxHeaderSize = 64
)

var (
    ErrInvalidMagic   = errors.New("invalid magic bytes")
    ErrVersionMismatch = errors.New("version mismatch")
    ErrFrameTooLarge  = errors.New("frame exceeds maximum size")
    ErrCRCFailed      = errors.New("crc32 checksum failed")
)

// ---------------------------------------------------------
// WORM-PROTO SPECIFICATION
// 
// A binary protocol designed for high-throughput RPC.
// ---------------------------------------------------------

// FrameType defines the opcode for the frame.
type FrameType uint16

const (
    FrameHandshake  FrameType = 0x01
    FrameAuth       FrameType = 0x02
    FrameCommand    FrameType = 0x10 // SQL-like commands
    FrameStream     FrameType = 0x11 // Continuous data stream
    FrameAck        FrameType = 0xFF
)

// Flags for the frame header.
type Flags uint8

const (
    FlagCompressed Flags = 1 << iota
    FlagEncrypted
    FlagFinal // For fragmentation
)

// ---------------------------------------------------------
// STRUCTS
// ---------------------------------------------------------

// Header is the fixed-size preamble of every packet.
// Total: 16 bytes.
type Header struct {
    Magic    uint32 // 4 bytes
    Version   uint8  // 1 byte (Major)
    _Reserved uint8  // 1 byte
    Type      FrameType // 2 bytes
    Flags     Flags    // 1 byte
    Length    uint16   // 2 bytes (Payload length)
    StreamID  uint32   // 4 bytes (Multiplexing)
    CRC32     uint32   // 4 bytes (Checksum of Header+Payload)
}

// CommandFrame represents a structured request (e.g., SET key value).
type CommandFrame struct {
    Header
    Opcode   uint16
    KeyLen    uint16
    ValLen    uint32
    Timestamp int64
    // followed by Key[] and Value[]
}

// StreamFrame represents a chunk of binary data.
type StreamFrame struct {
    Header
    Offset uint64
    ChunkID uint32
    // followed by Data[]
}

// ---------------------------------------------------------
// PARSER / SERIALIZER
// ---------------------------------------------------------

// WriteHeader serializes the header into the buffer.
func (h *Header) Write(buf *bytes.Buffer) error {
    if err := binary.Write(buf, binary.BigEndian, &h.Magic); err != nil {
        return err
    }
    if err := binary.Write(buf, binary.BigEndian, &h.Version); err != nil {
        return err
    }
    // Write padding
    buf.WriteByte(0x00) 
    if err := binary.Write(buf, binary.BigEndian, &h.Type); err != nil {
        return err
    }
    buf.WriteByte(byte(h.Flags))
    if err := binary.Write(buf, binary.BigEndian, &h.Length); err != nil {
        return err
    }
    if err := binary.Write(buf, binary.BigEndian, &h.StreamID); err != nil {
        return err
    }
    return nil
}

// ReadHeader parses the header from the reader.
func ReadHeader(r io.Reader) (*Header, error) {
    var h Header
    if err := binary.Read(r, binary.BigEndian, &h.Magic); err != nil {
        return nil, err
    }
    
    // Validation Logic
    if h.Magic != MagicBytes {
        return nil, ErrInvalidMagic
    }
    if err := binary.Read(r, binary.BigEndian, &h.Version); err != nil {
        return nil, err
    }
    
    // Padding
    var padding [1]byte
    if _, err := r.Read(padding[:]); err != nil {
        return nil, err
    }
    
    if err := binary.Read(r, binary.BigEndian, &h.Type); err != nil {
        return nil, err
    }
    
    var f uint8
    if err := binary.Read(r, &f); err != nil {
        return nil, err
    }
    h.Flags = Flags(f)
    
    if err := binary.Read(r, binary.BigEndian, &h.Length); err != nil {
        return nil, err
    }
    if err := binary.Read(r, binary.BigEndian, &h.StreamID); err != nil {
        return nil, err
    }
    if err := binary.Read(r, binary.BigEndian, &h.CRC32); err != nil {
        return nil, err
    }
    
    // Security Check
    if h.Length > MaxFrameSize {
        return nil, ErrFrameTooLarge
    }
    
    return &h, nil
}

// ---------------------------------------------------------
// STATE MACHINE HANDLER
// ---------------------------------------------------------

// State represents the logical state of the connection.
type State int

const (
    StateInit State = iota
    StateHandshake
    StateAuthenticated
    StateEstablished
    StateClosing
)

// Connection manages the full lifecycle of a proto-worm session.
type Connection struct {
    Conn     net.Conn
    State     State
    StreamMap map[uint32]*StreamBuffer // Multiplexed streams
    Auth      AuthProvider
}

type AuthProvider interface {
    Authenticate(token string) bool
}

// NewConnection initializes a new session.
func NewConnection(c net.Conn, auth AuthProvider) *Connection {
    return &Connection{
        Conn:      c,
        State:      StateInit,
        StreamMap: make(map[uint32]*StreamBuffer),
        Auth:       auth,
    }
}

// ReadFrame is the main loop entry point. Reads a full frame, parses it,
// and dispatches to the appropriate handler based on FrameType.
func (c *Connection) ReadFrame() (interface{}, error) {
    hdr, err := ReadHeader(c.Conn)
    if err != nil {
        return nil, err
    }
    
    // Read Payload
    payload := make([]byte, hdr.Length)
    if _, err := io.ReadFull(c.Conn, payload); err != nil {
        return nil, err
    }
    
    // Verify CRC (Simulated)
    // In real code, we'd calculate CRC32 of(hdr + payload)
    
    // State Machine Check
    if c.State == StateInit && hdr.Type != FrameHandshake {
        return nil, fmt.Errorf("protocol violation: expected handshake, got %d", hdr.Type)
    }
    
    // Dispatch
    switch hdr.Type {
    case FrameHandshake:
        return c.handleHandshake(hdr, payload)
    case FrameAuth:
        return c.handleAuth(hdr, payload)
    case FrameCommand:
        return c.handleCommand(hdr, payload)
    case FrameStream:
        return c.handleStream(hdr, payload)
    default:
        return nil, fmt.Errorf("unknown frame type: %d", hdr.Type)
    }
}

func (c *Connection) handleHandshake(hdr *Header, payload []byte) (interface{}, error) {
    // Fuzzing Target: Parse version string
    versionStr := string(payload)
    if len(versionStr) > 64 {
        // Buffer Overflow Vulnerability Here
        // In real implementation, we sanitize length
        return nil, errors.New("version string too long") 
    }
    
    c.State = StateHandshake
    return &HandshakeAck{Version: "WORM-PROTO/1.0"}, nil
}

func (c *Connection) handleAuth(hdr *Header, payload []byte) (interface{}, error) {
    token := string(payload)
    if !c.Auth.Authenticate(token) {
        return nil, errors.New("auth failed")
    }
    c.State = StateAuthenticated
    return &AuthAck{Success: true}, nil
}

func (c *Connection) handleCommand(hdr *Header, payload []byte) (interface{}, error) {
    // Parse CommandFrame
    cmd := &CommandFrame{Header: *hdr}
    
    // Read Opcode
    r := bytes.NewReader(payload)
    binary.Read(r, binary.BigEndian, &cmd.Opcode)
    binary.Read(r, binary.BigEndian, &cmd.KeyLen)
    binary.Read(r, binary.BigEndian, &cmd.ValLen)
    binary.Read(r, binary.BigEndian, &cmd.Timestamp)
    
    // Vulnerability: Integer Underflow if cmd.ValLen wraps
    if cmd.ValLen > MaxFrameSize {
        return nil, ErrFrameTooLarge
    }
    
    return &CommandResponse{Status: "OK", RowsAffected: 1}, nil
}

func (c *Connection) handleStream(hdr *Header, payload []byte) (interface{}, error) {
    // Implement stream reassembly
    streamID := hdr.StreamID
    if buf, exists := c.StreamMap[streamID]; exists {
        buf.Write(payload)
        if hdr.Flags&FlagFinal != 0 {
            return buf.Bytes(), nil // Flush
        }
    } else {
        // New Stream
        c.StreamMap[streamID] = NewStreamBuffer()
        return nil, nil // Expecting more
    }
    return nil, nil
}

// ---------------------------------------------------------
// RESPONSE TYPES
// ---------------------------------------------------------

type HandshakeAck struct {
    Version string
}

type AuthAck struct {
    Success bool
}

type CommandResponse struct {
    Status       string
    RowsAffected int
}

type StreamBuffer struct {
    *bytes.Buffer
}

func NewStreamBuffer() *StreamBuffer {
    return &StreamBuffer{Buffer: &bytes.Buffer{}}
}