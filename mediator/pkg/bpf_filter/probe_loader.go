package bpf_filter

import (
    "bytes"
    "encoding/binary"
    "fmt"
    "log"
    "net"
    "os"
    "path/filepath"
    "runtime"
    "strings"
    "syscall"
    "time"
    "unsafe"

    "github.com/cilium/ebpf"
    "github.com/cilium/ebpf/link"
    "github.com/gorilla/websocket"
    "github.com/prometheus/client_golang/prometheus"
    "github.com/sirupsen/logrus"
    "go.uber.org/zap"
)

// BpfObjects contains all eBPF programs and maps
type BpfObjects struct {
    XfsIngressFilter      *ebpf.Program 
    XfsFlows             *ebpf.Map    
    ModbusIngressFilter   *ebpf.Program 
    ModbusFlows           *ebpf.Map    
    S7CommPlusIngressFilter *ebpf.Program 
    S7CommPlusFlows        *ebpf.Map    
    Iso8583IngressFilter *ebpf.Program 
    Iso8583Flows         *ebpf.Map    
}

// ProbeLoader loads and manages eBPF programs in kernel space
type ProbeLoader struct {
    logger          *logrus.Logger
    objects         BpfObjects
    links           []link.Link
    collection       *ebpf.Collection
    bpfMLModel      *zap.MLModel
    protocolStats    map[string]*ProtocolStats
}

// ProtocolStats tracks statistics for each protocol
type ProtocolStats struct {
    PacketsCaptured uint64
    BytesCaptured    uint64
    LastSeen         time.Time
    Violations       uint64
    MLDetections     uint64
}

// FlowKey represents a unique network flow
type FlowKey struct {
    SrcIP    uint32
    DstIP    uint32
    SrcPort  uint16
    DstPort  uint16
    Protocol uint8
}

// FlowValue represents flow metadata
type FlowValue struct {
    PacketCount uint64
    ByteCount  uint64
    LastSeen    time.Time
    Pid         uint32
    MLScore     float32
}

// NewProbeLoader creates a new probe loader
func NewProbeLoader() *ProbeLoader {
    logger := logrus.New()
    logger.SetLevel(logrus.DebugLevel)
    
    return &ProbeLoader{
        logger:     logger,
        objects:    &BpfObjects{},
        links:      make([]link.Link, 0),
        collection:  nil,
        bpfMLModel:  nil,
        protocolStats: make(map[string]*ProtocolStats),
    }
}

// LoadBpfObjects loads all eBPF programs from embedded byte code
func (p *ProbeLoader) LoadBpfObjects() error {
    p.logger.Info("Loading eBPF objects")
    
    // Load the collection
    collection, err := ebpf.LoadCollectionSpec(&BpfObjects{})
    if err != nil {
        return fmt.Errorf("failed to load eBPF collection spec: %v", err)
    }
    
    p.collection = collection
    
    // Load all programs
    if err := p.loadProgram(&p.objects.XfsIngressFilter); err != nil {
        return fmt.Errorf("failed to load XFS eBPF program: %v", err)
    }
    
    if err := p.loadProgram(&p.objects.ModbusIngressFilter); err != nil {
        return fmt.Errorf("failed to load Modbus eBPF program: %v", err)
    }
    
    if err := p.loadProgram(&p.objects.S7CommPlusIngressFilter); err != nil {
        return fmt.Errorf("failed to load S7CommPlus eBPF program: %v", err)
    }
    
    if err := p.loadProgram(&p.objects.Iso8583IngressFilter); err != nil {
        return fmt.Errorf("failed to load ISO8583 eBPF program: %v", err)
    }
    
    p.logger.Info("Successfully loaded all eBPF programs")
    return nil
}

// loadProgram loads and attaches an individual eBPF program
func (p *ProbeLoader) loadProgram(program *ebpf.Program) error {
    p.logger.WithField("program", program.String()).Debug("Loading eBPF program")
    
    // Load the program
    spec, err := ebpf.LoadCollectionSpec(program)
    if err != nil {
        return fmt.Errorf("failed to load eBPF program spec: %v", err)
    }
    
    loadedProgram, err := ebpf.NewProgram(spec)
    if err != nil {
        return fmt.Errorf("failed to create eBPF program: %v", err)
    }
    
    *program = loadedProgram
    
    p.logger.WithField("program", program.String()).Debug("eBPF program loaded successfully")
    return nil
}

// AttachToInterface attaches all eBPF programs to the specified interface
func (p *ProbeLoader) AttachToInterface(ifaceName string) error {
    p.logger.WithField("interface", ifaceName).Info("Attaching eBPF programs to interface")
    
    // Find the interface
    iface, err := net.InterfaceByName(ifaceName)
    if err != nil {
        return fmt.Errorf("failed to find interface %s: %v", ifaceName, err)
    }
    
    // Attach XFS program
    link, err := link.AttachXDP(link.XDPOptions{
        Program:   p.objects.XfsIngressFilter,
        Interface: iface.Index,
    })
    if err != nil {
        p.logger.WithError(err).Error("Failed to attach XFS eBPF program")
    } else {
        p.links = append(p.links, link)
        p.logger.Info("XFS eBPF program attached successfully")
    }
    
    // Attach Modbus program
    link, err = link.AttachXDP(link.XDPOptions{
        Program:   p.objects.ModbusIngressFilter,
        Interface: iface.Index,
    })
    if err != nil {
        p.logger.WithError(err).Error("Failed to attach Modbus eBPF program")
    } else {
        p.links = append(p.links, link)
        p.logger.Info("Modbus eBPF program attached successfully")
    }
    
    // Attach S7CommPlus program
    link, err = link.AttachXDP(link.XDPOptions{
        Program:   p.objects.S7CommPlusIngressFilter,
        Interface: iface.Index,
    })
    if err != nil {
        p.logger.WithError(err).Error("Failed to attach S7CommPlus eBPF program")
    } else {
        p.links = append(p.links, link)
        p.logger.Info("S7CommPlus eBPF program attached successfully")
    }
    
    // Attach ISO8583 program
    link, err = link.AttachXDP(link.XDPOptions{
        Program:   p.objects.Iso8583IngressFilter,
        Interface: iface.Index,
    })
    if err != nil {
        p.logger.WithError(err).Error("Failed to attach ISO8583 eBPF program")
    } else {
        p.links = append(p.links, link)
        p.logger.Info("ISO8583 eBPF program attached successfully")
    }
    
    p.logger.Info("All eBPF programs attached successfully")
    return nil
}

// Detach detaches all eBPF programs
func (p *ProbeLoader) Detach() error {
    p.logger.Info("Detaching eBPF programs")
    
    for _, link := range p.links {
        if err := link.Close(); err != nil {
            p.logger.WithError(err).Error("Failed to close eBPF link")
        }
    }
    
    p.links = p.links[:0]
    p.logger.Info("All eBPF programs detached")
    return nil
}

// InitializeMLModel initializes the ML model for packet classification
func (p *ProbeLoader) InitializeMLModel() error {
    p.logger.Info("Initializing ML model for packet classification")
    
    // Create a new ML model
    model, err := zap.NewMLModel(zap.Config{
        Features: 20,
        Hidden:    10,
        LearningRate: 0.01,
    })
    if err != nil {
        return fmt.Errorf("failed to create ML model: %v", err)
    }
    
    p.bpfMLModel = model
    p.logger.Info("ML model initialized successfully")
    return nil
}

// ClassifyPacket uses the ML model to classify packets
func (p *ProbeLoader) ClassifyPacket(packet []byte) (string, float32) {
    if p.bpfMLModel == nil {
        return "unknown", 0.0
    }
    
    // Extract features from packet
    features := p.extractFeatures(packet)
    
    // Predict using ML model
    prediction, err := p.bpfMLModel.Predict(features)
    if err != nil {
        p.logger.WithError(err).Error("Failed to predict packet class")
        return "unknown", 0.0
    }
    
    // Get the predicted class and confidence
    class := prediction.Class
    confidence := prediction.Confidence
    
    return class, confidence
}

// extractFeatures extracts features from a packet for ML classification
func (p *ProbeLoader) extractFeatures(packet []byte) []float64 {
    features := make([]float64, 20)
    
    // Packet length
    if len(packet) > 0 {
        features[0] = float64(len(packet))
    }
    
    // Protocol-specific features
    if len(packet) >= 4 {
        // XFS signature
        if packet[0] == 0x02 && packet[1] == 0x00 {
            features[1] = 1.0
        }
        
        // Modbus signature
        if packet[0] == 0x00 && packet[1] == 0x00 && 
           len(packet) >= 8 && packet[4] == 0x00 && packet[5] == 0x00 {
            features[2] = 1.0
        }
        
        // S7CommPlus signature
        if packet[0] == 0x72 && packet[1] == 0x01 {
            features[3] = 1.0
        }
        
        // ISO8583 signature
        if packet[0] >= 0x30 && packet[0] <= 0x39 && 
           packet[1] >= 0x30 && packet[1] <= 0x39 &&
           packet[2] >= 0x30 && packet[2] <= 0x39 &&
           packet[3] >= 0x30 && packet[3] <= 0x39 {
            features[4] = 1.0
        }
    }
    
    // Statistical features
    if len(packet) >= 2 {
        // Byte entropy
        entropy := p.calculateEntropy(packet)
        features[5] = entropy
        
        // Byte frequency analysis
        freq := p.calculateByteFrequency(packet)
        features[6] = freq
    }
    
    // Pattern features
    if len(packet) >= 4 {
        // Sequential byte patterns
        patterns := p.detectSequentialPatterns(packet)
        features[7] = patterns
        
        // Repeated byte patterns
        repeats := p.detectRepeatedPatterns(packet)
        features[8] = repeats
    }
    
    return features
}

// calculateEntropy calculates the Shannon entropy of a packet
func (p *ProbeLoader) calculateEntropy(packet []byte) float64 {
    if len(packet) == 0 {
        return 0.0
    }
    
    // Count byte frequencies
    freq := make(map[byte]int)
    for _, b := range packet {
        freq[b]++
    }
    
    // Calculate entropy
    var entropy float64 = 0.0
    length := float64(len(packet))
    
    for _, count := range freq {
        if count > 0 {
            p := float64(count) / length
            if p > 0 {
                entropy -= p * math.Log2(p)
            }
        }
    }
    
    return entropy
}

// calculateByteFrequency calculates the frequency of the most common byte
func (p *ProbeLoader) calculateByteFrequency(packet []byte) float64 {
    if len(packet) == 0 {
        return 0.0
    }
    
    freq := make(map[byte]int)
    maxCount := 0
    
    for _, b := range packet {
        freq[b]++
        if freq[b] > maxCount {
            maxCount = freq[b]
        }
    }
    
    return float64(maxCount) / float64(len(packet))
}

// detectSequentialPatterns detects sequential byte patterns
func (p *ProbeLoader) detectSequentialPatterns(packet []byte) float64 {
    if len(packet) < 4 {
        return 0.0
    }
    
    patterns := 0
    for i := 0; i < len(packet)-3; i++ {
        if packet[i] == packet[i+1]-1 && 
           packet[i+1] == packet[i+2]-2 && 
           packet[i+2] == packet[i+3]-3 {
            patterns++
        }
    }
    
    return float64(patterns) / float64(len(packet)-3)
}

// detectRepeatedPatterns detects repeated byte patterns
func (p *ProbeLoader) detectRepeatedPatterns(packet []byte) float64 {
    if len(packet) < 4 {
        return 0.0
    }
    
    repeats := 0
    seen := make(map[byte]bool)
    
    for i := 0; i < len(packet); i++ {
        if seen[packet[i]] {
            repeats++
        } else {
            seen[packet[i]] = true
        }
    }
    
    return float64(repeats) / float64(len(packet))
}

// UpdateStats updates protocol statistics
func (p *ProbeLoader) UpdateStats(protocol string, packetSize int) {
    stats := p.protocolStats[protocol]
    if stats == nil {
        stats = &ProtocolStats{}
        p.protocolStats[protocol] = stats
    }
    
    stats.PacketsCaptured++
    stats.BytesCaptured += uint64(packetSize)
    stats.LastSeen = time.Now()
    
    // Update ML detection count
    if p.bpfMLModel != nil {
        packetBytes := make([]byte, packetSize)
        _, confidence := p.ClassifyPacket(packetBytes)
        if confidence > 0.8 {
            stats.MLDetections++
        }
    }
}

// GetStats returns the current protocol statistics
func (p *ProbeLoader) GetStats() map[string]*ProtocolStats {
    return p.protocolStats
}

// ResetStats resets all protocol statistics
func (p *ProbeLoader) ResetStats() {
    p.protocolStats = make(map[string]*ProtocolStats)
}
