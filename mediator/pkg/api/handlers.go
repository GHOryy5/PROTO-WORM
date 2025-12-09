package api

import (
    "context"
    "encoding/json"
    "fmt"
    "log"
    "time"

    "github.com/golang/protobuf/ptypes"
    "github.com/golang/protobuf/proto"
    "github.com/sirupsen/logrus"
    "go.uber.org/zap"
    "google.golang.org/grpc/codes"
    "google.golang.org/grpc/status"

    "proto-worm/pkg/db"
    "proto-worm/pkg/bpf_filter"
    "proto-worm/pkg/mutators"
)

// HandleCapturePacket handles packet capture requests
func (s *ProtocolService) HandleCapturePacket(ctx context.Context, req *CapturePacketRequest) (*CapturePacketResponse, error) {
    s.logger.WithFields(logrus.Fields{
        "request_id": req.RequestId,
        "protocol": req.Protocol,
        "data_size": len(req.Data),
    }).Debug("Received capture packet request")
    
    // Validate request
    if len(req.Data) == 0 {
        return nil, fmt.Errorf("empty packet data")
    }
    
    // Detect protocol
    protocol := s.bpfFilter.DetectProtocol(req.Data)
    if protocol == "unknown" {
        s.logger.WithField("protocol", protocol).Warn("Unknown protocol detected")
    }
    
    // Store packet in database
    packet := &db.Packet{
        Timestamp: time.Now(),
        Protocol: protocol,
        SrcIP: req.SrcIP,
        DstIP: req.DstIP,
        SrcPort: req.SrcPort,
        DstPort: req.DstPort,
        Payload: req.Data,
        Size: len(req.Data),
        MLClass: "unknown",
        MLConfidence: 0.0,
    }
    
    if err := s.db.StorePacket(packet); err != nil {
        return nil, fmt.Errorf("failed to store packet: %v", err)
    }
    
    // Update metrics
    s.UpdateMetrics("packets_captured", 1)
    s.UpdateMetrics("bytes_captured", float64(len(req.Data)))
    
    s.logger.WithFields(logrus.Fields{
        "request_id": req.RequestId,
        "protocol": protocol,
    }).Info("Packet captured and stored")
    
    return &CapturePacketResponse{
        RequestId: req.RequestId,
        Success:    true,
        Message:    "Packet captured successfully",
        Timestamp: time.Now().Unix(),
    }, nil
}

// HandleFuzzRequest handles fuzzing requests
func (s *ProtocolService) HandleFuzzRequest(ctx context.Context, req *FuzzRequest) (*FuzzResponse, error) {
    s.logger.WithFields(logrus.Fields{
        "request_id": req.RequestId,
        "protocol": req.Protocol,
        "fuzz_type": req.FuzzType,
        "iterations": req.Iterations,
    }).Debug("Received fuzz request")
    
    // Validate request
    if req.Iterations <= 0 || req.Iterations > 10000 {
        return nil, fmt.Errorf("invalid iteration count")
    }
    
    // Generate fuzzed packets
    fuzzedPackets, err := s.mutator.FuzzPackets(req.Protocol, req.OriginalPacket, req.FuzzType, int(req.Iterations))
    if err != nil {
        return nil, fmt.Errorf("failed to generate fuzzed packets: %v", err)
    }
    
    // Store fuzzed packets
    for i, packet := range fuzzedPackets {
        fuzzedPacket := &db.Packet{
            Timestamp: time.Now(),
            Protocol: req.Protocol,
            SrcIP: req.SrcIP,
            DstIP: req.DstIP,
            SrcPort: req.SrcPort,
            DstPort: req.DstPort,
            Payload: packet,
            Size: len(packet),
            MLClass: "fuzzed",
            MLConfidence: 0.8,
        }
        
        if err := s.db.StorePacket(fuzzedPacket); err != nil {
            s.logger.WithError(err).Error("Failed to store fuzzed packet")
            continue
        }
        
        s.UpdateMetrics("packets_fuzzed", 1)
    }
    
    s.logger.WithFields(logrus.Fields{
        "request_id": req.RequestId,
        "protocol": req.Protocol,
        "fuzzed_count": len(fuzzedPackets),
    }).Info("Fuzzing completed")
    
    return &FuzzResponse{
        RequestId: req.RequestId,
        Success:    true,
        Message:    fmt.Sprintf("Generated %d fuzzed packets", len(fuzzedPackets)),
        Timestamp: time.Now().Unix(),
        FuzzedPackets: fuzzedPackets,
    }, nil
}

// HandleAnalyzeRequest handles analysis requests
func (s *ProtocolService) HandleAnalyzeRequest(ctx context.Context, req *AnalyzeRequest) (*AnalyzeResponse, error) {
    s.logger.WithFields(logrus.Fields{
        "request_id": req.RequestId,
        "protocol": req.Protocol,
        "analysis_type": req.AnalysisType,
    }).Debug("Received analysis request")
    
    // Query packets for analysis
    packets, err := s.db.QueryPackets(db.QueryOptions{
        Protocol: req.Protocol,
        StartTime: req.StartTime,
        EndTime: req.EndTime,
        Limit: req.Limit,
    })
    
    if err != nil {
        return nil, fmt.Errorf("failed to query packets: %v", err)
    }
    
    // Perform analysis
    analysis, err := s.performAnalysis(req.AnalysisType, packets)
    if err != nil {
        return nil, fmt.Errorf("failed to perform analysis: %v", err)
    }
    
    s.logger.WithFields(logrus.Fields{
        "request_id": req.RequestId,
        "protocol": req.Protocol,
        "analysis_type": req.AnalysisType,
    }).Info("Analysis completed")
    
    return &AnalyzeResponse{
        RequestId: req.RequestId,
        Success:    true,
        Message:    analysis.Message,
        Timestamp: time.Now().Unix(),
        Analysis:    analysis,
    }, nil
}

// performAnalysis performs the actual analysis on packets
func (s *ProtocolService) performAnalysis(analysisType string, packets []*db.Packet) (*AnalysisResult, error) {
    var result AnalysisResult
    
    switch analysisType {
    case "statistical":
        result = s.performStatisticalAnalysis(packets)
    case "ml":
        result = s.performMLAnalysis(packets)
    case "vulnerability":
        result = s.performVulnerabilityAnalysis(packets)
    default:
        result = s.performBasicAnalysis(packets)
    }
    
    return &result, nil
}

// performStatisticalAnalysis performs statistical analysis on packets
func (s *ProtocolService) performStatisticalAnalysis(packets []*db.Packet) (*AnalysisResult, error) {
    if len(packets) == 0 {
        return &AnalysisResult{
            Message: "No packets to analyze",
        }, nil
    }
    
    // Calculate statistics
    totalPackets := len(packets)
    totalBytes := 0
    protocolCounts := make(map[string]int)
    
    for _, packet := range packets {
        totalBytes += packet.Size
        protocolCounts[packet.Protocol]++
    }
    
    return &AnalysisResult{
        Message: fmt.Sprintf("Statistical analysis completed. Total packets: %d, Total bytes: %d", totalPackets, totalBytes),
        Details: map[string]interface{}{
            "total_packets": totalPackets,
            "total_bytes": totalBytes,
            "protocol_counts": protocolCounts,
        },
    }, nil
}

// performMLAnalysis performs ML-based analysis on packets
func (s *ProtocolService) performMLAnalysis(packets []*db.Packet) (*AnalysisResult, error) {
    if len(packets) == 0 {
        return &AnalysisResult{
            Message: "No packets to analyze",
        }, nil
    }
    
    // Classify packets using ML model
    classifications := make(map[string]int)
    for _, packet := range packets {
        class := s.bpfFilter.ClassifyPacket(packet.Payload)
        classifications[class]++
    }
    
    return &AnalysisResult{
        Message: fmt.Sprintf("ML analysis completed. Classifications: %v", classifications),
        Details: map[string]interface{}{
            "classifications": classifications,
        },
    }, nil
}

// performVulnerabilityAnalysis performs vulnerability analysis on packets
func (s *ProtocolService) performVulnerabilityAnalysis(packets []*db.Packet) (*AnalysisResult, error) {
    if len(packets) == 0 {
        return &AnalysisResult{
            Message: "No packets to analyze",
        }, nil
    }
    
    // Detect potential vulnerabilities
    vulnerabilities := s.detectVulnerabilities(packets)
    
    return &AnalysisResult{
        Message: fmt.Sprintf("Vulnerability analysis completed. Potential vulnerabilities: %d", len(vulnerabilities)),
        Details: map[string]interface{}{
            "vulnerabilities": vulnerabilities,
        },
    }, nil
}

// detectVulnerabilities detects potential vulnerabilities in packets
func (s *ProtocolService) detectVulnerabilities(packets []*db.Packet) []string {
    var vulnerabilities []string
    
    for _, packet := range packets {
        // Check for buffer overflow patterns
        if s.isBufferOverflow(packet.Payload) {
            vulnerabilities = append(vulnerabilities, "buffer_overflow")
        }
        
        // Check for injection patterns
        if s.isInjectionAttempt(packet.Payload) {
            vulnerabilities = append(vulnerabilities, "injection_attempt")
        }
        
        // Check for protocol violations
        if s.isProtocolViolation(packet.Protocol, packet.Payload) {
            vulnerabilities = append(vulnerabilities, "protocol_violation")
        }
    }
    
    return vulnerabilities
}

// isBufferOverflow checks for buffer overflow patterns
func (s *ProtocolService) isBufferOverflow(payload []byte) bool {
    // Look for common buffer overflow patterns
    patterns := [][]byte{
        {0x41, 0x41, 0x41, 0x41}, // AAAA...
        {0x90, 0x90, 0x90, 0x90}, // \x90\x90\x90...
        {0x7f, 0x7f, 0x7f, 0x7f}, // \x7f\x7f\x7f...
    }
    
    for _, pattern := range patterns {
        if contains(payload, pattern) {
            return true
        }
    }
    
    return false
}

// isInjectionAttempt checks for injection patterns
func (s *ProtocolService) isInjectionAttempt(payload []byte) bool {
    // Look for common injection patterns
    patterns := []string{
        "' OR '1'='1",
        "' UNION SELECT",
        "'; DROP TABLE",
        "<script>",
        "<iframe",
    }
    
    payloadStr := string(payload)
    
    for _, pattern := range patterns {
        if contains(payloadStr, pattern) {
            return true
        }
    }
    
    return false
}

// isProtocolViolation checks for protocol violations
func (s *ProtocolService) isProtocolViolation(protocol string, payload []byte) bool {
    switch protocol {
    case "xfs":
        return s.isXFSViolation(payload)
    case "modbus":
        return s.isModbusViolation(payload)
    case "s7commplus":
        return s.isS7CommPlusViolation(payload)
    default:
        return false
    }
}

// isXFSViolation checks for XFS protocol violations
func (s *ProtocolService) isXFSViolation(payload []byte) bool {
    // Check for command sequence violations
    if len(payload) < 16 {
        return false
    }
    
    // Check for malformed headers
    command := uint16(payload[4]) | uint16(payload[5])<<8
    if command == 0xFFFF { // Invalid command
        return true
    }
    
    return false
}

// isModbusViolation checks for Modbus protocol violations
func (s *ProtocolService) isModbusViolation(payload []byte) bool {
    if len(payload) < 8 {
        return false
    }
    
    // Check for invalid function codes
    functionCode := payload[7]
    if functionCode < 1 || functionCode > 6 {
        return true
    }
    
    return false
}

// isS7CommPlusViolation checks for S7CommPlus protocol violations
func (s *ProtocolService) isS7CommPlusViolation(payload []byte) bool {
    if len(payload) < 12 {
        return false
    }
    
    // Check for invalid message types
    messageType := payload[11]
    if messageType == 0xFF { // Invalid message type
        return true
    }
    
    return false
}

// contains checks if a byte slice contains a pattern
func contains(slice []byte, pattern []byte) bool {
    if len(pattern) > len(slice) {
        return false
    }
    
    for i := 0; i <= len(slice)-len(pattern); i++ {
        match := true
        for j := 0; j < len(pattern); j++ {
            if slice[i+j-1] != pattern[j] {
                match = false
                break
            }
        }
        
        if match {
            return true
        }
    }
    
    return false
}
