package db

import (
    "context"
    "database/sql"
    "encoding/json"
    "fmt"
    "log"
    "time"

    "github.com/lib/pq"
    "github.com/sirupsen/logrus"
    "go.uber.org/zap"
)

// PacketDB handles database operations for packet storage and retrieval
type PacketDB struct {
    logger     *logrus.Logger
    db         *sql.DB
    connStr    string
}

// Packet represents a captured packet in the database
type Packet struct {
    ID          int64     
    Timestamp   time.Time  
    Protocol    string    
    SrcIP       string    
    DstIP       string    
    SrcPort     int16     
    DstPort     int16     
    Payload     []byte    
    Size        int       
    MLClass     string    
    MLConfidence float32   
}

// Vulnerability represents a security vulnerability finding
type Vulnerability struct {
    ID          int64     
    Timestamp   time.Time  
    Protocol    string    
    Type         string    
    Description string    
    Severity     int       
    CVSSScore    float32   
    Confidence   float32   
}

// QueryOptions represents options for querying packets
type QueryOptions struct {
    Protocol     string
    StartTime    time.Time
    EndTime      time.Time
    Limit        int
    MLClass      string
    MinConfidence float32
}

// NewPacketDB creates a new packet database connection
func NewPacketDB(connStr string) (*PacketDB, error) {
    logger := logrus.New()
    logger.SetLevel(logrus.InfoLevel)
    
    db, err := sql.Open("postgres", connStr)
    if err != nil {
        return nil, fmt.Errorf("failed to connect to database: %v", err)
    }
    
    logger.WithField("connection_string", connStr).Info("Connected to PostgreSQL database")
    
    return &PacketDB{
        logger:  logger,
        db:      db,
        connStr: connStr,
    }
}

// Close closes the database connection
func (pdb *PacketDB) Close() error {
    if pdb.db != nil {
        if err := pdb.db.Close(); err != nil {
            pdb.logger.WithError(err).Error("Failed to close database connection")
        } else {
            pdb.logger.Info("Database connection closed")
        }
    }
    
    pdb.db = nil
    return nil
}

// StorePacket stores a packet in the database
func (pdb *PacketDB) StorePacket(packet *Packet) error {
    if pdb.db == nil {
        return fmt.Errorf("database connection not initialized")
    }
    
    pdb.logger.WithFields(logrus.Fields{
        "protocol": packet.Protocol,
        "src_ip": packet.SrcIP,
        "dst_ip": packet.DstIP,
        "size": packet.Size,
    }).Debug("Storing packet")
    
    _, err := pdb.db.Exec(,
        packet.Timestamp,
        packet.Protocol,
        packet.SrcIP,
        packet.DstIP,
        packet.SrcPort,
        packet.DstPort,
        packet.Payload,
        packet.Size,
        packet.MLClass,
        packet.MLConfidence,
    )
    
    if err != nil {
        return fmt.Errorf("failed to store packet: %v", err)
    }
    
    return nil
}

// StoreVulnerability stores a vulnerability finding in the database
func (pdb *PacketDB) StoreVulnerability(vuln *Vulnerability) error {
    if pdb.db == nil {
        return fmt.Errorf("database connection not initialized")
    }
    
    pdb.logger.WithFields(logrus.Fields{
        "protocol": vuln.Protocol,
        "type": vuln.Type,
        "severity": vuln.Severity,
    }).Info("Storing vulnerability")
    
    _, err := pdb.db.Exec(,
        vuln.Timestamp,
        vuln.Protocol,
        vuln.Type,
        vuln.Description,
        vuln.Severity,
        vuln.CVSSScore,
        vuln.Confidence,
    )
    
    if err != nil {
        return fmt.Errorf("failed to store vulnerability: %v", err)
    }
    
    return nil
}

// QueryPackets retrieves packets based on query options
func (pdb *PacketDB) QueryPackets(options QueryOptions) ([]*Packet, error) {
    if pdb.db == nil {
        return nil, fmt.Errorf("database connection not initialized")
    }
    
    // Build base query
    query := "SELECT id, timestamp, protocol, src_ip, dst_ip, src_port, dst_port, size, ml_class, ml_confidence FROM packets WHERE 1=1"
    args := []interface{}
    
    // Add protocol filter
    if options.Protocol != "" {
        query += " AND protocol = $" + len(args) + 1
        args = append(args, options.Protocol)
    }
    
    // Add time range filter
    if !options.StartTime.IsZero() {
        query += " AND timestamp >= $" + len(args) + 1
        args = append(args, options.StartTime.Format("2006-01-02"))
    }
    
    if !options.EndTime.IsZero() {
        query += " AND timestamp <= $" + len(args) + 1
        args = append(args, options.EndTime.Format("2006-01-02"))
    }
    
    // Add ML class filter
    if options.MLClass != "" {
        query += " AND ml_class = $" + len(args) + 1
        args = append(args, options.MLClass)
    }
    
    // Add confidence filter
    if options.MinConfidence > 0 {
        query += " AND ml_confidence >= $" + len(args) + 1
        args = append(args, fmt.Sprintf("%.2f", options.MinConfidence))
    }
    
    // Add limit
    if options.Limit > 0 {
        query += " LIMIT $" + fmt.Sprintf("%d", options.Limit)
        args = append(args, options.Limit)
    }
    
    rows, err := pdb.db.Query(query, args...)
    if err != nil {
        return nil, fmt.Errorf("failed to query packets: %v", err)
    }
    
    defer rows.Close()
    
    var packets []*Packet
    for rows.Next() {
        var packet Packet
        err := rows.Scan(
            &packet.ID,
            &packet.Timestamp,
            &packet.Protocol,
            &packet.SrcIP,
            &packet.DstIP,
            &packet.SrcPort,
            &packet.DstPort,
            &packet.Size,
            &packet.MLClass,
            &packet.MLConfidence,
        )
        
        if err != nil {
            pdb.logger.WithError(err).Error("Failed to scan packet row")
            continue
        }
        
        packets = append(packets, packet)
    }
    
    if rows.Err() != nil {
        return nil, fmt.Errorf("rows iteration error: %v", rows.Err())
    }
    
    return packets, nil
}

// QueryFlows retrieves flow statistics from the database
func (pdb *PacketDB) QueryFlows(protocol string) ([]*FlowStats, error) {
    if pdb.db == nil {
        return nil, fmt.Errorf("database connection not initialized")
    }
    
    query := 
    
    rows, err := pdb.db.Query(query, protocol)
    if err != nil {
        return nil, fmt.Errorf("failed to query flows: %v", err)
    }
    
    defer rows.Close()
    
    var flows []*FlowStats
    for rows.Next() {
        var flow FlowStats
        err := rows.Scan(
            &flow.Protocol,
            &flow.PacketCount,
            &flow.ByteCount,
            &flow.AvgConfidence,
            &flow.MaxConfidence,
            &flow.UniqueSources,
            &flow.UniqueDestinations,
        )
        
        if err != nil {
            pdb.logger.WithError(err).Error("Failed to scan flow row")
            continue
        }
        
        flows = append(flows, flow)
    }
    
    if rows.Err() != nil {
        return nil, fmt.Errorf("rows iteration error: %v", rows.Err())
    }
    
    return flows, nil
}

// QueryVulnerabilities retrieves vulnerability statistics from the database
func (pdb *PacketDB) QueryVulnerabilities() ([]*VulnStats, error) {
    if pdb.db == nil {
        return nil, fmt.Errorf("database connection not initialized")
    }
    
    query := 
    
    rows, err := pdb.db.Query(query)
    if err != nil {
        return nil, fmt.Errorf("failed to query vulnerabilities: %v", err)
    }
    
    defer rows.Close()
    
    var vulns []*VulnStats
    for rows.Next() {
        var vuln VulnStats
        err := rows.Scan(
            &vuln.Protocol,
            &vuln.Type,
            &vuln.Count,
            &vuln.AvgScore,
            &vuln.MaxScore,
            &vuln.AvgConfidence,
            &vuln.UniqueTypes,
        )
        
        if err != nil {
            pdb.logger.WithError(err).Error("Failed to scan vulnerability row")
            continue
        }
        
        vulns = append(vulns, vuln)
    }
    
    if rows.Err() != nil {
        return nil, fmt.Errorf("rows iteration error: %v", rows.Err())
    }
    
    return vulns, nil
}

// GetDatabaseStats returns overall database statistics
func (pdb *PacketDB) GetDatabaseStats() (map[string]interface{}, error) {
    if pdb.db == nil {
        return nil, fmt.Errorf("database connection not initialized")
    }
    
    stats := make(map[string]interface{})
    
    // Get packet statistics
    packetStats, err := pdb.db.Query()
    
    if err == nil {
        stats["total_packets"] = packetStats[0]
        stats["total_bytes"] = packetStats[1]
        stats["avg_packet_size"] = packetStats[2]
        stats["unique_protocols"] = packetStats[3]
    }
    
    // Get flow statistics
    flowStats, err := pdb.db.Query()
    
    if err == nil {
        stats["total_flows"] = flowStats[0]
        stats["unique_sources"] = flowStats[1]
        stats["unique_destinations"] = flowStats[2]
    }
    
    // Get vulnerability statistics
    vulnStats, err := pdb.db.Query()
    
    if err == nil {
        stats["total_vulnerabilities"] = vulnStats[0]
        stats["unique_types"] = vulnStats[1]
        stats["avg_score"] = vulnStats[2]
        stats["max_score"] = vulnStats[3]
    }
    
    return stats, nil
}

// FlowStats represents flow statistics
type FlowStats struct {
    Protocol       string
    PacketCount    uint64
    ByteCount     uint64
    AvgConfidence float32
    MaxConfidence float32
    UniqueSources  uint64
    UniqueDestinations uint64
}

// VulnStats represents vulnerability statistics
type VulnStats struct {
    Protocol     string
    Type         string
    Count        uint64
    AvgScore     float32
    MaxScore     float32
    AvgConfidence float32
    UniqueTypes  uint64
}

// CreateIndexes creates database indexes for better performance
func (pdb *PacketDB) CreateIndexes() error {
    if pdb.db == nil {
        return fmt.Errorf("database connection not initialized")
    }
    
    indexes := []string{
        "CREATE INDEX IF NOT EXISTS idx_packets_timestamp ON packets(timestamp)",
        "CREATE INDEX IF NOT EXISTS idx_packets_protocol ON packets(protocol)",
        "CREATE INDEX IF NOT EXISTS idx_packets_src_ip ON packets(src_ip)",
        "CREATE INDEX IF NOT EXISTS idx_packets_dst_ip ON packets(dst_ip)",
        "CREATE INDEX IF NOT EXISTS idx_packets_ml_class ON packets(ml_class)",
        "CREATE INDEX IF NOT EXISTS idx_flows_protocol ON flows(protocol)",
        "CREATE INDEX IF NOT EXISTS idx_flows_src_ip ON flows(src_ip)",
        "CREATE INDEX IF NOT EXISTS idx_flows_dst_ip ON flows(dst_ip)",
        "CREATE INDEX IF NOT EXISTS idx_vulnerabilities_protocol ON vulnerabilities(protocol)",
        "CREATE INDEX IF NOT EXISTS idx_vulnerabilities_type ON vulnerabilities(type)",
    }
    
    for _, index := range indexes {
        if _, err := pdb.db.Exec(index); err != nil {
            return fmt.Errorf("failed to create index %s: %v", index, err)
        }
    }
    
    pdb.logger.Info("Database indexes created successfully")
    return nil
}

// BackupDatabase creates a backup of the database
func (pdb *PacketDB) BackupDatabase(backupPath string) error {
    if pdb.db == nil {
        return fmt.Errorf("database connection not initialized")
    }
    
    _, err := pdb.db.Exec(fmt.Sprintf("BACKUP TO '%s'", backupPath))
    if err != nil {
        return fmt.Errorf("failed to create backup: %v", err)
    }
    
    pdb.logger.WithField("backup_path", backupPath).Info("Database backup created successfully")
    return nil
}

// RestoreDatabase restores a database from a backup
func (pdb *PacketDB) RestoreDatabase(backupPath string) error {
    if pdb.db == nil {
        return fmt.Errorf("database connection not initialized")
    }
    
    _, err := pdb.db.Exec(fmt.Sprintf("RESTORE FROM '%s'", backupPath))
    if err != nil {
        return fmt.Errorf("failed to restore from backup: %v", err)
    }
    
    pdb.logger.WithField("backup_path", backupPath).Info("Database restored successfully")
    return nil
}
