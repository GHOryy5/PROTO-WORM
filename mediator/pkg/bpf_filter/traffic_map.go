package bpf_filter

import (
	"log"
	"time"

	"github.com/cilium/ebpf"
)

// Flows is the eBPF map shared with the kernel
var Flows *ebpf.Map 

// FlowKey represents a unique connection flow (Source/Dest IP and Port)
type FlowKey struct {
	SourceIP   uint32
	DestIP     uint32
	SourcePort uint16
	DestPort   uint16
}

// FlowStats holds metadata about the connection
type FlowStats struct {
	PacketCount uint64
	LastSeen    uint64 // Unix epoch
	ProtocolID  uint32 // e.g., 0x01 for XFS, 0x02 for S7COMM
}

// MonitorTrafficMap continuously iterates over the eBPF map to extract flow statistics.
// This data is used by the main capture agent to decide which flows to process.
func MonitorTrafficMap(interval time.Duration) {
	if Flows == nil {
		log.Println("[WARN] FlowMap not initialized. BPF not fully active.")
		return
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	log.Println("[BPF] Starting flow map monitor...")

	for range ticker.C {
		var (
			key FlowKey
			stats FlowStats
		)
		
		// Iterate over all entries in the eBPF hash map
		iter := Flows.Iterate()
		count := 0
		
		for iter.Next(&key, &stats) {
			// In a full implementation, the raw data would be read here and sent to the Rust core
			// via an asynchronous channel.
			log.Printf(
				"[FLOW] Protocol 0x%X - Packets: %d - Last Seen: %s",
				stats.ProtocolID,
				stats.PacketCount,
				time.Unix(int64(stats.LastSeen), 0).Format(time.RFC3339),
			)
			count++
		}
		
		if err := iter.Err(); err != nil {
			log.Printf("[ERROR] BPF map iteration failed: %v", err)
		}
		
		// This log line is key to showing continuous monitoring
		log.Printf("[BPF] Processed %d active flows.", count)
	}
}
