package main

import (
    "context"
    "flag"
    "fmt"
    "log"
    "os"
    "os/signal"
    "syscall"
    "time"

    "github.com/spf13/cobra"
    "github.com/spf13/viper"
    "go.uber.org/zap"

    "proto-worm/pkg/api"
    "proto-worm/pkg/bpf_filter"
    "proto-worm/pkg/db"
)

var (
    interfaceName = flag.String("interface", "", "Network interface to capture from")
    protocols    = flag.String("protocols", "", "Comma-separated list of protocols to monitor")
    outputDir    = flag.String("output", "", "Directory to save captured packets")
    serverAddr   = flag.String("server", "localhost:50051", "gRPC server address")
    filterPid    = flag.Int("pid", 0, "Process ID to filter (0 for all)")
    verbose      = flag.Bool("verbose", false, "Enable verbose logging")
    mlEnabled    = flag.Bool("ml", false, "Enable ML-based packet classification")
)

func main() {
    flag.Parse()
    
    // Configure logging
    if *verbose {
        log.SetLevel(log.DebugLevel)
    } else {
        log.SetLevel(log.InfoLevel)
    }
    
    // Load configuration
    viper.SetConfigName("capture-agent")
    viper.AddConfigPath("/etc/proto-worm/capture-agent.yaml")
    viper.AddConfigPath("/home/seattle/.proto-worm/capture-agent.yaml")
    viper.AutomaticEnv()
    viper.ReadInConfig()
    
    // Override with command line flags
    if *interfaceName != "" {
        viper.Set("interface", *interfaceName)
    }
    if *protocols != "" {
        viper.Set("protocols", *protocols)
    }
    if *outputDir != "" {
        viper.Set("output", *outputDir)
    }
    if *serverAddr != "" {
        viper.Set("server", *serverAddr)
    }
    if *filterPid != 0 {
        viper.Set("filterPid", *filterPid)
    }
    viper.Set("verbose", *verbose)
    viper.Set("ml", *mlEnabled)
    
    // Create a new capture agent
    agent, err := NewCaptureAgent()
    if err != nil {
        log.Fatalf("Failed to create capture agent: %v", err)
    }
    
    // Set up signal handling for graceful shutdown
    setupSignalHandling(agent)
    
    // Start the capture agent
    if err := agent.Start(); err != nil {
        log.Fatalf("Failed to start capture agent: %v", err)
    }
}

func setupSignalHandling(agent *CaptureAgent) {
    c := make(chan os.Signal, 1)
    signal.Notify(c, os.Interrupt, syscall.SIGTERM)
    
    go func() {
        <-c
        log.Println("Received termination signal, shutting down gracefully...")
        agent.Stop()
    }()
}
