//! XFS Network Client
//!
//! Handles asynchronous TCP communication for sending and receiving XFS messages.
//! This uses Tokio for non-blocking I/O, essential for high-performance fuzzing.

use anyhow::{Result, Context};
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::net::SocketAddr;
use crate::protocols::xfs::xfs_messages::WFSHDR;

/// Represents a persistent, asynchronous connection to an XFS Service Provider (SP).
pub struct XFSClient {
    stream: TcpStream,
    target_addr: SocketAddr,
}

impl XFSClient {
    /// Establishes an asynchronous TCP connection to the target service.
    pub async fn connect(addr: &str) -> Result<Self> {
        let target_addr: SocketAddr = addr.parse()
            .context("Failed to parse socket address. Format should be 'IP:PORT'")?;
        
        let stream = TcpStream::connect(target_addr).await
            .context(format!("Failed to connect to XFS Service Provider at {}", addr))?;

        println!("[NETWORK] Successfully connected to {}", addr);
        
        Ok(Self {
            stream,
            target_addr,
        })
    }

    /// Sends a raw XFS message (bytes) asynchronously.
    pub async fn send_request(&mut self, request_data: &[u8]) -> Result<()> {
        self.stream.write_all(request_data).await
            .context("Failed to write request data to stream")?;
        
        // Ensure the data is immediately sent out.
        self.stream.flush().await
            .context("Failed to flush stream after sending request")?;

        Ok(())
    }

    /// Reads a raw XFS response (bytes) asynchronously.
    ///
    /// The XFS protocol is structured such that the message size is contained
    /// within the WFSHDR. We must read the header first to know how much
    /// payload data to expect. This is a common and dangerous pattern in RE.
    pub async fn read_response(&mut self) -> Result<Vec<u8>> {
        // Step 1: Read the fixed-size WFSHDR
        let header_size = mem::size_of::<WFSHDR>();
        let mut header_buf = vec![0u8; header_size];
        
        // Use read_exact to ensure we get the full header
        self.stream.read_exact(&mut header_buf).await
            .context("Failed to read full WFSHDR from stream. Connection likely closed or packet truncated.")?;

        // Step 2: Extract the expected payload size (dw_size field)
        // We use the WFSHDR structure to safely parse the size.
        let header: WFSHDR = unsafe { 
            ptr::read_unaligned(header_buf.as_ptr() as *const WFSHDR) 
        };
        
        // dw_size is the size of the *data buffer* following the header.
        let payload_size = header.dw_size as usize;
        
        if payload_size > 1024 * 1024 * 4 { // Arbitrary safety limit (4MB)
            // This is a prime location for a logic bomb! Malformed size could lead to OOM.
            return Err(anyhow!("Payload size declared in WFSHDR is suspiciously large ({} bytes). Potential malicious packet.", payload_size));
        }

        // Step 3: Read the variable-sized payload
        let mut payload_buf = vec![0u8; payload_size];
        self.stream.read_exact(&mut payload_buf).await
            .context("Failed to read full payload data. Packet length mismatch or connection error.")?;

        // Step 4: Combine header and payload into the full XFS message
        let mut full_message = header_buf;
        full_message.extend_from_slice(&payload_buf);

        Ok(full_message)
    }

    /// Returns the target address string.
    pub fn target_addr(&self) -> String {
        self.target_addr.to_string()
    }
}

// FFI and C-like type imports needed for the WFSHDR struct access
use std::ptr;
use std::mem;
use std::os::raw::c_ulong;


#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;
    
    // Helper function to simulate a minimal XFS service provider response
    async fn serve_dummy_response(listener: TcpListener, payload: &[u8]) -> Result<()> {
        let (mut socket, _) = listener.accept().await?;

        // Create a dummy WFSHDR with correct size
        let mut header = WFSHDR::default();
        header.dw_size = payload.len() as c_ulong;
        
        // Convert WFSHDR to bytes (simplified to avoid full msg structure logic)
        let header_bytes = unsafe { 
            std::slice::from_raw_parts(
                &header as *const WFSHDR as *const u8,
                mem::size_of::<WFSHDR>(),
            )
        };
        
        // Concatenate and send
        let mut response = header_bytes.to_vec();
        response.extend_from_slice(payload);

        // Expect a request (read it to clear the buffer)
        let mut req_buf = [0u8; 1024];
        let n = socket.read(&mut req_buf).await.unwrap();
        assert!(n > 0);

        // Send the response
        socket.write_all(&response).await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_client_connection_and_io() -> Result<()> {
        // 1. Setup a dummy listener on a random port
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?.to_string();

        // 2. Start the service provider in a background task
        let dummy_payload = b"TEST_DATA_FROM_SP";
        let sp_handle = tokio::spawn(serve_dummy_response(listener, dummy_payload));

        // 3. Client connects and sends request
        let mut client = XFSClient::connect(&addr).await?;
        let request_bytes = vec![0x01, 0x02, 0x03];
        client.send_request(&request_bytes).await?;

        // 4. Client reads response
        let response_bytes = client.read_response().await?;

        // Verify the response
        let header_size = mem::size_of::<WFSHDR>();
        assert_eq!(response_bytes.len(), header_size + dummy_payload.len());
        
        // Verify the payload data is correct
        assert_eq!(&response_bytes[header_size..], dummy_payload);

        // Wait for the server task to finish
        sp_handle.await??;

        Ok(())
    }
}
