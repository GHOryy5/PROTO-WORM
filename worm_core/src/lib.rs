pub mod protocols;
pub mod parser_gen;
pub mod mutators;

use std::ffi::{c_char, CString};
use std::os::raw::c_int;
use protocols::xfs::xfs_messages;

// Main export function for FFI. Takes raw bytes (ptr, len) and returns a JSON string (ptr)
// The caller is responsible for freeing the resulting CString pointer.
#[no_mangle]
pub extern "C" fn parse_protocol_bytes(data_ptr: *const u8, data_len: c_int) -> *mut c_char {
    if data_ptr.is_null() || data_len <= 0 {
        let err_str = CString::new("{\"error\": \"Invalid input pointer or length\"}").unwrap();
        return err_str.into_raw();
    }

    // Safely convert C pointer to Rust slice
    let data_slice = unsafe {
        std::slice::from_raw_parts(data_ptr, data_len as usize)
    };

    let result = xfs_messages::parse_raw_packet(data_slice);

    let json_output = match result {
        Ok(cmd_str) => format!(
            "{{\"status\": \"OK\", \"protocol\": \"XFS\", \"command\": \"{}\"}}", 
            cmd_str
        ),
        Err(e) => format!(
            "{{\"status\": \"ERROR\", \"message\": \"{}\"}}", 
            e
        ),
    };

    // Allocate the result string on the C heap
    let c_str = CString::new(json_output).unwrap();
    c_str.into_raw()
}

// FFI function to free the memory allocated by Rust
#[no_mangle]
pub extern "C" fn free_string(s: *mut c_char) {
    if s.is_null() {
        return;
    }
    unsafe {
        // Retake ownership of the CString to drop it, freeing the memory.
        let _ = CString::from_raw(s);
    }
}
