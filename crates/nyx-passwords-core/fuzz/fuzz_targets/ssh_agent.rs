//! A request to the SSH agent, as any program of the user's can send one: parsed, and a
//! frame length read from its first bytes.
#![no_main]

use libfuzzer_sys::fuzz_target;
use nyx_passwords_core::ssh_agent::{Request, frame_len, parse};

fuzz_target!(|data: &[u8]| {
    if let Some(prefix) = data.get(..4) {
        let _ = frame_len(prefix.try_into().unwrap());
    }
    if let Some(Request::Sign { key, data: signed, .. }) = parse(data) {
        assert!(key.len() + signed.len() < data.len());
    }
});
