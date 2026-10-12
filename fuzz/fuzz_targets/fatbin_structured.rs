#![no_main]
//! Structure-aware CUDA fatbin fuzzing (Bug Bash 2026 playbook §6).
//!
//! A fatbin wrapper is framed: a 16-byte header with a magic word and a
//! `header_offset`/`header_size` window, then a packed list of 64-byte entry
//! headers each carrying a `header_len` and `payload_size`.  A raw byte-flipper
//! (`fatbin_parser.rs`) almost never lands the magic, let alone a window and
//! entry chain that survive the overflow/forward-progress checks, so the
//! multi-entry iteration, kind classification, and `cubins()`/`ptx_entries()`
//! filters are rarely reached.
//!
//! This target builds a *valid* wrapper (correct magic, computed header_size,
//! per-entry header_len/payload_size) from a typed description, so the parser
//! walks the whole entry chain while the kinds, flags, SM versions, header
//! padding and payloads stay fuzzer-controlled.  Raw bytes are also parsed, so
//! the original coverage is retained.  The same invariant the raw target checks
//! — payload slices stay strictly inside the buffer — is asserted here.

use arbitrary::{Arbitrary, Unstructured};
use hexray_formats::FatbinWrapper;
use libfuzzer_sys::fuzz_target;

const FATBIN_MAGIC: u32 = 0xBA55_ED50;
const WRAPPER_HEADER_SIZE: usize = 16;
const ENTRY_HEADER_SIZE: usize = 64;

#[derive(Debug, Arbitrary)]
struct FuzzedEntry {
    kind: u16,
    flags: u16,
    sm: u16,
    /// Extra header padding beyond the fixed 64-byte entry header (header_len
    /// may legitimately exceed ENTRY_HEADER_SIZE); clamped to keep inputs small.
    header_pad: u8,
    payload: Vec<u8>,
}

#[derive(Debug, Arbitrary)]
struct FuzzedFatbin {
    version: u32,
    entries: Vec<FuzzedEntry>,
}

impl FuzzedFatbin {
    fn build(&self) -> Vec<u8> {
        let mut out = vec![0u8; WRAPPER_HEADER_SIZE];
        out[0..4].copy_from_slice(&FATBIN_MAGIC.to_le_bytes());
        out[4..8].copy_from_slice(&self.version.to_le_bytes());
        out[8..12].copy_from_slice(&(WRAPPER_HEADER_SIZE as u32).to_le_bytes()); // header_offset

        let payload_start = out.len();
        for e in &self.entries {
            let pad = (e.header_pad % 32) as usize;
            let header_len = ENTRY_HEADER_SIZE + pad;
            let mut hdr = vec![0u8; header_len];
            hdr[0..2].copy_from_slice(&e.kind.to_le_bytes());
            hdr[2..4].copy_from_slice(&e.flags.to_le_bytes());
            hdr[4..8].copy_from_slice(&(header_len as u32).to_le_bytes());
            hdr[8..16].copy_from_slice(&(e.payload.len() as u64).to_le_bytes());
            hdr[28..30].copy_from_slice(&e.sm.to_le_bytes());
            out.extend_from_slice(&hdr);
            out.extend_from_slice(&e.payload);
        }
        let header_size = (out.len() - payload_start) as u32;
        out[12..16].copy_from_slice(&header_size.to_le_bytes());
        out
    }
}

fn exercise(bytes: &[u8]) {
    let Ok(w) = FatbinWrapper::parse(bytes) else {
        return;
    };
    let buffer_start = bytes.as_ptr() as usize;
    let buffer_end = buffer_start + bytes.len();
    for entry in &w.entries {
        let p = entry.payload.as_ptr() as usize;
        assert!(
            p >= buffer_start && p + entry.payload.len() <= buffer_end,
            "fatbin entry payload escaped buffer"
        );
        assert_eq!(entry.data().len(), entry.payload.len());
        let _ = entry.kind;
        let _ = entry.sm;
        let _ = entry.compressed;
    }
    let _ = w.cubins().count();
    let _ = w.ptx_entries().count();
    let _ = w.version;
}

fuzz_target!(|data: &[u8]| {
    // Structured path: a valid multi-entry wrapper.
    if let Ok(fuzzed) = FuzzedFatbin::arbitrary(&mut Unstructured::new(data)) {
        exercise(&fuzzed.build());
    }
    // Raw path: preserve the original byte-level coverage.
    exercise(data);
});
