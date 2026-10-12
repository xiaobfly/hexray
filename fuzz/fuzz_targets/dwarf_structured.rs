#![no_main]
//! Structure-aware DWARF fuzzing (Bug Bash 2026 playbook §6).
//!
//! `.debug_info` is length-prefixed and cross-references `.debug_abbrev`: a flat
//! byte-flipper (see `dwarf_parser.rs`, which splits raw bytes into thirds)
//! almost never produces a compilation-unit header that survives validation, so
//! coverage stops at the first length/version/abbrev checks and the attribute
//! and form decoders are never reached.
//!
//! This target builds a *well-framed* CU from a typed description: a valid
//! abbreviation table, a CU header whose `unit_length` is computed correctly,
//! and a DIE stream whose every attribute value is the exact length its form
//! demands.  Small mutations to the typed input therefore produce small,
//! still-walkable changes to the bytes — exactly the locality coverage-guided
//! fuzzing needs to drive the parser deep into form decoding.  The raw bytes are
//! also fed through unchanged, so nothing the old target covered is lost.

use arbitrary::{Arbitrary, Unstructured};
use hexray_formats::dwarf::{parse_eh_frame, DebugInfo, DebugInfoParser};
use libfuzzer_sys::fuzz_target;

/// (DW_AT, DW_FORM) pairs the generator draws from. The forms span the common
/// encodings — fixed-size, inline string, section-offset, reference, and LEB —
/// so the DIE walker exercises each decoding path.
const SPECS: &[(u64, u64)] = &[
    (0x03, 0x08), // DW_AT_name,      DW_FORM_string
    (0x03, 0x0e), // DW_AT_name,      DW_FORM_strp
    (0x0b, 0x0b), // DW_AT_byte_size, DW_FORM_data1
    (0x3e, 0x0b), // DW_AT_encoding,  DW_FORM_data1
    (0x11, 0x01), // DW_AT_low_pc,    DW_FORM_addr
    (0x12, 0x06), // DW_AT_high_pc,   DW_FORM_data4
    (0x1b, 0x08), // DW_AT_comp_dir,  DW_FORM_string
    (0x25, 0x0e), // DW_AT_producer,  DW_FORM_strp
    (0x13, 0x0b), // DW_AT_language,  DW_FORM_data1
    (0x3b, 0x0f), // DW_AT_decl_line, DW_FORM_udata
    (0x49, 0x13), // DW_AT_type,      DW_FORM_ref4
    (0x3f, 0x0c), // DW_AT_external,  DW_FORM_flag
    (0x3a, 0x05), // DW_AT_decl_file, DW_FORM_data2
    (0x0b, 0x07), // DW_AT_byte_size, DW_FORM_data8
    (0x6e, 0x0d), // DW_AT_linkage_name-ish, DW_FORM_sdata
    (0x10, 0x17), // DW_AT_stmt_list, DW_FORM_sec_offset
];

/// DWARF DIE tags the generator draws from.
const TAGS: &[u64] = &[
    0x11, // compile_unit
    0x2e, // subprogram
    0x34, // variable
    0x24, // base_type
    0x0f, // pointer_type
    0x05, // formal_parameter
    0x13, // structure_type
    0x0d, // member
];

#[derive(Debug, Arbitrary)]
struct FuzzedAbbrev {
    tag_sel: u8,
    /// Indices into `SPECS` (taken modulo its length) for this abbrev's attrs.
    attr_sels: Vec<u8>,
}

#[derive(Debug, Arbitrary)]
struct FuzzedDie {
    /// Which abbrev declaration this DIE instantiates.
    abbrev_sel: u8,
    /// Byte pool the attribute values are drawn from, so values have the exact
    /// length each form requires while still being fuzzer-controlled.
    value_pool: Vec<u8>,
}

#[derive(Debug, Arbitrary)]
struct FuzzedDwarf {
    version_sel: u8,
    addr64: bool,
    abbrevs: Vec<FuzzedAbbrev>,
    dies: Vec<FuzzedDie>,
    debug_str: Vec<u8>,
    extra: Vec<u8>,
}

/// Minimal unsigned-LEB128 encoder (all values here are small, but keep it
/// correct so the bytes are real DWARF).
fn push_uleb(out: &mut Vec<u8>, mut value: u64) {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
}

/// Number of value bytes a fixed-size form consumes; `None` for variable forms
/// handled specially (string / udata / sdata).
fn fixed_form_len(form: u64, addr_size: usize) -> Option<usize> {
    Some(match form {
        0x01 => addr_size,          // addr
        0x0b | 0x0c => 1,           // data1, flag
        0x05 => 2,                  // data2
        0x06 | 0x0e | 0x13 | 0x17 => 4, // data4, strp, ref4, sec_offset
        0x07 => 8,                  // data8
        _ => return None,
    })
}

struct PoolCursor<'a> {
    pool: &'a [u8],
    pos: usize,
}

impl<'a> PoolCursor<'a> {
    fn next_byte(&mut self) -> u8 {
        let b = self.pool.get(self.pos).copied().unwrap_or(0);
        self.pos = self.pos.wrapping_add(1);
        b
    }
    fn take(&mut self, n: usize, out: &mut Vec<u8>) {
        for _ in 0..n {
            out.push(self.next_byte());
        }
    }
}

impl FuzzedDwarf {
    fn build(&self) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let addr_size = if self.addr64 { 8 } else { 4 };

        // Always have at least one abbrev so DIEs have something to reference.
        let n_abbrev = self.abbrevs.len().max(1);

        // --- .debug_abbrev ---------------------------------------------------
        let mut abbrev = Vec::new();
        for (i, a) in self.abbrevs.iter().enumerate() {
            let code = (i as u64) + 1;
            push_uleb(&mut abbrev, code);
            push_uleb(&mut abbrev, TAGS[(a.tag_sel as usize) % TAGS.len()]);
            abbrev.push(0); // DW_CHILDREN_no — keep the DIE stream flat/walkable
            for sel in &a.attr_sels {
                let (at, form) = SPECS[(*sel as usize) % SPECS.len()];
                push_uleb(&mut abbrev, at);
                push_uleb(&mut abbrev, form);
            }
            push_uleb(&mut abbrev, 0); // end of attr specs
            push_uleb(&mut abbrev, 0);
        }
        if self.abbrevs.is_empty() {
            // Synthesize a trivial abbrev: code 1, base_type, no attrs.
            push_uleb(&mut abbrev, 1);
            push_uleb(&mut abbrev, 0x24);
            abbrev.push(0);
            push_uleb(&mut abbrev, 0);
            push_uleb(&mut abbrev, 0);
        }
        abbrev.push(0); // end of abbrev table

        // --- DIE stream ------------------------------------------------------
        let mut dies = Vec::new();
        for die in &self.dies {
            let idx = (die.abbrev_sel as usize) % n_abbrev;
            let code = (idx as u64) + 1;
            push_uleb(&mut dies, code);

            let specs: Vec<(u64, u64)> = match self.abbrevs.get(idx) {
                Some(a) => a
                    .attr_sels
                    .iter()
                    .map(|s| SPECS[(*s as usize) % SPECS.len()])
                    .collect(),
                None => Vec::new(),
            };

            let mut cursor = PoolCursor {
                pool: &die.value_pool,
                pos: 0,
            };
            for (_at, form) in specs {
                match fixed_form_len(form, addr_size) {
                    Some(n) => cursor.take(n, &mut dies),
                    None => match form {
                        0x08 => {
                            // DW_FORM_string: short inline NUL-terminated string.
                            for _ in 0..4 {
                                let b = cursor.next_byte();
                                dies.push(if b == 0 { b'a' } else { b });
                            }
                            dies.push(0);
                        }
                        0x0f => push_uleb(&mut dies, (cursor.next_byte() & 0x7f) as u64), // udata
                        0x0d => dies.push(cursor.next_byte() & 0x3f), // sdata, single positive byte
                        _ => {}
                    },
                }
            }
        }
        dies.push(0); // trailing null DIE

        // --- .debug_info CU header (32-bit DWARF) ----------------------------
        let version = 2 + (self.version_sel % 4) as u16; // 2..=5
        let mut info = Vec::new();
        let unit_length = (2 + 4 + 1 + dies.len()) as u32; // version + abbrev_off + addr_size + DIEs
        info.extend_from_slice(&unit_length.to_le_bytes());
        info.extend_from_slice(&version.to_le_bytes());
        info.extend_from_slice(&0u32.to_le_bytes()); // debug_abbrev_offset
        info.push(addr_size as u8);
        info.extend_from_slice(&dies);
        info.extend_from_slice(&self.extra);

        (info, abbrev, self.debug_str.clone())
    }
}

fn exercise(debug_info: &[u8], debug_abbrev: &[u8], debug_str: &[u8]) {
    let parser = DebugInfoParser::new(debug_info, debug_abbrev, Some(debug_str));
    if let Ok(units) = parser.parse_all() {
        let debug = DebugInfo::new(units, Vec::new());
        let _ = debug.find_location(0);
        let _ = debug.find_function(0);
        let _ = debug.functions().count();
    }
}

fuzz_target!(|data: &[u8]| {
    // Structured path: a well-framed CU the raw splitter could never produce.
    if let Ok(fuzzed) = FuzzedDwarf::arbitrary(&mut Unstructured::new(data)) {
        let (info, abbrev, strs) = fuzzed.build();
        exercise(&info, &abbrev, &strs);
    }

    // Raw path: preserve the original byte-flipper coverage.
    let first = data.len() / 3;
    let second = first + (data.len() - first) / 2;
    exercise(&data[..first], &data[first..second], &data[second..]);
    let big_endian = data.get(1).map(|b| b & 1 == 1).unwrap_or(false);
    let address_size = if data.first().map(|b| b & 1 == 1).unwrap_or(false) {
        8
    } else {
        4
    };
    let _ = parse_eh_frame(data, address_size, big_endian, 0);
});
