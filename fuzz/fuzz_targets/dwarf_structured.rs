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
        0x01 => addr_size,              // addr
        0x0b | 0x0c => 1,               // data1, flag
        0x05 => 2,                      // data2
        0x06 | 0x0e | 0x13 | 0x17 => 4, // data4, strp, ref4, sec_offset
        0x07 => 8,                      // data8
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

// Caps so the *harness* itself can never OOM/hang before reaching the parser:
// without them a crafted input (one abbrev with N attrs × M DIEs selecting it)
// expands multiplicatively. Output bytes are bounded by
// MAX_DIES × MAX_ATTRS_PER_ABBREV × max-form-size, a few KiB.
const MAX_ABBREVS: usize = 16;
const MAX_ATTRS_PER_ABBREV: usize = 16;
const MAX_DIES: usize = 64;
const MAX_VALUE_POOL: usize = 64;

impl FuzzedDwarf {
    fn build(&self) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let addr_size = if self.addr64 { 8 } else { 4 };

        // Bounded view of the fuzzer-chosen abbreviations.
        let abbrevs: Vec<&FuzzedAbbrev> = self.abbrevs.iter().take(MAX_ABBREVS).collect();
        let n_abbrev = abbrevs.len().max(1);

        // --- .debug_abbrev ---------------------------------------------------
        // Abbrev code 1 is ALWAYS the compilation-unit root with
        // DW_CHILDREN_yes, so the generated child DIEs are reachable from the
        // single root DIE that `parse_compilation_unit` actually walks. Every
        // other abbrev is DW_CHILDREN_no, keeping the child list flat.
        let mut abbrev = Vec::new();
        for (i, a) in abbrevs.iter().enumerate() {
            let code = (i as u64) + 1;
            push_uleb(&mut abbrev, code);
            if i == 0 {
                push_uleb(&mut abbrev, 0x11); // DW_TAG_compile_unit (root)
                abbrev.push(1); // DW_CHILDREN_yes
            } else {
                push_uleb(&mut abbrev, TAGS[(a.tag_sel as usize) % TAGS.len()]);
                abbrev.push(0); // DW_CHILDREN_no
            }
            for sel in a.attr_sels.iter().take(MAX_ATTRS_PER_ABBREV) {
                let (at, form) = SPECS[(*sel as usize) % SPECS.len()];
                push_uleb(&mut abbrev, at);
                push_uleb(&mut abbrev, form);
            }
            push_uleb(&mut abbrev, 0); // end of attr specs
            push_uleb(&mut abbrev, 0);
        }
        if abbrevs.is_empty() {
            // Synthesize the root abbrev: code 1, compile_unit, children=yes.
            push_uleb(&mut abbrev, 1);
            push_uleb(&mut abbrev, 0x11);
            abbrev.push(1);
            push_uleb(&mut abbrev, 0);
            push_uleb(&mut abbrev, 0);
        }
        abbrev.push(0); // end of abbrev table

        // Emit one DIE's attribute values (form-correct lengths from `pool`).
        let emit_die_values = |idx: usize, pool: &[u8], out: &mut Vec<u8>| {
            let specs: Vec<(u64, u64)> = abbrevs
                .get(idx)
                .map(|a| {
                    a.attr_sels
                        .iter()
                        .take(MAX_ATTRS_PER_ABBREV)
                        .map(|s| SPECS[(*s as usize) % SPECS.len()])
                        .collect()
                })
                .unwrap_or_default();
            let mut cursor = PoolCursor { pool, pos: 0 };
            for (_at, form) in specs {
                match fixed_form_len(form, addr_size) {
                    Some(n) => cursor.take(n, out),
                    None => match form {
                        0x08 => {
                            // DW_FORM_string: short inline NUL-terminated string.
                            for _ in 0..4 {
                                let b = cursor.next_byte();
                                out.push(if b == 0 { b'a' } else { b });
                            }
                            out.push(0);
                        }
                        0x0f => push_uleb(out, (cursor.next_byte() & 0x7f) as u64), // udata
                        0x0d => out.push(cursor.next_byte() & 0x3f), // sdata (positive)
                        _ => {}
                    },
                }
            }
        };

        // --- DIE stream: one compile_unit root, the rest as its children -----
        let mut dies = Vec::new();
        push_uleb(&mut dies, 1); // root uses abbrev code 1
        let empty = Vec::new();
        let root_pool = self.dies.first().map(|d| &d.value_pool).unwrap_or(&empty);
        emit_die_values(0, root_pool, &mut dies);
        // Children are only expressible when a non-root (children=no) abbrev
        // exists; otherwise every abbrev code would reopen a child list.
        if n_abbrev >= 2 {
            for die in self.dies.iter().skip(1).take(MAX_DIES) {
                let child_idx = 1 + (die.abbrev_sel as usize) % (n_abbrev - 1); // [1, n_abbrev-1]
                push_uleb(&mut dies, (child_idx as u64) + 1); // code in [2, n_abbrev]
                let pool: Vec<u8> = die
                    .value_pool
                    .iter()
                    .take(MAX_VALUE_POOL)
                    .copied()
                    .collect();
                emit_die_values(child_idx, &pool, &mut dies);
            }
        }
        push_uleb(&mut dies, 0); // end of the root's children

        // --- .debug_info CU header (32-bit DWARF), version-correct layout ----
        let version = 2 + (self.version_sel % 4) as u16; // 2..=5
        let mut body = Vec::new();
        body.extend_from_slice(&version.to_le_bytes());
        if version >= 5 {
            // DWARF 5: version, unit_type, address_size, debug_abbrev_offset.
            body.push(0x01); // DW_UT_compile
            body.push(addr_size as u8);
            body.extend_from_slice(&0u32.to_le_bytes()); // debug_abbrev_offset
        } else {
            // DWARF 2–4: version, debug_abbrev_offset, address_size.
            body.extend_from_slice(&0u32.to_le_bytes()); // debug_abbrev_offset
            body.push(addr_size as u8);
        }
        body.extend_from_slice(&dies);

        let mut info = Vec::new();
        info.extend_from_slice(&(body.len() as u32).to_le_bytes()); // unit_length
        info.extend_from_slice(&body);
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
