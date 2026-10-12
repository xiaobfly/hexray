//! Swarm testing for the decompiler (Groce et al., ISSTA 2012).
//!
//! Instead of testing with a single "default" configuration that enables every
//! optimization pass, swarm testing generates a diverse set of configurations
//! that each *omit* a random subset of passes.  Feature-omission diversity
//! leads to better coverage and fault detection because:
//!
//!  1. Some passes actively **suppress** behaviors that would expose bugs in
//!     other passes (active suppression).
//!  2. Passes compete for "space" within each test: with all passes on, any
//!     single pass has less opportunity to exercise deep behavior (passive
//!     suppression).
//!
//! The key invariants tested here must hold for **any** pass configuration:
//!
//!  - Decompilation must not panic or crash.
//!  - Output must be non-empty and contain the function name.
//!  - Output must have balanced braces (structurally valid).
//!  - Output must be deterministic (same config + same input → same output).
//!
//! Each proptest case selects which of the 24 optimization passes are enabled.
//! We deliberately do *not* draw a uniform `any::<u32>()` bitmask: that makes the
//! number of enabled passes a `Binomial(24, 0.5)`, concentrated so tightly around
//! 12 that the extreme shapes (the full production pipeline, and near-isolated
//! single passes) are never generated.  Instead [`arb_swarm_bits`] picks a
//! *density bucket* with explicit relative-integer weights and fills a bitmask at
//! that density, so the classic 50/50 swarm stays the common case while the tails
//! are exercised on a regular basis.  See that function and the
//! "when random isn't random enough" note beside it for the rationale.

use proptest::prelude::*;

use hexray_analysis::{CfgBuilder, Decompiler, DecompilerConfig};
use hexray_disasm::{Disassembler, X86_64Disassembler};

// =============================================================================
// Shared test data
// =============================================================================

/// Counting loop: `sum += i` for `i` in `0..10`.
///
/// Reused across multiple tests because loops exercise the most complex pass
/// interactions (register aliasing, dead-store elimination, copy propagation,
/// for-loop detection).
const LOOP_BYTES: &[u8] = &[
    0x55, // push rbp
    0x48, 0x89, 0xe5, // mov rbp, rsp
    0xc7, 0x45, 0xfc, 0x00, 0x00, 0x00, 0x00, // mov [rbp-4], 0
    0xc7, 0x45, 0xf8, 0x00, 0x00, 0x00, 0x00, // mov [rbp-8], 0
    0x83, 0x7d, 0xfc, 0x0a, // cmp [rbp-4], 10
    0x7d, 0x0c, // jge end
    0x8b, 0x45, 0xfc, // mov eax, [rbp-4]
    0x01, 0x45, 0xf8, // add [rbp-8], eax
    0x83, 0x45, 0xfc, 0x01, // add [rbp-4], 1
    0xeb, 0xee, // jmp loop
    0x8b, 0x45, 0xf8, // mov eax, [rbp-8]
    0x5d, // pop rbp
    0xc3, // ret
];

// =============================================================================
// Test Inputs — small x86-64 byte sequences with known structure
// =============================================================================

/// (name, bytes, start_addr)
fn test_programs() -> Vec<(&'static str, &'static [u8], u64)> {
    vec![
        // Minimal: just a return
        ("ret_only", [0xc3].as_slice(), 0x1000),
        // Simple prologue/epilogue with argument access
        (
            "simple_arg",
            &[
                0x55, // push rbp
                0x48, 0x89, 0xe5, // mov rbp, rsp
                0x89, 0x7d, 0xfc, // mov [rbp-4], edi
                0x8b, 0x45, 0xfc, // mov eax, [rbp-4]
                0x5d, // pop rbp
                0xc3, // ret
            ],
            0x1000,
        ),
        // Diamond if-else
        (
            "if_else",
            &[
                0x55, // push rbp
                0x48, 0x89, 0xe5, // mov rbp, rsp
                0x89, 0x7d, 0xfc, // mov [rbp-4], edi
                0x83, 0x7d, 0xfc, 0x00, // cmp [rbp-4], 0
                0x7e, 0x07, // jle +7
                0x8b, 0x45, 0xfc, // mov eax, [rbp-4]
                0xeb, 0x05, // jmp +5
                0xb8, 0x00, 0x00, 0x00, 0x00, // mov eax, 0
                0x5d, // pop rbp
                0xc3, // ret
            ],
            0x1000,
        ),
        // Counting loop (shared constant)
        ("counting_loop", LOOP_BYTES, 0x1000),
        // Multiply (imul)
        (
            "multiply",
            &[
                0x55, // push rbp
                0x48, 0x89, 0xe5, // mov rbp, rsp
                0x89, 0x7d, 0xfc, // mov [rbp-4], edi
                0x8b, 0x45, 0xfc, // mov eax, [rbp-4]
                0x0f, 0xaf, 0x45, 0xfc, // imul eax, [rbp-4]
                0x5d, // pop rbp
                0xc3, // ret
            ],
            0x1000,
        ),
        // Nested if: two comparisons
        (
            "nested_if",
            &[
                0x55, // push rbp
                0x48, 0x89, 0xe5, // mov rbp, rsp
                0x89, 0x7d, 0xfc, // mov [rbp-4], edi
                0x89, 0x75, 0xf8, // mov [rbp-8], esi
                0x83, 0x7d, 0xfc, 0x00, // cmp [rbp-4], 0
                0x7e, 0x0c, // jle +12
                0x83, 0x7d, 0xf8, 0x00, // cmp [rbp-8], 0
                0x7e, 0x06, // jle +6
                0x8b, 0x45, 0xfc, // mov eax, [rbp-4]
                0xeb, 0x0a, // jmp +10
                0x8b, 0x45, 0xf8, // mov eax, [rbp-8]
                0xeb, 0x05, // jmp +5
                0xb8, 0x00, 0x00, 0x00, 0x00, // mov eax, 0
                0x5d, // pop rbp
                0xc3, // ret
            ],
            0x1000,
        ),
    ]
}

// =============================================================================
// Helpers
// =============================================================================

fn disassemble_x86(bytes: &[u8], start: u64) -> Vec<hexray_core::Instruction> {
    let disasm = X86_64Disassembler::new();
    let mut instructions = Vec::new();
    let mut offset = 0;

    while offset < bytes.len() && instructions.len() < 500 {
        let remaining = &bytes[offset..];
        let addr = start + offset as u64;
        match disasm.decode_instruction(remaining, addr) {
            Ok(decoded) => {
                let is_ret = decoded.instruction.is_return();
                instructions.push(decoded.instruction);
                offset += decoded.size;
                if is_ret {
                    break;
                }
            }
            Err(_) => {
                offset += disasm.min_instruction_size().max(1);
            }
        }
    }
    instructions
}

fn decompile_with_config(bytes: &[u8], start: u64, name: &str, config: DecompilerConfig) -> String {
    let instructions = disassemble_x86(bytes, start);
    if instructions.is_empty() {
        return String::new();
    }
    let cfg = CfgBuilder::build(&instructions, start);
    let decompiler = Decompiler::new().with_addresses(false).with_config(config);
    decompiler.decompile(&cfg, name)
}

/// Net brace depth (0 when balanced).  Used only in failure diagnostics.
fn brace_depth(code: &str) -> i32 {
    code.chars().fold(0i32, |d, ch| {
        d + match ch {
            '{' => 1,
            '}' => -1,
            _ => 0,
        }
    })
}

/// Check that braces never go negative (close before open) and end balanced.
fn braces_well_formed(code: &str) -> bool {
    let mut depth: i32 = 0;
    for ch in code.chars() {
        match ch {
            '{' => depth += 1,
            '}' => depth -= 1,
            _ => {}
        }
        if depth < 0 {
            return false;
        }
    }
    depth == 0
}

// =============================================================================
// Swarm Configuration Strategy — weighted density, not uniform bitmasks
// =============================================================================
//
// The obvious swarm generator is `bits in any::<u32>()`: every pass is included
// independently with probability 1/2.  That sounds diverse, but it is a textbook
// case of *picking the wrong distribution* (see
// <https://ersc.io/blog/when-random-isnt-random-enough>): a uniform-over-bitmasks
// sampler makes the **number** of enabled passes a `Binomial(N, 0.5)`.  With the
// decompiler's N = 24 passes the count concentrates hard around 12
// (σ = √(24·0.25) ≈ 2.45), so in practice *every* generated configuration enables
// 7–17 passes.  The two most interesting shapes are then never produced:
//
//   * the **full production pipeline** (all passes on) — P ≈ 1/2²⁴ per draw, so
//     unseen across any realistic case budget; yet this is the config users
//     actually run, and the one where passes interact most; and
//   * **near-isolated** configs (0–3 passes) that let a single pass run almost
//     alone — exactly where a pass that normally hides behind an upstream pass
//     gets to expose its own bugs (the whole point of feature-omission swarms).
//
// Rather than sample bitmasks and hope the tails show up, we express the desired
// distribution directly, with relative integer weights (small, auditable, and
// obviously lopsided-or-not at a glance — the blog's core recommendation).  We
// pick a *density bucket* first, then fill a bitmask at that density.  This keeps
// the classic 50/50 swarm as the plurality case while guaranteeing the extremes
// are exercised on a regular basis.

/// Number of optimization passes the swarm ranges over.
fn num_passes() -> usize {
    hexray_analysis::OptimizationPass::all().len()
}

/// Bitmask with every pass enabled (the full production pipeline).
fn all_passes_mask() -> u32 {
    let n = num_passes();
    if n >= 32 {
        u32::MAX
    } else {
        (1u32 << n) - 1
    }
}

/// A swarm bitmask in which each pass is independently enabled with probability
/// `p`.  Used to realise a chosen density bucket.
fn bits_at_density(p: f64) -> impl Strategy<Value = u32> {
    proptest::collection::vec(proptest::bool::weighted(p), num_passes()).prop_map(|flags| {
        flags
            .iter()
            .enumerate()
            .filter(|&(_, &on)| on)
            .fold(0u32, |mask, (i, _)| mask | (1u32 << i))
    })
}

/// Weighted-density swarm-configuration strategy.
///
/// The weights are relative integers (1:3:4:3:1, summing to 12).  Read off the
/// intent at a glance: the 50/50 swarm is the plurality (4/12), the two "near"
/// tails are well represented (3/12 each), and the hard extremes — empty and
/// full — each get a steady 1/12 so they are *guaranteed* to appear, unlike with
/// a uniform bitmask where they never do.
fn arb_swarm_bits() -> impl Strategy<Value = u32> {
    let full = all_passes_mask();
    prop_oneof![
        1 => Just(0u32),            // all passes OFF — raw structuring baseline
        3 => bits_at_density(0.12), // near-isolated: typically 1–3 passes active
        4 => bits_at_density(0.5),  // the classic Groce 50/50 swarm
        3 => bits_at_density(0.88), // near-complete: one or two passes omitted
        1 => Just(full),            // full production pipeline — all passes ON
    ]
}

// =============================================================================
// Swarm Testing Properties
// =============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    /// Core swarm invariant: decompilation must not panic and must produce
    /// structurally valid output for any random subset of passes.
    ///
    /// This is the direct application of Groce et al.'s swarm testing:
    /// each `bits` value is a random test configuration C_i where each
    /// of the 24 passes has ~50% probability of inclusion.
    #[test]
    fn swarm_decompile_never_crashes(bits in arb_swarm_bits()) {
        let config = DecompilerConfig::from_swarm_bits(bits);

        for (name, bytes, start) in test_programs() {
            let code = decompile_with_config(bytes, start, name, config.clone());

            // Invariant 1: output is non-empty
            prop_assert!(
                !code.is_empty(),
                "swarm config 0x{:08x} ({}) produced empty output for '{}'",
                bits, config.describe(), name
            );

            // Invariant 2: function name appears in output
            prop_assert!(
                code.contains(name),
                "swarm config 0x{:08x} output for '{}' missing function name\n\
                 config: {}\ncode:\n{}",
                bits, name, config.describe(), code
            );

            // Invariant 3: balanced braces
            prop_assert!(
                braces_well_formed(&code),
                "swarm config 0x{:08x} output for '{}' has unbalanced braces \
                 (depth={})\nconfig: {}\ncode:\n{}",
                bits, name, brace_depth(&code), config.describe(), code
            );
        }
    }

    /// Determinism: the same swarm configuration and input must always
    /// produce identical output.
    #[test]
    fn swarm_decompile_is_deterministic(bits in arb_swarm_bits()) {
        for (name, bytes, start) in test_programs() {
            let config1 = DecompilerConfig::from_swarm_bits(bits);
            let config2 = DecompilerConfig::from_swarm_bits(bits);

            let code1 = decompile_with_config(bytes, start, name, config1);
            let code2 = decompile_with_config(bytes, start, name, config2);

            prop_assert_eq!(
                &code1, &code2,
                "swarm config 0x{:08x} is non-deterministic for '{}'\n\
                 config: {}",
                bits, name, DecompilerConfig::from_swarm_bits(bits).describe()
            );
        }
    }

    /// Monotonicity sanity check: enabling strictly more passes should not
    /// *reduce* the output to empty.  (The output may differ, but both
    /// the subset and the superset must produce non-empty results.)
    #[test]
    fn swarm_superset_still_produces_output(
        base_bits in arb_swarm_bits(),
        extra_bits in any::<u32>(),
    ) {
        let subset_bits = base_bits;
        let superset_bits = base_bits | extra_bits;

        let subset_config = DecompilerConfig::from_swarm_bits(subset_bits);
        let superset_config = DecompilerConfig::from_swarm_bits(superset_bits);

        for (name, bytes, start) in test_programs() {
            let sub_code = decompile_with_config(bytes, start, name, subset_config.clone());
            let sup_code = decompile_with_config(bytes, start, name, superset_config.clone());

            prop_assert!(
                !sub_code.is_empty(),
                "subset config 0x{:08x} produced empty output for '{}'",
                subset_bits, name
            );
            prop_assert!(
                !sup_code.is_empty(),
                "superset config 0x{:08x} produced empty output for '{}'",
                superset_bits, name
            );
        }
    }
}

// =============================================================================
// Targeted Swarm Tests — fixed programs × random configs
// =============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    /// High-volume swarm test on the loop program, which historically has the
    /// most complex pass interactions (register aliasing, dead-store
    /// elimination, copy propagation, for-loop detection).
    #[test]
    fn swarm_loop_program_robust(bits in arb_swarm_bits()) {
        let config = DecompilerConfig::from_swarm_bits(bits);
        let code = decompile_with_config(LOOP_BYTES, 0x1000, "sum_loop", config.clone());

        prop_assert!(!code.is_empty());
        prop_assert!(code.contains("sum_loop"));
        prop_assert!(braces_well_formed(&code));

        // The loop body must exist in some form — either as a structured loop
        // or as goto-based control flow.  The output must contain either a
        // loop keyword or a label (indicating goto-based lowering).
        let has_structure = code.contains("while")
            || code.contains("for")
            || code.contains("do")
            || code.contains("goto")
            || code.contains("loop");
        prop_assert!(
            has_structure,
            "swarm config 0x{:08x} lost all loop structure for sum_loop\n\
             config: {}\ncode:\n{}",
            bits, config.describe(), code
        );
    }
}

// =============================================================================
// System Binary Swarm Tests (macOS only)
// =============================================================================

#[cfg(target_os = "macos")]
mod system_binary_swarm {
    use super::*;
    use hexray_core::Architecture;
    use hexray_disasm::Arm64Disassembler;
    use hexray_formats::{detect_format, BinaryFormat, BinaryType, MachO};

    /// Extract the first small function from a system binary.
    fn extract_function(path: &str) -> Option<(Architecture, Vec<u8>, u64, String)> {
        let data = std::fs::read(path).ok()?;
        match detect_format(&data) {
            BinaryType::MachO => {
                let macho = MachO::parse(&data).ok()?;
                let arch = macho.architecture();
                for sym in macho.symbols() {
                    if sym.is_function() && sym.address != 0 && (4..=2048).contains(&sym.size) {
                        let bytes = macho.bytes_at(sym.address, sym.size as usize)?;
                        return Some((arch, bytes.to_vec(), sym.address, sym.name.clone()));
                    }
                }
                None
            }
            _ => None,
        }
    }

    fn disassemble_arm64(bytes: &[u8], start: u64) -> Vec<hexray_core::Instruction> {
        let disasm = Arm64Disassembler::new();
        let mut out = Vec::new();
        let mut off = 0;
        while off < bytes.len() && out.len() < 500 {
            match disasm.decode_instruction(&bytes[off..], start + off as u64) {
                Ok(d) => {
                    let ret = d.instruction.is_return();
                    out.push(d.instruction);
                    off += d.size;
                    if ret {
                        break;
                    }
                }
                Err(_) => {
                    off += 4;
                }
            }
        }
        out
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        /// Swarm test a real function extracted from /bin/ls.
        /// This exercises the decompiler on production machine code with
        /// diverse pass configurations.
        #[test]
        fn swarm_system_binary(bits in arb_swarm_bits()) {
            if let Some((arch, bytes, addr, name)) = extract_function("/bin/ls") {
                let instructions = match arch {
                    Architecture::X86_64 => disassemble_x86(&bytes, addr),
                    Architecture::Arm64 => disassemble_arm64(&bytes, addr),
                    _ => return Ok(()),
                };
                if instructions.is_empty() {
                    return Ok(());
                }

                let cfg = CfgBuilder::build(&instructions, addr);
                let config = DecompilerConfig::from_swarm_bits(bits);
                let decompiler = Decompiler::new()
                    .with_addresses(false)
                    .with_config(config.clone());

                let code = decompiler.decompile(&cfg, &name);

                prop_assert!(
                    !code.is_empty(),
                    "swarm config 0x{:08x} produced empty output for system func '{}'\n\
                     config: {}",
                    bits, name, config.describe()
                );
                prop_assert!(
                    braces_well_formed(&code),
                    "swarm config 0x{:08x} produced unbalanced braces for system func '{}'\n\
                     config: {}\ncode:\n{}",
                    bits, name, config.describe(), &code[..code.len().min(500)]
                );
            }
        }
    }
}

// =============================================================================
// Strategy self-check — the weighted swarm actually reaches the tails
// =============================================================================

/// Guards the whole point of [`arb_swarm_bits`]: that it reliably produces the
/// distribution tails a uniform `any::<u32>()` bitmask provably starves.
///
/// We sample the strategy deterministically and assert that, within a modest
/// budget, we see the all-off config, the full pipeline, a near-isolated config
/// (1–4 passes), and a near-complete one (all but 1–4 passes).  A uniform
/// bitmask would (essentially) never hit the first two: P(all-on) = P(all-off)
/// = 1/2²⁴ per draw, i.e. ~1e-4 expected occurrences across these 4 000 draws.
#[test]
fn weighted_swarm_reaches_distribution_tails() {
    use proptest::strategy::{Strategy, ValueTree};
    use proptest::test_runner::TestRunner;

    let mut runner = TestRunner::deterministic();
    let strat = arb_swarm_bits();
    let n = num_passes() as u32;
    let full = all_passes_mask();

    let (mut saw_empty, mut saw_full, mut saw_sparse, mut saw_dense) = (false, false, false, false);

    for _ in 0..4000 {
        let bits = strat.new_tree(&mut runner).unwrap().current();
        let k = bits.count_ones();
        saw_empty |= bits == 0;
        saw_full |= bits == full;
        saw_sparse |= (1..=4).contains(&k);
        saw_dense |= k < n && k >= n.saturating_sub(4);
    }

    assert!(
        saw_empty,
        "weighted swarm never produced the all-off config"
    );
    assert!(saw_full, "weighted swarm never produced the full pipeline");
    assert!(
        saw_sparse,
        "weighted swarm never produced a near-isolated config (1-4 passes)"
    );
    assert!(
        saw_dense,
        "weighted swarm never produced a near-complete config"
    );
}

// =============================================================================
// Reachability witness — the swarm properties are not vacuous
// =============================================================================
//
// Bug Bash 2026 playbook §3: a safety property ("never panics", "balanced
// braces", "deterministic") passes trivially on a decompiler that only ever
// emitted `return 0;`.  A *witness* turns "the properties hold" into "the
// properties hold **and** the inputs actually reach the interesting states",
// by proving the generated swarm configs drive the decompiler through its deep
// control-flow recovery.  Without this, a regression that silently narrowed the
// fixtures (or neutered structuring) would leave every property green while
// testing nothing.
//
// We assert only on states these fixtures *guarantee* are reachable — structured
// loops and conditionals (see `swarm_coverage_report`, which measures 100% loop
// recovery for the loop fixture).  Goto-fallback and switch recovery are 0% for
// these deliberately-simple fixtures, so they are tracked by the informational
// report rather than asserted here; extending the witness to cover them needs a
// jump-table / irreducible-CFG fixture (follow-up).

/// Witness: across a modest deterministic swarm sample, the decompiler recovers
/// both structured loops and conditionals from the fixtures, so the never-crash
/// / determinism / balanced-brace properties above are exercised against real
/// recovered control flow rather than trivial output.
#[test]
fn swarm_witnesses_reach_interesting_control_flow() {
    use proptest::strategy::{Strategy, ValueTree};
    use proptest::test_runner::TestRunner;

    let mut runner = TestRunner::deterministic();
    let strat = arb_swarm_bits();

    let (mut saw_loop, mut saw_conditional) = (false, false);

    'outer: for _ in 0..500 {
        let bits = strat.new_tree(&mut runner).unwrap().current();
        let config = DecompilerConfig::from_swarm_bits(bits);
        for (name, bytes, start) in test_programs() {
            let code = decompile_with_config(bytes, start, name, config.clone());
            saw_loop |= code.contains("while") || code.contains("for (") || code.contains("for(");
            saw_conditional |= code.contains("if (") || code.contains("if(");
            if saw_loop && saw_conditional {
                break 'outer;
            }
        }
    }

    assert!(
        saw_loop,
        "swarm never recovered a structured loop (while/for) across 500 configs — \
         loop structuring is no longer exercised, so the swarm invariants are vacuous"
    );
    assert!(
        saw_conditional,
        "swarm never recovered a conditional (if) across 500 configs — \
         conditional structuring is no longer exercised, so the swarm invariants are vacuous"
    );
}

// =============================================================================
// Bounded-resource invariant — no output blowup, no hang
// =============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    /// Bug Bash 2026 playbook §7: a correct decompiler can still fall over by
    /// exploding memory or hanging on pathological input.  This codifies the
    /// quadratic/OOM regression class (e.g. the historical `substitute_vars`
    /// expression blowup) as an automatic check: no swarm config may make the
    /// output grow unboundedly relative to the unoptimized baseline, exceed a
    /// generous absolute cap, or take anywhere near a hang threshold.
    #[test]
    fn swarm_output_and_time_are_bounded(bits in arb_swarm_bits()) {
        // These fixtures render to well under 2 KiB; a 64 KiB cap is enormous
        // slack yet still catches an OOM-class blowup (megabytes).
        const ABSOLUTE_CAP: usize = 64 * 1024;
        // Optimization should never 32x the unoptimized output; a real blowup
        // dwarfs this.
        const RELATIVE_FACTOR: usize = 32;
        const RELATIVE_SLACK: usize = 8 * 1024;
        // A single small function decompiles in well under a millisecond here; a
        // 10 s ceiling only fires on a genuine hang / superlinear blowup.
        let hang_threshold = std::time::Duration::from_secs(10);

        let config = DecompilerConfig::from_swarm_bits(bits);
        let baseline_config = DecompilerConfig::from_swarm_bits(0);

        for (name, bytes, start) in test_programs() {
            let baseline = decompile_with_config(bytes, start, name, baseline_config.clone());

            let t0 = std::time::Instant::now();
            let code = decompile_with_config(bytes, start, name, config.clone());
            let elapsed = t0.elapsed();

            prop_assert!(
                code.len() <= ABSOLUTE_CAP,
                "swarm config 0x{:08x} produced {} bytes for '{}' (cap {}) — output blowup\nconfig: {}",
                bits, code.len(), name, ABSOLUTE_CAP, config.describe()
            );

            let relative_cap = baseline
                .len()
                .saturating_mul(RELATIVE_FACTOR)
                .saturating_add(RELATIVE_SLACK);
            prop_assert!(
                code.len() <= relative_cap,
                "swarm config 0x{:08x} produced {} bytes for '{}' vs baseline {} \
                 (relative cap {}) — output blowup\nconfig: {}",
                bits, code.len(), name, baseline.len(), relative_cap, config.describe()
            );

            prop_assert!(
                elapsed < hang_threshold,
                "swarm config 0x{:08x} took {:?} for '{}' (threshold {:?}) — \
                 possible hang / superlinear blowup\nconfig: {}",
                bits, elapsed, name, hang_threshold, config.describe()
            );
        }
    }
}

// =============================================================================
// Swarm Coverage Statistics (ignored by default — run with --ignored)
// =============================================================================

/// Print a pass-frequency report for a 1000-element swarm set.
///
/// This test is `#[ignore]`d by default because it is informational, not a
/// correctness check.  Run with `cargo test -- --ignored swarm_coverage` to
/// see which pass combinations trigger which output patterns.
#[test]
#[ignore]
fn swarm_coverage_report() {
    use std::collections::HashMap;

    let all_passes = hexray_analysis::OptimizationPass::all();
    let num_configs: usize = 1000;
    let mut pass_trigger_count: HashMap<&str, usize> = HashMap::new();
    let mut pass_suppress_count: HashMap<&str, usize> = HashMap::new();
    let mut total_with_loops = 0usize;
    let mut total_with_gotos = 0usize;
    let mut total_with_switch = 0usize;
    let mut total_configs = 0usize;

    // Use a simple PRNG for reproducibility (xorshift32)
    let mut rng_state = 0xDEAD_BEEFu32;
    let mut next_u32 = || -> u32 {
        rng_state ^= rng_state << 13;
        rng_state ^= rng_state >> 17;
        rng_state ^= rng_state << 5;
        rng_state
    };

    for _ in 0..num_configs {
        let bits = next_u32();
        let config = DecompilerConfig::from_swarm_bits(bits);
        let code = decompile_with_config(LOOP_BYTES, 0x1000, "loop_fn", config);

        if code.is_empty() {
            continue;
        }
        total_configs += 1;

        let has_loop = code.contains("while") || code.contains("for");
        let has_goto = code.contains("goto");
        let has_switch = code.contains("switch");

        if has_loop {
            total_with_loops += 1;
        }
        if has_goto {
            total_with_gotos += 1;
        }
        if has_switch {
            total_with_switch += 1;
        }

        // Per-pass trigger/suppress analysis (à la Table 2 & 6 in the paper)
        for (i, pass) in all_passes.iter().enumerate() {
            let pass_on = bits & (1 << i) != 0;
            if pass_on && has_loop {
                *pass_trigger_count.entry(pass.name()).or_default() += 1;
            }
            if pass_on && has_goto {
                *pass_suppress_count.entry(pass.name()).or_default() += 1;
            }
        }
    }

    println!("\n=== Swarm Coverage Report ({total_configs} configs) ===");
    println!(
        "  Structured loops: {}/{} ({:.1}%)",
        total_with_loops,
        total_configs,
        total_with_loops as f64 / total_configs as f64 * 100.0
    );
    println!(
        "  Goto fallback:    {}/{} ({:.1}%)",
        total_with_gotos,
        total_configs,
        total_with_gotos as f64 / total_configs as f64 * 100.0
    );
    println!(
        "  Switch detected:  {}/{} ({:.1}%)",
        total_with_switch,
        total_configs,
        total_with_switch as f64 / total_configs as f64 * 100.0
    );

    println!("\n  Top loop triggers (pass present when loop detected):");
    let mut triggers: Vec<_> = pass_trigger_count.iter().collect();
    triggers.sort_by(|a, b| b.1.cmp(a.1));
    for (name, count) in triggers.iter().take(10) {
        println!(
            "    {:<35} {:>4} ({:.1}%)",
            name,
            count,
            **count as f64 / total_configs as f64 * 100.0
        );
    }

    println!("\n  Top goto triggers (pass present when goto emitted):");
    let mut suppressors: Vec<_> = pass_suppress_count.iter().collect();
    suppressors.sort_by(|a, b| b.1.cmp(a.1));
    for (name, count) in suppressors.iter().take(10) {
        println!(
            "    {:<35} {:>4} ({:.1}%)",
            name,
            count,
            **count as f64 / total_configs as f64 * 100.0
        );
    }
}
