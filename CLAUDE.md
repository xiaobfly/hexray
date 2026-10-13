# CLAUDE.md — working agreement for hexray

hexray is a multi-architecture binary **decompiler**: it parses object/executable
files (ELF, Mach-O, PE, AR, CUDA cubin/fatbin/PTX), disassembles
(x86-64, arm64, riscv, CUDA SASS, AMDGPU), and reconstructs readable pseudo-C.
It is a *deep & narrow* system — a small public surface over a large, intricate
transformation of **untrusted bytes**. That shape is what makes the correctness
practices below pay off, and it is why they are non-negotiable here.

Workspace: 9 crates (see `docs/TESTING.md` and each crate's `src/lib.rs`).
Cargo.lock is gitignored; the version lives once in `[workspace.package]`.

---

## Correctness practices (Bug Bash 2026 playbook)

- **Code is cheap, correctness is not.** The bottleneck is verification, not
  typing. The human owns intent (types, interfaces, invariants, tests); the agent
  fills in implementation. **Review the diff — don't merge or ship what you don't
  understand or haven't run.**
- Prefer **executable** checks over prose. A spec that can't run and isn't wired
  to the code will rot (see `specs/tla/` + its Rust conformance test for the one
  place a model earns its keep).
- For any pure function or pass with an invariant, add **property-based tests**
  (`proptest`), not just example-based ones.
- Keep output **deterministic**: same input + same config → byte-identical output.
  No `rand`, wall-clock, or hash-iteration order in anything that reaches output.
- Name the **invariants** (below). For a property that could pass vacuously, add a
  **reachability witness** — a check proving the interesting state is actually
  reached (e.g. the swarm witness in `proptest_swarm_decompiler.rs`).
- When a reference implementation exists, use **differential testing** against it
  (disasm vs objdump/llvm-objdump, symbols vs nm, SASS vs `nvdisasm`, demangling
  vs `cpp_demangle`). A disagreement is a bug in one of them.
- Everything we parse is **untrusted**: never panic, never hang, never blow up
  memory on adversarial bytes. Prefer structure-aware fuzzing for formats with
  internal length/offset/framing (a byte-flipper never gets past the header).
- Reliability ≠ correctness. Bound inputs; the per-component caps and budgets are
  our stability margins against pathological input.

---

## hexray's named invariants

These must hold for **any** optimization-pass configuration and for **any** input
bytes. They are enforced by the test suites noted in parentheses.

1. **Never crash.** No panic / abort on arbitrary or malformed input — decoders,
   format parsers, CFG, SSA, structurer, emitter (`proptest_swarm_decompiler.rs`,
   `proptest_decoder.rs`, `proptest_formats.rs`, every `fuzz/fuzz_targets/*`).
2. **Structurally valid output.** Non-empty, contains the function name, balanced
   braces (`proptest_swarm_decompiler.rs`).
3. **Deterministic.** Same config + same input → identical output
   (`proptest_swarm_decompiler.rs`, `decompiler_regression.rs`).
4. **Bounded.** Output size and run time stay bounded relative to input; no
   quadratic/exponential blowup (bounded-resource witness in
   `proptest_swarm_decompiler.rs`; per-component caps like
   `MAX_COMPUTED_DISPATCH_ENTRIES`, emulator instruction/stack budgets).
5. **Reachability.** The swarm generator actually exercises deep control-flow
   recovery (structured loops, goto fallback, conditionals) — so invariants 1–3
   are not vacuous (witness test in `proptest_swarm_decompiler.rs`).
6. **Reference agreement.** Disassembly, symbols, strings, SASS and demangling do
   not diverge from the system/reference oracle beyond documented thresholds
   (`tests/differential/`, `hexray-demangle` differential oracle).
7. **In-bounds slices.** Payload/section slices stay strictly inside the input
   buffer (asserted in the structure-aware fuzz targets).
8. **Incremental-cache soundness.** Modeled in TLA+ and kept in lockstep with the
   implementation (`specs/tla/IncrementalInvalidation.tla` + `scripts/check-tla`).

When you add a safety invariant, add its witness in the **same** change.

---

## Build, test, and the local tiered workflow

CI is **local-first** (no GitHub Actions). Hooks are installed via
`scripts/install-hooks.sh`.

```bash
scripts/ci-local --tier fast      # pre-commit: fmt + workspace check
scripts/ci-local --tier medium    # pre-push: + clippy + tests (+ strict callback)
scripts/ci-local --tier full      # exhaustive, release-quality
scripts/check-feature-matrix      # non-default arch/feature combos compile
scripts/check-fuzz-targets        # every fuzz target still compiles (don't let them rot)
scripts/check-tla                 # TLC model-check + Rust conformance
scripts/check-memory-safety       # targeted nightly miri gate
scripts/check-security            # cargo audit
scripts/quality-smoke             # cheap control-flow quality fail-fast
```

See `docs/TESTING.md` for the full map. Run the medium tier before pushing.

**ci-local is heavy — run it on a disposable aarch64 spot, not a laptop.** If it
is green you may `git push --no-verify`.

### Release gate (non-negotiable)

Cut a release only after a clean run on a **fresh aarch64 spot**:
`cargo test --workspace` **and** `cargo clippy --all-targets` must both be clean.
Then bump `[workspace.package]` version, add a CHANGELOG entry, tag, and
`gh release create --latest`. Terminate the spot afterward.

---

## How we work with agents here

- **Humans own the load-bearing parts** — data model, public interfaces, the
  invariants above, and the tests/properties that define "correct". Agents fill in
  the boxes against a fast, machine-checkable loop (types + proptests + differential
  + fuzz + the TLA conformance test).
- **Review loop:** before merge, run the codex review loop to **2 consecutive
  clean passes** (`codex exec review --base <branch>
  --dangerously-bypass-approvals-and-sandbox`), unless the user says otherwise.
- **Branch discipline:** never commit to `main` directly; never force-push or merge
  without the user. Work on a branch / worktree, push, open a PR.
- **Tests are a floor, not a ceiling:** "the tests pass" is not "the feature is
  good". Keep output quality (readability of the pseudo-C) in the loop.

### File-scope guardrails (don't change without the user asking)

- `specs/tla/*` and the incremental-invalidation conformance test — the model and
  code change together or not at all.
- Differential thresholds in `tests/differential/` and `docs/TESTING.md` — loosening
  a threshold hides a regression; tighten only with evidence.
- `fuzz/corpus/**` and `fuzz/artifacts/**` — committed seeds / reproducers; add, do
  not rewrite.
- The swarm density distribution / weights in `proptest_swarm_decompiler.rs` — they
  exist for a stated reason (reaching the pipeline tails); change only deliberately.
- Release/version mechanics in `[workspace.package]` and `CHANGELOG` — bump per the
  release gate above, not ad hoc.
