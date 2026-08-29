# Handoff — C++ try/catch catch-body recovery (LSDA gap B)

> Task #29 "LSDA gap B". Branch `feat/eh-unwind-edges-catch-bodies`, **not merged**.
> This documents a working-but-not-merge-ready feature and the exact decision blocking merge.

## TL;DR

The branch recovers C++ `try/catch` **including populated catch handler bodies**
from LSDA/`.gcc_except_table` info — previously catch clauses were dropped
entirely (a typed try/catch decompiled to just the bare `if/else` of the try
body). It works correctly for the **common case** (single typed catch, `-O0`).
A codex review found **4 P1 (correctness) + 2 P2** issues in the general case.
One of them (**P1-4, over-broad try scope**) has **no clean gate** — see
"The blocker" below. The owner chose to keep this a WIP handoff rather than
push the full fix now.

## Repo / process facts (read first)

- Repo: `/home/ubuntu/src/hexray` (Rust decompiler workspace).
- Branch: `feat/eh-unwind-edges-catch-bodies`, HEAD `4199f054d` (single squashed
  commit). Base `main` = `96401aa77`. **Nothing merged to main.**
- Commit identity is NOT configured. Commit as:
  `git -c user.name="Isaiah Weiner" -c user.email="zoratu@zoratu.com" commit --author="Isaiah Weiner <zoratu@zoratu.com>" ...`
- Merge workflow for this project: codex-review loop to **2 consecutive clean
  passes**, then a **RELEASE gate on a fresh aarch64 EC2 spot**
  (`cargo test --workspace` + `cargo clippy --all-targets`), then `--no-ff`
  merge, then push `--no-verify`. Spot tooling in `~/src/spot` (`./spot.py`).
- Codex review: `codex exec review --base main --dangerously-bypass-approvals-and-sandbox`
  (auth via ChatGPT). **Quirk:** this codex CLI (v0.145) does NOT print a
  "tokens used" completion marker. Detect completion by: the `codex exec review`
  process is gone (`pgrep -af "codex exec review"`) and the log stops growing.
  Findings appear under `Full review comments:` as `- [P1]/[P2] ...` lines.
- `cargo fmt` is NOT run (main is not rustfmt-clean); hand-format new code, do
  not whole-file-format.

## What works today (demonstrated)

Build the fixture (dev box is aarch64 — use the x86_64 cross compiler):
```
SC=<scratchpad>   # any tmp dir
cat > $SC/catch.cpp <<'EOF'
#include <stdexcept>
int g;
int handle_catch() {
    try { if (g) throw std::runtime_error("x"); return 1; }
    catch (const std::runtime_error& e) { g = 42; return -1; }
}
int rethrow_catch() { try { return g; } catch (...) { g = 7; throw; } }
EOF
x86_64-linux-gnu-g++-13 -std=c++17 -O0 -c $SC/catch.cpp -o $SC/catch_O0.o
cargo run -q -p hexray --bin hexray -- $SC/catch_O0.o decompile handle_catch
```
`handle_catch` now emits (was: just the `if/else`, catch dropped):
```c
try {
    if (ret == 0) { err = 1; return 1; }
    else { throw std::runtime_error(data_120); }
}
catch (type@0x148& e) {
    saved1 = ret; result = rdx; rdx = result;   // residual dead bookkeeping
    *(uint32_t*)(&g_ptr_f9) = 42;   // g = 42   <- real handler recovered
    err = -1;
    return err;
}
```
Full workspace test suite is green. Non-EH functions and simple throw-only
functions (`throw 42`, `throw std::runtime_error("x")`) are unchanged.

## Architecture (how it works)

Codex validated this overall shape ("keep the separate EH edge channel; do
block-id assembly, not address-overlap"). Pipeline, in order:

1. **CFG unwind-edge channel** — `crates/hexray-core/src/cfg.rs`.
   `ControlFlowGraph` gains `eh_successors`/`eh_predecessors` (kept OUT of the
   normal `successors()`/`predecessors()` so dominators/loops/RPO/structuring
   are provably unaffected). API: `add_eh_edge`, `eh_successors`,
   `eh_predecessors`, `is_landing_pad`, `has_eh_edges` (cfg.rs:~28,67,80,97,102).
   `ControlFlowGraph` is now `Clone`. Unit tests in cfg.rs `mod tests`.

2. **Populate edges from LSDA** — `augment_cfg_with_eh_edges`
   (`decompiler/mod.rs:2811`). Clones the CFG and adds an unwind edge from every
   block whose span OVERLAPS a protected range (try block or cleanup range) to
   that range's landing-pad block. Called in
   `structure_with_coroutine_targets` (mod.rs `structure()` path) gated on
   `self.exception_info.is_some()`, so non-EH functions never even clone.

3. **Structure landing pads as bounded sub-regions** — `Structurer::structure`
   (`decompiler/structurer/mod.rs:1813`). After structuring the entry region,
   for each `is_landing_pad` block it runs `structure_region(lp)` (the main
   region ran first, so this stops at the already-processed continuation with a
   goto/return, bounding the handler to its own blocks), stores the result in
   `self.landing_pad_bodies: HashMap<BasicBlockId, Vec<StructuredNode>>` keyed by
   landing-pad block id, and marks those blocks processed so the generic
   fallback skips them. Gated on `cfg.has_eh_edges()`.
   Cleanup-pad suppression (`detect_cleanup_side_blocks`) is gated OFF when
   `has_eh_edges()` (structurer/mod.rs:235) — the new path handles all landing
   pads (catch AND cleanup).

4. **Assemble TryCatch by block id** — `apply_exception_handling`
   (`decompiler/mod.rs:2847`), called from `from_cfg...` at
   structurer/mod.rs:511 — **after** call-arg propagation but **before**
   `simplify_statements` (whose first step `merge_adjacent_blocks` flattens
   single-statement blocks into `Expr` nodes, dropping the block ids/ranges the
   assembly joins on). For each try block, the protected block-id set =
   blocks whose span overlaps the LSDA try range. A top-level body node belongs
   to a try if any block it contains (`collect_block_ids`, mod.rs:2961) is
   protected; consecutive protected nodes are absorbed into the try body; catch
   handler bodies are attached from `landing_pad_bodies` via `build_catch_handlers`
   (mod.rs:2918). Cleanup-only functions and cleanup entries are NOT rendered as
   catch. `simplify_node_copies` (simplify.rs:659) was given a `TryCatch` arm so
   the wrapped try body is still copy-propagated (its `__cxa_throw` triple then
   collapses via the existing throw-collapse pass).

5. **Strip landing-pad scaffolding** — Step 3b in `decompile`
   (`decompiler/mod.rs:1488`, fn `strip_exception_scaffolding` mod.rs:3105).
   Runs in the decompile pass because it needs call-target name resolution
   (reuses the same reloc/symbol resolve closure as the throw-collapse Step 3a).
   Drops `__cxa_begin_catch`/`__cxa_end_catch`/`__cxa_free_exception`/
   `__cxa_get_exception_ptr`/`_Unwind_Resume` runtime calls (and blocks left
   empty by that), and unwraps the redundant type-selector
   `if (<reg> == N) { handler }` (gated on a raw-register-vs-int condition via
   `is_selector_condition` mod.rs:3082 / `is_raw_register_name` mod.rs:3042).

Removed the old fragile address-overlap post-pass (`wrap_cleanup_regions` and
`get_node_address_range` are gone). Net ~-130 LOC vs the old approach.

Tests added: cfg.rs eh-edge channel tests; mod.rs
`test_apply_exception_handling_wraps_try_by_protected_block_id`,
`test_apply_exception_handling_leaves_cleanup_only_unchanged`,
`strip_exception_scaffolding_cleans_catch_body` (mod.rs:3826).

## Codex review round 1 findings (in `/tmp/cx_eh_1.log`, lines ~8525+)

4 × P1 (correctness), 2 × P2. All legitimate.

- **P1-1 Shared landing pad drops catches** (mod.rs `build_catch_handlers`,
  dedup by `landing_pad`). `catch(A) catch(B) catch(...)` share ONE landing pad
  in Itanium LSDA; dedup keeps only the first, losing the rest.
  → **Gateable**: decline reconstruction when a try has >1 renderable
  (non-cleanup) handler; the proper fix is to split the shared landing pad by
  selector value into separate `catch` clauses.

- **P1-2 Catch-body call args lost** (structurer/mod.rs:511 region). Handler
  bodies live in `landing_pad_bodies` until attached at assembly, which is AFTER
  the two `CallArgPropagation` passes — so `catch(...){ sink(x+7); }` emits
  `sink()`. → Fix: run the propagation prepasses on `landing_pad_bodies` before
  attaching, or attach before propagation.

- **P1-3 Caught-object value dropped** (mod.rs:3258, in `drop_scaffolding_calls`
  / `statement_call_name`). Scaffolding-strip removes `e = __cxa_begin_catch()`
  / `__cxa_get_exception_ptr()` even when `e` is USED, so `catch(E& e){ e.field }`
  breaks. → **Bounded fix**: only strip these when the captured value is unused;
  otherwise keep the assignment (and ideally rewrite uses to the catch variable).

- **P1-4 Over-broad try scope** (mod.rs:2881-2884). The any-intersection test
  assigns a WHOLE top-level compound node (`If`/`Switch`/loop) to the try body
  when only one arm contains a protected block, e.g.
  `if(x){ try{foo} catch{} } else { bar }` puts `bar` inside the try.
  → **THE BLOCKER — see below.** Proper fix: descend into / split compound nodes
  along protected block ids.

- **P2-5 Nested try in catch body** not reconstructed (`build_catch_handlers`
  clones handler body unchanged; nested `TryBlockInfo` never consumed).
  → Recursively apply EH reconstruction to catch bodies.

- **P2-6 Selector registers x86-only** (`is_raw_register_name`). Non-x86 targets
  hold the selector in e.g. AArch64 `x1` / RISC-V `a1`; the selector-`if` is then
  not unwrapped. → Safe to leave (not wrong, just less clean); make arch-aware.

## The blocker (P1-4 has no clean gate)

The demonstrated working case is **structurally identical** to the P1-4 bug:
- `handle_catch`: `[entry, If{then: return 1, else: throw}]` — protected block
  (throw) in one arm; wrapping the whole `If` is CORRECT (the whole if/else is
  the try body in source).
- bug: `if(x){ try{foo} catch{} } else { bar }` — protected block (foo) in one
  arm; wrapping the whole `If` is WRONG (`bar` isn't in the try).

Both are "an `If` with a protected block in one arm." The only difference is
whether the *sibling* arm is lexically inside the try, and that is **not
recoverable from the LSDA's per-call-site protected ranges** (`return 1` sits
just past the last protected call-site range at the boundary). So any block-id/
address gate that rejects the bug also rejects the working case. Therefore
"gate to the provably-correct subset" (the chosen plan B) cannot deliver P1-4 —
it needs the real structural fix (descend/split compound nodes).

## Three ways forward

- **A — Full fix (matches project's codex-clean bar).** Implement: (P1-4)
  descend/split compound nodes along protected block ids so only the protected
  sub-region is wrapped; (P1-1) split shared landing pad by selector into
  multiple `catch` clauses; (P1-2) propagate through landing-pad bodies;
  (P1-3) preserve used caught-object values; (P2-5) recurse into catch bodies;
  (P2-6) arch-aware selector registers. Substantial, multi-cycle. Then codex
  loop → spot-gate → merge.

- **B (partial) — accept P1-4 as a documented over-approximation** (it only
  widens try scope in the uncommon "try nested inside a conditional branch"
  shape; never drops code or crashes), do the bounded fixes (P1-3, gate P1-1,
  arch P2-6), and merge below the usual codex-clean bar. Note: codex will keep
  flagging P1-4/P1-2 each round, so "2 consecutive clean passes" is unreachable
  without either fixing them or a human accepting the limitations.

- **C — Shelve as experimental WIP** (current state). Nothing merged; branch is
  a clean single squashed commit. Revisit as a dedicated project.

Owner leaning at handoff time: **C** (or A if catch-body recovery becomes a
priority). B is a poor fit because the codex-clean merge bar can't be met while
P1-4 is unfixed.

## Deferred / not started (separate efforts, documented in commit body)

- **RTTI catch-type names** (`type@0x148` → `std::runtime_error`). Investigated:
  the typeinfo lives in a `.gcc_except_table` relocation OUTSIDE the decompiler's
  `.text` relocation table, so it needs LSDA type-table relocation resolution
  (a "gap-A-style" effort in `exception_handling.rs` / `dwarf/lsda.rs`), not an
  emitter-side fix.
- Residual dead register bookkeeping in catch bodies (e.g. `saved1 = ret;`).
- try/catch-function return type can regress to `void`.
- **rethrow** (`throw;`) — `rethrow_catch` fixture still doesn't recover it.

## Key files & entry points

- `crates/hexray-core/src/cfg.rs` — EH edge channel + tests.
- `crates/hexray-analysis/src/decompiler/mod.rs` — `augment_cfg_with_eh_edges`
  (2811), `apply_exception_handling` (2847), `build_catch_handlers` (2918),
  `collect_block_ids` (2961), scaffolding strip fns (3042-3320), Step 3b wiring
  (1488), tests (~3760-3900). `ExceptionInfo`/`TryBlockInfo`/`CatchInfo`/
  `CleanupInfo` structs (~78-116). `RelocationTable`/`SymbolTable` `get`/`get_data`.
- `crates/hexray-analysis/src/decompiler/structurer/mod.rs` — `structure()`
  landing-pad loop (1813), assembly call + gate (505-520), cleanup-suppression
  gate (235), `StructuredCfg`/`Structurer.landing_pad_bodies` fields.
- `crates/hexray-analysis/src/decompiler/structurer/simplify.rs` —
  `simplify_node_copies` TryCatch arm (659); `merge_adjacent_blocks` inside
  `simplify_statements` (518) is the flattener the assembly must run before.
- `crates/hexray-analysis/src/exception_handling.rs` — LSDA → `ExceptionInfo`
  (`convert_exception_info`, `get_catch_type_name` — the `type@0xNNN` fallback).

## Commands

```
# build + smoke test one function
cargo run -q -p hexray --bin hexray -- <file.o> decompile <fn>

# targeted tests
cargo test -q -p hexray-core -p hexray-analysis
cargo test -q -p hexray-analysis -- apply_exception_handling strip_exception_scaffolding

# codex review (detect completion via process-gone, NOT a marker)
codex exec review --base main --dangerously-bypass-approvals-and-sandbox

# x86_64 EH fixtures on this aarch64 dev box
x86_64-linux-gnu-g++-13 -std=c++17 -O0 -c foo.cpp -o foo_O0.o
```

Good luck. Start by re-reading `apply_exception_handling` (mod.rs:2847) and the
P1-4 analysis above before touching anything.
