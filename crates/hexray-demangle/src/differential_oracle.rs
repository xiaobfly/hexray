//! Differential testing of hexray's own Itanium parser against the
//! `cpp_demangle` reference oracle (Bug Bash 2026 playbook, §5 / the Cedar
//! pattern).
//!
//! `cpp_demangle` is already a dependency: [`demangle`](super::demangle) uses it
//! as the primary path and only falls back to the bespoke [`demangle_itanium`]
//! parser when the reference is low-fidelity. That bespoke parser is where our
//! *own* bugs would live, so this module uses `cpp_demangle` as a reference
//! implementation and asserts the two never disagree about **which symbol** was
//! named.
//!
//! The two demanglers deliberately differ in *fidelity* (the fallback drops
//! return types, renders template args and qualifiers differently, etc.), so a
//! byte-for-byte diff would be a false-positive factory. Instead we compare a
//! formatting-robust projection — the **name path**: the `::`-separated sequence
//! of identifiers naming the function, with template arguments, parameters,
//! return type and trailing qualifiers stripped. A disagreement there (e.g. our
//! parser recovering `foo::baz` where the oracle says `foo::bar`) is a real bug
//! in one of the two implementations.
//!
//! We only assert when the projection is unambiguous for *both* sides and both
//! accept the symbol; cases where either side declines, or where a top-level
//! space makes the head ambiguous (a return type, or an `operator new`-style
//! name), are skipped rather than guessed at. That keeps the asserting tests
//! free of false positives; the full-output divergence report lives in the
//! `#[ignore]`d `report_name_path_divergences` for human triage.

use super::{demangle, demangle_itanium};
use cpp_demangle::{DemangleOptions, Symbol as CppSymbol};

/// Normalize a symbol to the canonical `_Z...` form the way [`super::demangle`]
/// does: accept a single leading underscore (Mach-O's `__Z...`).
fn normalize_itanium(name: &str) -> Option<&str> {
    if name.starts_with("_Z") {
        Some(name)
    } else if name.starts_with('_') && name[1..].starts_with("_Z") {
        Some(&name[1..])
    } else {
        None
    }
}

/// The reference oracle: `cpp_demangle` with return types suppressed, to match
/// the primary path in [`super::demangle`].
fn cpp_oracle(name: &str) -> Option<String> {
    let normalized = normalize_itanium(name)?;
    let symbol = CppSymbol::new(normalized).ok()?;
    let options = DemangleOptions::new().no_return_type();
    symbol.demangle_with_options(&options).ok()
}

/// Project a demangled name onto its **name path**: the `::`-separated
/// identifiers that name the function, with template args / parameters / return
/// type / qualifiers removed.
///
/// Returns `None` when the head is ambiguous (contains a top-level space — a
/// return type or an `operator`-with-space name) or malformed, so callers skip
/// rather than compare something meaningless.
fn name_path(demangled: &str) -> Option<Vec<String>> {
    // Drop ELF/Mach-O version and relocation suffixes: "...@GLIBCXX_3.4@plt".
    let s = demangled.split('@').next().unwrap_or(demangled);
    let s = s.trim();

    // Strip leading "[thunk, ...] " style annotation groups.
    let mut s = s;
    loop {
        s = s.trim_start();
        if let Some(rest) = s.strip_prefix('[') {
            let close = rest.find(']')?;
            s = &rest[close + 1..];
        } else {
            break;
        }
    }

    // Take the head: everything before the top-level '(' that opens the
    // parameter list. Depth tracks template `<...>` nesting.
    let mut depth = 0i32;
    let mut head_end = s.len();
    for (idx, ch) in s.char_indices() {
        match ch {
            '<' => depth += 1,
            '>' => depth -= 1,
            '(' if depth <= 0 => {
                head_end = idx;
                break;
            }
            _ => {}
        }
    }
    let head = s[..head_end].trim();
    if head.is_empty() {
        return None;
    }
    // A top-level space means a return type prefix or an operator name with a
    // space ("operator new") — ambiguous for path extraction, so decline.
    if has_top_level_space(head) {
        return None;
    }

    // Split on top-level "::" and strip each segment's template arguments and
    // GNU ABI tags.  The two demanglers disagree on ABI-tag *fidelity* — the
    // bespoke parser drops `[abi:...]` while cpp_demangle renders it — so the
    // projection normalizes it away rather than treating it as a name mismatch.
    let segments = split_top_level_scope(head);
    let mut path = Vec::with_capacity(segments.len());
    for seg in segments {
        let seg = strip_abi_tags(&seg);
        // Symbolic operator names (`operator<`, `operator<=`, `operator()`, …)
        // must be recognized BEFORE template stripping: `strip_template_args`
        // would read the `<` in `operator<` as a template opener and collapse
        // both `operator<` and `operator<=` to `operator`, masking a genuine
        // operator-name disagreement.  They are declined as ambiguous (matching
        // the projection's skip-when-unsure stance) rather than compared.
        if is_operator_function(seg) {
            return None;
        }
        let base = strip_template_args(seg);
        if base.is_empty() {
            return None;
        }
        path.push(base);
    }
    Some(path)
}

/// True when a segment is a C++ `operator` function name whose spelling cannot be
/// safely template-stripped — exactly `operator`, or `operator` immediately
/// followed by a non-identifier character (`operator<`, `operator<=`,
/// `operator()`, `operator[]`, `operator+`, `operator""_x`, …).  A normal
/// identifier that merely starts with "operator" (e.g. `operatorX`) is NOT
/// flagged, and space-bearing forms (`operator new`, `operator int`) are already
/// declined by `name_path`'s top-level-space check.
fn is_operator_function(segment: &str) -> bool {
    let Some(rest) = segment.strip_prefix("operator") else {
        return false;
    };
    match rest.chars().next() {
        None => true, // exactly "operator"
        Some(c) => !(c.is_ascii_alphanumeric() || c == '_'),
    }
}

fn has_top_level_space(s: &str) -> bool {
    let mut depth = 0i32;
    for ch in s.chars() {
        match ch {
            '<' => depth += 1,
            '>' => depth -= 1,
            ' ' if depth <= 0 => return true,
            _ => {}
        }
    }
    false
}

/// Split on `::` that appears at template depth 0.
fn split_top_level_scope(head: &str) -> Vec<String> {
    let bytes = head.as_bytes();
    let mut depth = 0i32;
    let mut segments = Vec::new();
    let mut start = 0usize;
    let mut i = 0usize;
    while i < bytes.len() {
        match bytes[i] {
            b'<' => depth += 1,
            b'>' => depth -= 1,
            b':' if depth <= 0 && i + 1 < bytes.len() && bytes[i + 1] == b':' => {
                segments.push(head[start..i].to_string());
                i += 2;
                start = i;
                continue;
            }
            _ => {}
        }
        i += 1;
    }
    segments.push(head[start..].to_string());
    segments
}

/// Remove trailing GNU ABI-tag groups (`[abi:...]`) from a segment, e.g.
/// `name[abi:cxx11]` → `name`, `name[abi:a][abi:b]` → `name`.  A `[` is only
/// treated as an ABI tag when it is balanced and closes at the segment end, so a
/// genuine `operator[]` (which `name_path` already declines via its top-level
/// space check for most shapes) or stray bracket does not silently truncate.
fn strip_abi_tags(segment: &str) -> &str {
    let mut s = segment.trim_end();
    while let Some(open) = s.rfind("[abi:") {
        // Everything from `open` must be a single `[...]` closing at the end.
        if s.ends_with(']') && !s[open + 1..s.len() - 1].contains('[') {
            s = s[..open].trim_end();
        } else {
            break;
        }
    }
    s
}

/// Remove a trailing top-level `<...>` template argument list from one segment.
fn strip_template_args(segment: &str) -> String {
    if let Some(open) = segment.find('<') {
        segment[..open].trim().to_string()
    } else {
        segment.trim().to_string()
    }
}

/// A curated corpus of real Itanium symbols whose name path is unambiguous.
/// Reused across the asserting tests.
fn corpus() -> Vec<&'static str> {
    vec![
        "_Z3foov",
        "_Z3bari",
        "_ZN3foo3barEv",
        "_ZN3std6vectorIiE4sizeEv",
        "_ZN5ClassC1Ev",
        "_ZN5ClassD1Ev",
        "_ZN3DogC2Ev",
        "_Z3fooPi",
        "_Z3fooRi",
        "_Z3fooOi",
        "_Z3fooKi",
        "_Z3barIiLi42EEvv",
        "_ZN3abc3def3ghiEv",
        "_ZNSt6vectorIiSaIiEE5emptyEv",
        "_Z14sum_with_throwRKSt6vectorIiSaIiEE",
        "__ZN3foo3barEv", // Mach-O leading underscore
                          // NOTE: legacy-Rust symbols (e.g. `_ZN3foo17h05af221e174051e9E`) are
                          // deliberately excluded: they share the `_ZN...E` shape but are *not*
                          // C++. hexray routes them to the Rust demangler (→ `foo`) while
                          // cpp_demangle mis-reads the `17h...` hash as a C++ namespace segment.
                          // That divergence is hexray being correct, not a bug, so it has no place
                          // in a C++ reference-oracle corpus.
    ]
}

#[test]
#[cfg_attr(miri, ignore)] // cpp_demangle is skipped under miri elsewhere in this crate; match that.
fn public_demangle_name_path_agrees_with_oracle() {
    let mut mismatches = Vec::new();
    for sym in corpus() {
        let (Some(ours), Some(theirs)) = (demangle(sym), cpp_oracle(sym)) else {
            continue;
        };
        let (Some(our_path), Some(their_path)) = (name_path(&ours), name_path(&theirs)) else {
            continue;
        };
        if our_path != their_path {
            mismatches.push(format!(
                "{sym}: hexray={ours:?} path={our_path:?} vs oracle={theirs:?} path={their_path:?}"
            ));
        }
    }
    assert!(
        mismatches.is_empty(),
        "public demangle() name-path diverged from cpp_demangle oracle:\n{}",
        mismatches.join("\n")
    );
}

#[test]
#[cfg_attr(miri, ignore)]
fn own_itanium_parser_name_path_agrees_with_oracle() {
    // Audit the *bespoke* Itanium parser directly (not the public path, which
    // prefers cpp_demangle), so divergences in our own code surface.
    let mut mismatches = Vec::new();
    for sym in corpus() {
        let Some(normalized) = normalize_itanium(sym) else {
            continue;
        };
        let (Some(ours), Some(theirs)) = (demangle_itanium(normalized), cpp_oracle(sym)) else {
            continue;
        };
        let (Some(our_path), Some(their_path)) = (name_path(&ours), name_path(&theirs)) else {
            continue;
        };
        if our_path != their_path {
            mismatches.push(format!(
                "{sym}: hexray-itanium={ours:?} path={our_path:?} \
                 vs oracle={theirs:?} path={their_path:?}"
            ));
        }
    }
    assert!(
        mismatches.is_empty(),
        "bespoke Itanium parser name-path diverged from cpp_demangle oracle:\n{}",
        mismatches.join("\n")
    );
}

// ---------------------------------------------------------------------------
// Property-based differential: generate valid Itanium nested names and assert
// the bespoke parser never contradicts the oracle about the name path.
// ---------------------------------------------------------------------------

use proptest::prelude::*;

/// A source-name identifier: lowercase ASCII, which is always valid length-
/// prefixed Itanium content.
fn arb_ident() -> impl Strategy<Value = String> {
    proptest::collection::vec(prop::sample::select(&b"abcdefghijklmnop"[..]), 1..=8)
        .prop_map(|chars| chars.into_iter().map(|c| c as char).collect())
}

/// A trailing builtin return/parameter type code the parser understands.
fn arb_type_code() -> impl Strategy<Value = &'static str> {
    prop::sample::select(vec!["v", "i", "l", "c", "f", "d", "b", "Pi", "Ri", "Ki"])
}

/// Build a valid `_ZN<seg>+E<type>` nested-name mangling from parts.
fn arb_mangled_nested_name() -> impl Strategy<Value = String> {
    (
        proptest::collection::vec(arb_ident(), 1..=4),
        arb_type_code(),
    )
        .prop_map(|(segments, ty)| {
            let mut out = String::from("_ZN");
            for seg in &segments {
                out.push_str(&seg.len().to_string());
                out.push_str(seg);
            }
            out.push('E');
            out.push_str(ty);
            out
        })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    /// On well-formed nested names that both demanglers accept, the bespoke
    /// parser must recover the same name path as the oracle. This is the core
    /// §5 differential property on valid input.
    #[test]
    #[cfg_attr(miri, ignore)]
    fn generated_nested_names_agree_on_name_path(sym in arb_mangled_nested_name()) {
        if let (Some(ours), Some(theirs)) = (demangle_itanium(&sym), cpp_oracle(&sym)) {
            if let (Some(our_path), Some(their_path)) = (name_path(&ours), name_path(&theirs)) {
                prop_assert_eq!(
                    &our_path, &their_path,
                    "name-path divergence for {}: hexray={:?} oracle={:?}",
                    sym, ours, theirs
                );
            }
        }
    }

    /// Fuzz-style safety: on arbitrary bytes rendered as a `_Z`-prefixed ASCII
    /// string, neither demangler may panic, and when both accept they must not
    /// contradict each other about the name path.
    #[test]
    #[cfg_attr(miri, ignore)]
    fn arbitrary_symbols_never_contradict_oracle(body in "[A-Za-z0-9_]{0,64}") {
        let sym = format!("_Z{body}");
        let ours = demangle_itanium(&sym);   // must not panic
        let theirs = cpp_oracle(&sym);        // must not panic
        if let (Some(o), Some(t)) = (ours, theirs) {
            if let (Some(op), Some(tp)) = (name_path(&o), name_path(&t)) {
                prop_assert_eq!(
                    &op, &tp,
                    "name-path contradiction for {}: hexray={:?} oracle={:?}",
                    sym, o, t
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Informational divergence report (not a correctness gate).
// ---------------------------------------------------------------------------

/// Print every corpus symbol where the *full* public demangling differs from the
/// oracle's full demangling (formatting and fidelity differences included). Run
/// with `cargo test -p hexray-demangle -- --ignored report_name_path`.
#[test]
#[ignore]
fn report_name_path_divergences() {
    println!("\n=== demangle() vs cpp_demangle full-output divergences ===");
    for sym in corpus() {
        let ours = demangle(sym);
        let theirs = cpp_oracle(sym);
        if ours.as_deref() != theirs.as_deref() {
            println!("  {sym}\n    hexray: {ours:?}\n    oracle: {theirs:?}");
        }
    }
}

#[cfg(test)]
mod unit {
    use super::*;

    #[test]
    fn name_path_strips_params_templates_and_suffixes() {
        assert_eq!(name_path("foo()"), Some(vec!["foo".to_string()]));
        assert_eq!(
            name_path("foo::bar(int, int)"),
            Some(vec!["foo".to_string(), "bar".to_string()])
        );
        assert_eq!(
            name_path("std::vector<int>::size()"),
            Some(vec![
                "std".to_string(),
                "vector".to_string(),
                "size".to_string()
            ])
        );
        assert_eq!(
            name_path("std::foo()@GLIBCXX_3.4@plt"),
            Some(vec!["std".to_string(), "foo".to_string()])
        );
    }

    #[test]
    fn name_path_declines_ambiguous_heads() {
        // Return-type prefix or operator-with-space → declined (top-level space).
        assert_eq!(name_path("int foo(int)"), None);
        assert_eq!(name_path("operator new(unsigned long)"), None);
    }

    #[test]
    fn name_path_strips_abi_tags() {
        // GNU ABI tags differ in fidelity between the two demanglers; the
        // projection must drop them so both sides compare equal.
        assert_eq!(name_path("foo[abi:cxx11]()"), Some(vec!["foo".to_string()]));
        assert_eq!(
            name_path("ns::bar[abi:a][abi:b](int)"),
            Some(vec!["ns".to_string(), "bar".to_string()])
        );
        // The exact counterexample codex found (seed 3).
        assert_eq!(
            name_path("Aa0AAA_[abi:_A_00a_AA_AAa0_AAAA0A_0AAaaA0a]"),
            Some(vec!["Aa0AAA_".to_string()])
        );
    }

    #[test]
    fn name_path_declines_symbolic_operators() {
        // `<` in the operator spelling must NOT be read as a template opener;
        // these are declined so `operator<` vs `operator<=` can never be
        // silently equated.
        assert_eq!(name_path("operator<(int)"), None);
        assert_eq!(name_path("operator<=(int)"), None);
        assert_eq!(name_path("ns::operator==(int)"), None);
        assert_eq!(name_path("operator()(int)"), None);
        assert_eq!(name_path("operator[](int)"), None);
        // A normal identifier that merely starts with "operator" is unaffected.
        assert_eq!(
            name_path("operatorX(int)"),
            Some(vec!["operatorX".to_string()])
        );
    }

    #[test]
    fn name_path_does_not_split_inside_template_args() {
        assert_eq!(
            name_path("a::b<c::d>::e()"),
            Some(vec!["a".to_string(), "b".to_string(), "e".to_string()])
        );
    }
}
