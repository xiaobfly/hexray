//! The shared per-function analysis entry point.
//!
//! `hexray <binary> decompile` and `hexray db query decompile` must produce the
//! same pseudo-C, so neither owns the pipeline: both build an
//! [`AnalysisInputs`], call [`analyze_function`] (or [`analyze_replay`] when the
//! instructions and CFG already exist in a database) and then
//! [`render_function`].
//!
//! The split matters for persistence:
//! - analysis produces the instructions, CFG, signature and diagnostics that a
//!   database stores;
//! - rendering produces text for one canonical [`RenderConfig`], and is the
//!   only step that needs a `DecompilerConfig`.
//!
//! Nothing here prints. The CLI decides what to show, and the database decides
//! what to keep.

use std::sync::Arc;

use anyhow::{bail, Result};
use hexray_analysis::{
    CfgBuilder, Decompiler, DecompilerConfig, FunctionSignature, OptimizationLevel,
    OptimizationPass, VariableOverride,
};
use hexray_core::{ControlFlowGraph, Instruction, SymbolKind};
use hexray_formats::{BinaryFormat, BinaryType};
use hexray_types::TypeDatabase;

use crate::{
    build_binary_data_context, build_relocation_table, build_string_table, build_symbol_table,
    build_tls_access_targets, build_tls_slot_map, build_tls_symbol_offset_map,
    collect_noreturn_call_sites, collect_throw_thunks, default_calling_convention,
    disassemble_function_for_cfg, get_dwarf_function_names,
    seed_direct_callee_signature_hints, seed_resolved_call_target_names,
    apply_instruction_relocations, rewrite_tls_memory_operands, Binary,
    DirectCalleeSignatureSeedContext, DwarfFunctionNames, AnalysisProject,
};

/// Severity of a pipeline diagnostic, mirroring the stored model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DiagnosticSeverity {
    Info,
    Warning,
    Error,
}

impl PipelineDiagnostic {
    /// Convert to the stored representation.
    pub(crate) fn to_stored(&self) -> hexray_db::Diagnostic {
        hexray_db::Diagnostic {
            code: self.code.to_string(),
            severity: match self.severity {
                DiagnosticSeverity::Info => hexray_db::Severity::Info,
                DiagnosticSeverity::Warning => hexray_db::Severity::Warning,
                DiagnosticSeverity::Error => hexray_db::Severity::Error,
            },
            message: self.message.clone(),
            address: self.address.map(hexray_db::Address),
        }
    }
}

/// One diagnostic emitted while analyzing a function.
#[derive(Debug, Clone)]
pub(crate) struct PipelineDiagnostic {
    pub code: &'static str,
    pub severity: DiagnosticSeverity,
    pub message: String,
    pub address: Option<u64>,
}

impl PipelineDiagnostic {
    fn new(code: &'static str, severity: DiagnosticSeverity, message: impl Into<String>) -> Self {
        Self {
            code,
            severity,
            message: message.into(),
            address: None,
        }
    }

    fn info(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(code, DiagnosticSeverity::Info, message)
    }

    fn at(mut self, address: u64) -> Self {
        self.address = Some(address);
        self
    }
}

/// Comments to weave into the emitted pseudo-C.
#[derive(Debug, Clone, Default)]
pub(crate) struct CommentOverlay {
    entries: Vec<(u64, String)>,
}

impl CommentOverlay {
    /// Build from an `AnalysisProject` (the CLI path).
    pub(crate) fn from_project(project: Option<&AnalysisProject>) -> Self {
        let Some(project) = project else {
            return Self::default();
        };
        let mut entries: Vec<(u64, String)> = project
            .annotated_addresses()
            .filter_map(|address| {
                project
                    .get_comment(address)
                    .map(|comment| (address, comment.to_string()))
            })
            .collect();
        entries.sort_by_key(|(address, _)| *address);
        Self { entries }
    }

    /// Build from explicit pairs (the database path).
    pub(crate) fn from_pairs(mut entries: Vec<(u64, String)>) -> Self {
        entries.sort_by_key(|(address, _)| *address);
        Self { entries }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// What the caller wants analyzed.
#[derive(Debug, Clone)]
pub(crate) struct FunctionRequest {
    /// Symbol name or `0x`-prefixed address text.
    pub target: String,
    /// User name for the function, when the caller already resolved one.
    #[allow(dead_code)]
    pub name_override: Option<String>,
}

impl FunctionRequest {
    pub(crate) fn new(target: impl Into<String>) -> Self {
        Self {
            target: target.into(),
            name_override: None,
        }
    }
}

/// Everything analysis reads besides the binary itself.
pub(crate) struct AnalysisInputs<'a> {
    pub project: Option<&'a AnalysisProject>,
    pub type_db: Option<&'a Arc<TypeDatabase>>,
    pub config: Option<&'a DecompilerConfig>,
    pub diagnostics: bool,
    /// DWARF resolved by the caller: a file on disk for the CLI, an embedded
    /// resource for a reopened database.
    pub debug_info: Option<&'a hexray_formats::dwarf::DebugInfo>,
    /// Explicit user signature, taking priority over recovery.
    pub signature_override: Option<&'a FunctionSignature>,
    pub variable_overrides: &'a [VariableOverride],
    /// User names by address, applied on top of the loader symbol table.
    pub names: &'a [(u64, String)],
}

/// Options for turning an analyzed function into pseudo-C.
#[derive(Debug, Clone, Default)]
pub(crate) struct RenderOptions {
    pub show_addresses: bool,
    pub comments: Option<CommentOverlay>,
}

/// The result of analysis: everything a database needs to store the function.
pub(crate) struct AnalyzedFunction {
    pub start: u64,
    pub name: String,
    pub instructions: Vec<Instruction>,
    pub cfg: ControlFlowGraph,
    pub diagnostics: Vec<PipelineDiagnostic>,
    /// Fully configured decompiler, ready to render.
    decompiler: Decompiler,
}

/// The result of rendering.
pub(crate) struct RenderedFunction {
    pub text: String,
}

/// Persisted analysis replayed instead of re-disassembling.
pub(crate) struct ReplayInput {
    pub start: u64,
    pub name: String,
    pub symbol_kind: Option<SymbolKind>,
    pub instructions: Vec<Instruction>,
    pub cfg: ControlFlowGraph,
    /// Address bound the original analysis used, for diagnostics only.
    pub max_bytes: usize,
    pub stop_after_first_return: bool,
}

/// Analyze a function by resolving `request.target` in `binary`.
pub(crate) fn analyze_function(
    binary: &Binary<'_>,
    request: &FunctionRequest,
    inputs: &AnalysisInputs<'_>,
) -> Result<AnalyzedFunction> {
    let fmt = binary.as_format();
    let relocation_table = build_relocation_table(binary);
    let info = crate::resolve_decompile_target_info(
        fmt,
        inputs.project,
        &request.target,
        &relocation_table,
    )
    .map_err(|_| {
        anyhow::anyhow!(
            "Symbol '{}' not found. It may be an external/undefined symbol (e.g., from a shared library).",
            request.target
        )
    })?;

    if info.start_addr == 0 {
        bail!("Invalid address 0x0 - symbol may be undefined or external");
    }
    if !is_executable_address(fmt, info.start_addr) {
        bail!(
            "Address {:#x} is not in an executable section - cannot decompile data",
            info.start_addr
        );
    }

    let name = request
        .name_override
        .clone()
        .unwrap_or_else(|| info.name.clone());
    let mut instructions = disassemble_function_for_cfg(
        fmt,
        info.start_addr,
        info.max_bytes,
        info.stop_after_first_return,
    )?;
    apply_instruction_relocations(&mut instructions, &relocation_table);

    build_from_instructions(
        binary,
        info.start_addr,
        name,
        info.symbol_kind,
        info.max_bytes,
        info.stop_after_first_return,
        instructions,
        &relocation_table,
        inputs,
    )
}

/// Analyze a function whose entry address is already known.
///
/// Used by whole-image analysis, where the function was discovered from a call
/// target rather than resolved by name.
pub(crate) fn analyze_address(
    binary: &Binary<'_>,
    start: u64,
    name: String,
    symbol_kind: Option<SymbolKind>,
    max_bytes: usize,
    stop_after_first_return: bool,
    inputs: &AnalysisInputs<'_>,
) -> Result<AnalyzedFunction> {
    let fmt = binary.as_format();
    if start == 0 {
        bail!("Invalid address 0x0 - symbol may be undefined or external");
    }
    if !is_executable_address(fmt, start) {
        bail!(
            "Address {:#x} is not in an executable section - cannot decompile data",
            start
        );
    }
    let relocation_table = build_relocation_table(binary);
    let mut instructions =
        disassemble_function_for_cfg(fmt, start, max_bytes, stop_after_first_return)?;
    apply_instruction_relocations(&mut instructions, &relocation_table);
    build_from_instructions(
        binary,
        start,
        name,
        symbol_kind,
        max_bytes,
        stop_after_first_return,
        instructions,
        &relocation_table,
        inputs,
    )
}

/// Analyze a function whose instructions and CFG were persisted earlier.
///
/// Only the context tables are rebuilt from the binary; no instruction is
/// re-decoded, so a patch that invalidated the CFG cannot silently produce a
/// half-new result.
pub(crate) fn analyze_replay(
    binary: &Binary<'_>,
    replay: ReplayInput,
    inputs: &AnalysisInputs<'_>,
) -> Result<AnalyzedFunction> {
    let relocation_table = build_relocation_table(binary);
    build_from_instructions_with_cfg(
        binary,
        replay.start,
        replay.name,
        replay.symbol_kind,
        replay.max_bytes,
        replay.stop_after_first_return,
        replay.instructions,
        Some(replay.cfg),
        &relocation_table,
        inputs,
    )
}

/// Render an analyzed function to pseudo-C.
pub(crate) fn render_function(
    analyzed: AnalyzedFunction,
    options: &RenderOptions,
) -> Result<RenderedFunction> {
    let analyzed = analyzed;
    let decompiler = analyzed.decompiler.with_addresses(options.show_addresses);
    let pseudocode = decompiler.decompile(&analyzed.cfg, &analyzed.name);
    let text = apply_comment_overlay(
        pseudocode,
        options.comments.as_ref(),
        options.show_addresses,
    );
    Ok(RenderedFunction {
        text: ensure_nonempty_pseudocode(text),
    })
}

fn is_executable_address(fmt: &dyn BinaryFormat, address: u64) -> bool {
    fmt.sections().any(|section| {
        let start = section.virtual_address();
        let end = start.saturating_add(section.size());
        address >= start && address < end && section.is_executable()
    })
}

#[allow(clippy::too_many_arguments)]
fn build_from_instructions(
    binary: &Binary<'_>,
    start: u64,
    name: String,
    symbol_kind: Option<SymbolKind>,
    max_bytes: usize,
    stop_after_first_return: bool,
    instructions: Vec<Instruction>,
    relocation_table: &hexray_analysis::RelocationTable,
    inputs: &AnalysisInputs<'_>,
) -> Result<AnalyzedFunction> {
    build_from_instructions_with_cfg(
        binary,
        start,
        name,
        symbol_kind,
        max_bytes,
        stop_after_first_return,
        instructions,
        None,
        relocation_table,
        inputs,
    )
}

#[allow(clippy::too_many_arguments)]
fn build_from_instructions_with_cfg(
    binary: &Binary<'_>,
    start: u64,
    name: String,
    symbol_kind: Option<SymbolKind>,
    max_bytes: usize,
    stop_after_first_return: bool,
    instructions: Vec<Instruction>,
    replay_cfg: Option<ControlFlowGraph>,
    relocation_table: &hexray_analysis::RelocationTable,
    inputs: &AnalysisInputs<'_>,
) -> Result<AnalyzedFunction> {
    let fmt = binary.as_format();
    let mut diagnostics = Vec::new();
    let arch = fmt.architecture();

    let tls_access_targets = build_tls_access_targets(binary);
    let tls_symbol_offsets = build_tls_symbol_offset_map(binary);
    let tls_slot_map = build_tls_slot_map(binary);

    let instructions = match replay_cfg {
        Some(_) => instructions,
        None => {
            let mut instructions = instructions;
            rewrite_tls_memory_operands(&mut instructions, &tls_access_targets, &tls_slot_map);
            instructions
        }
    };

    // User names win over loader symbols.
    let mut symbol_table = build_symbol_table(binary);
    // User names win over loader symbols, then the project overlay (the CLI
    // path) wins over both.
    for (address, name) in inputs.names {
        symbol_table.insert(*address, name.clone());
    }
    if let Some(project) = inputs.project {
        for address in project.overridden_functions() {
            if let Some(name) = project.get_function_name(address) {
                symbol_table.insert(address, name.to_string());
            }
        }
    }
    let throw_thunks = collect_throw_thunks(binary, &symbol_table, relocation_table);

    let dwarf_names = match inputs.debug_info {
        Some(debug_info) => get_dwarf_function_names(debug_info, start, binary),
        None => {
            diagnostics.push(PipelineDiagnostic::info(
                "no-debug-info",
                "no DWARF information available for this function",
            ));
            DwarfFunctionNames::default()
        }
    };

    let const_db = Arc::new(hexray_types::ConstantDatabase::with_builtins());
    let calling_convention = default_calling_convention(
        match binary {
            Binary::Elf(_) => BinaryType::Elf,
            Binary::MachO(_) => BinaryType::MachO,
            Binary::Pe(_) => BinaryType::Pe,
        },
        arch,
    );
    let pointer_size = match fmt.bitness() {
        hexray_core::Bitness::Bits32 => 4usize,
        hexray_core::Bitness::Bits64 => 8usize,
    };

    let mut binary_data_ctx = build_binary_data_context(fmt);
    seed_resolved_call_target_names(&mut binary_data_ctx, &symbol_table, relocation_table);
    let seed_ctx = DirectCalleeSignatureSeedContext {
        relocation_table,
        symbol_table: &symbol_table,
        calling_convention,
        tls_access_targets: &tls_access_targets,
        tls_slot_map: &tls_slot_map,
    };
    let cfg = match replay_cfg {
        Some(cfg) => cfg,
        None => {
            seed_direct_callee_signature_hints(
                binary,
                &instructions,
                &mut binary_data_ctx,
                &seed_ctx,
            );
            let noreturn_call_sites =
                collect_noreturn_call_sites(&instructions, fmt, relocation_table);
            CfgBuilder::build_with_binary_context_and_noreturn_calls(
                &instructions,
                start,
                &binary_data_ctx,
                &noreturn_call_sites,
            )
        }
    };

    let string_table = build_string_table(fmt);
    let mut decompiler = Decompiler::new()
        .with_addresses(true)
        .with_string_table(string_table)
        .with_symbol_table(symbol_table)
        .with_relocation_table(relocation_table.clone())
        .with_tls_symbol_offsets(tls_symbol_offsets)
        .with_throw_thunks(throw_thunks)
        .with_current_function_kind(symbol_kind)
        .with_binary_data(binary_data_ctx)
        .with_dwarf_names(dwarf_names.stack_names)
        .with_dwarf_param_names(dwarf_names.parameter_names)
        .with_dwarf_scope_ranges(dwarf_names.local_scope_ranges)
        .with_constant_database(const_db)
        .with_struct_inference(true)
        .with_calling_convention(calling_convention)
        .with_pointer_size(pointer_size);

    decompiler = decompiler.analyze_cpp_special(&cfg, &instructions, Some(&name));
    if let Some(info) = binary.exception_info_for_function(start, start, relocation_table) {
        decompiler = decompiler.with_exception_info(info);
    }
    if let Some(db) = inputs.type_db {
        decompiler = decompiler.with_type_database(db.clone());
    }
    if let Some(config) = inputs.config {
        decompiler = decompiler.with_config(config.clone());
    }
    if let Some(signature) = inputs.signature_override {
        decompiler = decompiler.with_signature_override(signature.clone());
    }
    if !inputs.variable_overrides.is_empty() {
        decompiler = decompiler.with_variable_overrides(inputs.variable_overrides.to_vec());
    }

    if inputs.diagnostics {
        let signature = decompiler.recover_signature(&cfg);
        crate::print_signature_diagnostics(&name, &signature);
    }
    if instructions.is_empty() {
        diagnostics.push(
            PipelineDiagnostic::new(
                "no-instructions",
                DiagnosticSeverity::Error,
                "no instruction could be decoded at this address",
            )
            .at(start),
        );
    } else if cfg.block_ids().next().is_none() {
        diagnostics.push(
            PipelineDiagnostic::new(
                "empty-cfg",
                DiagnosticSeverity::Warning,
                "decoded instructions produced no basic blocks",
            )
            .at(start),
        );
    }

    let _ = (max_bytes, stop_after_first_return);
    Ok(AnalyzedFunction {
        start,
        name,
        instructions,
        cfg,
        diagnostics,
        decompiler,
    })
}

/// Weave project/bookmark comments into the pseudo-C after each basic block
/// whose address range contains them.
pub(crate) fn apply_comment_overlay(
    pseudocode: String,
    overlay: Option<&CommentOverlay>,
    show_addresses: bool,
) -> String {
    if !show_addresses {
        return pseudocode;
    }
    let Some(overlay) = overlay else {
        return pseudocode;
    };
    if overlay.is_empty() {
        return pseudocode;
    }

    let comments = &overlay.entries;
    let trailing_newline = pseudocode.ends_with('\n');
    let mut rendered = String::new();
    let mut next_comment = 0usize;

    for line in pseudocode.lines() {
        rendered.push_str(line);
        rendered.push('\n');

        let Some((start, end, indent)) = parse_basic_block_address_line(line) else {
            continue;
        };

        while next_comment < comments.len() && comments[next_comment].0 < start {
            next_comment += 1;
        }
        while next_comment < comments.len() && comments[next_comment].0 <= end {
            rendered.push_str(&indent);
            rendered.push_str("// ");
            rendered.push_str(&comments[next_comment].1);
            rendered.push('\n');
            next_comment += 1;
        }
    }

    if trailing_newline {
        rendered
    } else {
        rendered.trim_end_matches('\n').to_string()
    }
}

pub(crate) fn ensure_nonempty_pseudocode(mut pseudocode: String) -> String {
    if pseudocode.trim().is_empty() {
        pseudocode.push_str("/* decompilation body not recoverable */");
    }
    pseudocode
}

fn parse_basic_block_address_line(line: &str) -> Option<(u64, u64, String)> {
    let indent_len = line.len() - line.trim_start().len();
    let indent = line[..indent_len].to_string();
    let trimmed = &line[indent_len..];
    if !trimmed.starts_with("// bb") {
        return None;
    }

    let open = trimmed.find('[')?;
    let close = trimmed[open + 1..].find(']')? + open + 1;
    let range = &trimmed[open + 1..close];
    let (start_str, end_str) = range.split_once("..")?;
    let start = u64::from_str_radix(start_str.strip_prefix("0x")?, 16).ok()?;
    let end = u64::from_str_radix(end_str.strip_prefix("0x")?, 16).ok()?;

    Some((start, end, indent))
}

/// Build a `DecompilerConfig` from CLI options.
pub(crate) fn build_decompiler_config(
    opt_level: &str,
    enable_passes: &[String],
    disable_passes: &[String],
) -> Result<DecompilerConfig> {
    let level = OptimizationLevel::parse(opt_level).ok_or_else(|| {
        anyhow::anyhow!(
            "Unknown optimization level '{}'. Use: none, basic, standard, aggressive",
            opt_level
        )
    })?;

    let mut config = DecompilerConfig::new(level);
    for name in enable_passes {
        if let Some(pass) = parse_optimization_pass(name) {
            config = config.enable_pass(pass);
        } else {
            bail!("Unknown optimization pass '{}'", name);
        }
    }
    for name in disable_passes {
        if let Some(pass) = parse_optimization_pass(name) {
            config = config.disable_pass(pass);
        } else {
            bail!("Unknown optimization pass '{}'", name);
        }
    }
    Ok(config)
}

fn parse_optimization_pass(name: &str) -> Option<OptimizationPass> {
    OptimizationPass::all()
        .iter()
        .copied()
        .find(|pass| pass.name().eq_ignore_ascii_case(name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overlay_is_only_applied_with_addresses() {
        let overlay = CommentOverlay::from_pairs(vec![(0x1000, "hello".to_string())]);
        let text = "// bb [0x1000..0x1010]\n  return 0;\n".to_string();
        assert_eq!(
            apply_comment_overlay(text.clone(), Some(&overlay), true),
            "// bb [0x1000..0x1010]\n// hello\n  return 0;\n"
        );
        assert_eq!(
            apply_comment_overlay(text.clone(), Some(&overlay), false),
            text
        );
        assert_eq!(apply_comment_overlay(text.clone(), None, true), text);
    }

    #[test]
    fn empty_pseudocode_is_replaced() {
        assert_eq!(
            ensure_nonempty_pseudocode("   \n".to_string()),
            "   \n/* decompilation body not recoverable */"
        );
        assert_eq!(ensure_nonempty_pseudocode("x".into()), "x");
    }

    #[test]
    fn unknown_optimization_level_is_an_error() {
        assert!(build_decompiler_config("ludicrous", &[], &[]).is_err());
        assert!(build_decompiler_config("standard", &["nope".into()], &[]).is_err());
        assert!(build_decompiler_config("standard", &[], &[]).is_ok());
    }
}
