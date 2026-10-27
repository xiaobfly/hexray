//! `hexray db` — the persistent analysis project front end.
//!
//! This module owns everything that needs a parser or the CLI:
//! - turning an input file into a validated image layout (`mappings`,
//!   `sections`, layout fingerprint) and the effective patched bytes;
//! - running the analysis passes and publishing them into `hexray-db`;
//! - the query/edit/REPL surface.
//!
//! It never re-implements analysis: decoding, CFG construction, xref recovery
//! and pseudo-C rendering all go through [`crate::analysis_pipeline`], the same
//! entry point the plain `hexray <binary> decompile` command uses.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use clap::{Parser as _, Subcommand};
use hexray_core::{Architecture, ControlFlow, Instruction, Operand};
use hexray_db::store::MAX_PAYLOAD_BYTES;
use hexray_db::{
    Address, AnalysisBatch, AnalysisPayload, AnalysisState, AnnotationKind, BlockPayload,
    BoundsOrigin, ContainerKind, CreateInput, Database, DbError, Dependency, DependencyKind,
    Diagnostic, EdgeKind, Edit, EditOutcome, FileOffset, FunctionCfgPayload, FunctionOrigin,
    FunctionOverrideRow, FunctionRow, ImageIndexPayload, ImageInfo, ItemKind, ItemRow, MappingInfo,
    MappingPermissions, OpenMode, OverallState, PatchRow, RenderConfig, RenderPayload, Revision,
    SectionInfo, Severity, StringEncoding, StringRow, SymbolInfo, SymbolOrigin, TypeKind, TypeRow,
    UnitKey, UnitPublish, VariableLocator, XrefKind, XrefOrigin, XrefRow,
};
use hexray_formats::{detect_format, ArArchive, BinaryFormat, BinaryType, Elf, MachO, Pe, Section};
use hexray_types::TypeDatabase;
use std::sync::Arc;

use crate::Binary;
use serde_json::json;

use crate::analysis_pipeline::{
    analyze_address, analyze_replay, build_decompiler_config, render_function, AnalysisInputs,
    CommentOverlay, RenderOptions, ReplayInput,
};

// ---------------------------------------------------------------------------
// CLI surface
// ---------------------------------------------------------------------------

/// Flags that bound how much input an operation may touch.
#[derive(Debug, Clone, clap::Args)]
pub(crate) struct InputLimits {
    /// Maximum accepted size of the original input file.
    #[arg(long, default_value_t = 8 * 1024 * 1024 * 1024u64)]
    pub max_source_bytes: u64,
    /// Maximum accepted size of the analyzed image.
    #[arg(long, default_value_t = 256 * 1024 * 1024u64)]
    pub max_analysis_bytes: u64,
}

impl Default for InputLimits {
    fn default() -> Self {
        Self {
            max_source_bytes: 8 * 1024 * 1024 * 1024,
            max_analysis_bytes: 256 * 1024 * 1024,
        }
    }
}

/// How to pick one image out of a container.
#[derive(Debug, Clone, clap::Args, Default)]
pub(crate) struct Selection {
    /// Mach-O architecture to select from a fat binary.
    #[arg(long)]
    pub arch: Option<String>,
    /// `ar` member name to analyze.
    #[arg(long)]
    pub member: Option<String>,
    /// Zero-based `ar` member index, required when names collide.
    #[arg(long)]
    pub member_index: Option<u64>,
    /// Authorized split-DWARF sidecar; repeatable.
    #[arg(long = "debug-file")]
    pub debug_files: Vec<PathBuf>,
}

/// Pseudo-C rendering options, mirroring the standalone `decompile` command.
#[derive(Debug, Clone, clap::Args, Default)]
pub(crate) struct RenderFlags {
    /// Emit basic-block address comments.
    #[arg(long)]
    pub show_addresses: bool,
    /// Optimization level: none, basic, standard, aggressive.
    #[arg(long, default_value = "standard")]
    pub opt_level: String,
    /// Enable an optimization pass (repeatable).
    #[arg(long = "enable-pass")]
    pub enable_passes: Vec<String>,
    /// Disable an optimization pass (repeatable).
    #[arg(long = "disable-pass")]
    pub disable_passes: Vec<String>,
}

#[derive(Subcommand, Clone)]
pub(crate) enum DbAction {
    /// Describe the selectable images inside an input file
    InputInfo {
        binary: PathBuf,
        #[command(flatten)]
        selection: Selection,
        #[arg(long)]
        json: bool,
    },
    /// Create a new analysis project
    Create {
        binary: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
        #[command(flatten)]
        selection: Selection,
        #[command(flatten)]
        limits: InputLimits,
        #[arg(long)]
        json: bool,
    },
    /// Show project metadata and analysis state
    Info {
        database: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Run or repair analysis
    Analyze {
        database: PathBuf,
        /// Restrict to one function (address or name)
        #[arg(long)]
        function: Option<String>,
        /// Recompute even when the stored result is current
        #[arg(long)]
        force: bool,
        /// Also generate pseudo-C
        #[arg(long)]
        render: bool,
        #[command(flatten)]
        render_flags: RenderFlags,
        #[command(flatten)]
        limits: InputLimits,
        #[arg(long)]
        json: bool,
    },
    /// Interactive project shell
    Open {
        database: PathBuf,
        #[arg(long)]
        read_only: bool,
    },
    /// Read analysis results
    Query {
        database: PathBuf,
        #[command(subcommand)]
        command: QueryAction,
        #[arg(long, global = true)]
        json: bool,
        /// Show historical results even when they are not current
        #[arg(long, global = true)]
        allow_stale: bool,
        /// Rebuild missing or stale results (writes to the project)
        #[arg(long, global = true)]
        update: bool,
        #[command(flatten)]
        limits: InputLimits,
    },
    /// Apply one user edit
    Edit {
        database: PathBuf,
        #[command(subcommand)]
        command: EditAction,
        /// Required revision; the write fails if the project moved on
        #[arg(long, global = true)]
        expect_revision: Option<u64>,
    },
    /// Undo the most recent edit
    Undo {
        database: PathBuf,
        #[arg(long)]
        expect_revision: Option<u64>,
    },
    /// Redo the most recently undone edit
    Redo {
        database: PathBuf,
        #[arg(long)]
        expect_revision: Option<u64>,
    },
    /// Copy the project to a new file
    Backup {
        database: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
    },
    /// Write a binary with the recorded byte patches applied
    ExportBinary {
        database: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
    },
    /// Verify database integrity
    Check {
        database: PathBuf,
        /// Re-hash the embedded source and validate patch ranges
        #[arg(long)]
        deep: bool,
        #[arg(long)]
        json: bool,
    },
    /// Import user state from a legacy project or session
    ImportLegacy {
        legacy: PathBuf,
        #[arg(long)]
        binary: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
        #[command(flatten)]
        selection: Selection,
        #[command(flatten)]
        limits: InputLimits,
        /// Accept a legacy file whose weak digest does not match
        #[arg(long)]
        accept_unverified_legacy: bool,
        #[arg(long)]
        json: bool,
    },
}

/// Read-only queries. Every variant is answered from the database, never by
/// re-parsing the source.
#[derive(Subcommand, Clone)]
pub(crate) enum QueryAction {
    /// Sections and loaded mappings
    Info {
        #[arg(long)]
        limit: Option<usize>,
        #[arg(long)]
        offset: Option<usize>,
    },
    Sections {
        #[arg(long)]
        limit: Option<usize>,
        #[arg(long)]
        offset: Option<usize>,
    },
    Symbols {
        #[arg(long)]
        limit: Option<usize>,
        #[arg(long)]
        offset: Option<usize>,
    },
    Functions {
        #[arg(long)]
        limit: Option<usize>,
        #[arg(long)]
        offset: Option<usize>,
    },
    Disasm {
        function: String,
        #[arg(long)]
        limit: Option<usize>,
        #[arg(long)]
        offset: Option<usize>,
    },
    Cfg {
        function: String,
        #[arg(long)]
        dot: bool,
        #[arg(long)]
        html: bool,
    },
    Xrefs {
        address: String,
        #[arg(long)]
        limit: Option<usize>,
        #[arg(long)]
        offset: Option<usize>,
    },
    Callgraph {
        function: Option<String>,
        #[arg(long)]
        dot: bool,
        #[arg(long)]
        html: bool,
    },
    Strings {
        #[arg(long)]
        limit: Option<usize>,
        #[arg(long)]
        offset: Option<usize>,
    },
    Bytes {
        address: String,
        length: u64,
    },
    Decompile {
        function: String,
        #[command(flatten)]
        render_flags: RenderFlags,
    },
    Variables {
        function: String,
    },
    Types {
        #[arg(long)]
        limit: Option<usize>,
        #[arg(long)]
        offset: Option<usize>,
    },
    History {
        #[arg(long)]
        limit: Option<usize>,
        #[arg(long)]
        offset: Option<usize>,
    },
    Changes {
        #[arg(long)]
        limit: Option<usize>,
        #[arg(long)]
        offset: Option<usize>,
    },
    /// Emulate a function (temporary computation, never persisted)
    Emulate {
        #[command(subcommand)]
        action: crate::commands::emulate::EmulateAction,
    },
    /// Trace a function (temporary computation, never persisted)
    Trace {
        #[command(subcommand)]
        action: crate::commands::trace::TraceAction,
    },
    /// Signature scans (read-only)
    Signatures {
        #[command(subcommand)]
        action: crate::commands::signatures::SignaturesAction,
    },
}

/// User edits. Each maps 1:1 onto a [`hexray_db::Edit`].
#[derive(Subcommand, Clone)]
pub(crate) enum EditAction {
    /// Overwrite bytes at a source file offset or image address
    Patch {
        address: String,
        /// Hex bytes, e.g. `554889e5`
        hex_bytes: String,
    },
    MakeCode {
        address: String,
        length: u64,
    },
    MakeData {
        address: String,
        length: u64,
        #[arg(long = "type")]
        type_name: Option<String>,
    },
    Undefine {
        address: String,
        length: u64,
    },
    FunctionCreate {
        start: String,
        end: String,
    },
    FunctionBounds {
        start: String,
        end: String,
    },
    FunctionRemove {
        start: String,
    },
    FunctionExclude {
        start: String,
        /// `true` or `false`
        excluded: String,
    },
    Name {
        address: String,
        name: String,
    },
    Comment {
        address: String,
        text: String,
    },
    Tag {
        address: String,
        text: String,
    },
    Bookmark {
        address: String,
        label: Option<String>,
    },
    Signature {
        function: String,
        /// One C function prototype
        prototype: String,
    },
    CallingConvention {
        function: String,
        convention: String,
    },
    TypeImport {
        /// UTF-8 header file
        header: PathBuf,
    },
    TypeRemove {
        name: String,
    },
    ApplyType {
        address: String,
        #[arg(long = "type")]
        type_name: String,
        #[arg(long)]
        length: Option<u64>,
    },
    Variable {
        function: String,
        /// Locator JSON, as printed by `query variables`
        locator: String,
        #[arg(long)]
        name: Option<String>,
        #[arg(long = "type")]
        type_name: Option<String>,
    },
    Clear {
        /// One of name, comment, tag, bookmark, signature, calling-convention,
        /// type, variable
        target: String,
        address: String,
        #[arg(long)]
        locator: Option<String>,
    },
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

pub(crate) fn handle(action: DbAction) -> Result<()> {
    match action {
        DbAction::InputInfo {
            binary,
            selection,
            json,
        } => input_info(&binary, &selection, json),
        DbAction::Create {
            binary,
            output,
            selection,
            limits,
            json,
        } => create(&binary, &output, &selection, &limits, json),
        DbAction::Info { database, json } => info(&database, json),
        DbAction::Analyze {
            database,
            function,
            force,
            render,
            render_flags,
            limits,
            json,
        } => analyze(
            &database,
            function,
            force,
            render,
            &render_flags,
            &limits,
            json,
        ),
        DbAction::Open {
            database,
            read_only,
        } => run_repl(&database, read_only),
        DbAction::Query {
            database,
            command,
            json,
            allow_stale,
            update,
            limits,
        } => query(&database, command, json, allow_stale, update, &limits),
        DbAction::Edit {
            database,
            command,
            expect_revision,
        } => edit(&database, command, expect_revision),
        DbAction::Undo {
            database,
            expect_revision,
        } => undo(&database, expect_revision),
        DbAction::Redo {
            database,
            expect_revision,
        } => redo(&database, expect_revision),
        DbAction::Backup { database, output } => backup(&database, &output),
        DbAction::ExportBinary { database, output } => export_binary(&database, &output),
        DbAction::Check {
            database,
            deep,
            json,
        } => check(&database, deep, json),
        DbAction::ImportLegacy {
            legacy,
            binary,
            output,
            selection,
            limits,
            accept_unverified_legacy,
            json,
        } => import_legacy(
            &legacy,
            &binary,
            &output,
            &selection,
            &limits,
            accept_unverified_legacy,
            json,
        ),
    }
}

/// Keep the store error's concrete type so `main` can map it to the documented
/// exit class (3 for revision conflicts, 4 for lock/resource limits).
fn db<T>(result: Result<T, DbError>) -> Result<T> {
    result.map_err(anyhow::Error::new)
}

// ---------------------------------------------------------------------------
// Engine fingerprint
// ---------------------------------------------------------------------------

/// Identifier of the analysis engine.
///
/// Any change that can alter output for the same input must bump
/// [`hexray_db::ANALYSIS_FORMAT_REVISION`]; the schema version moves separately.
fn engine_fingerprint() -> [u8; 32] {
    let mut canonical = String::new();
    canonical.push_str("hexray-analysis\n");
    canonical.push_str(&format!(
        "analysis-format-revision={}\n",
        hexray_db::ANALYSIS_FORMAT_REVISION
    ));
    canonical.push_str(&format!("crate-version={}\n", env!("CARGO_PKG_VERSION")));
    // The decoder set is fixed by the CLI's `hexray-disasm` feature selection;
    // it is part of the fingerprint because it decides what can be decoded.
    let mut arches: Vec<&str> = vec![
        "x86",
        "x86_64",
        "arm64",
        "riscv32",
        "riscv64",
        "cuda-sass",
        "amdgpu",
    ];
    arches.sort_unstable();
    canonical.push_str(&format!("architectures={}\n", arches.join(",")));
    hexray_db::sha256(canonical.as_bytes())
}

// ---------------------------------------------------------------------------
// Input loading: container -> image selection -> validated layout
// ---------------------------------------------------------------------------

/// One selectable image inside an input container.
#[derive(Debug, Clone)]
struct ImageSelection {
    container_kind: ContainerKind,
    container_offset: u64,
    container_length: u64,
    member_name: Option<String>,
    member_index: Option<u64>,
    slice_label: Option<String>,
    selector_json: String,
}

/// An input file split into the full source and the selected image.
struct LoadedInput {
    source: Vec<u8>,
    selection: ImageSelection,
}

fn describe_images(path: &Path, selection: &Selection) -> Result<Vec<String>> {
    let bytes =
        std::fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    match detect_format(&bytes) {
        BinaryType::Ar => {
            let archive = ArArchive::parse(&bytes).context("failed to parse ar archive")?;
            let mut out = Vec::new();
            for (index, member) in archive.regular_members().enumerate() {
                out.push(format!(
                    "member_index={index} name={} size={}",
                    member.name(),
                    member.data().len()
                ));
            }
            Ok(out)
        }
        BinaryType::MachO => {
            let labels = MachO::list_slices(&bytes);
            if labels.is_empty() {
                Ok(vec!["thin mach-o".to_string()])
            } else {
                Ok(labels)
            }
        }
        BinaryType::Elf => Ok(vec!["elf".to_string()]),
        BinaryType::Pe => Ok(vec!["pe".to_string()]),
        BinaryType::Unknown => {
            let _ = selection;
            Ok(Vec::new())
        }
    }
}

fn select_input(path: &Path, selection: &Selection, limits: &InputLimits) -> Result<LoadedInput> {
    let metadata =
        std::fs::metadata(path).with_context(|| format!("failed to stat {}", path.display()))?;
    if metadata.len() > limits.max_source_bytes {
        bail!(
            "input is {} bytes, above the {} byte limit (raise --max-source-bytes)",
            metadata.len(),
            limits.max_source_bytes
        );
    }
    let source =
        std::fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    let container = detect_format(&source);

    let selection = match container {
        BinaryType::Ar => {
            let archive = ArArchive::parse(&source).context("failed to parse ar archive")?;
            let members: Vec<_> = archive.regular_members().collect();
            let index = match (&selection.member, selection.member_index) {
                (_, Some(index)) => {
                    let index = usize::try_from(index)
                        .map_err(|_| anyhow::anyhow!("member index is out of range"))?;
                    if index >= members.len() {
                        bail!(
                            "member index {index} is out of range; the archive holds {} members",
                            members.len()
                        );
                    }
                    index
                }
                (Some(name), None) => {
                    let matches: Vec<usize> = members
                        .iter()
                        .enumerate()
                        .filter(|(_, member)| member.name() == name)
                        .map(|(index, _)| index)
                        .collect();
                    match matches.len() {
                        0 => bail!("no ar member named '{name}'"),
                        1 => matches[0],
                        _ => bail!(
                            "ar member name '{name}' is ambiguous ({} matches); pass --member-index",
                            matches.len()
                        ),
                    }
                }
                (None, None) => bail!(
                    "this input is an ar archive; select a member with --member <name> \
                     or --member-index <n> (see `db input-info`)"
                ),
            };
            let member = &members[index];
            let data = member.data();
            let offset = member.data_offset() as u64;
            ImageSelection {
                container_kind: ContainerKind::Ar,
                container_offset: offset,
                container_length: data.len() as u64,
                member_name: Some(member.name().to_string()),
                member_index: Some(index as u64),
                slice_label: None,
                selector_json: json!({
                    "member_index": index,
                    "member_name": member.name(),
                })
                .to_string(),
            }
        }
        BinaryType::MachO => {
            let parsed = MachO::parse_with_arch(&source, selection.arch.as_deref())
                .context("failed to parse Mach-O")?;
            let offset = parsed.file_offset() as u64;
            let length = parsed
                .slice_size()
                .map(|size| size as u64)
                .unwrap_or_else(|| source.len() as u64 - offset.min(source.len() as u64));
            let label = parsed.slice_label();
            ImageSelection {
                container_kind: ContainerKind::MachO,
                container_offset: offset,
                container_length: length,
                member_name: None,
                member_index: None,
                slice_label: Some(label.clone()),
                selector_json: json!({ "slice": label }).to_string(),
            }
        }
        BinaryType::Elf => ImageSelection {
            container_kind: ContainerKind::Elf,
            container_offset: 0,
            container_length: source.len() as u64,
            member_name: None,
            member_index: None,
            slice_label: None,
            selector_json: json!({ "image": "elf" }).to_string(),
        },
        BinaryType::Pe => ImageSelection {
            container_kind: ContainerKind::Pe,
            container_offset: 0,
            container_length: source.len() as u64,
            member_name: None,
            member_index: None,
            slice_label: None,
            selector_json: json!({ "image": "pe" }).to_string(),
        },
        BinaryType::Unknown => bail!(
            "{} is not a supported input (ELF, Mach-O, PE or ar). CUDA fatbin, HIP wrappers \
             and PTX must be extracted to a supported object first.",
            path.display()
        ),
    };

    if selection.container_kind == ContainerKind::Ar {
        // An ar member may itself be a Mach-O slice: allow one more level.
        let start = usize::try_from(selection.container_offset)
            .map_err(|_| anyhow::anyhow!("member offset is out of range"))?;
        let end = start
            .checked_add(usize::try_from(selection.container_length)?)
            .ok_or_else(|| anyhow::anyhow!("member range overflows"))?;
        if end > source.len() {
            bail!("selected member extends past the end of the archive");
        }
    }

    if selection.container_length > limits.max_analysis_bytes {
        bail!(
            "selected image is {} bytes, above the {} byte analysis limit \
             (raise --max-analysis-bytes)",
            selection.container_length,
            limits.max_analysis_bytes
        );
    }

    Ok(LoadedInput { source, selection })
}

/// Build the persisted image description from the selected slice.
struct ParsedImage<'a> {
    binary: Binary<'a>,
    info: ImageInfo,
}

fn parse_image<'a>(image_bytes: &'a [u8], selection: &ImageSelection) -> Result<ParsedImage<'a>> {
    let format = detect_format(image_bytes);
    let binary = match format {
        BinaryType::Elf => Binary::Elf(Elf::parse(image_bytes).context("failed to parse ELF")?),
        BinaryType::MachO => {
            Binary::MachO(MachO::parse(image_bytes).context("failed to parse Mach-O slice")?)
        }
        BinaryType::Pe => Binary::Pe(Pe::parse(image_bytes).context("failed to parse PE")?),
        other => bail!("selected image is {other:?}, not a supported object"),
    };
    let info = build_image_info(&binary, selection)?;
    Ok(ParsedImage { binary, info })
}

fn build_image_info(binary: &Binary<'_>, selection: &ImageSelection) -> Result<ImageInfo> {
    let fmt = binary.as_format();
    let arch = fmt.architecture();
    let bitness = match fmt.bitness() {
        hexray_core::Bitness::Bits32 => 32u8,
        hexray_core::Bitness::Bits64 => 64u8,
    };
    let endianness = match fmt.endianness() {
        hexray_core::Endianness::Little => "little",
        hexray_core::Endianness::Big => "big",
    }
    .to_string();
    let abi = match binary {
        Binary::Pe(_) => {
            if bitness == 64 {
                hexray_db::AbiInfo::llp64()
            } else {
                hexray_db::AbiInfo::ilp32()
            }
        }
        _ => {
            if bitness == 64 {
                hexray_db::AbiInfo::lp64()
            } else {
                hexray_db::AbiInfo::ilp32()
            }
        }
    };
    let mut abi = abi;
    abi.big_endian = endianness == "big";

    let mappings = build_mappings(binary)?;
    let sections = build_sections(fmt);
    let mut info = ImageInfo {
        format: binary.format_name().to_ascii_lowercase(),
        architecture: format_architecture(arch),
        bitness,
        endianness,
        abi,
        entry_address: fmt.entry_point().map(Address),
        selector_json: selection.selector_json.clone(),
        container_offset: FileOffset(selection.container_offset),
        container_length: selection.container_length,
        member_name: selection.member_name.clone(),
        member_index: selection.member_index,
        slice_label: selection.slice_label.clone(),
        layout_fingerprint: [0u8; 32],
        mappings,
        sections,
    };
    info.layout_fingerprint = compute_layout_fingerprint(&info);
    Ok(info)
}

/// Architectures this project can structure and render as pseudo-C.
///
/// GPU code objects (CUDA SASS, AMDGPU) are decodable and stored, but they
/// have no pseudo-C path: rendering publishes an `unsupported` unit instead.
fn supports_pseudo_c(arch: Architecture) -> bool {
    matches!(
        arch,
        Architecture::X86
            | Architecture::X86_64
            | Architecture::Arm64
            | Architecture::RiscV32
            | Architecture::RiscV64
    )
}

/// Short architecture label stored in the database. The detailed
/// (ABI-specific) form is only used in messages.
fn format_architecture(arch: Architecture) -> String {
    match arch {
        Architecture::X86 => "x86".to_string(),
        Architecture::X86_64 => "x86_64".to_string(),
        Architecture::Arm64 => "arm64".to_string(),
        Architecture::RiscV32 => "riscv32".to_string(),
        Architecture::RiscV64 => "riscv64".to_string(),
        other => crate::format_arch_for_info(other),
    }
}

fn build_mappings(binary: &Binary<'_>) -> Result<Vec<MappingInfo>> {
    let mut mappings = Vec::new();
    match binary {
        Binary::Elf(elf) => {
            for (index, segment) in elf.segments.iter().enumerate() {
                if !segment.is_load() {
                    continue;
                }
                mappings.push(MappingInfo {
                    name: format!("PT_LOAD[{index}]"),
                    va: Address(segment.p_vaddr),
                    memory_size: segment.p_memsz,
                    file_offset: if segment.p_filesz > 0 {
                        Some(FileOffset(segment.p_offset))
                    } else {
                        None
                    },
                    file_size: segment.p_filesz,
                    permissions: MappingPermissions {
                        read: segment.is_readable(),
                        write: segment.is_writable(),
                        execute: segment.is_executable(),
                    },
                    origin: "program_header".to_string(),
                });
            }
        }
        Binary::MachO(macho) => {
            for segment in &macho.segments {
                if segment.filesize == 0 && segment.vmsize == 0 {
                    continue;
                }
                mappings.push(MappingInfo {
                    name: segment.segname.clone(),
                    va: Address(segment.vmaddr),
                    memory_size: segment.vmsize,
                    file_offset: if segment.filesize > 0 {
                        Some(FileOffset(segment.fileoff))
                    } else {
                        None
                    },
                    file_size: segment.filesize,
                    permissions: MappingPermissions {
                        read: segment.is_readable(),
                        write: segment.is_writable(),
                        execute: segment.is_executable(),
                    },
                    origin: "segment".to_string(),
                });
            }
        }
        Binary::Pe(pe) => {
            let base = pe.image_base();
            let mut mappings: Vec<MappingInfo> = Vec::new();
            for section in &pe.sections {
                let start = base + u64::from(section.virtual_address);
                let memory_size = u64::from(section.virtual_size.max(section.size_of_raw_data));
                mappings.push(MappingInfo {
                    name: section.name.clone(),
                    va: Address(start),
                    memory_size,
                    file_offset: if section.size_of_raw_data > 0 {
                        Some(FileOffset(u64::from(section.pointer_to_raw_data)))
                    } else {
                        None
                    },
                    file_size: u64::from(section.size_of_raw_data),
                    permissions: MappingPermissions {
                        read: section.is_readable(),
                        write: section.is_writable(),
                        execute: section.is_executable(),
                    },
                    origin: "section".to_string(),
                });
            }
            // Consecutive sections with identical permissions form one mapping;
            // keeping them separate preserves the header/body distinction the
            // patch guard needs.
            mappings.sort_by_key(|mapping| mapping.va.0);
        }
    }

    if mappings.is_empty() {
        // Sections are a strictly worse fallback, but a stripped container
        // with no program headers still has to be readable. GPU code objects
        // are the reason this cannot require SHF_ALLOC: a CUBIN's `.text.sm_*`
        // is executable without being allocated, and dropping it would leave
        // the image with no mappings at all.
        for section in binary.as_format().sections() {
            if section.size() == 0 || !(section.is_allocated() || section.is_executable()) {
                continue;
            }
            mappings.push(MappingInfo {
                name: section.name().to_string(),
                va: Address(section.virtual_address()),
                memory_size: section.size(),
                file_offset: Some(FileOffset(section.file_offset())),
                file_size: section.size(),
                permissions: MappingPermissions {
                    read: true,
                    write: section.is_writable(),
                    execute: section.is_executable(),
                },
                origin: "section_fallback".to_string(),
            });
        }
    }

    mappings.sort_by_key(|mapping| mapping.va.0);
    if mappings.is_empty() {
        bail!("the selected image exposes no loadable mappings");
    }
    Ok(mappings)
}

fn build_sections(fmt: &dyn BinaryFormat) -> Vec<SectionInfo> {
    let mut sections: Vec<SectionInfo> = fmt
        .sections()
        .map(|section| SectionInfo {
            name: section.name().to_string(),
            va: Address(section.virtual_address()),
            memory_size: section.size(),
            file_offset: Some(FileOffset(section.file_offset())),
            file_size: section.size(),
            flags: format!(
                "{}{}{}",
                if section.is_allocated() { "A" } else { "-" },
                if section.is_writable() { "W" } else { "-" },
                if section.is_executable() { "X" } else { "-" },
            ),
        })
        .collect();
    sections.sort_by_key(|section| (section.va.0, section.name.clone()));
    sections
}

/// SHA-256 over the canonical layout description. Any change here invalidates
/// stored mappings, so patching cannot silently reshape the image.
fn compute_layout_fingerprint(info: &ImageInfo) -> [u8; 32] {
    let mut canonical = String::new();
    canonical.push_str(&format!(
        "layout-fingerprint-version={}\n",
        hexray_db::LAYOUT_FINGERPRINT_VERSION
    ));
    canonical.push_str(&format!("format={}\n", info.format));
    canonical.push_str(&format!("architecture={}\n", info.architecture));
    canonical.push_str(&format!("bitness={}\n", info.bitness));
    canonical.push_str(&format!("endianness={}\n", info.endianness));
    canonical.push_str(&format!(
        "entry={}\n",
        info.entry_address
            .map(|address| address.to_hex())
            .unwrap_or_default()
    ));
    canonical.push_str(&format!("selector={}\n", info.selector_json));
    let mut mappings = info.mappings.clone();
    mappings.sort_by_key(|mapping| mapping.va.0);
    for mapping in &mappings {
        canonical.push_str(&format!(
            "map {} {} {} {} {} {} {}\n",
            mapping.name,
            mapping.va.to_hex(),
            mapping.memory_size,
            mapping
                .file_offset
                .map(|offset| offset.to_hex())
                .unwrap_or_default(),
            mapping.file_size,
            mapping.permissions.as_str(),
            mapping.origin
        ));
    }
    let mut sections = info.sections.clone();
    sections.sort_by_key(|section| (section.va.0, section.name.clone()));
    for section in &sections {
        canonical.push_str(&format!(
            "sec {} {} {} {} {} {}\n",
            section.name,
            section.va.to_hex(),
            section.memory_size,
            section
                .file_offset
                .map(|offset| offset.to_hex())
                .unwrap_or_default(),
            section.file_size,
            section.flags
        ));
    }
    hexray_db::sha256(canonical.as_bytes())
}

/// Apply recorded patches to a copy of the source.
fn effective_source(source: &[u8], patches: &[PatchRow]) -> Result<Vec<u8>> {
    let mut bytes = source.to_vec();
    for patch in patches {
        let start = usize::try_from(patch.offset.0)
            .map_err(|_| anyhow::anyhow!("patch offset is out of range"))?;
        let end = start
            .checked_add(patch.bytes.len())
            .ok_or_else(|| anyhow::anyhow!("patch range overflows"))?;
        if end > bytes.len() {
            bail!("patch at {} extends past the input", patch.offset.to_hex());
        }
        bytes[start..end].copy_from_slice(&patch.bytes);
    }
    Ok(bytes)
}

// ---------------------------------------------------------------------------
// Consistent materialization
// ---------------------------------------------------------------------------

/// Everything one operation needs, read in a single snapshot.
///
/// Capturing the whole picture up front is what makes the later write safe:
/// computation never observes a partially updated database, and the publish
/// step can compare the revision it planned against.
struct Materialized {
    revision: Revision,
    engine: [u8; 32],
    source: Vec<u8>,
    image_bytes: Vec<u8>,
    image: ImageInfo,
    functions: Vec<FunctionRow>,
    items: Vec<ItemRow>,
    symbols: Vec<SymbolInfo>,
    names: Vec<(Address, String)>,
    annotations: Vec<(Address, AnnotationKind, String)>,
    function_overrides: Vec<(Address, FunctionOverrideRow)>,
    variable_overrides: Vec<hexray_db::VariableOverrideRow>,
    types: Vec<TypeRow>,
    strings: Vec<StringRow>,
    xrefs: Vec<XrefRow>,
    units: BTreeMap<UnitKey, (AnalysisState, u64)>,
    instructions: BTreeMap<u64, Vec<Instruction>>,
    cfgs: BTreeMap<u64, hexray_db::store::CfgData>,
    decompiled: BTreeMap<(u64, [u8; 32]), String>,
    builtin_types_json: Option<String>,
    /// Stored split-DWARF sidecars, in import order.
    dwarf_sidecars: Vec<Vec<u8>>,
}

impl Materialized {
    fn function(&self, address: Address) -> Option<&FunctionRow> {
        self.functions.iter().find(|row| row.address == address)
    }

    fn name_at(&self, address: Address) -> Option<&str> {
        self.names
            .iter()
            .find(|(candidate, _)| *candidate == address)
            .map(|(_, name)| name.as_str())
    }

    fn unit_state(&self, key: &UnitKey) -> Option<AnalysisState> {
        self.units.get(key).map(|(state, _)| *state)
    }

    fn unit_generation(&self, key: &UnitKey) -> Option<u64> {
        self.units.get(key).map(|(_, generation)| *generation)
    }

    fn comment_overlay(&self) -> CommentOverlay {
        CommentOverlay::from_pairs(
            self.annotations
                .iter()
                .filter(|(_, kind, _)| *kind == AnnotationKind::Comment)
                .map(|(address, _, text)| (address.0, text.clone()))
                .collect(),
        )
    }

    /// Range of a user data item covering `address`.
    fn data_item_at(&self, address: u64) -> Option<&ItemRow> {
        self.items.iter().find(|item| {
            item.kind == ItemKind::Data
                && address >= item.address.0
                && address < item.address.0.saturating_add(item.length)
        })
    }
}

fn load_materialized(database: &mut Database) -> Result<Materialized> {
    let snapshot = database.snapshot()?;
    let revision = snapshot.data_revision();
    let engine = snapshot.engine_fingerprint();
    let source = db(snapshot.source_bytes())?;
    let patches = db(snapshot.patches())?;
    let image = db(snapshot.image())?;
    let functions = db(snapshot.functions_with_state(true))?;
    let items = db(snapshot.items())?;
    let symbols = db(snapshot.symbols())?;
    let names = db(snapshot.names())?;
    let annotations = db(snapshot.annotations())?;
    let function_overrides = db(snapshot.function_overrides())?;
    let variable_overrides = db(snapshot.variable_overrides())?;
    let types = db(snapshot.types())?;
    let strings = db(snapshot.strings())?;
    let xrefs = db(snapshot.all_xrefs())?;
    let type_snapshot = db(snapshot.resource("type_snapshot", "builtin"))?;
    let builtin_types_json = type_snapshot
        .as_deref()
        .and_then(|bytes| std::str::from_utf8(bytes).ok())
        .map(str::to_string);
    let mut dwarf_sidecars = Vec::new();
    for name in db(snapshot.resource_names("dwarf_sidecar"))? {
        if let Some(bytes) = db(snapshot.resource("dwarf_sidecar", &name))? {
            dwarf_sidecars.push(bytes);
        }
    }
    let unit_rows = db(snapshot.all_units())?;
    let decompiled_rows = db(snapshot.all_decompiled())?;

    let mut units = BTreeMap::new();
    for unit in &unit_rows {
        units.insert(unit.key, (unit.state, unit.generation));
    }

    let mut instructions = BTreeMap::new();
    let mut cfgs = BTreeMap::new();
    for function in functions.iter().filter(|row| row.is_live()) {
        let decoded = db(snapshot.instructions(function.address))?;
        if !decoded.is_empty() {
            instructions.insert(function.address.0, decoded);
        }
        cfgs.insert(function.address.0, db(snapshot.cfg(function.address))?);
    }

    let mut decompiled = BTreeMap::new();
    for (address, config, text) in decompiled_rows {
        decompiled.insert((address.0, config), text);
    }

    let effective = effective_source(&source, &patches)?;
    let image_bytes =
        if image.container_offset.0 == 0 && image.container_length == effective.len() as u64 {
            effective
        } else {
            let start = usize::try_from(image.container_offset.0)
                .map_err(|_| anyhow::anyhow!("image offset is out of range"))?;
            let end = start
                .checked_add(usize::try_from(image.container_length)?)
                .ok_or_else(|| anyhow::anyhow!("image range overflows"))?;
            if end > effective.len() {
                bail!("stored image range exceeds the stored input");
            }
            effective[start..end].to_vec()
        };

    Ok(Materialized {
        revision,
        engine,
        source,
        image_bytes,
        image,
        functions,
        items,
        symbols,
        names,
        annotations,
        function_overrides,
        variable_overrides,
        types,
        strings,
        xrefs,
        units,
        instructions,
        cfgs,
        decompiled,
        builtin_types_json,
        dwarf_sidecars,
    })
}

fn selection_from_image(image: &ImageInfo) -> ImageSelection {
    ImageSelection {
        container_kind: hexray_db::ContainerKind::Elf,
        container_offset: image.container_offset.0,
        container_length: image.container_length,
        member_name: image.member_name.clone(),
        member_index: image.member_index,
        slice_label: image.slice_label.clone(),
        selector_json: image.selector_json.clone(),
    }
}

// ---------------------------------------------------------------------------
// Address and function resolution
// ---------------------------------------------------------------------------

fn parse_address(text: &str) -> Result<Address> {
    let trimmed = text.trim();
    let stripped = trimmed.strip_prefix("sub_").unwrap_or(trimmed);
    let stripped = stripped
        .strip_prefix("0x")
        .or_else(|| stripped.strip_prefix("0X"))
        .unwrap_or(stripped);
    u64::from_str_radix(stripped, 16)
        .map(Address)
        .map_err(|_| anyhow::anyhow!("'{text}' is neither an address nor a numeric symbol"))
}

/// Resolve a user-supplied function reference (address or unique name).
fn resolve_function(materialized: &Materialized, text: &str) -> Result<Address> {
    if let Ok(address) = parse_address(text) {
        if materialized
            .functions
            .iter()
            .any(|row| row.address == address)
        {
            return Ok(address);
        }
        bail!("no function at {}", address.to_hex());
    }

    let matches: Vec<Address> = materialized
        .names
        .iter()
        .filter(|(_, name)| name == text)
        .map(|(address, _)| *address)
        .chain(
            materialized
                .symbols
                .iter()
                .filter(|symbol| symbol.name == text)
                .map(|symbol| symbol.address),
        )
        .collect();
    let mut unique: BTreeSet<u64> = matches.into_iter().map(|address| address.0).collect();
    if unique.len() > 1 {
        let listed: Vec<String> = unique
            .iter()
            .map(|address| Address(*address).to_hex())
            .collect();
        bail!(
            "name '{text}' matches several addresses: {}; use an address",
            listed.join(", ")
        );
    }
    match unique.pop_first() {
        Some(address) => Ok(Address(address)),
        None => bail!("no function named '{text}'"),
    }
}

fn function_display_name(materialized: &Materialized, function: &FunctionRow) -> String {
    if let Some(name) = materialized.name_at(function.address) {
        return name.to_string();
    }
    if let Some(symbol) = materialized
        .symbols
        .iter()
        .find(|symbol| symbol.address == function.address)
    {
        return hexray_demangle::demangle_or_original(&symbol.name).to_string();
    }
    format!("sub_{:x}", function.address.0)
}

fn function_limit(function: &FunctionRow) -> (usize, bool) {
    match function.declared_end {
        Some(end) if end.0 > function.address.0 => (
            usize::try_from(end.0 - function.address.0).unwrap_or(4096),
            function.bounds_origin == BoundsOrigin::Heuristic,
        ),
        _ => (4096, true),
    }
}

// ---------------------------------------------------------------------------
// `db input-info`
// ---------------------------------------------------------------------------

fn input_info(binary: &Path, selection: &Selection, json_output: bool) -> Result<()> {
    let images = describe_images(binary, selection)?;
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "path": binary.to_string_lossy(),
                "images": images,
            }))?
        );
        return Ok(());
    }
    println!("Selectable images in {}", binary.display());
    if images.is_empty() {
        println!("  none (unsupported input)");
    }
    for image in &images {
        println!("  {image}");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// `db create`
// ---------------------------------------------------------------------------

fn create(
    binary: &Path,
    output: &Path,
    selection: &Selection,
    limits: &InputLimits,
    json_output: bool,
) -> Result<()> {
    let loaded = select_input(binary, selection, limits)?;
    let staged = {
        let parent = output
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."));
        std::fs::create_dir_all(&parent).ok();
        let image_bytes = {
            let start = usize::try_from(loaded.selection.container_offset)?;
            let end = start
                .checked_add(usize::try_from(loaded.selection.container_length)?)
                .ok_or_else(|| anyhow::anyhow!("image range overflows"))?;
            loaded.source[start..end].to_vec()
        };
        let parsed = parse_image(&image_bytes, &loaded.selection)?;
        let mut input = build_create_input(binary, &loaded, &parsed)?;
        let engine = engine_fingerprint();
        input.engine_fingerprint = engine;
        let mut staged = db(hexray_db::store::StagedProject::create(&parent, &input))?;
        drop(parsed);
        store_debug_sidecars(staged.database(), selection)?;

        // First analysis pass: whole-image discovery, no pseudo-C yet.
        let report = run_analysis(
            staged.database(),
            &AnalyzeRequest {
                function: None,
                force: true,
                render: None,
                limits: limits.clone(),
            },
        )?;
        if report.partial > 0 {
            eprintln!(
                "note: {} function(s) were only partially analyzed; re-run `db analyze` to continue",
                report.partial
            );
        }
        staged
    };

    let database = db(staged.publish(output))?;
    let revision = db(database.revision())?;
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "database": output.to_string_lossy(),
                "revision": revision.0,
                "stored_input": binary.to_string_lossy(),
            }))?
        );
    } else {
        println!(
            "Created {} (revision {}, input {})",
            output.display(),
            revision.0,
            binary.display()
        );
    }
    Ok(())
}

/// Capture authorized split-DWARF sidecars into the project so a reopened
/// database never searches the filesystem.
fn store_debug_sidecars(database: &mut Database, selection: &Selection) -> Result<usize> {
    let mut stored = 0usize;
    for path in &selection.debug_files {
        let metadata = std::fs::metadata(path)
            .with_context(|| format!("failed to stat --debug-file {}", path.display()))?;
        if metadata.len() > MAX_PAYLOAD_BYTES as u64 {
            bail!(
                "--debug-file {} is larger than the {MAX_PAYLOAD_BYTES} byte payload limit",
                path.display()
            );
        }
        let bytes = std::fs::read(path)
            .with_context(|| format!("failed to read --debug-file {}", path.display()))?;
        let name = path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| format!("sidecar-{stored}"));
        db(database.put_resource("dwarf_sidecar", &name, &bytes))?;
        stored += 1;
    }
    Ok(stored)
}

fn build_create_input(
    original_path: &Path,
    loaded: &LoadedInput,
    parsed: &ParsedImage<'_>,
) -> Result<CreateInput> {
    let fmt = parsed.binary.as_format();
    let relocation_table = crate::build_relocation_table(&parsed.binary);
    let symbols: Vec<SymbolInfo> =
        crate::collect_analysis_symbols(&parsed.binary, &relocation_table)
            .into_iter()
            .map(|symbol| SymbolInfo {
                address: Address(symbol.address),
                name: symbol.name.clone(),
                kind: format!("{:?}", symbol.kind).to_ascii_lowercase(),
                size: symbol.size,
                origin: SymbolOrigin::Loader,
            })
            .collect();

    let functions = discover_functions(&parsed.binary);
    let strings = detect_strings(fmt);
    let builtin = builtin_type_database(&parsed.binary, parsed.info.abi)?;

    Ok(CreateInput {
        original_path: original_path.to_path_buf(),
        source_bytes: loaded.source.clone(),
        container_kind: loaded.selection.container_kind,
        image: parsed.info.clone(),
        engine_fingerprint: [0u8; 32],
        symbols,
        functions,
        strings,
        xrefs: Vec::new(),
        builtin_types_json: serde_json::to_string(&builtin).ok(),
        diagnostics: Vec::new(),
    })
}

/// Decode one GPU kernel with its architecture decoder.
///
/// GPU objects have no CPU analysis path: there is no CFG builder, callgraph
/// walk or parameter recovery here, so the caller stores the decoded stream
/// as a single straight-line block. An empty result is not an error; the
/// caller publishes an `unsupported` unit with a diagnostic instead.
fn decode_gpu_function(
    binary: &Binary<'_>,
    start: u64,
    max_bytes: usize,
) -> Result<Vec<Instruction>> {
    let fmt = binary.as_format();
    let Some(bytes) = fmt.bytes_at(start, max_bytes) else {
        return Ok(Vec::new());
    };
    let mut instructions: Vec<Instruction> =
        crate::disassemble_block_for_arch(fmt.architecture(), bytes, start)
            .into_iter()
            .filter_map(|decoded| decoded.ok())
            .collect();
    instructions.sort_by_key(|instruction| instruction.address);
    Ok(instructions)
}

/// Seed set for GPU code objects: the entry point, every defined symbol that
/// lands in an executable section, and — for CUBINs — the marked entry
/// kernels.
///
/// The symbol kind is deliberately not filtered: CUDA `.text.*` kernels and
/// HSA kernel symbols (`STT_AMDGPU_HSA_KERNEL`, reported as `Other`) are the
/// metadata this discovery set exists for. There is no call-target walk on
/// this path.
fn gpu_function_starts(binary: &Binary<'_>) -> Vec<(u64, u64)> {
    let fmt = binary.as_format();
    let relocation_table = crate::build_relocation_table(binary);
    let symbols = crate::collect_analysis_symbols(binary, &relocation_table);
    let mut starts: Vec<(u64, u64)> = Vec::new();
    if let Some(entry) = fmt.entry_point() {
        if entry != 0 {
            starts.push((entry, 0));
        }
    }
    for symbol in &symbols {
        if !symbol.is_defined() || symbol.address == 0 {
            continue;
        }
        if !is_executable(fmt, symbol.address) {
            continue;
        }
        starts.push((symbol.address, symbol.size));
    }
    if let Binary::Elf(elf) = binary {
        if let Ok(view) = elf.cubin_view() {
            for kernel in view.entry_kernels() {
                let address = kernel
                    .symbol
                    .map(|symbol| symbol.address)
                    .filter(|address| *address != 0)
                    .unwrap_or_else(|| kernel.section.virtual_address());
                if address != 0 {
                    starts.push((address, kernel.size));
                }
            }
        }
    }
    starts.sort_by_key(|(address, _)| *address);
    starts.dedup_by_key(|(address, _)| *address);
    starts
}

/// Row for a GPU function. Unlike [`function_row_for`] there is no symbol-kind
/// filter, so an unknown-size kernel keeps `declared_end: None` rather than
/// pretending a size.
fn gpu_function_row(
    binary: &Binary<'_>,
    existing: Option<&FunctionRow>,
    address: u64,
    size: u64,
) -> FunctionRow {
    if let Some(existing) = existing {
        if existing.origin == FunctionOrigin::User {
            return existing.clone();
        }
    }
    FunctionRow {
        address: Address(address),
        declared_end: (size > 0).then(|| Address(address.saturating_add(size))),
        bounds_origin: if size > 0 {
            BoundsOrigin::Symbol
        } else if Some(address) == binary.as_format().entry_point() {
            BoundsOrigin::Entry
        } else {
            BoundsOrigin::Heuristic
        },
        origin: FunctionOrigin::Auto,
        excluded: false,
        user_removed: false,
        present: true,
    }
}

/// Initial discovery, using the same start set the callgraph analysis uses.
fn discover_functions(binary: &Binary<'_>) -> Vec<FunctionRow> {
    let fmt = binary.as_format();
    if !supports_pseudo_c(fmt.architecture()) {
        return gpu_function_starts(binary)
            .into_iter()
            .map(|(address, size)| gpu_function_row(binary, None, address, size))
            .collect();
    }
    let relocation_table = crate::build_relocation_table(binary);
    let symbols = crate::collect_analysis_symbols(binary, &relocation_table);
    let mut starts = crate::discover_function_starts(fmt, fmt.architecture(), &symbols);
    starts.sort_by_key(|(address, _, _)| *address);
    starts.dedup_by_key(|(address, _, _)| *address);

    starts
        .into_iter()
        .map(|(address, size, heuristic)| {
            let _ = size;
            let symbol = symbols
                .iter()
                .find(|symbol| symbol.address == address && symbol.is_function());
            FunctionRow {
                address: Address(address),
                declared_end: symbol
                    .filter(|symbol| symbol.size > 0)
                    .map(|symbol| Address(address.saturating_add(symbol.size))),
                bounds_origin: if symbol.is_some_and(|symbol| symbol.size > 0) {
                    BoundsOrigin::Symbol
                } else if Some(address) == fmt.entry_point() {
                    BoundsOrigin::Entry
                } else {
                    let _ = heuristic;
                    BoundsOrigin::Heuristic
                },
                origin: FunctionOrigin::Auto,
                excluded: false,
                user_removed: false,
                present: true,
            }
        })
        .collect()
}

/// Snapshot of the built-in type library, pinned into the project so a later
/// tool upgrade cannot change what an existing project means.
fn builtin_type_database(binary: &Binary<'_>, abi: hexray_db::AbiInfo) -> Result<TypeDatabase> {
    let mut database = match crate::load_type_database(binary, Some("auto"))? {
        Some(database) => (*database).clone(),
        None => TypeDatabase::new(),
    };
    database.set_arch(abi.to_arch_info());
    Ok(database)
}

fn detect_strings(fmt: &dyn BinaryFormat) -> Vec<StringRow> {
    let detector = hexray_analysis::StringDetector::with_config(hexray_analysis::StringConfig {
        min_length: 4,
        ..Default::default()
    });
    let mut out = Vec::new();
    for section in fmt.sections() {
        let data = section.data();
        if data.is_empty() {
            continue;
        }
        for detected in detector.detect(data, section.virtual_address()) {
            let encoding = match detected.encoding {
                hexray_analysis::StringEncoding::Ascii => StringEncoding::Ascii,
                hexray_analysis::StringEncoding::Utf8 => StringEncoding::Utf8,
                hexray_analysis::StringEncoding::Utf16Le => StringEncoding::Utf16Le,
                hexray_analysis::StringEncoding::Utf16Be => StringEncoding::Utf16Be,
            };
            out.push(StringRow {
                address: Address(detected.address),
                encoding,
                bytes: detected.content.as_bytes().to_vec(),
                text: Some(detected.content.clone()),
            });
        }
    }
    out.sort_by_key(|row| (row.address.0, row.encoding.as_str()));
    out
}

// ---------------------------------------------------------------------------
// Analysis
// ---------------------------------------------------------------------------

/// What to analyze.
struct AnalyzeRequest {
    /// Restrict to one function; `None` means every stale or missing function.
    function: Option<String>,
    /// Recompute even when stored results are current.
    force: bool,
    /// Also generate pseudo-C with this configuration.
    render: Option<RenderConfig>,
    limits: InputLimits,
}

impl AnalyzeRequest {
    fn new() -> Self {
        Self {
            function: None,
            force: false,
            render: None,
            limits: InputLimits::default(),
        }
    }
}

/// What one analysis run did.
#[derive(Debug, Default)]
struct AnalyzeReport {
    discovered: usize,
    analyzed: usize,
    reused: usize,
    partial: usize,
    unsupported: usize,
    failed: usize,
    rendered: usize,
    reused_render: usize,
    stale_skipped: usize,
}

fn project_type_database(
    materialized: &Materialized,
    binary: &Binary<'_>,
) -> Result<Arc<TypeDatabase>> {
    let mut database = match materialized
        .types
        .is_empty()
        .then(|| db_builtin_types(materialized, binary))
        .transpose()
    {
        Ok(Some(database)) => database,
        _ => db_builtin_types(materialized, binary)?,
    };
    database.set_arch(materialized.image.abi.to_arch_info());

    for row in &materialized.types {
        let parsed = serde_json::from_str::<hexray_types::CType>(&row.payload_json);
        match (row.kind, parsed) {
            (TypeKind::Prototype, _) => {
                if let Ok(prototype) =
                    serde_json::from_str::<hexray_types::FunctionPrototype>(&row.payload_json)
                {
                    database.add_function(prototype);
                }
            }
            (TypeKind::Typedef, Ok(ty)) => database.add_typedef(row.name.clone(), ty),
            (_, Ok(ty)) => database.add_type(row.name.clone(), ty),
            (_, Err(_)) => {}
        }
    }
    Ok(Arc::new(database))
}

fn db_builtin_types(materialized: &Materialized, _binary: &Binary<'_>) -> Result<TypeDatabase> {
    let mut database = match &materialized.builtin_types_json {
        Some(json) => TypeDatabase::from_json(json)
            .map_err(|error| anyhow::anyhow!("stored type snapshot is unreadable: {error}"))?,
        None => TypeDatabase::new(),
    };
    database.set_arch(materialized.image.abi.to_arch_info());
    Ok(database)
}

/// Canonical digest of a type database, independent of hash iteration order.
fn type_snapshot_digest(database: &TypeDatabase) -> [u8; 32] {
    let mut canonical = String::new();
    let mut type_names: Vec<&str> = database.type_names().collect();
    type_names.sort_unstable();
    for name in type_names {
        if let Ok(json) = serde_json::to_string(&database.get_type(name)) {
            canonical.push_str(&format!("type {name} {json}\n"));
        }
    }
    let mut typedef_names: Vec<&str> = database.typedef_names().collect();
    typedef_names.sort_unstable();
    for name in typedef_names {
        if let Ok(json) = serde_json::to_string(&database.get_type(name)) {
            canonical.push_str(&format!("typedef {name} {json}\n"));
        }
    }
    let mut function_names: Vec<&str> = database.function_names().collect();
    function_names.sort_unstable();
    for name in function_names {
        if let Ok(json) = serde_json::to_string(&database.get_function(name)) {
            canonical.push_str(&format!("prototype {name} {json}\n"));
        }
    }
    hexray_db::sha256(canonical.as_bytes())
}

fn run_analysis(database: &mut Database, request: &AnalyzeRequest) -> Result<AnalyzeReport> {
    let materialized = load_materialized(database)?;
    let parsed = parse_image(
        &materialized.image_bytes,
        &selection_from_image(&materialized.image),
    )?;
    let binary = &parsed.binary;
    let fmt = binary.as_format();
    let mut report = AnalyzeReport::default();

    let type_database = project_type_database(&materialized, binary)?;
    let debug_info = load_project_dwarf(&materialized, fmt)?;
    let project = crate::AnalysisProject::new(&materialized.image.selector_json).ok();

    let index_key = UnitKey::image_index();
    let index_current = materialized.unit_state(&index_key) == Some(AnalysisState::Current);
    let need_discovery =
        request.force || !index_current || !materialized.functions.iter().any(|f| f.is_live());

    let mut discovered: Vec<FunctionRow> = if need_discovery {
        discovery_pass(binary, &materialized)?
    } else {
        materialized.functions.clone()
    };
    discovered.sort_by_key(|row| row.address.0);
    report.discovered = discovered.iter().filter(|row| row.is_live()).count();

    if need_discovery {
        let symbols: Vec<SymbolInfo> =
            crate::collect_analysis_symbols(binary, &crate::build_relocation_table(binary))
                .into_iter()
                .map(|symbol| SymbolInfo {
                    address: Address(symbol.address),
                    name: symbol.name.clone(),
                    kind: format!("{:?}", symbol.kind).to_ascii_lowercase(),
                    size: symbol.size,
                    origin: SymbolOrigin::Loader,
                })
                .collect();
        let strings = detect_strings(fmt);
        let payload = ImageIndexPayload {
            functions: discovered.clone(),
            symbols,
            strings,
            xrefs: Vec::new(),
        };
        let function_count = discovered.iter().filter(|row| row.is_live()).count();
        // A GPU project can never reach `ready`: pseudo-C is unsupported, so
        // the index unit stays partial and `db info` never claims completion.
        let gpu = !supports_pseudo_c(fmt.architecture());
        let unit = UnitPublish {
            key: index_key,
            expected_generation: materialized.unit_generation(&index_key),
            // No discovered function is not a complete analysis either: report
            // it as partial so `db info` never claims a finished project.
            state: if gpu || function_count == 0 {
                AnalysisState::Partial
            } else {
                AnalysisState::Current
            },
            input_fingerprint: hexray_db::sha256(materialized.source.as_slice()),
            dependencies_complete: true,
            diagnostics: if gpu {
                vec![Diagnostic::new(
                    "gpu-pseudo-c-unsupported",
                    Severity::Info,
                    "pseudo-C is unsupported for GPU code objects",
                )]
            } else {
                Vec::new()
            },
            dependencies: Vec::new(),
            payload: AnalysisPayload::ImageIndex(Box::new(payload)),
        };
        db(database.publish(materialized.revision, &AnalysisBatch { units: vec![unit] }))?;
    }

    // Which functions still need a decoded CFG?
    let targets: Vec<Address> = match &request.function {
        Some(reference) => vec![resolve_function(&materialized, reference)?],
        None => discovered
            .iter()
            .filter(|row| row.is_live() && !row.excluded)
            .map(|row| row.address)
            .collect(),
    };

    let mut batch = AnalysisBatch::default();
    let mut pending_cfg: Vec<u64> = Vec::new();
    for address in &targets {
        let Some(function) = materialized.function(*address) else {
            continue;
        };
        let key = UnitKey::function_cfg(*address);
        let current = materialized.unit_state(&key) == Some(AnalysisState::Current);
        let has_instructions = materialized.instructions.contains_key(&address.0);
        if !request.force && current && has_instructions {
            report.reused += 1;
            continue;
        }
        if materialized.data_item_at(address.0).is_some()
            && materialized
                .function(*address)
                .is_some_and(|row| row.origin == FunctionOrigin::Auto)
        {
            // A user data definition is a hard barrier for automatic analysis.
            report.stale_skipped += 1;
            continue;
        }
        pending_cfg.push(address.0);
        if pending_cfg.len() >= 10_000 {
            break;
        }
        let _ = function;
    }

    let name_pairs: Vec<(u64, String)> = materialized
        .names
        .iter()
        .map(|(address, name)| (address.0, name.clone()))
        .collect();
    let signature_overrides = build_signature_overrides(&materialized, fmt.architecture())?;
    let variable_overrides = build_variable_overrides(&materialized, &discovered);

    for address in &pending_cfg {
        let address = Address(*address);
        let Some(function) = materialized.function(address) else {
            continue;
        };
        let (max_bytes, stop_after_first_return) = function_limit(function);
        if !supports_pseudo_c(fmt.architecture()) {
            // GPU objects: decode with the architecture decoder and store one
            // straight-line block. There is no CFG, xref or callgraph
            // recovery on this path, and an empty decode is an explicit
            // unsupported unit rather than a silent empty CFG.
            let decoded = decode_gpu_function(binary, address.0, max_bytes)?;
            let (blocks, block_instructions) = match decoded.split_first() {
                Some((first, _)) => {
                    let last = decoded.last().unwrap_or(first);
                    let end = last.address.saturating_add(last.size as u64);
                    (
                        vec![BlockPayload {
                            id: 0,
                            start: Address(first.address),
                            end: Address(end),
                            terminator: hexray_core::BlockTerminator::Unknown,
                        }],
                        vec![(
                            0u32,
                            decoded
                                .iter()
                                .map(|instruction| Address(instruction.address))
                                .collect(),
                        )],
                    )
                }
                None => (Vec::new(), Vec::new()),
            };
            let mut diagnostics = Vec::new();
            let state = if decoded.is_empty() {
                diagnostics.push(Diagnostic::new(
                    "no-instructions",
                    Severity::Warning,
                    format!(
                        "the {} decoder produced no instructions for {}",
                        format_architecture(fmt.architecture()),
                        address.to_hex()
                    ),
                ));
                report.unsupported += 1;
                AnalysisState::Unsupported
            } else {
                report.analyzed += 1;
                AnalysisState::Current
            };
            let dependencies = match (decoded.first(), decoded.last()) {
                (Some(first), Some(last)) => {
                    let start = first.address;
                    let length = last
                        .address
                        .saturating_add(last.size as u64)
                        .saturating_sub(start);
                    vec![Dependency {
                        kind: DependencyKind::Range,
                        key: "bytes".to_string(),
                        range: hexray_db::AddressRange::new(Address(start), length).ok(),
                        target_generation: 0,
                    }]
                }
                _ => Vec::new(),
            };
            batch.units.push(UnitPublish {
                key: UnitKey::function_cfg(address),
                expected_generation: materialized.unit_generation(&UnitKey::function_cfg(address)),
                state,
                input_fingerprint: hash_instructions(&decoded),
                dependencies_complete: !decoded.is_empty(),
                diagnostics,
                dependencies,
                payload: AnalysisPayload::FunctionCfg(Box::new(FunctionCfgPayload {
                    function: function.clone(),
                    instructions: decoded,
                    blocks,
                    block_instructions,
                    edges: Vec::new(),
                    xrefs: Vec::new(),
                })),
            });
            continue;
        }
        let name = function_display_name(&materialized, function);
        let inputs = AnalysisInputs {
            project: project.as_ref(),
            type_db: Some(&type_database),
            config: None,
            diagnostics: false,
            debug_info: debug_info.as_ref(),
            signature_override: signature_overrides.get(&address.0),
            variable_overrides: variable_overrides
                .get(&address.0)
                .map(Vec::as_slice)
                .unwrap_or(&[]),
            names: &name_pairs,
        };
        match analyze_address(
            binary,
            address.0,
            name.clone(),
            None,
            max_bytes,
            stop_after_first_return,
            &inputs,
        ) {
            Ok(analyzed) => {
                let payload = cfg_payload(&analyzed);
                let state = AnalysisState::Current;
                let diagnostics: Vec<Diagnostic> = analyzed
                    .diagnostics
                    .iter()
                    .map(|diagnostic| diagnostic.to_stored())
                    .collect();
                batch.units.push(UnitPublish {
                    key: UnitKey::function_cfg(address),
                    expected_generation: materialized
                        .unit_generation(&UnitKey::function_cfg(address)),
                    state,
                    input_fingerprint: hash_instructions(&analyzed.instructions),
                    dependencies_complete: true,
                    diagnostics,
                    dependencies: cfg_dependencies(&materialized, address, &analyzed),
                    payload: AnalysisPayload::FunctionCfg(Box::new(payload)),
                });
                report.analyzed += 1;
            }
            Err(error) => {
                report.failed += 1;
                let diagnostic =
                    Diagnostic::new("analysis-failed", Severity::Error, format!("{error}"));
                batch.units.push(UnitPublish {
                    key: UnitKey::function_cfg(address),
                    expected_generation: materialized
                        .unit_generation(&UnitKey::function_cfg(address)),
                    state: AnalysisState::Failed,
                    input_fingerprint: [0u8; 32],
                    dependencies_complete: false,
                    diagnostics: vec![diagnostic],
                    dependencies: Vec::new(),
                    payload: AnalysisPayload::FunctionCfg(Box::new(FunctionCfgPayload {
                        function: function.clone(),
                        instructions: Vec::new(),
                        blocks: Vec::new(),
                        block_instructions: Vec::new(),
                        edges: Vec::new(),
                        xrefs: Vec::new(),
                    })),
                });
            }
        }
    }

    if !batch.units.is_empty() {
        db(database.publish(materialized.revision, &batch))?;
    }

    if let Some(config) = &request.render {
        // The batch above may have replaced instructions and CFGs, so the
        // rendering pass must observe the state it will store into.
        let refreshed = load_materialized(database)?;
        let report_render =
            render_functions(database, &refreshed, &targets, config, request.force)?;
        report.rendered = report_render.rendered;
        report.reused_render = report_render.reused;
        report.partial += report_render.partial;
        report.unsupported += report_render.unsupported;
    }

    Ok(report)
}

fn hash_instructions(instructions: &[Instruction]) -> [u8; 32] {
    let mut canonical = Vec::new();
    for instruction in instructions {
        canonical.extend_from_slice(&instruction.address.to_be_bytes());
        canonical.extend_from_slice(&(instruction.size as u64).to_be_bytes());
        canonical.extend_from_slice(&instruction.bytes);
        canonical.extend_from_slice(instruction.mnemonic.as_bytes());
        canonical.push(0);
    }
    hexray_db::sha256(&canonical)
}

fn cfg_payload(analyzed: &crate::analysis_pipeline::AnalyzedFunction) -> FunctionCfgPayload {
    let mut blocks = Vec::new();
    let mut block_instructions = Vec::new();
    let mut edges = Vec::new();
    for block_id in analyzed.cfg.block_ids() {
        let Some(block) = analyzed.cfg.block(block_id) else {
            continue;
        };
        blocks.push(hexray_db::BlockPayload {
            id: block_id.0,
            start: Address(block.start),
            end: Address(block.end),
            terminator: block.terminator.clone(),
        });
        block_instructions.push((
            block_id.0,
            block
                .instructions
                .iter()
                .map(|instruction| Address(instruction.address))
                .collect(),
        ));
        for successor in analyzed.cfg.successors(block_id) {
            edges.push((block_id.0, successor.0, EdgeKind::Normal));
        }
        for successor in analyzed.cfg.eh_successors(block_id) {
            edges.push((block_id.0, successor.0, EdgeKind::Unwind));
        }
    }
    let xrefs = xrefs_for_function(analyzed.start, &analyzed.instructions, &analyzed.cfg);
    FunctionCfgPayload {
        function: FunctionRow {
            address: Address(analyzed.start),
            declared_end: analyzed.instructions.last().map(|instruction| {
                Address(instruction.address.saturating_add(instruction.size as u64))
            }),
            bounds_origin: BoundsOrigin::Heuristic,
            origin: FunctionOrigin::Auto,
            excluded: false,
            user_removed: false,
            present: true,
        },
        instructions: analyzed.instructions.clone(),
        blocks,
        block_instructions,
        edges,
        xrefs,
    }
}

fn xrefs_for_function(
    function: u64,
    instructions: &[Instruction],
    cfg: &hexray_core::ControlFlowGraph,
) -> Vec<XrefRow> {
    let mut out = Vec::new();
    let mut seen: BTreeSet<(u64, u64, &'static str)> = BTreeSet::new();
    for instruction in instructions {
        let mut push = |to: u64, kind: XrefKind| {
            if seen.insert((instruction.address, to, kind.as_str())) {
                out.push(XrefRow {
                    from: Address(instruction.address),
                    to: Address(to),
                    kind,
                    owner: Some(Address(function)),
                    origin: XrefOrigin::Auto,
                });
            }
        };
        match &instruction.control_flow {
            ControlFlow::Call { target, .. } => push(*target, XrefKind::Call),
            ControlFlow::UnconditionalBranch { target } => push(*target, XrefKind::Jump),
            ControlFlow::ConditionalBranch {
                target,
                fallthrough,
                ..
            } => {
                push(*target, XrefKind::Jump);
                push(*fallthrough, XrefKind::Jump);
            }
            ControlFlow::IndirectBranch { possible_targets } => {
                for target in possible_targets {
                    push(*target, XrefKind::Jump);
                }
            }
            _ => {}
        }
        for operand in &instruction.operands {
            if let Operand::Memory(memory) = operand {
                if let Some(target) = crate::rip_relative_memory_target(memory, instruction) {
                    push(target, XrefKind::Data);
                }
            }
        }
    }
    let _ = cfg;
    out.sort_by_key(|row| (row.from.0, row.to.0, row.kind.as_str()));
    out
}

fn cfg_dependencies(
    materialized: &Materialized,
    function: Address,
    analyzed: &crate::analysis_pipeline::AnalyzedFunction,
) -> Vec<Dependency> {
    let mut dependencies = Vec::new();
    let end = analyzed
        .instructions
        .last()
        .map(|instruction| instruction.address.saturating_add(instruction.size as u64))
        .unwrap_or(function.0);
    dependencies.push(Dependency {
        kind: DependencyKind::Range,
        key: "bytes".to_string(),
        range: hexray_db::AddressRange::new(function, end.saturating_sub(function.0)).ok(),
        target_generation: 0,
    });
    for instruction in &analyzed.instructions {
        if let ControlFlow::Call { target, .. } = &instruction.control_flow {
            dependencies.push(Dependency {
                kind: DependencyKind::Signature,
                key: format!("function:{target:x}"),
                range: None,
                target_generation: materialized
                    .unit_generation(&UnitKey::function_cfg(Address(*target)))
                    .unwrap_or(0),
            });
        }
    }
    dependencies
}

// ---------------------------------------------------------------------------
// Discovery, overrides, DWARF
// ---------------------------------------------------------------------------

const MAX_DISCOVERED_FUNCTIONS: usize = 10_000;

/// Whole-image function discovery.
///
/// Seed set: loader symbols, the entry point, CET/lifecycle arrays and
/// already-published functions. The queue then grows by following direct calls
/// and materialized internal targets, exactly like the standalone callgraph
/// walk. User data definitions and user-suppressed functions are hard
/// barriers, so re-running discovery never resurrects them.
fn discovery_pass(binary: &Binary<'_>, materialized: &Materialized) -> Result<Vec<FunctionRow>> {
    let fmt = binary.as_format();
    if !supports_pseudo_c(fmt.architecture()) {
        // GPU objects are discovered from metadata only: no call-target walk
        // and no decode gate, because the caller stores whatever the decoder
        // produces (an empty decode becomes an unsupported unit).
        let suppressed: BTreeSet<u64> = materialized
            .functions
            .iter()
            .filter(|row| row.user_removed)
            .map(|row| row.address.0)
            .collect();
        let mut found: BTreeMap<u64, FunctionRow> = BTreeMap::new();
        for (address, size) in gpu_function_starts(binary) {
            if found.len() >= MAX_DISCOVERED_FUNCTIONS {
                break;
            }
            if address == 0 || suppressed.contains(&address) {
                continue;
            }
            if !is_executable(fmt, address) || materialized.data_item_at(address).is_some() {
                continue;
            }
            found.insert(
                address,
                gpu_function_row(
                    binary,
                    materialized.function(Address(address)),
                    address,
                    size,
                ),
            );
        }
        // User-defined functions survive a rebuild.
        for function in materialized
            .functions
            .iter()
            .filter(|row| row.origin == FunctionOrigin::User)
        {
            found
                .entry(function.address.0)
                .or_insert_with(|| function.clone());
        }
        return Ok(found.into_values().collect());
    }
    let relocation_table = crate::build_relocation_table(binary);
    let symbols = crate::collect_analysis_symbols(binary, &relocation_table);
    let mut starts: Vec<(u64, u64, bool)> =
        crate::discover_function_starts(fmt, fmt.architecture(), &symbols);
    for function in materialized.functions.iter().filter(|row| row.is_live()) {
        let (max_bytes, heuristic) = function_limit(function);
        starts.push((function.address.0, max_bytes as u64, heuristic));
    }
    starts.sort_by_key(|(address, _, _)| *address);
    starts.dedup_by_key(|(address, _, _)| *address);

    let suppressed: BTreeSet<u64> = materialized
        .functions
        .iter()
        .filter(|row| row.user_removed)
        .map(|row| row.address.0)
        .collect();

    let mut found: BTreeMap<u64, FunctionRow> = BTreeMap::new();
    let mut queue: VecDeque<(u64, u64, bool)> = starts.iter().copied().collect();
    let mut visited: BTreeSet<u64> = BTreeSet::new();

    while let Some((address, size, heuristic)) = queue.pop_front() {
        if found.len() >= MAX_DISCOVERED_FUNCTIONS {
            break;
        }
        if address == 0 || !visited.insert(address) {
            continue;
        }
        if suppressed.contains(&address) {
            continue;
        }
        if !is_executable(fmt, address) || materialized.data_item_at(address).is_some() {
            continue;
        }
        let decoded = match crate::disassemble_function_for_cfg(
            fmt,
            address,
            size.max(64) as usize,
            heuristic,
        ) {
            Ok(instructions) => instructions,
            Err(_) => continue,
        };
        found.insert(
            address,
            function_row_for(binary, materialized, address, &symbols),
        );
        for (target, _) in crate::extract_internal_call_targets(&decoded, fmt) {
            if !visited.contains(&target) {
                queue.push_back((target, 4096, true));
            }
        }
        for target in crate::discover_materialized_internal_targets(&decoded, fmt) {
            if !visited.contains(&target) {
                queue.push_back((target, 4096, true));
            }
        }
    }

    // User-defined functions survive a rebuild.
    for function in materialized
        .functions
        .iter()
        .filter(|row| row.origin == FunctionOrigin::User)
    {
        found
            .entry(function.address.0)
            .or_insert_with(|| function.clone());
    }

    Ok(found.into_values().collect())
}

fn function_row_for(
    binary: &Binary<'_>,
    materialized: &Materialized,
    address: u64,
    symbols: &[hexray_core::Symbol],
) -> FunctionRow {
    if let Some(existing) = materialized.function(Address(address)) {
        if existing.origin == FunctionOrigin::User {
            return existing.clone();
        }
    }
    let symbol = crate::find_preferred_symbol_at(symbols, address)
        .filter(|symbol| symbol.is_function() && symbol.size > 0 && symbol.address == address);
    FunctionRow {
        address: Address(address),
        declared_end: symbol.map(|symbol| Address(address.saturating_add(symbol.size))),
        bounds_origin: if symbol.is_some() {
            BoundsOrigin::Symbol
        } else if Some(address) == binary.as_format().entry_point() {
            BoundsOrigin::Entry
        } else {
            BoundsOrigin::Heuristic
        },
        origin: FunctionOrigin::Auto,
        excluded: false,
        user_removed: false,
        present: true,
    }
}

fn is_executable(fmt: &dyn BinaryFormat, address: u64) -> bool {
    fmt.executable_sections().any(|section| {
        let start = section.virtual_address();
        let end = start.saturating_add(section.size());
        address >= start && address < end
    })
}

/// Convert persisted `function_overrides` into decoder-ready signatures.
fn build_signature_overrides(
    materialized: &Materialized,
    arch: Architecture,
) -> Result<BTreeMap<u64, hexray_analysis::FunctionSignature>> {
    let mut out = BTreeMap::new();
    let fallback_convention = match arch {
        Architecture::Arm64 => hexray_analysis::CallingConvention::Aarch64,
        Architecture::RiscV64 | Architecture::RiscV32 => hexray_analysis::CallingConvention::RiscV,
        _ => {
            if materialized.image.format == "pe" {
                hexray_analysis::CallingConvention::Win64
            } else {
                hexray_analysis::CallingConvention::SystemV
            }
        }
    };

    for (address, row) in &materialized.function_overrides {
        if row.signature.is_none() && row.calling_convention.is_none() {
            continue;
        }
        let mut signature = match &row.signature {
            Some(prototype) => prototype_to_signature(prototype, fallback_convention)
                .with_context(|| format!("signature override for {}", address.to_hex()))?,
            None => hexray_analysis::FunctionSignature::new(fallback_convention),
        };
        if let Some(name) = &row.calling_convention {
            signature.convention = calling_convention_from_name(name).ok_or_else(|| {
                anyhow::anyhow!(
                    "unknown calling convention '{name}' for {} (use systemv, win64, aarch64 or riscv)",
                    address.to_hex()
                )
            })?;
        }
        out.insert(address.0, signature);
    }
    Ok(out)
}

fn calling_convention_from_name(name: &str) -> Option<hexray_analysis::CallingConvention> {
    Some(match name.trim().to_ascii_lowercase().as_str() {
        "systemv" | "sysv" | "cdecl" => hexray_analysis::CallingConvention::SystemV,
        "win64" | "msx64" | "microsoft" => hexray_analysis::CallingConvention::Win64,
        "aarch64" | "aapcs64" | "aapcs" => hexray_analysis::CallingConvention::Aarch64,
        "riscv" | "riscv64" => hexray_analysis::CallingConvention::RiscV,
        _ => return None,
    })
}

fn prototype_to_signature(
    prototype: &str,
    convention: hexray_analysis::CallingConvention,
) -> Result<hexray_analysis::FunctionSignature> {
    let header = format!("{};", prototype.trim().trim_end_matches(';'));
    let database = hexray_types::parser::parse_header(&header)
        .map_err(|error| anyhow::anyhow!("'{prototype}' is not a C function prototype: {error}"))?;
    let Some(name) = database.function_names().next().map(str::to_string) else {
        bail!("'{prototype}' does not declare a function");
    };
    let Some(declared) = database.get_function(&name) else {
        bail!("'{prototype}' does not declare a function");
    };

    let return_type = param_type_from_ctype(&declared.return_type);
    let mut parameters = Vec::new();
    let registers = convention.integer_arg_registers();
    for (index, parameter) in declared.parameters.iter().enumerate() {
        let location = match registers.get(index) {
            Some(register) => hexray_analysis::ParameterLocation::IntegerRegister {
                name: (*register).to_string(),
                index,
            },
            None => hexray_analysis::ParameterLocation::Stack {
                offset: 16 + 8 * (index as i64 - registers.len() as i64),
            },
        };
        parameters.push(hexray_analysis::Parameter {
            name: parameter.0.clone(),
            param_type: param_type_from_ctype(&parameter.1),
            location,
            type_confidence: u8::MAX,
        });
    }

    let mut signature = hexray_analysis::FunctionSignature::new(convention);
    signature.return_type = return_type.clone();
    signature.has_return = return_type != hexray_analysis::ParamType::Void;
    signature.is_variadic = declared.variadic;
    signature.parameters = parameters;
    signature.return_confidence = u8::MAX;
    Ok(signature)
}

fn param_type_from_ctype(ty: &hexray_types::CType) -> hexray_analysis::ParamType {
    use hexray_analysis::ParamType;
    use hexray_types::CType;
    match ty {
        CType::Void => ParamType::Void,
        CType::Int(int) => {
            let bits = u8::try_from(int.size.saturating_mul(8)).unwrap_or(64);
            if int.signed {
                ParamType::SignedInt(bits)
            } else {
                ParamType::UnsignedInt(bits)
            }
        }
        CType::Float(float) => {
            ParamType::Float(u8::try_from(float.size.saturating_mul(8)).unwrap_or(64))
        }
        CType::Pointer(inner) => match param_type_from_ctype(inner) {
            ParamType::Void => ParamType::Pointer,
            other => ParamType::TypedPointer(Box::new(other)),
        },
        CType::Array(array) => {
            ParamType::TypedPointer(Box::new(param_type_from_ctype(&array.element)))
        }
        other => ParamType::Named(ctype_display(other)),
    }
}

fn ctype_display(ty: &hexray_types::CType) -> String {
    use hexray_types::CType;
    match ty {
        CType::Void => "void".to_string(),
        CType::Int(int) => format!(
            "{}{}",
            if int.signed { "int" } else { "uint" },
            int.size * 8
        ),
        CType::Float(float) => format!("float{}", float.size * 8),
        CType::Pointer(inner) => format!("{}*", ctype_display(inner)),
        CType::Array(array) => format!("{}[]", ctype_display(&array.element)),
        CType::Struct(structure) => format!(
            "struct {}",
            structure.name.as_deref().unwrap_or("<anonymous>")
        ),
        CType::Union(union) => format!("union {}", union.name.as_deref().unwrap_or("<anonymous>")),
        CType::Enum(enumeration) => {
            format!(
                "enum {}",
                enumeration.name.as_deref().unwrap_or("<anonymous>")
            )
        }
        CType::Function(function) => format!("{} (*)()", ctype_display(&function.return_type)),
        CType::Typedef(alias) => alias.name.clone(),
        CType::Named(name) => name.clone(),
    }
}

fn build_variable_overrides(
    materialized: &Materialized,
    _functions: &[FunctionRow],
) -> BTreeMap<u64, Vec<hexray_analysis::VariableOverride>> {
    use hexray_analysis::VariableOverrideLocator;

    let mut out: BTreeMap<u64, Vec<hexray_analysis::VariableOverride>> = BTreeMap::new();
    for row in &materialized.variable_overrides {
        let locator = match &row.locator {
            VariableLocator::Parameter { index } => VariableOverrideLocator::Parameter(*index),
            VariableLocator::Stack { offset } => {
                let Ok(parsed) = offset.parse::<i64>() else {
                    continue;
                };
                VariableOverrideLocator::Stack(parsed)
            }
            VariableLocator::Expression { generation: _, key } => {
                let Some((kind, rest)) = key.split_once(':') else {
                    continue;
                };
                let mut parts = rest.split(':');
                let Ok(index) = parts.next().unwrap_or_default().parse::<u32>() else {
                    continue;
                };
                let Ok(size) = parts.next().unwrap_or_default().parse::<u8>() else {
                    continue;
                };
                match kind {
                    "register" => VariableOverrideLocator::Register {
                        index: u16::try_from(index).unwrap_or(u16::MAX),
                        size,
                    },
                    "temp" => VariableOverrideLocator::Temp { index, size },
                    _ => continue,
                }
            }
        };
        out.entry(row.function.0)
            .or_default()
            .push(hexray_analysis::VariableOverride {
                locator,
                name: row.name.clone(),
                type_name: row.type_name.clone(),
            });
    }
    out
}

/// Load DWARF for a project without touching the filesystem: sections come
/// from the effective image, and split-DWARF sidecars come from stored
/// resources only.
fn load_project_dwarf(
    materialized: &Materialized,
    fmt: &dyn BinaryFormat,
) -> Result<Option<hexray_formats::dwarf::DebugInfo>> {
    let main = crate::parse_dwarf_from_sections(fmt);
    let address_size = match fmt.architecture() {
        Architecture::X86 | Architecture::RiscV32 => 4u8,
        _ => 8u8,
    };
    if let Some(sidecar) = materialized
        .dwarf_sidecars
        .first()
        .and_then(|bytes| crate::parse_split_dwarf_bytes(bytes, fmt, address_size))
    {
        return Ok(Some(sidecar));
    }
    Ok(main)
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

fn cfg_from_records(
    data: &hexray_db::store::CfgData,
    instructions: &[Instruction],
) -> Result<hexray_core::ControlFlowGraph> {
    use hexray_core::{BasicBlock, BasicBlockId, ControlFlowGraph};
    let mut decoded: BTreeMap<u64, &Instruction> = BTreeMap::new();
    for instruction in instructions {
        decoded.insert(instruction.address, instruction);
    }
    let entry = data
        .blocks
        .first()
        .map(|block| BasicBlockId(block.id))
        .unwrap_or(BasicBlockId::ENTRY);
    let mut cfg = ControlFlowGraph::new(entry);
    for payload in &data.blocks {
        let mut block = BasicBlock::new(BasicBlockId(payload.id), payload.start.0);
        block.end = payload.end.0;
        for address in data.block_instructions(payload.id) {
            if let Some(instruction) = decoded.get(&address.0) {
                block.push_instruction((*instruction).clone());
            }
        }
        block.terminator = payload.terminator.clone();
        cfg.add_block(block);
    }
    for (from, to, kind) in &data.edges {
        match kind {
            EdgeKind::Normal => cfg.add_edge(BasicBlockId(*from), BasicBlockId(*to)),
            EdgeKind::Unwind => cfg.add_eh_edge(BasicBlockId(*from), BasicBlockId(*to)),
        }
    }
    Ok(cfg)
}

#[derive(Debug, Default)]
struct RenderReport {
    rendered: usize,
    reused: usize,
    partial: usize,
    unsupported: usize,
}

fn render_functions(
    database: &mut Database,
    materialized: &Materialized,
    targets: &[Address],
    config: &RenderConfig,
    force: bool,
) -> Result<RenderReport> {
    let mut report = RenderReport::default();
    let selection = selection_from_image(&materialized.image);
    let parsed = parse_image(&materialized.image_bytes, &selection)?;
    let binary = &parsed.binary;
    if !supports_pseudo_c(binary.as_format().architecture()) {
        // GPU code objects have no pseudo-C path. Mark every target's render
        // unit unsupported so the reason is stored, `db info` stays partial,
        // and `db query decompile` can report the same reason instead of
        // asking for a rebuild that can never succeed.
        let fingerprint = config.fingerprint();
        let mut batch = AnalysisBatch::default();
        for address in targets {
            let Some(function) = materialized.function(*address) else {
                continue;
            };
            if !function.is_live() {
                continue;
            }
            let key = UnitKey::function_render(*address, fingerprint);
            batch.units.push(UnitPublish {
                key,
                expected_generation: materialized.unit_generation(&key),
                state: AnalysisState::Unsupported,
                input_fingerprint: fingerprint,
                dependencies_complete: true,
                diagnostics: vec![Diagnostic::new(
                    "gpu-pseudo-c-unsupported",
                    Severity::Info,
                    "pseudo-C is unsupported for GPU code objects",
                )],
                dependencies: Vec::new(),
                payload: AnalysisPayload::FunctionRender(Box::new(RenderPayload {
                    function: *address,
                    config_fingerprint: fingerprint,
                    text: String::new(),
                })),
            });
        }
        if !batch.units.is_empty() {
            db(database.publish(materialized.revision, &batch))?;
        }
        return Ok(RenderReport {
            unsupported: targets.len(),
            ..Default::default()
        });
    }
    // Rebuild the render context from the state passed in: callers reload the
    // snapshot after publishing a CFG batch, so this never mixes instructions
    // from before a rebuild with the text produced after it.
    let type_database = project_type_database(materialized, binary)?;
    let debug_info = load_project_dwarf(materialized, binary.as_format())?;
    let project = crate::AnalysisProject::new(&materialized.image.selector_json).ok();
    let type_database = &type_database;
    let debug_info = debug_info.as_ref();
    let project = project.as_ref();
    let fingerprint = config.fingerprint();
    let decompiler_config = build_decompiler_config(
        &config.optimization_level,
        &config.enable_passes,
        &config.disable_passes,
    )?;
    let name_pairs: Vec<(u64, String)> = materialized
        .names
        .iter()
        .map(|(address, name)| (address.0, name.clone()))
        .collect();
    let signature_overrides =
        build_signature_overrides(materialized, binary.as_format().architecture())?;
    let variable_overrides = build_variable_overrides(materialized, &materialized.functions);
    let overlay = materialized.comment_overlay();

    let mut batch = AnalysisBatch::default();
    for address in targets {
        let Some(function) = materialized.function(*address) else {
            continue;
        };
        if !function.is_live() {
            continue;
        }
        let key = UnitKey::function_render(*address, fingerprint);
        let stored = materialized.decompiled.get(&(address.0, fingerprint));
        let current = materialized.unit_state(&key) == Some(AnalysisState::Current);
        if !force && current && stored.is_some() {
            report.reused += 1;
            continue;
        }
        let Some(instructions) = materialized.instructions.get(&address.0) else {
            report.partial += 1;
            continue;
        };
        let Some(cfg_data) = materialized.cfgs.get(&address.0) else {
            report.partial += 1;
            continue;
        };
        let cfg = match cfg_from_records(cfg_data, instructions) {
            Ok(cfg) => cfg,
            Err(error) => {
                report.unsupported += 1;
                eprintln!("warning: {} CFG is unreadable: {error}", address.to_hex());
                continue;
            }
        };
        let name = function_display_name(materialized, function);
        let (max_bytes, stop_after_first_return) = function_limit(function);
        let inputs = AnalysisInputs {
            project,
            type_db: Some(type_database),
            config: Some(&decompiler_config),
            diagnostics: false,
            debug_info,
            signature_override: signature_overrides.get(&address.0),
            variable_overrides: variable_overrides
                .get(&address.0)
                .map(Vec::as_slice)
                .unwrap_or(&[]),
            names: &name_pairs,
        };
        let analyzed = analyze_replay(
            binary,
            ReplayInput {
                start: address.0,
                name,
                symbol_kind: None,
                instructions: instructions.clone(),
                cfg,
                max_bytes,
                stop_after_first_return,
            },
            &inputs,
        )?;
        let rendered = render_function(
            analyzed,
            &RenderOptions {
                show_addresses: config.show_addresses,
                comments: Some(overlay.clone()),
            },
        )?;
        batch.units.push(UnitPublish {
            key,
            expected_generation: materialized.unit_generation(&key),
            state: AnalysisState::Current,
            input_fingerprint: fingerprint,
            dependencies_complete: true,
            diagnostics: Vec::new(),
            dependencies: vec![
                Dependency {
                    kind: DependencyKind::Range,
                    key: "bytes".to_string(),
                    range: hexray_db::AddressRange::new(*address, 1).ok(),
                    target_generation: 0,
                },
                Dependency {
                    kind: DependencyKind::Name,
                    key: format!("address:{:x}", address.0),
                    range: None,
                    target_generation: 0,
                },
            ],
            payload: AnalysisPayload::FunctionRender(Box::new(RenderPayload {
                function: *address,
                config_fingerprint: fingerprint,
                text: rendered.text,
            })),
        });
        report.rendered += 1;
    }

    if !batch.units.is_empty() {
        db(database.publish(materialized.revision, &batch))?;
    }
    Ok(report)
}

fn render_config_for(
    materialized: &Materialized,
    type_database: &TypeDatabase,
    flags: &RenderFlags,
) -> RenderConfig {
    RenderConfig {
        optimization_level: flags.opt_level.clone(),
        enable_passes: flags.enable_passes.clone(),
        disable_passes: flags.disable_passes.clone(),
        show_addresses: flags.show_addresses,
        indent: "    ".to_string(),
        type_snapshot_sha256: type_snapshot_digest(type_database),
        engine_fingerprint: materialized.engine,
    }
}

// ---------------------------------------------------------------------------
// `db info`, `db analyze`, `db check`, `db backup`, `db export-binary`
// ---------------------------------------------------------------------------

fn info(path: &Path, json_output: bool) -> Result<()> {
    let mut database = db(Database::open(path, OpenMode::ReadOnly))?;
    let snapshot = db(database.snapshot())?;
    let info = db(snapshot.info())?;
    if json_output {
        println!("{}", serde_json::to_string_pretty(&info)?);
        return Ok(());
    }
    println!("Project:        {}", path.display());
    println!("UUID:           {}", info.uuid);
    println!("Revision:       {}", info.revision.0);
    println!("Created:        {}", info.created_at);
    println!("Schema version: {}", info.schema_version);
    println!(
        "State:          {}",
        match info.overall_state {
            OverallState::Ready => "ready",
            OverallState::Partial => "partial (some analysis is pending or stale)",
            OverallState::Pending => "pending (no analysis yet)",
        }
    );
    println!(
        "Input:          {} bytes sha256 {}",
        info.source_size,
        hexray_db::hex_encode(&info.source_sha256[..8])
    );
    println!(
        "Image:          {} {}",
        info.image.format, info.image.architecture
    );
    println!("Selector:       {}", info.image.selector_json.trim());
    println!(
        "Entry:          {}",
        info.image
            .entry_address
            .map(|address| address.to_hex())
            .unwrap_or_else(|| "-".to_string())
    );
    println!("Mappings:       {}", info.image.mappings.len());
    println!("Sections:       {}", info.image.sections.len());
    println!("Functions:      {}", info.function_count);
    println!("Instructions:   {}", info.instruction_count);
    println!("Strings:        {}", info.string_count);
    println!("Xrefs:          {}", info.xref_count);
    println!("Patches:        {}", info.patch_count);
    println!("Debug sidecars: {}", info.debug_sidecars);
    println!("Undo depth:     {}", info.undo_depth);
    println!("Redo depth:     {}", info.redo_depth);
    if info.engine_fingerprint != info.stored_engine_fingerprint {
        println!(
            "Engine:         changed since creation ({} -> {}); stored results are stale",
            hexray_db::hex_encode(&info.stored_engine_fingerprint[..8]),
            hexray_db::hex_encode(&info.engine_fingerprint[..8])
        );
    }
    Ok(())
}

fn analyze(
    path: &Path,
    function: Option<String>,
    force: bool,
    render: bool,
    render_flags: &RenderFlags,
    limits: &InputLimits,
    json_output: bool,
) -> Result<()> {
    let mut database = db(Database::open(path, OpenMode::ReadWrite))?;
    let mut request = AnalyzeRequest::new();
    request.function = function;
    request.force = force;
    request.limits = limits.clone();
    if render {
        let materialized = load_materialized(&mut database)?;
        let selection = selection_from_image(&materialized.image);
        let parsed = parse_image(&materialized.image_bytes, &selection)?;
        let type_database = project_type_database(&materialized, &parsed.binary)?;
        request.render = Some(render_config_for(
            &materialized,
            &type_database,
            render_flags,
        ));
    }
    let report = run_analysis(&mut database, &request)?;
    let revision = db(database.revision())?;

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "revision": revision.0,
                "discovered": report.discovered,
                "analyzed": report.analyzed,
                "reused": report.reused,
                "rendered": report.rendered,
                "reused_render": report.reused_render,
                "partial": report.partial,
                "unsupported": report.unsupported,
                "failed": report.failed,
                "skipped": report.stale_skipped,
            }))?
        );
        return Ok(());
    }
    println!(
        "Analyzed {} function(s), reused {}, rendered {} (reused {}). Revision {}.",
        report.analyzed, report.reused, report.rendered, report.reused_render, revision.0
    );
    if report.partial + report.unsupported + report.failed > 0 {
        println!(
            "Incomplete: {} partial, {} unsupported, {} failed",
            report.partial, report.unsupported, report.failed
        );
    }
    Ok(())
}

fn check(path: &Path, deep: bool, json_output: bool) -> Result<()> {
    let database = db(Database::open(path, OpenMode::ReadOnly))?;
    let report = db(database.check(deep))?;
    if json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("quick_check:        {}", report.quick_check);
        println!(
            "foreign_key_check:  {}",
            report.foreign_key_violations.len()
        );
        for violation in &report.foreign_key_violations {
            println!("  {violation}");
        }
        if deep {
            println!("source digest:      {}", report.source_digest_matches);
            println!("patch ranges:       {}", report.patch_ranges_valid);
        }
        for problem in &report.problems {
            println!("problem:            {problem}");
        }
    }
    if !report.passed() {
        bail!("database check failed");
    }
    Ok(())
}

fn backup(path: &Path, output: &Path) -> Result<()> {
    let database = db(Database::open(path, OpenMode::ReadOnly))?;
    db(database.backup(output))?;
    println!("Backed up {} to {}", path.display(), output.display());
    Ok(())
}

/// Write a binary with every recorded patch applied.
///
/// The output keeps the original length. No checksum or signature is
/// recomputed: the file may not load if it was signed.
fn export_binary(path: &Path, output: &Path) -> Result<()> {
    if same_file(path, output)? {
        bail!("refusing to write the export over the project file");
    }
    let mut database = db(Database::open(path, OpenMode::ReadOnly))?;
    let (source, patches, original_path) = {
        let snapshot = db(database.snapshot())?;
        (
            db(snapshot.source_bytes())?,
            db(snapshot.patches())?,
            db(snapshot.original_path())?,
        )
    };
    if let Ok(original) = std::fs::canonicalize(&original_path) {
        if let Ok(target) = std::fs::canonicalize(output) {
            if original == target {
                bail!("refusing to overwrite the original input");
            }
        }
    }
    let exported = effective_source(&source, &patches)?;
    if exported.len() != source.len() {
        bail!("patched export changed the input length");
    }
    if output.exists() {
        bail!("destination already exists: {}", output.display());
    }
    let parent = output
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    let staging = tempfile::Builder::new()
        .prefix(".hexray-export-")
        .tempdir_in(&parent)
        .map_err(|error| anyhow::anyhow!("{error}"))?;
    let staged = staging.path().join("export.bin");
    {
        use std::io::Write;
        let mut file = std::fs::File::create(&staged)
            .with_context(|| format!("failed to create {}", staged.display()))?;
        file.write_all(&exported)?;
        file.sync_all()?;
    }
    std::fs::hard_link(&staged, output)
        .map_err(|error| anyhow::anyhow!("failed to publish {}: {error}", output.display()))?;
    println!(
        "Wrote {} ({} bytes, {} patch region(s)). Signatures and checksums were not repaired.",
        output.display(),
        exported.len(),
        patches.len()
    );
    Ok(())
}

fn same_file(left: &Path, right: &Path) -> Result<bool> {
    let left = std::fs::canonicalize(left).unwrap_or_else(|_| left.to_path_buf());
    let right = std::fs::canonicalize(right).unwrap_or_else(|_| right.to_path_buf());
    Ok(left == right)
}

// ---------------------------------------------------------------------------
// Patchable regions
// ---------------------------------------------------------------------------

/// Section names that hold metadata a byte patch must never touch: rewriting
/// them would invalidate the layout the project validated at creation.
fn is_metadata_section(name: &str) -> bool {
    const PREFIXES: &[&str] = &[
        ".debug",
        ".zdebug",
        ".symtab",
        ".strtab",
        ".dynsym",
        ".dynstr",
        ".gnu",
        ".hash",
        ".rela",
        ".rel",
        ".relocs",
        ".dynamic",
        ".interp",
        ".note",
        ".comment",
        ".eh_frame",
        ".gcc_except_table",
        ".ARM.exidx",
        ".ARM.extab",
        ".llvm",
        ".nv_debug",
        "__debug",
        "__symbol",
        "__reloc",
        "__linkedit",
        "__dysymtab",
        ".idata",
        ".edata",
        ".rsrc",
        ".reloc",
        ".tls",
    ];
    PREFIXES.iter().any(|prefix| name.starts_with(prefix))
        || name.contains("reloc")
        || name.contains("import")
        || name.contains("export")
}

/// File ranges (relative to the analyzed image) that may be patched.
fn patchable_ranges(materialized: &Materialized, fmt: &dyn BinaryFormat) -> Vec<(FileOffset, u64)> {
    let header_ranges = header_file_ranges(fmt, materialized);
    let mut candidates: Vec<(FileOffset, u64)> = Vec::new();

    let mut any_section = false;
    for section in fmt.sections() {
        if !section.is_allocated() || section.size() == 0 {
            continue;
        }
        any_section = true;
        let name = section.name();
        if is_metadata_section(name) {
            continue;
        }
        if !fmt
            .executable_sections()
            .any(|executable| std::ptr::eq(executable, section))
        {
            // Non-executable data sections are still patchable; only skip
            // sections with no file payload.
        }
        candidates.push((FileOffset(section.file_offset()), section.size()));
    }

    if !any_section {
        // Sectionless images: program headers are the only layout truth.
        for mapping in &materialized.image.mappings {
            let Some(offset) = mapping.file_offset else {
                continue;
            };
            if mapping.file_size == 0 {
                continue;
            }
            candidates.push((offset, mapping.file_size));
        }
    }

    // Never allow a patch to reach into container structure.
    let mut allowed = Vec::new();
    for (start, length) in candidates {
        let end = start.0.saturating_add(length);
        let mut cursor = start.0;
        let mut blocked: Vec<(u64, u64)> = header_ranges
            .iter()
            .filter(|(header_start, header_len)| {
                let header_end = header_start.saturating_add(*header_len);
                *header_start < end && cursor < header_end
            })
            .map(|(header_start, header_len)| (*header_start, header_start + header_len))
            .collect();
        blocked.sort_unstable();
        for (block_start, block_end) in blocked {
            if block_start > cursor {
                allowed.push((FileOffset(cursor), block_start - cursor));
            }
            cursor = cursor.max(block_end);
        }
        if cursor < end {
            allowed.push((FileOffset(cursor), end - cursor));
        }
    }
    allowed
}

/// Container structure that a patch must not modify.
fn header_file_ranges(fmt: &dyn BinaryFormat, _materialized: &Materialized) -> Vec<(u64, u64)> {
    let mut ranges = Vec::new();
    let sections: Vec<_> = fmt.sections().collect();
    let first_section_offset = sections
        .iter()
        .map(|section| section.file_offset())
        .min()
        .unwrap_or(u64::MAX);
    if first_section_offset != u64::MAX && first_section_offset > 0 {
        ranges.push((0u64, first_section_offset));
    }
    ranges
}

/// Translate a user-supplied patch target into a source file offset.
fn resolve_patch_offset(
    materialized: &Materialized,
    fmt: &dyn BinaryFormat,
    text: &str,
) -> Result<FileOffset> {
    let address = parse_address(text)?;
    let image_offset = if let Some(mapping) = materialized
        .image
        .mappings
        .iter()
        .filter(|mapping| {
            address.0 >= mapping.va.0
                && address.0 < mapping.va.0.saturating_add(mapping.memory_size)
        })
        .collect::<Vec<_>>()
        .first()
    {
        let delta = address.0 - mapping.va.0;
        let Some(file_offset) = mapping.file_offset else {
            bail!(
                "{} is inside zero-fill memory with no file backing; it cannot be patched",
                address.to_hex()
            );
        };
        if delta >= mapping.file_size {
            bail!(
                "{} is beyond the file-backed part of mapping {}",
                address.to_hex(),
                mapping.name
            );
        }
        file_offset
            .0
            .checked_add(delta)
            .ok_or_else(|| anyhow::anyhow!("mapping offset overflows for {}", address.to_hex()))?
    } else {
        // A bare file offset is accepted too; it is validated below.
        address.0
    };

    let _ = fmt;
    let source_offset = materialized
        .image
        .container_offset
        .0
        .checked_add(image_offset)
        .ok_or_else(|| anyhow::anyhow!("source offset overflows"))?;
    Ok(FileOffset(source_offset))
}

/// Which image-relative file offset a source offset maps to.
fn image_file_offset(materialized: &Materialized, source_offset: FileOffset) -> Result<FileOffset> {
    source_offset
        .0
        .checked_sub(materialized.image.container_offset.0)
        .map(FileOffset)
        .ok_or_else(|| anyhow::anyhow!("patch lies before the selected image"))
}

fn require_patchable(
    materialized: &Materialized,
    fmt: &dyn BinaryFormat,
    source_offset: FileOffset,
    length: u64,
) -> Result<()> {
    let image_offset = image_file_offset(materialized, source_offset)?;
    let end = image_offset
        .0
        .checked_add(length)
        .ok_or_else(|| anyhow::anyhow!("patch range overflows at {}", image_offset.to_hex()))?;
    for (start, size) in patchable_ranges(materialized, fmt) {
        let range_end = start.0.saturating_add(size);
        if image_offset.0 >= start.0 && end <= range_end {
            return Ok(());
        }
    }
    bail!(
        "patch {}..{:#x} is not inside a patchable code or data region \
         (headers, tables, symbols and debug metadata are protected)",
        image_offset.to_hex(),
        end
    )
}

// ---------------------------------------------------------------------------
// `db query`
// ---------------------------------------------------------------------------

const LIST_LIMIT_DEFAULT: usize = 1000;
const LIST_LIMIT_MAX: usize = 10_000;
const BYTES_LIMIT: usize = 1024 * 1024;

fn list_window(limit: Option<usize>, offset: Option<usize>) -> (usize, usize) {
    let limit = limit.unwrap_or(LIST_LIMIT_DEFAULT).min(LIST_LIMIT_MAX);
    (limit, offset.unwrap_or(0))
}

fn page<T>(items: Vec<T>, limit: usize, offset: usize) -> Vec<T> {
    items.into_iter().skip(offset).take(limit).collect()
}

fn query(
    path: &Path,
    action: QueryAction,
    json_output: bool,
    allow_stale: bool,
    update: bool,
    limits: &InputLimits,
) -> Result<()> {
    if allow_stale && update {
        bail!("--allow-stale and --update are mutually exclusive");
    }

    let needs_write = update;
    let mut database = db(Database::open(
        path,
        if needs_write {
            OpenMode::ReadWrite
        } else {
            OpenMode::ReadOnly
        },
    ))?;

    let mut materialized = load_materialized(&mut database)?;

    match &action {
        QueryAction::Decompile {
            function,
            render_flags,
        } => {
            let address = resolve_function(&materialized, function)?;
            let selection = selection_from_image(&materialized.image);
            let parsed = parse_image(&materialized.image_bytes, &selection)?;
            // A GPU code object has no pseudo-C path at all, so refuse before
            // touching stored artifacts or rebuilding anything.
            if !supports_pseudo_c(parsed.binary.as_format().architecture()) {
                bail!("pseudo-C is unsupported for GPU code objects");
            }
            let type_database = project_type_database(&materialized, &parsed.binary)?;
            let config = render_config_for(&materialized, &type_database, render_flags);
            let fingerprint = config.fingerprint();
            let key = UnitKey::function_render(address, fingerprint);

            // A stored `unsupported` unit is final for this target: rebuilding
            // cannot produce pseudo-C for a GPU object, so fail with the same
            // reason the analysis recorded and do not touch the database.
            if materialized.unit_state(&key) == Some(AnalysisState::Unsupported) {
                bail!("pseudo-C is unsupported for GPU code objects");
            }

            if update {
                // Rebuild whatever is stale or missing — CFG first, then the
                // rendered text — through the same path `db analyze` uses.
                run_analysis(
                    &mut database,
                    &AnalyzeRequest {
                        function: Some(address.to_hex()),
                        force: false,
                        render: Some(config.clone()),
                        limits: limits.clone(),
                    },
                )?;
                materialized = load_materialized(&mut database)?;
            }

            let state = materialized.unit_state(&key);
            if state == Some(AnalysisState::Unsupported) {
                bail!("pseudo-C is unsupported for GPU code objects");
            }
            let stored = materialized
                .decompiled
                .get(&(address.0, fingerprint))
                .cloned();
            match stored {
                Some(text) if state == Some(AnalysisState::Current) => {
                    if json_output {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&json!({
                                "function": address.to_hex(),
                                "state": "current",
                                "config": fingerprint
                                    .iter()
                                    .map(|byte| format!("{byte:02x}"))
                                    .collect::<String>(),
                                "text": text,
                            }))?
                        );
                    } else {
                        println!("{text}");
                    }
                }
                Some(text) if allow_stale => {
                    let state = state.map(|state| state.as_str()).unwrap_or("missing");
                    if json_output {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&json!({
                                "function": address.to_hex(),
                                "state": state,
                                "stale": true,
                                "text": text,
                            }))?
                        );
                    } else {
                        println!(
                            "// stale: state is {state}; \
                             run `db query ... decompile ... --update`"
                        );
                        println!("{text}");
                    }
                }
                Some(_) => bail!(
                    "pseudo-C for this configuration is {}; pass --allow-stale to view it \
                     or --update to rebuild it",
                    state.map(|state| state.as_str()).unwrap_or("missing")
                ),
                None => {
                    if needs_write {
                        bail!("no pseudo-C was produced for this function");
                    }
                    bail!(
                        "no current pseudo-C for this configuration; \
                         re-run with `--update` (or `db analyze --render`)"
                    );
                }
            }
            return Ok(());
        }
        QueryAction::Trace { action } => {
            let selection = selection_from_image(&materialized.image);
            let parsed = parse_image(&materialized.image_bytes, &selection)?;
            return crate::commands::handle_trace_command(
                parsed.binary.as_format(),
                action.clone(),
            );
        }
        QueryAction::Emulate { action } => {
            let selection = selection_from_image(&materialized.image);
            let parsed = parse_image(&materialized.image_bytes, &selection)?;
            return crate::commands::handle_emulate_command(
                parsed.binary.as_format(),
                action.clone(),
            );
        }
        QueryAction::Signatures { action } => {
            let selection = selection_from_image(&materialized.image);
            let parsed = parse_image(&materialized.image_bytes, &selection)?;
            return crate::commands::handle_signatures_command(
                parsed.binary.as_format(),
                action.clone(),
            );
        }
        _ => {}
    }

    match action {
        QueryAction::Info { limit, offset } => {
            let (limit, offset) = list_window(limit, offset);
            let info = {
                let snapshot = db(database.snapshot())?;
                db(snapshot.info())?
            };
            if json_output {
                println!("{}", serde_json::to_string_pretty(&info)?);
            } else {
                println!("format      {}", info.image.format);
                println!("arch        {}", info.image.architecture);
                println!("bitness     {}", info.image.bitness);
                println!("endianness  {}", info.image.endianness);
                println!(
                    "abi         pointer={} long={}",
                    info.image.abi.pointer_size, info.image.abi.long_size
                );
                println!(
                    "entry       {}",
                    info.image
                        .entry_address
                        .map(|a| a.to_hex())
                        .unwrap_or_else(|| "-".into())
                );
                println!("mappings    {}", info.image.mappings.len());
                for mapping in page(info.image.mappings.clone(), limit, offset) {
                    println!(
                        "  {:<16} {} size {:#x} file {}",
                        mapping.name,
                        mapping.va.to_hex(),
                        mapping.memory_size,
                        mapping
                            .file_offset
                            .map(|offset| offset.to_hex())
                            .unwrap_or_else(|| "-".to_string())
                    );
                }
            }
        }
        QueryAction::Sections { limit, offset } => {
            let (limit, offset) = list_window(limit, offset);
            let rows = page(materialized.image.sections.clone(), limit, offset);
            if json_output {
                println!("{}", serde_json::to_string_pretty(&rows)?);
            } else {
                for section in rows {
                    println!(
                        "{:<28} {} size {:#x} file {} {}",
                        section.name,
                        section.va.to_hex(),
                        section.memory_size,
                        section
                            .file_offset
                            .map(|offset| offset.to_hex())
                            .unwrap_or_else(|| "-".to_string()),
                        section.flags
                    );
                }
            }
        }
        QueryAction::Symbols { limit, offset } => {
            let (limit, offset) = list_window(limit, offset);
            let rows = page(materialized.symbols.clone(), limit, offset);
            if json_output {
                println!("{}", serde_json::to_string_pretty(&rows)?);
            } else {
                for symbol in rows {
                    println!(
                        "{} {:<8} {:<6} {}",
                        symbol.address.to_hex(),
                        symbol.kind,
                        symbol.size,
                        symbol.name
                    );
                }
            }
        }
        QueryAction::Functions { limit, offset } => {
            let (limit, offset) = list_window(limit, offset);
            let rows: Vec<_> = page(
                materialized
                    .functions
                    .iter()
                    .filter(|row| row.is_live())
                    .cloned()
                    .collect(),
                limit,
                offset,
            );
            if json_output {
                let payload: Vec<_> = rows
                    .iter()
                    .map(|row| {
                        json!({
                            "address": row.address.to_hex(),
                            "name": function_display_name(&materialized, row),
                            "end": row.declared_end.map(|end| end.to_hex()),
                            "bounds": row.bounds_origin.as_str(),
                            "origin": row.origin.as_str(),
                            "excluded": row.excluded,
                            "state": materialized
                                .unit_state(&UnitKey::function_cfg(row.address))
                                .map(|state| state.as_str())
                                .unwrap_or("missing"),
                        })
                    })
                    .collect();
                println!("{}", serde_json::to_string_pretty(&payload)?);
            } else {
                for row in rows {
                    println!(
                        "{} {:<12} {:<9} {}",
                        row.address.to_hex(),
                        materialized
                            .unit_state(&UnitKey::function_cfg(row.address))
                            .map(|state| state.as_str())
                            .unwrap_or("missing"),
                        row.bounds_origin.as_str(),
                        function_display_name(&materialized, &row)
                    );
                }
            }
        }
        QueryAction::Disasm {
            function,
            limit,
            offset,
        } => {
            let address = resolve_function(&materialized, &function)?;
            let (limit, offset) = list_window(limit, offset);
            let instructions = materialized
                .instructions
                .get(&address.0)
                .cloned()
                .unwrap_or_default();
            let rows = page(instructions, limit, offset);
            if json_output {
                println!("{}", serde_json::to_string_pretty(&rows)?);
            } else {
                for instruction in rows {
                    println!(
                        "{}  {:<8} {:<24} {}",
                        Address(instruction.address).to_hex(),
                        instruction
                            .bytes
                            .iter()
                            .map(|byte| format!("{byte:02x}"))
                            .collect::<String>(),
                        instruction.mnemonic,
                        instruction
                            .operands
                            .iter()
                            .map(|operand| format!("{operand}"))
                            .collect::<Vec<_>>()
                            .join(", ")
                    );
                }
            }
        }
        QueryAction::Cfg {
            function,
            dot,
            html,
        } => {
            let address = resolve_function(&materialized, &function)?;
            let Some(instructions) = materialized.instructions.get(&address.0) else {
                bail!(
                    "no decoded instructions for {}; run `db analyze`",
                    address.to_hex()
                );
            };
            let Some(data) = materialized.cfgs.get(&address.0) else {
                bail!("no CFG for {}; run `db analyze`", address.to_hex());
            };
            let cfg = cfg_from_records(data, instructions)?;
            let name = materialized
                .function(address)
                .map(|row| function_display_name(&materialized, row))
                .unwrap_or_else(|| format!("sub_{:x}", address.0));
            if dot {
                println!(
                    "{}",
                    hexray_analysis::CfgDotExporter::new().export_to_string(&cfg, &name)
                );
            } else if html {
                println!(
                    "{}",
                    hexray_analysis::CfgHtmlExporter::new().export_to_string(&cfg, &name)
                );
            } else if json_output {
                println!("{}", serde_json::to_string_pretty(data)?);
            } else {
                println!("CFG {} ({} blocks)", name, data.blocks.len());
                for block in &data.blocks {
                    println!(
                        "  bb{:<4} {}..{} {:?}",
                        block.id,
                        block.start.to_hex(),
                        block.end.to_hex(),
                        block.terminator
                    );
                    for address in data.block_instructions(block.id) {
                        println!("      {}", address.to_hex());
                    }
                }
                for (from, to, kind) in &data.edges {
                    println!("  edge bb{from} -> bb{to} ({})", kind.as_str());
                }
            }
        }
        QueryAction::Xrefs {
            address,
            limit,
            offset,
        } => {
            let address = parse_address(&address)?;
            let (limit, offset) = list_window(limit, offset);
            let mut rows: Vec<XrefRow> = materialized
                .xrefs
                .iter()
                .filter(|row| row.from == address || row.to == address)
                .cloned()
                .collect();
            rows.sort_by_key(|row| (row.from.0, row.to.0));
            let rows = page(rows, limit, offset);
            if json_output {
                println!("{}", serde_json::to_string_pretty(&rows)?);
            } else {
                for row in rows {
                    println!(
                        "{} -> {} {} ({})",
                        row.from.to_hex(),
                        row.to.to_hex(),
                        row.kind.as_str(),
                        row.owner
                            .map(|owner| owner.to_hex())
                            .unwrap_or_else(|| "image".into())
                    );
                }
            }
        }
        QueryAction::Callgraph {
            function,
            dot,
            html,
        } => {
            let root = match &function {
                Some(reference) => Some(resolve_function(&materialized, reference)?),
                None => None,
            };
            let mut graph = hexray_analysis::CallGraph::new();
            for row in materialized.functions.iter().filter(|row| row.is_live()) {
                graph.add_node(
                    row.address.0,
                    Some(function_display_name(&materialized, row)),
                    false,
                );
            }
            for row in &materialized.xrefs {
                if row.kind != XrefKind::Call {
                    continue;
                }
                if let Some(root) = root {
                    if row.from != root {
                        continue;
                    }
                }
                graph.add_call(
                    row.from.0,
                    row.to.0,
                    hexray_analysis::CallSite {
                        call_address: row.from.0,
                        call_type: hexray_analysis::CallType::Direct,
                    },
                );
            }
            if dot {
                println!(
                    "{}",
                    hexray_analysis::CallGraphDotExporter::new().export_to_string(&graph)
                );
            } else if html {
                println!(
                    "{}",
                    hexray_analysis::CallGraphHtmlExporter::new().export_to_string(&graph)
                );
            } else if json_output {
                println!(
                    "{}",
                    hexray_analysis::CallGraphJsonExporter::new().export_to_string(&graph)
                );
            } else {
                for row in materialized
                    .xrefs
                    .iter()
                    .filter(|row| row.kind == XrefKind::Call)
                {
                    if let Some(root) = root {
                        if row.from != root {
                            continue;
                        }
                    }
                    let target = materialized
                        .function(row.to)
                        .map(|function| function_display_name(&materialized, function))
                        .unwrap_or_else(|| format!("sub_{:x}", row.to.0));
                    println!("{} -> {target}", Address(row.from.0).to_hex());
                }
            }
        }
        QueryAction::Strings { limit, offset } => {
            let (limit, offset) = list_window(limit, offset);
            let rows = page(materialized.strings.clone(), limit, offset);
            if json_output {
                println!("{}", serde_json::to_string_pretty(&rows)?);
            } else {
                for row in rows {
                    println!(
                        "{} {:<6} {}",
                        row.address.to_hex(),
                        row.encoding.as_str(),
                        row.text
                            .unwrap_or_else(|| String::from_utf8_lossy(&row.bytes).into_owned())
                    );
                }
            }
        }
        QueryAction::Bytes { address, length } => {
            let address = parse_address(&address)?;
            if length as usize > BYTES_LIMIT {
                bail!("byte requests are limited to {BYTES_LIMIT} bytes");
            }
            let bytes = read_image_bytes(&materialized, address, length)?;
            if json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "address": address.to_hex(),
                        "length": bytes.len(),
                        "hex": bytes.iter().map(|byte| format!("{byte:02x}")).collect::<String>(),
                    }))?
                );
            } else {
                for (index, chunk) in bytes.chunks(16).enumerate() {
                    let offset = address.0 as usize + index * 16;
                    let hex: Vec<String> = chunk.iter().map(|byte| format!("{byte:02x}")).collect();
                    println!("{:016x}  {}", offset, hex.join(" "));
                }
            }
        }
        QueryAction::Variables { function } => {
            let address = resolve_function(&materialized, &function)?;
            let rows: Vec<_> = materialized
                .variable_overrides
                .iter()
                .filter(|row| row.function == address)
                .collect();
            if json_output {
                println!("{}", serde_json::to_string_pretty(&rows)?);
            } else {
                println!("Editable variable locators for {}", address.to_hex());
                for row in rows {
                    println!(
                        "  {} name={} type={}",
                        row.locator.to_key(),
                        row.name.clone().unwrap_or_else(|| "-".into()),
                        row.type_name.clone().unwrap_or_else(|| "-".into())
                    );
                }
                // Doubled braces because these are `println!` literals, not
                // format placeholders.
                println!(r#"  {{"kind":"parameter","index":0}}"#);
                println!(r#"  {{"kind":"stack","offset":"-16"}}"#);
                println!(r#"  {{"kind":"expression","generation":1,"key":"register:0:4"}}"#);
            }
        }
        QueryAction::Types { limit, offset } => {
            let (limit, offset) = list_window(limit, offset);
            let rows = page(materialized.types.clone(), limit, offset);
            if json_output {
                println!("{}", serde_json::to_string_pretty(&rows)?);
            } else {
                for row in rows {
                    println!("{:<20} {:<10} {}", row.name, row.kind.as_str(), row.origin);
                }
            }
        }
        QueryAction::History { limit, offset } => {
            let (limit, offset) = list_window(limit, offset);
            let snapshot = db(database.snapshot())?;
            let events = db(snapshot.history_events(limit, offset))?;
            let commands = db(snapshot.command_history(limit, offset))?;
            if json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "events": events,
                        "commands": commands.iter().map(|row| json!({
                            "id": row.id,
                            "actor": row.actor,
                            "command": row.command,
                            "success": row.success,
                            "timestamp": row.timestamp,
                            "truncated": row.truncated,
                        })).collect::<Vec<_>>(),
                    }))?
                );
            } else {
                for event in events {
                    println!(
                        "#{:<6} {:<12} rev {:<6} {} {}",
                        event.id,
                        event.action,
                        event.revision.0,
                        event.kind.unwrap_or_default(),
                        event.timestamp
                    );
                }
            }
        }
        QueryAction::Changes { limit, offset } => {
            let (limit, offset) = list_window(limit, offset);
            let snapshot = db(database.snapshot())?;
            let events = db(snapshot.history_events(limit, offset))?;
            if json_output {
                println!("{}", serde_json::to_string_pretty(&events)?);
            } else {
                for event in events {
                    println!(
                        "#{:<6} {:<12} rev {:<6} {}",
                        event.id,
                        event.action,
                        event.revision.0,
                        event.kind.unwrap_or_default()
                    );
                }
            }
        }
        QueryAction::Decompile { .. }
        | QueryAction::Trace { .. }
        | QueryAction::Emulate { .. }
        | QueryAction::Signatures { .. } => unreachable!("handled before the read path"),
    }
    Ok(())
}

fn read_image_bytes(materialized: &Materialized, address: Address, length: u64) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut remaining = length;
    let mut cursor = address.0;
    while remaining > 0 {
        let Some(mapping) = materialized.image.mappings.iter().find(|mapping| {
            cursor >= mapping.va.0 && cursor < mapping.va.0.saturating_add(mapping.memory_size)
        }) else {
            bail!("{} is not mapped", Address(cursor).to_hex());
        };
        let delta = cursor - mapping.va.0;
        let available_memory = mapping.memory_size - delta;
        let (chunk_len, zero_fill) = if delta < mapping.file_size {
            let file_backed = (mapping.file_size - delta).min(available_memory);
            (file_backed.min(remaining), false)
        } else {
            (available_memory.min(remaining), true)
        };
        if chunk_len == 0 {
            break;
        }
        if zero_fill {
            out.resize(out.len() + chunk_len as usize, 0);
        } else {
            let Some(file_offset) = mapping.file_offset else {
                out.resize(out.len() + chunk_len as usize, 0);
                remaining -= chunk_len;
                cursor += chunk_len;
                continue;
            };
            let start = usize::try_from(file_offset.0 + delta)?;
            let end = start
                .checked_add(usize::try_from(chunk_len)?)
                .ok_or_else(|| anyhow::anyhow!("byte range overflows"))?;
            let bytes = materialized
                .image_bytes
                .get(start..end)
                .ok_or_else(|| anyhow::anyhow!("byte range is outside the stored image"))?;
            out.extend_from_slice(bytes);
        }
        remaining -= chunk_len;
        cursor += chunk_len;
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// `db edit`, `db undo`, `db redo`
// ---------------------------------------------------------------------------

fn edit(path: &Path, action: EditAction, expect_revision: Option<u64>) -> Result<()> {
    let mut database = db(Database::open(path, OpenMode::ReadWrite))?;
    let mut materialized = load_materialized(&mut database)?;
    let edits = build_edits(&materialized, &action)?;

    let mut revision = expect_revision
        .map(Revision)
        .unwrap_or(materialized.revision);
    let mut applied = 0usize;
    for edit in edits {
        let result = db(database.apply(revision, &edit))?;
        match result {
            EditOutcome::Applied(next) => {
                applied += 1;
                revision = next;
            }
            EditOutcome::Unchanged(current) => {
                revision = current;
            }
        }
        materialized.revision = revision;
    }

    if applied == 0 {
        println!("No change; revision stays {}.", revision.0);
    } else {
        println!("Applied {applied} edit(s); revision {}.", revision.0);
    }
    Ok(())
}

fn build_edits(materialized: &Materialized, action: &EditAction) -> Result<Vec<Edit>> {
    let selection = selection_from_image(&materialized.image);
    let parsed = parse_image(&materialized.image_bytes, &selection)?;
    let fmt = parsed.binary.as_format();

    let mut edits = Vec::new();
    match action {
        EditAction::Patch { address, hex_bytes } => {
            let bytes = parse_hex_bytes(hex_bytes)?;
            let offset = resolve_patch_offset(materialized, fmt, address)?;
            require_patchable(materialized, fmt, offset, bytes.len() as u64)?;
            edits.push(Edit::PatchBytes {
                file_offset: offset,
                bytes,
            });
        }
        EditAction::MakeCode { address, length } => edits.push(Edit::SetItem {
            address: parse_address(address)?,
            length: *length,
            kind: ItemKind::Code,
            type_name: None,
        }),
        EditAction::MakeData {
            address,
            length,
            type_name,
        } => edits.push(Edit::SetItem {
            address: parse_address(address)?,
            length: *length,
            kind: ItemKind::Data,
            type_name: type_name.clone(),
        }),
        EditAction::Undefine { address, length } => edits.push(Edit::ClearItem {
            address: parse_address(address)?,
            length: *length,
        }),
        EditAction::FunctionCreate { start, end } => edits.push(Edit::CreateFunction {
            start: parse_address(start)?,
            end: parse_address(end)?,
        }),
        EditAction::FunctionBounds { start, end } => edits.push(Edit::SetFunctionBounds {
            start: parse_address(start)?,
            end: parse_address(end)?,
        }),
        EditAction::FunctionRemove { start } => edits.push(Edit::RemoveFunction {
            start: parse_address(start)?,
        }),
        EditAction::FunctionExclude { start, excluded } => {
            let excluded = match excluded.trim().to_ascii_lowercase().as_str() {
                "true" | "1" | "yes" => true,
                "false" | "0" | "no" => false,
                other => bail!("'{other}' is not a boolean"),
            };
            edits.push(Edit::SetFunctionExcluded {
                start: parse_address(start)?,
                excluded,
            });
        }
        EditAction::Name { address, name } => edits.push(Edit::SetName {
            address: parse_address(address)?,
            name: Some(name.clone()),
        }),
        EditAction::Comment { address, text } => edits.push(Edit::SetComment {
            address: parse_address(address)?,
            text: Some(text.clone()),
        }),
        EditAction::Tag { address, text } => edits.push(Edit::SetTag {
            address: parse_address(address)?,
            text: Some(text.clone()),
        }),
        EditAction::Bookmark { address, label } => edits.push(Edit::SetBookmark {
            address: parse_address(address)?,
            label: label.clone(),
        }),
        EditAction::Signature {
            function,
            prototype,
        } => {
            // Validate here: the store cannot tell a C prototype from prose.
            prototype_to_signature(prototype, hexray_analysis::CallingConvention::SystemV)
                .context("signature")?;
            edits.push(Edit::SetFunctionSignature {
                start: parse_address(function)?,
                prototype: Some(prototype.clone()),
            });
        }
        EditAction::CallingConvention {
            function,
            convention,
        } => {
            if calling_convention_from_name(convention).is_none() {
                bail!(
                    "unknown calling convention '{convention}' (use systemv, win64, aarch64 or riscv)"
                );
            }
            edits.push(Edit::SetCallingConvention {
                start: parse_address(function)?,
                convention: Some(convention.clone()),
            });
        }
        EditAction::TypeImport { header } => {
            let metadata = std::fs::metadata(header)
                .with_context(|| format!("failed to stat {}", header.display()))?;
            if metadata.len() > 16 * 1024 * 1024 {
                bail!("header is larger than the 16 MiB limit");
            }
            let text = std::fs::read_to_string(header)
                .with_context(|| format!("failed to read {}", header.display()))?;
            let database = hexray_types::parser::parse_header(&text).map_err(|error| {
                anyhow::anyhow!("failed to parse {}: {error}", header.display())
            })?;
            let mut type_names: Vec<&str> = database.type_names().collect();
            type_names.sort_unstable();
            for name in type_names {
                if let Some(ty) = database.get_type(name) {
                    let kind = match ty {
                        hexray_types::CType::Struct(_) => TypeKind::Struct,
                        hexray_types::CType::Union(_) => TypeKind::Union,
                        hexray_types::CType::Enum(_) => TypeKind::Enum,
                        _ => TypeKind::Typedef,
                    };
                    edits.push(Edit::PutType {
                        name: name.to_string(),
                        kind,
                        payload_json: serde_json::to_string(ty)?,
                    });
                }
            }
            let mut typedefs: Vec<&str> = database.typedef_names().collect();
            typedefs.sort_unstable();
            for name in typedefs {
                if let Some(ty) = database.get_type(name) {
                    edits.push(Edit::PutType {
                        name: name.to_string(),
                        kind: TypeKind::Typedef,
                        payload_json: serde_json::to_string(ty)?,
                    });
                }
            }
            let mut functions: Vec<&str> = database.function_names().collect();
            functions.sort_unstable();
            for name in functions {
                if let Some(prototype) = database.get_function(name) {
                    edits.push(Edit::PutType {
                        name: name.to_string(),
                        kind: TypeKind::Prototype,
                        payload_json: serde_json::to_string(prototype)?,
                    });
                }
            }
            if edits.is_empty() {
                bail!("{} declares no types", header.display());
            }
        }
        EditAction::TypeRemove { name } => edits.push(Edit::RemoveType { name: name.clone() }),
        EditAction::ApplyType {
            address,
            type_name,
            length,
        } => edits.push(Edit::ApplyType {
            address: parse_address(address)?,
            type_name: Some(type_name.clone()),
            length: *length,
        }),
        EditAction::Variable {
            function,
            locator,
            name,
            type_name,
        } => edits.push(Edit::SetVariableOverride {
            function: parse_address(function)?,
            locator: VariableLocator::from_json(locator)
                .map_err(|error| anyhow::anyhow!("{error}"))?,
            name: name.clone(),
            type_name: type_name.clone(),
        }),
        EditAction::Clear {
            target,
            address,
            locator,
        } => {
            let target_kind = hexray_db::edit::OverrideTarget::parse(target).ok_or_else(|| {
                anyhow::anyhow!(
                    "unknown clear target '{target}' \
                     (use name, comment, tag, bookmark, signature, calling-convention, type, variable)"
                )
            })?;
            edits.push(Edit::RemoveOverride {
                target: target_kind,
                address: parse_address(address)?,
                locator: match locator {
                    Some(locator) => Some(
                        VariableLocator::from_json(locator)
                            .map_err(|error| anyhow::anyhow!("{error}"))?,
                    ),
                    None => None,
                },
            });
        }
    }
    Ok(edits)
}

fn parse_hex_bytes(text: &str) -> Result<Vec<u8>> {
    let cleaned: String = text
        .chars()
        .filter(|character| !character.is_whitespace() && *character != '_')
        .collect();
    let cleaned = cleaned
        .strip_prefix("0x")
        .or_else(|| cleaned.strip_prefix("0X"))
        .unwrap_or(&cleaned);
    if cleaned.is_empty() {
        bail!("patch bytes must not be empty");
    }
    if !cleaned.len().is_multiple_of(2) {
        bail!("patch bytes must have an even number of hex digits");
    }
    let mut out = Vec::with_capacity(cleaned.len() / 2);
    for chunk in cleaned.as_bytes().chunks(2) {
        let pair = std::str::from_utf8(chunk).map_err(|_| anyhow::anyhow!("patch is not ASCII"))?;
        out.push(
            u8::from_str_radix(pair, 16)
                .map_err(|_| anyhow::anyhow!("'{pair}' is not a hex byte"))?,
        );
    }
    Ok(out)
}

fn undo(path: &Path, expect_revision: Option<u64>) -> Result<()> {
    let mut database = db(Database::open(path, OpenMode::ReadWrite))?;
    let expected = match expect_revision {
        Some(revision) => Revision(revision),
        None => db(database.revision())?,
    };
    match db(database.undo(expected))? {
        EditOutcome::Applied(revision) => println!("Undone; revision {}.", revision.0),
        EditOutcome::Unchanged(revision) => println!("Nothing to undo; revision {}.", revision.0),
    }
    Ok(())
}

fn redo(path: &Path, expect_revision: Option<u64>) -> Result<()> {
    let mut database = db(Database::open(path, OpenMode::ReadWrite))?;
    let expected = match expect_revision {
        Some(revision) => Revision(revision),
        None => db(database.revision())?,
    };
    match db(database.redo(expected))? {
        EditOutcome::Applied(revision) => println!("Redone; revision {}.", revision.0),
        EditOutcome::Unchanged(revision) => println!("Nothing to redo; revision {}.", revision.0),
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// `db import-legacy`
// ---------------------------------------------------------------------------

fn import_legacy(
    legacy: &Path,
    binary: &Path,
    output: &Path,
    selection: &Selection,
    limits: &InputLimits,
    accept_unverified: bool,
    json_output: bool,
) -> Result<()> {
    if !legacy.exists() {
        bail!("legacy file not found: {}", legacy.display());
    }
    if output.exists() {
        bail!("destination already exists: {}", output.display());
    }
    let loaded = select_input(binary, selection, limits)?;
    let image_bytes = {
        let start = usize::try_from(loaded.selection.container_offset)?;
        let end = start
            .checked_add(usize::try_from(loaded.selection.container_length)?)
            .ok_or_else(|| anyhow::anyhow!("image range overflows"))?;
        loaded.source[start..end].to_vec()
    };
    let parsed = parse_image(&image_bytes, &loaded.selection)?;
    let source_digest = hexray_db::sha256(&loaded.source);
    let legacy_source = db(hexray_db::legacy::read_legacy_source(
        legacy,
        &source_digest,
        &loaded.source,
        accept_unverified,
    ))?;

    let mut input = build_create_input(binary, &loaded, &parsed)?;
    input.engine_fingerprint = engine_fingerprint();
    let parent = output
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    std::fs::create_dir_all(&parent).ok();
    let mut staged = db(hexray_db::store::StagedProject::create(&parent, &input))?;
    drop(parsed);
    store_debug_sidecars(staged.database(), selection)?;
    let summary = db(staged.database().import_legacy(&legacy_source))?;
    let _ = run_analysis(
        staged.database(),
        &AnalyzeRequest {
            function: None,
            force: true,
            render: None,
            limits: limits.clone(),
        },
    )?;
    let database = db(staged.publish(output))?;
    let revision = db(database.revision())?;

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "database": output.to_string_lossy(),
                "revision": revision.0,
                "legacy": legacy.to_string_lossy(),
                "kind": legacy_source.kind.as_str(),
                "identity": legacy_source.identity_status.as_str(),
                "imported_records": summary.imported_records,
                "applied": summary.applied,
                "unresolved": summary.unresolved,
                "by_kind": summary.by_kind.iter().map(|row| json!({
                    "kind": row.kind,
                    "applied": row.applied,
                    "unresolved": row.unresolved,
                })).collect::<Vec<_>>(),
            }))?
        );
    } else {
        println!(
            "Imported {} ({}, identity {}) into {} (revision {}).",
            legacy.display(),
            legacy_source.kind.as_str(),
            legacy_source.identity_status.as_str(),
            output.display(),
            revision.0
        );
        print!("{}", summary.render());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// `db open` — interactive project shell
// ---------------------------------------------------------------------------

/// One REPL command.
enum ReplOutcome {
    Continue,
    Quit,
}

/// Parsers used to reuse the exact one-shot command grammar inside the shell.
#[derive(clap::Parser)]
struct QueryParser {
    #[command(subcommand)]
    command: QueryAction,
}

#[derive(clap::Parser)]
struct EditParser {
    #[command(subcommand)]
    command: EditAction,
}

fn run_repl(path: &Path, read_only: bool) -> Result<()> {
    // Validate once up front so the shell refuses to open a broken project.
    {
        let database = db(Database::open(
            path,
            if read_only {
                OpenMode::ReadOnly
            } else {
                OpenMode::ReadWrite
            },
        ))?;
        println!(
            "hexray db {} — {} mode, revision {}",
            path.display(),
            if read_only { "read-only" } else { "read-write" },
            db(database.revision())?.0
        );
        println!("Commands: info sections symbols functions disasm cfg xrefs callgraph strings");
        println!("          bytes decompile variables types trace emulate signatures");
        println!("          name comment tag bookmark patch make-code make-data undefine");
        println!("          function-create function-bounds function-remove function-exclude");
        println!("          signature calling-convention type-import type-remove apply-type");
        println!("          variable clear undo redo refresh check backup export-binary quit");
    }

    // Without a terminal (pipes, CI) there is no line editor to drive; read
    // one command per line instead of failing outright.
    if !std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        return run_repl_batch(path, read_only);
    }

    let mut editor = rustyline::DefaultEditor::new()
        .map_err(|error| anyhow::anyhow!("failed to start the shell: {error}"))?;
    loop {
        match editor.readline("hxdb> ") {
            Ok(line) => {
                if line.trim().is_empty() {
                    continue;
                }
                let _ = editor.add_history_entry(line.trim());
                match handle_repl_line(path, read_only, &line) {
                    Ok(ReplOutcome::Continue) => {}
                    Ok(ReplOutcome::Quit) => return Ok(()),
                    Err(error) => eprintln!("error: {error}"),
                }
            }
            Err(rustyline::error::ReadlineError::Interrupted) => continue,
            Err(rustyline::error::ReadlineError::Eof) => return Ok(()),
            Err(error) => return Err(anyhow::anyhow!("shell error: {error}")),
        }
    }
}

fn run_repl_batch(path: &Path, read_only: bool) -> Result<()> {
    use std::io::BufRead as _;
    let stdin = std::io::stdin();
    for line in stdin.lock().lines() {
        let line = line.context("failed to read a command")?;
        if line.trim().is_empty() {
            continue;
        }
        println!("hxdb> {line}");
        match handle_repl_line(path, read_only, &line) {
            Ok(ReplOutcome::Continue) => {}
            Ok(ReplOutcome::Quit) => return Ok(()),
            Err(error) => {
                eprintln!("error: {error}");
                // A batch script stops at the first failure so a broken step
                // cannot silently be followed by successful ones.
                return Err(error);
            }
        }
    }
    Ok(())
}

fn handle_repl_line(path: &Path, read_only: bool, line: &str) -> Result<ReplOutcome> {
    let Some(args) = shlex::split(line) else {
        bail!("unbalanced quote in command");
    };
    if args.is_empty() {
        return Ok(ReplOutcome::Continue);
    }
    run_repl_command(path, read_only, &args)
}

fn run_repl_command(path: &Path, read_only: bool, args: &[String]) -> Result<ReplOutcome> {
    let command = args[0].as_str();
    let rest: Vec<String> = args[1..].to_vec();
    let mut json_output = false;
    let mut update = false;
    let mut bare = Vec::new();
    for argument in &rest {
        match argument.as_str() {
            "--json" => json_output = true,
            "--update" => update = true,
            _ => bare.push(argument.clone()),
        }
    }
    if update && read_only {
        bail!("'--update' needs a writable project (reopen without --read-only)");
    }

    let writable_edit = |name: &str| -> Result<()> {
        if read_only {
            bail!("'{name}' needs a writable project (reopen without --read-only)");
        }
        Ok(())
    };

    match command {
        "quit" | "exit" => return Ok(ReplOutcome::Quit),
        "info" => {
            query(
                path,
                QueryAction::Info {
                    limit: None,
                    offset: None,
                },
                json_output,
                false,
                false,
                &InputLimits::default(),
            )?;
        }
        "sections" | "symbols" | "functions" | "strings" | "types" | "history" | "changes" => {
            run_query_repl(path, command, &bare, json_output, update)?;
        }
        "disasm" | "cfg" | "xrefs" | "callgraph" | "bytes" | "decompile" | "variables"
        | "trace" | "emulate" | "signatures" => {
            run_query_repl(path, command, &bare, json_output, update)?;
        }
        "undo" => {
            writable_edit("undo")?;
            undo(path, None)?;
        }
        "redo" => {
            writable_edit("redo")?;
            redo(path, None)?;
        }
        "refresh" => {
            let database = db(Database::open(path, OpenMode::ReadOnly))?;
            println!("Re-read project; revision {}.", db(database.revision())?.0);
        }
        "check" => {
            let deep = bare.iter().any(|argument| argument == "--deep");
            let unexpected: Vec<&String> = bare.iter().filter(|arg| *arg != "--deep").collect();
            if !unexpected.is_empty() {
                bail!("check takes no arguments (got {:?})", unexpected);
            }
            check(path, deep, json_output)?;
        }
        "backup" => {
            let target = bare
                .first()
                .ok_or_else(|| anyhow::anyhow!("backup <file>"))?;
            backup(path, Path::new(target))?;
        }
        "export-binary" => {
            let target = bare
                .first()
                .ok_or_else(|| anyhow::anyhow!("export-binary <file>"))?;
            export_binary(path, Path::new(target))?;
        }
        other => {
            writable_edit(other)?;
            let parsed = EditParser::try_parse_from(
                std::iter::once("edit".to_string())
                    .chain(std::iter::once(command.to_string()))
                    .chain(bare.iter().cloned()),
            )
            .map_err(|error| anyhow::anyhow!("{error}"))?;
            edit(path, parsed.command, None)?;
        }
    }
    Ok(ReplOutcome::Continue)
}

fn parse_query_action(command: &str, args: Vec<String>) -> Result<QueryAction> {
    // clap treats argv[0] as the program name, so the shell command word is the
    // subcommand of a synthetic `query` parser.
    let parsed = QueryParser::try_parse_from(
        std::iter::once("query".to_string())
            .chain(std::iter::once(command.to_string()))
            .chain(args),
    )
    .map_err(|error| anyhow::anyhow!("{error}"))?;
    Ok(parsed.command)
}

fn run_query_repl(
    path: &Path,
    command: &str,
    args: &[String],
    json_output: bool,
    update: bool,
) -> Result<()> {
    let action = parse_query_action(command, args.to_vec())?;
    query(
        path,
        action,
        json_output,
        false,
        update,
        &InputLimits::default(),
    )
}
