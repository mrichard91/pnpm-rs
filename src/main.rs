use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::env;
use std::fs;
use std::io::{self};
use std::path::{Component, Path, PathBuf};
#[cfg(unix)]
use std::os::unix::fs::symlink;

use anyhow::{anyhow, bail, Context, Result};
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use chrono::{Duration as ChronoDuration, Utc};
use clap::{Parser, Subcommand};
use flate2::read::GzDecoder;
use semver::{Version, VersionReq};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use sha1::{Digest, Sha1};
use sha2::{Sha256, Sha512};
use tar::{Archive, EntryType};
use tempfile::TempDir;
use glob::glob;
use yara::Compiler;

const VERSION_STR: &str = "0.1";
const DEFAULT_REGISTRY: &str = "https://registry.npmjs.org/";
const MAX_MANIFEST_SIZE: usize = 5 * 1024 * 1024;
const MAX_PACKAGE_NAME_LEN: usize = 214;

#[derive(Parser, Debug)]
#[command(
    name = "pnpm-rs",
    version = VERSION_STR,
    disable_version_flag = true,
    about = "Safe, limited pnpm replacement in Rust"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
    #[arg(long, default_value_t = false)]
    debug: bool,
    #[arg(long, default_value_t = false)]
    frozen_lockfile: bool,
}

#[derive(Subcommand, Debug)]
enum Commands {
    Add {
        packages: Vec<String>,
        #[arg(long, short = 'D')]
        save_dev: bool,
        #[arg(long, short = 'O')]
        save_optional: bool,
        #[arg(long, short = 'E')]
        save_exact: bool,
        #[arg(long)]
        save_peer: bool,
    },
    Install,
    Remove {
        packages: Vec<String>,
    },
    Update {
        packages: Vec<String>,
    },
    List {
        #[arg(long)]
        json: bool,
        #[arg(long)]
        long: bool,
        #[arg(long)]
        parseable: bool,
        #[arg(long)]
        prod: bool,
        #[arg(long)]
        dev: bool,
        #[arg(long)]
        optional: bool,
        #[arg(long)]
        only: Option<String>,
        #[arg(long)]
        global: bool,
        #[arg(short, long)]
        recursive: bool,
        #[arg(long)]
        depth: Option<String>,
        packages: Vec<String>,
    },
    Ls {
        #[arg(long)]
        json: bool,
        #[arg(long)]
        long: bool,
        #[arg(long)]
        parseable: bool,
        #[arg(long)]
        prod: bool,
        #[arg(long)]
        dev: bool,
        #[arg(long)]
        optional: bool,
        #[arg(long)]
        only: Option<String>,
        #[arg(long)]
        global: bool,
        #[arg(short, long)]
        recursive: bool,
        #[arg(long)]
        depth: Option<String>,
        packages: Vec<String>,
    },
    Init {
        #[arg(long)]
        name: Option<String>,
    },
    Config {
        args: Vec<String>,
    },
    Store {
        args: Vec<String>,
    },
    Run {
        args: Vec<String>,
    },
    Exec {
        args: Vec<String>,
    },
    Dlx {
        args: Vec<String>,
    },
    Fetch {
        args: Vec<String>,
    },
    Why {
        args: Vec<String>,
    },
    Patch {
        args: Vec<String>,
    },
    SecurityScan {
        #[arg(long)]
        yara: Option<String>,
        #[arg(long, default_value_t = 5)]
        older_than_years: i64,
    },
    #[command(external_subcommand)]
    Other(Vec<String>),
}

fn main() -> Result<()> {
    if has_version_flag() {
        println!("pnpm-rs {VERSION_STR}");
        return Ok(());
    }

    let cli = Cli::parse();
    let cwd = env::current_dir().context("read current directory")?;

    match cli.command {
        Commands::Init { name } => init_project(&cwd, name),
        Commands::Add { packages, save_dev, save_optional, save_exact, save_peer } => {
            if cli.frozen_lockfile {
                bail!("pnpm-rs: cannot add packages with --frozen-lockfile");
            }
            if packages.is_empty() {
                bail!("pnpm-rs add requires at least one package");
            }
            let section = if save_dev {
                DepSection::DevDependencies
            } else if save_optional {
                DepSection::OptionalDependencies
            } else if save_peer {
                DepSection::PeerDependencies
            } else {
                DepSection::Dependencies
            };
            let specs = packages
                .iter()
                .map(|spec| parse_package_spec(spec))
                .collect::<Result<Vec<_>>>()?;
            add_packages(&cwd, &specs, cli.debug, section, save_exact)
        }
        Commands::Install => install_from_manifest(&cwd, cli.debug, cli.frozen_lockfile),
        Commands::Remove { packages } => remove_packages(&cwd, &packages, cli.debug),
        Commands::Update { packages } => update_packages(&cwd, &packages, cli.debug),
        Commands::List {
            json,
            long,
            parseable,
            prod,
            dev,
            optional,
            only,
            global,
            recursive,
            depth,
            packages,
        } => {
            let opts = ListOptions {
                json,
                long,
                parseable,
                prod,
                dev,
                optional,
                only,
                global,
                recursive,
                depth,
                packages,
            };
            list_packages(&cwd, &opts)
        }
        Commands::Ls {
            json,
            long,
            parseable,
            prod,
            dev,
            optional,
            only,
            global,
            recursive,
            depth,
            packages,
        } => {
            let opts = ListOptions {
                json,
                long,
                parseable,
                prod,
                dev,
                optional,
                only,
                global,
                recursive,
                depth,
                packages,
            };
            list_packages(&cwd, &opts)
        }
        Commands::Config { args } => stub_command("config", &args),
        Commands::Store { args } => stub_command("store", &args),
        Commands::Run { args } => stub_command("run", &args),
        Commands::Exec { args } => stub_command("exec", &args),
        Commands::Dlx { args } => stub_command("dlx", &args),
        Commands::Fetch { args } => stub_command("fetch", &args),
        Commands::Why { args } => {
            if args.is_empty() {
                bail!("pnpm-rs why requires a package name");
            }
            why_packages(&cwd, &args)
        }
        Commands::Patch { args } => stub_command("patch", &args),
        Commands::SecurityScan {
            yara,
            older_than_years,
        } => security_scan(&cwd, cli.debug, yara.as_deref(), older_than_years),
        Commands::Other(args) => stub_command("unknown", &args),
    }
}

fn has_version_flag() -> bool {
    env::args().any(|arg| arg == "-v" || arg == "--version")
}

fn stub_command(name: &str, args: &[String]) -> Result<()> {
    let joined = if args.is_empty() {
        String::from("(no args)")
    } else {
        args.join(" ")
    };
    bail!("pnpm-rs: command '{name}' is not implemented in safe mode. args: {joined}")
}

fn init_project(cwd: &Path, name: Option<String>) -> Result<()> {
    let package_json_path = cwd.join("package.json");
    if package_json_path.exists() {
        bail!("package.json already exists in {}", cwd.display());
    }
    ensure_project_initialized(cwd, name)
}

fn ensure_project_initialized(cwd: &Path, name: Option<String>) -> Result<()> {
    let package_json_path = cwd.join("package.json");
    if package_json_path.exists() {
        return Ok(());
    }

    let fallback_name = cwd
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("pnpm-rs-project");
    let project_name = name.unwrap_or_else(|| fallback_name.to_string());

    let package_json = serde_json::json!({
        "name": project_name,
        "version": "1.0.0",
        "private": true
    });
    let contents = serde_json::to_string_pretty(&package_json)?;
    fs::write(&package_json_path, contents + "\n")
        .with_context(|| format!("write {}", package_json_path.display()))?;
    Ok(())
}

#[derive(Clone, Debug)]
struct PackageSpec {
    name: String,
    requested: Option<String>,
}

fn parse_package_spec(input: &str) -> Result<PackageSpec> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        bail!("empty package spec");
    }
    if trimmed.starts_with("file:")
        || trimmed.starts_with("link:")
        || trimmed.starts_with("workspace:")
        || trimmed.contains("://")
        || trimmed.starts_with("git+")
    {
        bail!("exotic dependency sources are not allowed: {trimmed}");
    }
    // npm: prefix just means "from npm registry" which is our default
    let trimmed = trimmed.strip_prefix("npm:").unwrap_or(trimmed);
    if trimmed.starts_with('@') {
        let mut parts = trimmed.rsplitn(2, '@');
        let maybe_version = parts.next();
        let name_part = parts.next();
        if let (Some(version), Some(name)) = (maybe_version, name_part) {
            if name.contains('/') && !version.is_empty() {
                validate_package_name(name)?;
                return Ok(PackageSpec {
                    name: name.to_string(),
                    requested: Some(version.to_string()),
                });
            }
        }
        validate_package_name(trimmed)?;
        return Ok(PackageSpec {
            name: trimmed.to_string(),
            requested: None,
        });
    }

    let (name, version) = match trimmed.split_once('@') {
        Some((left, right)) if !right.is_empty() => (left, Some(right)),
        _ => (trimmed, None),
    };

    validate_package_name(name)?;

    Ok(PackageSpec {
        name: name.to_string(),
        requested: version.map(|s| s.to_string()),
    })
}

fn format_save_version(requested: Option<&str>, resolved: &str, save_exact: bool) -> String {
    if save_exact {
        return resolved.to_string();
    }
    if let Some(req) = requested {
        let trimmed = req.trim();
        if trimmed.starts_with('^')
            || trimmed.starts_with('~')
            || trimmed.starts_with('>')
            || trimmed.starts_with('<')
            || trimmed.starts_with('=')
            || trimmed.contains("||")
            || trimmed.contains(" - ")
        {
            return trimmed.to_string();
        }
    }
    format!("^{resolved}")
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum DepSection {
    Dependencies,
    DevDependencies,
    OptionalDependencies,
    PeerDependencies,
}

impl DepSection {
    fn key(&self) -> &'static str {
        match self {
            DepSection::Dependencies => "dependencies",
            DepSection::DevDependencies => "devDependencies",
            DepSection::OptionalDependencies => "optionalDependencies",
            DepSection::PeerDependencies => "peerDependencies",
        }
    }
}

fn add_packages(cwd: &Path, specs: &[PackageSpec], debug: bool, section: DepSection, save_exact: bool) -> Result<()> {
    ensure_project_initialized(cwd, None)?;
    let registry = resolve_registry(cwd)?;
    let mut manifest = read_package_json(cwd)?;
    let section_key = section.key();
    {
        let obj = manifest.as_object_mut().expect("package.json object");
        if !obj.contains_key(section_key) {
            obj.insert(
                section_key.to_string(),
                JsonValue::Object(Default::default()),
            );
        }
    }

    let (existing_deps, existing_dev, existing_optional) = collect_manifest_deps(&manifest);
    let mut root_specs = Vec::new();
    for (name, req) in existing_deps.iter().chain(existing_dev.iter()).chain(existing_optional.iter()) {
        root_specs.push(PackageSpec {
            name: name.clone(),
            requested: Some(req.clone()),
        });
    }
    for spec in specs {
        root_specs.push(spec.clone());
    }

    let overrides = read_overrides(&manifest);
    let resolve = resolve_dependencies(&root_specs, debug, &overrides, &registry)?;

    let deps = manifest
        .as_object_mut()
        .expect("package.json object")
        .get_mut(section_key)
        .and_then(|v| v.as_object_mut())
        .expect("dep section object");

    for spec in specs {
        let version = resolve
            .root_resolved
            .get(&spec.name)
            .ok_or_else(|| anyhow!("failed to resolve {}", spec.name))?;
        let save_version = format_save_version(spec.requested.as_deref(), version, save_exact);
        deps.insert(spec.name.clone(), JsonValue::String(save_version));
    }

    write_package_json(cwd, &manifest)?;
    install_with_resolution(cwd, &resolve, debug, &registry)
}

#[derive(Default)]
struct ScanIssue {
    name: String,
    version: String,
    details: Vec<String>,
}

#[derive(Default)]
struct YaraSummary {
    files_scanned: usize,
    rule_matches: usize,
    string_matches: usize,
    rules: HashSet<String>,
    packages_with_matches: HashSet<String>,
}

fn security_scan(
    cwd: &Path,
    debug: bool,
    yara_rules_path: Option<&str>,
    older_than_years: i64,
) -> Result<()> {
    let lockfile_path = cwd.join("pnpm-lock.yaml");
    if !lockfile_path.exists() {
        bail!("pnpm-lock.yaml not found; run pnpm-rs install first");
    }

    let raw = fs::read_to_string(&lockfile_path)
        .with_context(|| format!("read {}", lockfile_path.display()))?;
    let lockfile: LockfileIn = serde_yaml::from_str(&raw).context("parse pnpm-lock.yaml")?;
    let packages = match &lockfile.packages {
        Some(packages) if !packages.is_empty() => packages,
        _ => {
            println!("Security scan: no packages found in lockfile");
            return Ok(());
        }
    };

    let mut findings: Vec<ScanIssue> = Vec::new();
    let mut metadata_cache: HashMap<String, RegistryPackage> = HashMap::new();
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .build()
        .context("build http client")?;
    let cutoff = Utc::now() - ChronoDuration::days(365 * older_than_years);
    let yara_rules = if let Some(path) = yara_rules_path {
        Some(compile_yara_rules(path)?)
    } else {
        None
    };
    let mut yara_summary = YaraSummary::default();

    for (key, _snapshot) in packages {
        let Some((name, version)) = parse_lockfile_key(key) else { continue };
        let mut issue = ScanIssue {
            name: name.clone(),
            version: version.clone(),
            details: Vec::new(),
        };

        let install_path = store_package_path(cwd, &name, &version).join("package.json");
        match read_json_file(&install_path) {
            Ok(json) => {
                scan_package_json(&json, &mut issue);
            }
            Err(err) => {
                issue
                    .details
                    .push(format!("missing or unreadable package.json: {err}"));
            }
        }

        match fetch_registry_metadata(&client, &name, &mut metadata_cache, debug, DEFAULT_REGISTRY) {
            Ok(meta) => {
                if !meta.versions.contains_key(&version) {
                    issue
                        .details
                        .push("registry metadata missing version entry".to_string());
                }
                match package_publish_time(&meta, &version) {
                    Ok(Some(ts)) => {
                        if ts < cutoff {
                        issue.details.push(format!(
                            "package version older than {older_than_years} years (published {})",
                            ts.to_rfc3339()
                        ));
                        }
                    }
                    Ok(None) => {
                        issue
                            .details
                            .push("missing publish time metadata for version".to_string());
                    }
                    Err(err) => {
                        issue
                            .details
                            .push(format!("unparseable publish time metadata: {err}"));
                    }
                }
            }
            Err(err) => {
                issue
                    .details
                    .push(format!("registry metadata error: {err}"));
            }
        }

        if let Some(rules) = &yara_rules {
            let package_root = store_package_path(cwd, &name, &version);
            let package_label = format!("{name}@{version}");
            match scan_with_yara(rules, &package_root, Some(&package_label)) {
                Ok(result) => {
                    yara_summary.files_scanned += result.files_scanned;
                    yara_summary.rule_matches += result.rule_matches;
                    yara_summary.string_matches += result.string_matches;
                    if !result.matches.is_empty() {
                        yara_summary
                            .packages_with_matches
                            .insert(format!("{name}@{version}"));
                    }
                    for match_detail in result.matches {
                        yara_summary.rules.insert(match_detail.rule.clone());
                        issue
                            .details
                            .push(format!("yara match {} in {}", match_detail.rule, match_detail.path.display()));
                        if !match_detail.tags.is_empty() {
                            issue
                                .details
                                .push(format!("  tags: {}", match_detail.tags.join(", ")));
                        }
                        for line in match_detail.strings {
                            issue.details.push(format!("  {line}"));
                        }
                    }
                }
                Err(err) => {
                    issue
                        .details
                        .push(format!("yara scan error: {err}"));
                }
            }
        }

        if !issue.details.is_empty() {
            findings.push(issue);
        }
    }

    print_security_report(&findings, packages.len());
    print_yara_summary(&yara_summary, yara_rules_path.is_some());
    Ok(())
}

fn install_from_manifest(cwd: &Path, debug: bool, frozen_lockfile: bool) -> Result<()> {
    ensure_project_initialized(cwd, None)?;
    let registry = resolve_registry(cwd)?;
    let manifest = read_package_json(cwd)?;
    let (deps, dev_deps, optional_deps) = collect_manifest_deps(&manifest);

    // Lockfile-first install (Changes 11 & 12)
    if let Some(lockfile) = read_lockfile(cwd)? {
        if lockfile_satisfies_manifest(&lockfile, &deps, &dev_deps, &optional_deps) {
            install_from_lockfile(cwd, &lockfile, debug, &registry)?;
            return Ok(());
        } else if frozen_lockfile {
            bail!("pnpm-rs: lockfile does not match package.json (--frozen-lockfile)");
        }
    } else if frozen_lockfile {
        bail!("pnpm-rs: no lockfile found (--frozen-lockfile)");
    }

    let overrides = read_overrides(&manifest);
    let mut root_specs = Vec::new();
    for (name, req) in deps.iter().chain(dev_deps.iter()).chain(optional_deps.iter()) {
        root_specs.push(PackageSpec {
            name: name.clone(),
            requested: Some(req.clone()),
        });
    }
    let resolve = resolve_dependencies(&root_specs, debug, &overrides, &registry)?;
    install_with_resolution(cwd, &resolve, debug, &registry)
}

fn remove_packages(cwd: &Path, packages: &[String], debug: bool) -> Result<()> {
    ensure_project_initialized(cwd, None)?;
    let mut manifest = read_package_json(cwd)?;
    if let Some(deps) = manifest.get_mut("dependencies").and_then(|v| v.as_object_mut()) {
        for name in packages {
            deps.remove(name);
            let path = cwd.join("node_modules").join(name);
            if path.exists() {
                fs::remove_dir_all(&path)
                    .with_context(|| format!("remove {}", path.display()))?;
            }
        }
    }
    write_package_json(cwd, &manifest)?;
    install_from_manifest(cwd, debug, false)
}

fn update_packages(cwd: &Path, packages: &[String], debug: bool) -> Result<()> {
    if packages.is_empty() {
        return install_from_manifest(cwd, debug, false);
    }
    let manifest = read_package_json(cwd)?;
    let mut specs = Vec::new();
    for name in packages {
        let existing = manifest
            .get("dependencies")
            .and_then(|v| v.get(name))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        specs.push(PackageSpec {
            name: name.to_string(),
            requested: existing.or(Some("latest".to_string())),
        });
    }
    add_packages(cwd, &specs, debug, DepSection::Dependencies, false)
}

struct ListOptions {
    json: bool,
    long: bool,
    parseable: bool,
    prod: bool,
    dev: bool,
    optional: bool,
    only: Option<String>,
    global: bool,
    recursive: bool,
    depth: Option<String>,
    packages: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
struct ListNode {
    name: String,
    version: String,
    path: String,
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    dependencies: HashMap<String, ListNode>,
}

fn list_packages(cwd: &Path, opts: &ListOptions) -> Result<()> {
    if opts.global {
        println!("pnpm-rs: global list is not implemented; showing local project only");
    }

    let roots = if opts.recursive {
        let mut dirs = Vec::new();
        if let Some(workspace_root) = find_workspace_root(cwd) {
            collect_workspace_dirs(&workspace_root, &mut dirs)?;
        } else {
            dirs.push(cwd.to_path_buf());
        }
        dirs
    } else {
        vec![cwd.to_path_buf()]
    };

    for (idx, root) in roots.iter().enumerate() {
        if opts.recursive {
            println!("\nProject: {}", root.display());
        }
        list_single_project(root, opts)?;
        if idx + 1 < roots.len() {
            println!();
        }
    }

    Ok(())
}

fn list_single_project(cwd: &Path, opts: &ListOptions) -> Result<()> {
    let manifest = read_package_json(cwd)?;
    let requested = collect_requested_deps(&manifest, opts)?;
    if requested.is_empty() {
        println!("(no dependencies)");
        return Ok(());
    }

    let lockfile_path = cwd.join("pnpm-lock.yaml");
    let lockfile = if lockfile_path.exists() {
        let raw = fs::read_to_string(&lockfile_path)
            .with_context(|| format!("read {}", lockfile_path.display()))?;
        Some(serde_yaml::from_str::<LockfileIn>(&raw).context("parse pnpm-lock.yaml")?)
    } else {
        None
    };

    let package_index = lockfile
        .as_ref()
        .and_then(|lf| lf.snapshots.as_ref().map(build_package_index_from_snapshots))
        .or_else(|| {
            lockfile
                .as_ref()
                .and_then(|lf| lf.packages.as_ref())
                .map(build_package_index_from_packages)
        })
        .unwrap_or_default();

    let depth = parse_depth(opts.depth.as_deref())?;
    let mut nodes = Vec::new();
    for (name, req) in requested {
        if !opts.packages.is_empty() && !opts.packages.contains(&name) {
            continue;
        }
        let version = resolve_version_for_list(&name, &req, &package_index);
        let node = build_list_node(cwd, &name, &version, depth, &package_index);
        nodes.push(node);
    }

    if opts.json {
        let json = serde_json::to_string_pretty(&nodes)?;
        println!("{json}");
        return Ok(());
    }

    if opts.parseable {
        for node in nodes {
            println!("{}:{}", node.name, node.path);
        }
        return Ok(());
    }

    for node in nodes {
        print_node(&node, depth, 0, opts.long);
    }
    Ok(())
}

fn collect_requested_deps(manifest: &JsonValue, opts: &ListOptions) -> Result<Vec<(String, String)>> {
    let mut result = Vec::new();
    let only = opts.only.as_deref();
    let no_filter = !opts.prod && !opts.dev && !opts.optional && only.is_none();
    let include_prod = if no_filter { true } else { only.map_or(opts.prod, |v| v == "prod" || v == "production") };
    let include_dev = if no_filter { true } else { only.map_or(opts.dev, |v| v == "dev" || v == "development") };
    let include_optional = if no_filter { true } else { only.map_or(opts.optional, |v| v == "optional") };

    if include_prod {
        if let Some(deps) = manifest.get("dependencies").and_then(|v| v.as_object()) {
            for (name, version) in deps {
                let req = version.as_str().unwrap_or("*");
                result.push((name.clone(), req.to_string()));
            }
        }
    }
    if include_dev {
        if let Some(deps) = manifest.get("devDependencies").and_then(|v| v.as_object()) {
            for (name, version) in deps {
                let req = version.as_str().unwrap_or("*");
                result.push((name.clone(), req.to_string()));
            }
        }
    }
    if include_optional {
        if let Some(deps) = manifest.get("optionalDependencies").and_then(|v| v.as_object()) {
            for (name, version) in deps {
                let req = version.as_str().unwrap_or("*");
                result.push((name.clone(), req.to_string()));
            }
        }
    }
    result.sort();
    result.dedup_by(|a, b| a.0 == b.0);
    Ok(result)
}

fn parse_depth(raw: Option<&str>) -> Result<usize> {
    match raw {
        None => Ok(0),
        Some(value) if value.eq_ignore_ascii_case("infinity") => Ok(usize::MAX),
        Some(value) => value
            .parse::<usize>()
            .map_err(|_| anyhow!("invalid depth value: {value}")),
    }
}

fn build_package_index_from_packages(packages: &HashMap<String, PackageSnapshotIn>) -> PackageIndex {
    let mut by_name = HashMap::new();
    let mut by_key = HashMap::new();
    for (key, snapshot) in packages {
        let deps = snapshot.dependencies.clone().unwrap_or_default();
        insert_package_index(&mut by_name, &mut by_key, key, deps, "entries");
    }
    PackageIndex { by_name, by_key }
}

fn build_package_index_from_snapshots(snapshots: &HashMap<String, SnapshotIn>) -> PackageIndex {
    let mut by_name = HashMap::new();
    let mut by_key = HashMap::new();
    for (key, snapshot) in snapshots {
        let deps = merge_dep_maps(
            snapshot.dependencies.clone(),
            snapshot.optional_dependencies.clone(),
            snapshot.peer_dependencies.clone(),
        );
        insert_package_index(&mut by_name, &mut by_key, key, deps, "snapshots");
    }
    PackageIndex { by_name, by_key }
}

fn merge_dep_maps(
    primary: Option<HashMap<String, String>>,
    optional: Option<HashMap<String, String>>,
    peer: Option<HashMap<String, String>>,
) -> HashMap<String, String> {
    let mut deps = primary.unwrap_or_default();
    if let Some(map) = optional {
        for (dep, ver) in map {
            deps.entry(dep).or_insert(ver);
        }
    }
    if let Some(map) = peer {
        for (dep, ver) in map {
            deps.entry(dep).or_insert(ver);
        }
    }
    deps
}

fn insert_package_index(
    by_name: &mut HashMap<String, Vec<String>>,
    by_key: &mut HashMap<String, HashMap<String, String>>,
    key: &str,
    deps: HashMap<String, String>,
    label: &str,
) {
    if let Some((name, version)) = parse_lockfile_key(key) {
        by_name.entry(name.clone()).or_default().push(version.clone());
        let normalized_key = format!("{name}@{version}");
        if !by_key.contains_key(&normalized_key) {
            by_key.insert(normalized_key, deps);
        } else {
            warn(&format!(
                "duplicate lockfile {label} for {name}@{version}; using first snapshot"
            ));
        }
    }
}

#[derive(Default)]
struct PackageIndex {
    by_name: HashMap<String, Vec<String>>,
    by_key: HashMap<String, HashMap<String, String>>,
}

fn resolve_version_for_list(name: &str, req: &str, index: &PackageIndex) -> String {
    let versions = match index.by_name.get(name) {
        Some(v) => v,
        None => return "<missing>".to_string(),
    };

    let base_req = req.split('(').next().unwrap_or(req).trim();
    let lower_req = base_req.to_ascii_lowercase();
    if lower_req.starts_with("link:") || lower_req.starts_with("file:") || lower_req.starts_with("workspace:") {
        return base_req.to_string();
    }
    if versions.contains(&base_req.to_string()) {
        return base_req.to_string();
    }
    for part in split_or_range(base_req) {
        let normalized = match normalize_range(&part) {
            Ok(value) => value,
            Err(err) => {
                warn(&format!(
                    "unsupported version range '{base_req}' for {name}: {err}; using highest available"
                ));
                continue;
            }
        };
        let Ok(range) = VersionReq::parse(&normalized) else { continue };
        let mut best: Option<Version> = None;
        for v in versions {
            if let Ok(ver) = Version::parse(v) {
                if range.matches(&ver) {
                    if best.as_ref().map_or(true, |b| &ver > b) {
                        best = Some(ver);
                    }
                }
            }
        }
        if let Some(best) = best {
            return best.to_string();
        }
    }
    versions.iter().max().cloned().unwrap_or_else(|| "<missing>".to_string())
}

fn build_list_node(
    cwd: &Path,
    name: &str,
    version: &str,
    depth: usize,
    index: &PackageIndex,
) -> ListNode {
    let path = package_install_path(cwd, name);
    let path_str = path.display().to_string();
    let mut node = ListNode {
        name: name.to_string(),
        version: version.to_string(),
        path: path_str,
        dependencies: HashMap::new(),
    };

    if depth == 0 || version == "<missing>" {
        return node;
    }

        let key = format!("{name}@{version}");
    if let Some(deps) = index.by_key.get(&key) {
        for (dep, req) in deps {
            let dep_version = resolve_version_for_list(dep, req, index);
            let child = build_list_node(cwd, dep, &dep_version, depth.saturating_sub(1), index);
            node.dependencies.insert(dep.clone(), child);
        }
    }
    node
}

fn print_node(node: &ListNode, depth: usize, indent: usize, long: bool) {
    let prefix = "  ".repeat(indent);
    if long {
        println!("{prefix}{}@{} ({})", node.name, node.version, node.path);
    } else {
        println!("{prefix}{}@{}", node.name, node.version);
    }
    if depth == 0 {
        return;
    }
    let mut children: Vec<_> = node.dependencies.values().collect();
    children.sort_by(|a, b| a.name.cmp(&b.name));
    for child in children {
        print_node(child, depth.saturating_sub(1), indent + 1, long);
    }
}

fn collect_workspace_dirs(root: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    let workspace_file = root.join("pnpm-workspace.yaml");
    if !workspace_file.exists() {
        out.push(root.to_path_buf());
        return Ok(());
    }
    let raw = fs::read_to_string(&workspace_file)
        .with_context(|| format!("read {}", workspace_file.display()))?;
    let yaml: serde_yaml::Value = serde_yaml::from_str(&raw).context("parse pnpm-workspace.yaml")?;
    let patterns = yaml
        .get("packages")
        .and_then(|value| value.as_sequence())
        .cloned()
        .unwrap_or_default();
    if patterns.is_empty() {
        out.push(root.to_path_buf());
        return Ok(());
    }
    for pattern in patterns {
        let Some(pattern_str) = pattern.as_str() else { continue };
        let joined = root.join(pattern_str);
        let joined_str = joined.to_string_lossy().to_string();
        for entry in glob(&joined_str).with_context(|| format!("glob {}", joined_str))? {
            let Ok(path) = entry else { continue };
            if path.is_dir() && path.join("package.json").exists() {
                out.push(path);
            }
        }
    }
    Ok(())
}

fn find_workspace_root(start: &Path) -> Option<PathBuf> {
    let mut current = start.to_path_buf();
    loop {
        if current.join("pnpm-workspace.yaml").exists() {
            return Some(current);
        }
        if !current.pop() {
            break;
        }
    }
    None
}

fn read_package_json(cwd: &Path) -> Result<JsonValue> {
    let package_json_path = cwd.join("package.json");
    let raw = fs::read_to_string(&package_json_path)
        .with_context(|| format!("read {}", package_json_path.display()))?;
    if raw.len() > MAX_MANIFEST_SIZE {
        bail!("package.json too large");
    }
    serde_json::from_str(&raw).with_context(|| "parse package.json")
}

fn read_json_file(path: &Path) -> Result<JsonValue> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("read {}", path.display()))?;
    if raw.len() > MAX_MANIFEST_SIZE {
        bail!("file too large");
    }
    serde_json::from_str(&raw).with_context(|| format!("parse {}", path.display()))
}

fn write_package_json(cwd: &Path, json: &JsonValue) -> Result<()> {
    let package_json_path = cwd.join("package.json");
    let contents = serde_json::to_string_pretty(json)?;
    fs::write(&package_json_path, contents + "\n")
        .with_context(|| format!("write {}", package_json_path.display()))?;
    Ok(())
}

fn parse_npmrc(cwd: &Path) -> Result<Option<String>> {
    let candidates = [
        cwd.join(".npmrc"),
        dirs_home().map(|h| h.join(".npmrc")).unwrap_or_default(),
    ];
    for path in &candidates {
        if !path.exists() {
            continue;
        }
        let raw = fs::read_to_string(path)
            .with_context(|| format!("read {}", path.display()))?;
        for line in raw.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with('#') || trimmed.starts_with(';') {
                continue;
            }
            if let Some(value) = trimmed.strip_prefix("registry=") {
                let value = value.trim().trim_matches('"').trim_matches('\'');
                if !value.is_empty() {
                    return Ok(Some(value.to_string()));
                }
            }
        }
    }
    Ok(None)
}

fn dirs_home() -> Option<PathBuf> {
    env::var_os("HOME").map(PathBuf::from)
}

fn resolve_registry(cwd: &Path) -> Result<String> {
    if let Some(registry) = parse_npmrc(cwd)? {
        let parsed = reqwest::Url::parse(&registry)
            .with_context(|| format!("parse registry URL: {registry}"))?;
        if parsed.scheme() != "https" {
            bail!("registry must use https: {registry}");
        }
        let mut url = registry;
        if !url.ends_with('/') {
            url.push('/');
        }
        return Ok(url);
    }
    Ok(DEFAULT_REGISTRY.to_string())
}

fn registry_host(registry: &str) -> Option<String> {
    reqwest::Url::parse(registry).ok().and_then(|u| u.host_str().map(|s| s.to_string()))
}

fn custom_registry_host(registry: &str) -> Option<String> {
    if registry == DEFAULT_REGISTRY {
        None
    } else {
        registry_host(registry)
    }
}

fn collect_manifest_deps(
    manifest: &JsonValue,
) -> (HashMap<String, String>, HashMap<String, String>, HashMap<String, String>) {
    let mut deps = HashMap::new();
    let mut dev_deps = HashMap::new();
    let mut optional_deps = HashMap::new();
    if let Some(obj) = manifest.get("dependencies").and_then(|v| v.as_object()) {
        for (name, version) in obj {
            deps.insert(name.clone(), version.as_str().unwrap_or("*").to_string());
        }
    }
    if let Some(obj) = manifest.get("devDependencies").and_then(|v| v.as_object()) {
        for (name, version) in obj {
            dev_deps.insert(name.clone(), version.as_str().unwrap_or("*").to_string());
        }
    }
    if let Some(obj) = manifest.get("optionalDependencies").and_then(|v| v.as_object()) {
        for (name, version) in obj {
            optional_deps.insert(name.clone(), version.as_str().unwrap_or("*").to_string());
        }
    }
    (deps, dev_deps, optional_deps)
}

fn scan_package_json(json: &JsonValue, issue: &mut ScanIssue) {
    let obj = match json.as_object() {
        Some(obj) => obj,
        None => {
            issue.details.push("package.json is not an object".to_string());
            return;
        }
    };

    if let Some(scripts) = obj.get("scripts") {
        if let Some(map) = scripts.as_object() {
            for key in ["preinstall", "install", "postinstall", "prepare"] {
                if let Some(cmd) = map.get(key).and_then(|v| v.as_str()) {
                    issue
                        .details
                        .push(format!("lifecycle script {key}: {cmd}"));
                } else if map.contains_key(key) {
                    issue
                        .details
                        .push(format!("lifecycle script {key}: (non-string)"));
                }
            }
        } else {
            issue.details.push("scripts field is not an object".to_string());
        }
    }

    if let Some(bin) = obj.get("bin") {
        match bin {
            JsonValue::String(_) | JsonValue::Object(_) => {
                issue.details.push("package exposes binaries".to_string());
            }
            _ => {
                issue
                    .details
                    .push("bin field is not a string or object".to_string());
            }
        }
    }

    for field in [
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
    ] {
        if let Some(value) = obj.get(field) {
            match value.as_object() {
                Some(map) => {
                    for (dep, req_val) in map {
                        let req = match req_val.as_str() {
                            Some(req) => req,
                            None => {
                                issue.details.push(format!(
                                    "{field} entry {dep} has non-string version"
                                ));
                                continue;
                            }
                        };
                        if is_exotic_requirement(req) {
                            issue.details.push(format!(
                                "exotic dependency spec in {field}: {dep}@{req}"
                            ));
                        }
                    }
                }
                None => {
                    issue
                        .details
                        .push(format!("{field} field is not an object"));
                }
            }
        }
    }
}

fn is_exotic_requirement(req: &str) -> bool {
    let lower = req.to_ascii_lowercase();
    lower.starts_with("file:")
        || lower.starts_with("link:")
        || lower.starts_with("workspace:")
        || lower.starts_with("npm:")
        || lower.starts_with("git+")
        || lower.contains("://")
}

fn package_publish_time(meta: &RegistryPackage, version: &str) -> Result<Option<chrono::DateTime<Utc>>> {
    let Some(times) = &meta.time else { return Ok(None); };
    let Some(ts) = times.get(version) else { return Ok(None); };
    let parsed = chrono::DateTime::parse_from_rfc3339(ts)
        .with_context(|| format!("parse timestamp {ts}"))?
        .with_timezone(&Utc);
    Ok(Some(parsed))
}

fn compile_yara_rules(path: &str) -> Result<yara::Rules> {
    let source = fs::read_to_string(path)
        .with_context(|| format!("read yara rules {}", path))?;
    let compiler = Compiler::new().context("initialize yara compiler")?;
    let compiler = compiler
        .add_rules_str(&source)
        .context("parse yara rules")?;
    compiler.compile_rules().context("compile yara rules")
}

struct YaraMatchDetail {
    path: PathBuf,
    rule: String,
    tags: Vec<String>,
    strings: Vec<String>,
}

struct YaraScanResult {
    files_scanned: usize,
    rule_matches: usize,
    string_matches: usize,
    matches: Vec<YaraMatchDetail>,
}

fn scan_with_yara(
    rules: &yara::Rules,
    root: &Path,
    stream_label: Option<&str>,
) -> Result<YaraScanResult> {
    let mut files = Vec::new();
    collect_files(root, &mut files)?;
    let files_scanned = files.len();
    let mut matches = Vec::new();
    let mut rule_matches = 0;
    let mut string_matches = 0;
    for file in files {
        let result = rules
            .scan_file(&file, 10)
            .with_context(|| format!("scan {}", file.display()))?;
        for rule in result.iter() {
            rule_matches += 1;
            let tags = rule.tags.iter().map(|t| t.to_string()).collect::<Vec<_>>();
            let mut strings = Vec::new();
            for yr_string in &rule.strings {
                for m in &yr_string.matches {
                    string_matches += 1;
                    strings.push(format!(
                        "{} @ 0x{:x} (len {}): {}",
                        yr_string.identifier,
                        m.offset,
                        m.length,
                        format_match_data(&m.data)
                    ));
                }
            }
            let detail = YaraMatchDetail {
                path: file.clone(),
                rule: rule.identifier.to_string(),
                tags,
                strings,
            };
            if let Some(label) = stream_label {
                print_yara_match(label, &detail);
            }
            matches.push(detail);
        }
    }
    Ok(YaraScanResult {
        files_scanned,
        rule_matches,
        string_matches,
        matches,
    })
}

fn collect_files(root: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    if !root.exists() {
        return Ok(());
    }
    let meta = fs::symlink_metadata(root)
        .with_context(|| format!("stat {}", root.display()))?;
    let file_type = meta.file_type();
    if file_type.is_symlink() {
        return Ok(());
    }
    if file_type.is_file() {
        out.push(root.to_path_buf());
        return Ok(());
    }
    if file_type.is_dir() {
        for entry in fs::read_dir(root).with_context(|| format!("read {}", root.display()))? {
            let entry = entry?;
            collect_files(&entry.path(), out)?;
        }
    }
    Ok(())
}

fn format_match_data(data: &[u8]) -> String {
    if data.is_empty() {
        return "(empty)".to_string();
    }
    let printable = data.iter().all(|b| matches!(b, 0x20..=0x7e));
    let max_len = 64;
    if printable {
        let mut s = String::from_utf8_lossy(data).to_string();
        if s.len() > max_len {
            s.truncate(max_len);
            s.push_str("...");
        }
        format!("\"{}\"", s.replace('\\', "\\\\").replace('\"', "\\\""))
    } else {
        let mut hex = String::new();
        for (idx, byte) in data.iter().enumerate() {
            if idx >= max_len {
                hex.push_str("...");
                break;
            }
            hex.push_str(&format!("{:02x}", byte));
        }
        format!("0x{hex}")
    }
}

fn print_yara_match(label: &str, detail: &YaraMatchDetail) {
    println!("YARA match {label} {} {}", detail.rule, detail.path.display());
    if !detail.tags.is_empty() {
        println!("  tags: {}", detail.tags.join(", "));
    }
    for line in &detail.strings {
        println!("  {line}");
    }
}

fn print_security_report(findings: &[ScanIssue], total: usize) {
    println!("Security scan report:");
    println!("- packages scanned: {total}");
    if findings.is_empty() {
        println!("- issues found: 0");
        println!("No issues detected.");
        return;
    }
    let issue_count: usize = findings.iter().map(|f| f.details.len()).sum();
    println!("- packages with issues: {}", findings.len());
    println!("- issues found: {issue_count}");
    for finding in findings {
        println!();
        println!("{}@{}", finding.name, finding.version);
        for detail in &finding.details {
            println!("- {detail}");
        }
    }
}

fn print_yara_summary(summary: &YaraSummary, enabled: bool) {
    if !enabled {
        return;
    }
    println!();
    println!("YARA summary:");
    println!("- files scanned: {}", summary.files_scanned);
    println!("- rule matches: {}", summary.rule_matches);
    println!("- string matches: {}", summary.string_matches);
    println!("- rules matched: {}", summary.rules.len());
    println!(
        "- packages with matches: {}",
        summary.packages_with_matches.len()
    );
    if !summary.rules.is_empty() {
        let mut rules: Vec<_> = summary.rules.iter().cloned().collect();
        rules.sort();
        println!("- rule list: {}", rules.join(", "));
    }
}

#[derive(Clone, Debug, Deserialize)]
struct RegistryPackage {
    versions: HashMap<String, RegistryVersion>,
    #[serde(rename = "dist-tags")]
    dist_tags: HashMap<String, String>,
    time: Option<HashMap<String, String>>,
}

#[derive(Clone, Debug, Deserialize)]
struct RegistryVersion {
    dependencies: Option<HashMap<String, String>>,
    #[serde(rename = "optionalDependencies")]
    optional_dependencies: Option<HashMap<String, String>>,
    #[serde(rename = "peerDependencies")]
    peer_dependencies: Option<HashMap<String, String>>,
    #[serde(rename = "peerDependenciesMeta")]
    peer_dependencies_meta: Option<HashMap<String, PeerDepMeta>>,
    engines: Option<JsonValue>,
    #[serde(rename = "hasBin")]
    has_bin: Option<bool>,
    dist: RegistryDist,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct PeerDepMeta {
    optional: Option<bool>,
}

#[derive(Clone, Debug, Deserialize)]
struct RegistryDist {
    tarball: String,
    integrity: Option<String>,
    shasum: Option<String>,
}

#[derive(Clone, Debug)]
struct ResolvedNode {
    name: String,
    version: String,
    dependencies: BTreeMap<String, String>,
    optional_dependencies: BTreeMap<String, String>,
    peer_dependencies: BTreeMap<String, String>,
}

#[derive(Clone, Debug)]
struct ResolveResult {
    root_resolved: HashMap<String, String>,
    nodes: HashMap<String, ResolvedNode>,
    metadata: HashMap<String, RegistryPackage>,
}

fn read_overrides(manifest: &JsonValue) -> HashMap<String, String> {
    let mut result = HashMap::new();
    if let Some(pnpm) = manifest.get("pnpm") {
        if let Some(overrides) = pnpm.get("overrides").and_then(|v| v.as_object()) {
            for (name, value) in overrides {
                if let Some(s) = value.as_str() {
                    result.insert(name.clone(), s.to_string());
                }
            }
        }
    }
    result
}

fn resolve_dependencies(specs: &[PackageSpec], debug: bool, overrides: &HashMap<String, String>, registry: &str) -> Result<ResolveResult> {
    println!("Progress: resolving dependencies");
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .build()
        .context("build http client")?;

    let mut root_resolved: HashMap<String, String> = HashMap::new();
    let mut nodes: HashMap<String, ResolvedNode> = HashMap::new();
    let mut metadata_cache: HashMap<String, RegistryPackage> = HashMap::new();
    let mut queue = VecDeque::new();

    for spec in specs {
        validate_package_name(&spec.name)?;
        let meta = fetch_registry_metadata(&client, &spec.name, &mut metadata_cache, debug, registry)?;
        let reqs = spec
            .requested
            .as_ref()
            .map(|s| vec![s.clone()])
            .unwrap_or_default();
        let version = select_version(&spec.name, &reqs, &meta, overrides)?;
        root_resolved.insert(spec.name.clone(), version.clone());
        queue.push_back((spec.name.clone(), version));
    }

    while let Some((name, version)) = queue.pop_front() {
        let key = node_key(&name, &version);
        if nodes.contains_key(&key) {
            continue;
        }
        let meta = fetch_registry_metadata(&client, &name, &mut metadata_cache, debug, registry)?;
        if debug {
            eprintln!("pnpm-rs debug: resolved {}@{}", name, version);
        }

        let version_entry = meta
            .versions
            .get(&version)
            .ok_or_else(|| anyhow!("missing version metadata for {name}@{version}"))?;
        if version_entry.engines.is_some() {
            warn(&format!("engines for {name}@{version} are recorded but not enforced"));
        }

        let dependencies = resolve_dependency_set(
            &client,
            version_entry.dependencies.as_ref(),
            &mut metadata_cache,
            &mut queue,
            debug,
            overrides,
            registry,
        )?;
        let optional_dependencies = resolve_dependency_set(
            &client,
            version_entry.optional_dependencies.as_ref(),
            &mut metadata_cache,
            &mut queue,
            debug,
            overrides,
            registry,
        )?;

        // Resolve non-optional peer dependencies
        let peer_deps_to_resolve: Option<HashMap<String, String>> = version_entry
            .peer_dependencies
            .as_ref()
            .map(|peers| {
                let meta_map = version_entry.peer_dependencies_meta.as_ref();
                peers
                    .iter()
                    .filter(|(pname, _)| {
                        let is_optional = meta_map
                            .and_then(|m| m.get(pname.as_str()))
                            .and_then(|m| m.optional)
                            .unwrap_or(false);
                        !is_optional
                    })
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect()
            });

        let peer_dependencies = resolve_dependency_set(
            &client,
            peer_deps_to_resolve.as_ref(),
            &mut metadata_cache,
            &mut queue,
            debug,
            overrides,
            registry,
        )?;

        nodes.insert(
            key,
            ResolvedNode {
                name,
                version,
                dependencies,
                optional_dependencies,
                peer_dependencies,
            },
        );
    }

    Ok(ResolveResult {
        root_resolved,
        nodes,
        metadata: metadata_cache,
    })
}

fn resolve_dependency_set(
    client: &reqwest::blocking::Client,
    deps: Option<&HashMap<String, String>>,
    metadata_cache: &mut HashMap<String, RegistryPackage>,
    queue: &mut VecDeque<(String, String)>,
    debug: bool,
    overrides: &HashMap<String, String>,
    registry: &str,
) -> Result<BTreeMap<String, String>> {
    let Some(deps) = deps else { return Ok(BTreeMap::new()); };
    let mut resolved = BTreeMap::new();
    for (dep, req) in deps {
        let alias = ensure_safe_requirement(dep, req)?;
        let (fetch_name, fetch_req) = if let Some((real_name, real_req)) = &alias {
            (real_name.as_str(), real_req.as_str())
        } else {
            (dep.as_str(), req.as_str())
        };
        let dep_meta = fetch_registry_metadata(client, fetch_name, metadata_cache, debug, registry)?;
        let dep_version = select_version(fetch_name, &[fetch_req.to_string()], &dep_meta, overrides)?;
        resolved.insert(dep.to_string(), dep_version.clone());
        queue.push_back((fetch_name.to_string(), dep_version));
    }
    Ok(resolved)
}

fn ensure_safe_requirement(name: &str, req: &str) -> Result<Option<(String, String)>> {
    validate_package_name(name)?;
    let lower = req.to_ascii_lowercase();
    if lower.starts_with("file:")
        || lower.starts_with("link:")
        || lower.starts_with("workspace:")
        || lower.starts_with("git+")
        || lower.contains("://")
    {
        bail!("exotic dependency sources are not allowed for {name}: {req}");
    }
    // npm:real-name@range -> use real-name and range
    if let Some(rest) = req.strip_prefix("npm:") {
        let (real_name, real_req) = if rest.starts_with('@') {
            // scoped: npm:@scope/pkg@range
            match rest[1..].find('@') {
                Some(idx) => {
                    let at_idx = idx + 1;
                    (&rest[..at_idx], &rest[at_idx + 1..])
                }
                None => (rest, "*"),
            }
        } else {
            match rest.find('@') {
                Some(idx) => (&rest[..idx], &rest[idx + 1..]),
                None => (rest, "*"),
            }
        };
        validate_package_name(real_name)?;
        return Ok(Some((real_name.to_string(), real_req.to_string())));
    }
    Ok(None)
}

fn validate_package_name(name: &str) -> Result<()> {
    if name.is_empty() {
        bail!("package name cannot be empty");
    }
    if name.len() > MAX_PACKAGE_NAME_LEN {
        bail!("package name too long: {name}");
    }
    if name.trim() != name {
        bail!("package name has leading/trailing whitespace: {name}");
    }
    if name.chars().any(|c| c.is_control() || c.is_whitespace()) {
        bail!("package name has invalid whitespace/control chars: {name}");
    }
    if name.contains('\\') || name.contains("..") {
        bail!("package name has invalid path-like segments: {name}");
    }

    if let Some(rest) = name.strip_prefix('@') {
        let Some((scope, pkg)) = rest.split_once('/') else {
            bail!("scoped package must use @scope/name: {name}");
        };
        if scope.is_empty() || pkg.is_empty() || pkg.contains('/') {
            bail!("invalid scoped package format: {name}");
        }
        if !is_valid_name_segment(scope) || !is_valid_name_segment(pkg) {
            bail!("invalid package name characters: {name}");
        }
        return Ok(());
    }

    if name.contains('/') || !is_valid_name_segment(name) {
        bail!("invalid package name: {name}");
    }
    Ok(())
}

fn is_valid_name_segment(segment: &str) -> bool {
    if segment.is_empty() || segment.starts_with('.') || segment.starts_with('_') {
        return false;
    }
    segment
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '-' | '_' | '.'))
}

fn fetch_registry_metadata(
    client: &reqwest::blocking::Client,
    name: &str,
    cache: &mut HashMap<String, RegistryPackage>,
    debug: bool,
    registry: &str,
) -> Result<RegistryPackage> {
    if let Some(existing) = cache.get(name) {
        return Ok(existing.clone());
    }
    {
        let encoded = urlencoding::encode(name);
        let url = format!("{registry}{encoded}");
        println!("Fetching metadata: {name}");
        if debug {
            eprintln!("pnpm-rs debug: GET {url}");
        }
        let response = client
            .get(&url)
            .header("User-Agent", "pnpm-rs")
            .send()
            .with_context(|| format!("fetch registry metadata {url}"))?;
        if !response.status().is_success() {
            bail!("registry lookup failed for {name}: {}", response.status());
        }
        let package: RegistryPackage = response.json().context("parse registry json")?;
        cache.insert(name.to_string(), package);
    }
    Ok(cache.get(name).expect("metadata cached").clone())
}

fn select_version(name: &str, reqs: &[String], meta: &RegistryPackage, overrides: &HashMap<String, String>) -> Result<String> {
    let override_vec;
    let reqs = if let Some(override_req) = overrides.get(name) {
        override_vec = vec![override_req.clone()];
        &override_vec[..]
    } else {
        reqs
    };
    if reqs.is_empty() {
        return Ok(dist_tag_latest(name, meta)?);
    }
    let mut selected: Option<Version> = None;
    let mut exact: Option<String> = None;

    for req in reqs {
        if meta.versions.contains_key(req) {
            exact = Some(req.clone());
            continue;
        }
        if let Some(tag) = meta.dist_tags.get(req) {
            exact = Some(tag.clone());
            continue;
        }
        for part in split_or_range(req) {
            let normalized = match normalize_range(&part) {
                Ok(value) => value,
                Err(err) => {
                    warn(&format!("unsupported version range '{req}': {err}; falling back to latest"));
                    continue;
                }
            };
            let parsed = VersionReq::parse(&normalized)
                .with_context(|| format!("parse version req {req}"))?;
            for version_str in meta.versions.keys() {
                let Ok(version) = Version::parse(version_str) else { continue };
                if parsed.matches(&version) {
                    if selected.as_ref().map_or(true, |v| &version > v) {
                        selected = Some(version);
                    }
                }
            }
        }
    }

    if let Some(exact) = exact {
        return Ok(exact);
    }
    if let Some(chosen) = selected {
        return Ok(chosen.to_string());
    }

    bail!("no versions found for {name} matching {reqs:?}")
}

fn dist_tag_latest(name: &str, meta: &RegistryPackage) -> Result<String> {
    meta.dist_tags
        .get("latest")
        .cloned()
        .ok_or_else(|| anyhow!("registry did not include latest tag for {name}"))
}

fn node_key(name: &str, version: &str) -> String {
    format!("{name}@{version}")
}

fn split_or_range(req: &str) -> Vec<String> {
    let normalized = req.replace("||", "|");
    normalized
        .split('|')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect()
}

fn normalize_range(req: &str) -> Result<String> {
    let trimmed = req.trim();
    if trimmed.is_empty() || trimmed == "*" {
        return Ok("*".to_string());
    }
    if trimmed == "latest" {
        return Ok("*".to_string());
    }
    if let Some((left, right)) = split_hyphen_range(trimmed) {
        let left_norm = normalize_version_token(&left)?;
        let right_norm = normalize_version_token(&right)?;
        return Ok(format!(">={left_norm}, <={right_norm}"));
    }
    let replaced = trimmed.replace(',', " ");
    let raw_tokens: Vec<&str> = replaced.split_whitespace().collect();
    let mut combined = Vec::new();
    let mut idx = 0;
    while idx < raw_tokens.len() {
        let token = raw_tokens[idx];
        if is_comparator(token) && idx + 1 < raw_tokens.len() {
            let next = raw_tokens[idx + 1];
            combined.push(format!("{token}{next}"));
            idx += 2;
            continue;
        }
        combined.push(token.to_string());
        idx += 1;
    }
    let mut tokens = Vec::new();
    for raw in combined {
        let token = normalize_token(&raw)?;
        if !token.is_empty() {
            tokens.push(token);
        }
    }
    if tokens.is_empty() {
        bail!("unsupported version range: {req}");
    }
    Ok(tokens.join(", "))
}

fn split_hyphen_range(input: &str) -> Option<(String, String)> {
    let parts: Vec<&str> = input.split(" - ").collect();
    if parts.len() == 2 {
        Some((parts[0].trim().to_string(), parts[1].trim().to_string()))
    } else {
        None
    }
}

fn normalize_token(token: &str) -> Result<String> {
    let token = token.trim();
    if token.is_empty() {
        return Ok(String::new());
    }
    if token == "*" || token.eq_ignore_ascii_case("latest") {
        return Ok("*".to_string());
    }
    if token.starts_with("^") || token.starts_with("~") {
        let op = &token[0..1];
        let ver = normalize_version_token(&token[1..])?;
        return Ok(format!("{op}{ver}"));
    }
    for op in [">=", "<=", ">", "<", "="] {
        if token.starts_with(op) {
            let ver = normalize_version_token(&token[op.len()..])?;
            return Ok(format!("{op}{ver}"));
        }
    }
    if token.contains('x') || token.contains('X') || token.contains('*') {
        return expand_wildcard(token);
    }
    let norm = normalize_version_token(token)?;
    if token == norm {
        return Ok(norm);
    }
    Ok(norm)
}

fn is_comparator(token: &str) -> bool {
    matches!(token, ">=" | "<=" | ">" | "<" | "=")
}

fn normalize_version_token(version: &str) -> Result<String> {
    let raw = version.trim().trim_start_matches('v');
    if raw.is_empty() {
        bail!("invalid version token '{version}'");
    }
    if raw.contains('x') || raw.contains('X') || raw.contains('*') {
        return expand_wildcard(raw);
    }
    let parts: Vec<&str> = raw.split('.').collect();
    let normalized = match parts.len() {
        1 => format!("{}.0.0", parts[0]),
        2 => format!("{}.{}.0", parts[0], parts[1]),
        _ => raw.to_string(),
    };
    Ok(normalized)
}

fn expand_wildcard(token: &str) -> Result<String> {
    let raw = token.trim().trim_start_matches('v');
    let parts: Vec<&str> = raw.split('.').collect();
    if parts.is_empty() {
        return Ok("*".to_string());
    }
    let major = parts[0];
    if major.eq_ignore_ascii_case("x") || major == "*" {
        return Ok("*".to_string());
    }
    let major_num: u64 = major
        .parse()
        .with_context(|| format!("parse wildcard {token}"))?;
    if parts.len() == 1 || parts[1].eq_ignore_ascii_case("x") || parts[1] == "*" {
        return Ok(format!(">={major_num}.0.0, <{}.0.0", major_num + 1));
    }
    let minor_num: u64 = parts[1]
        .parse()
        .with_context(|| format!("parse wildcard {token}"))?;
    if parts.len() == 2 || parts[2].eq_ignore_ascii_case("x") || parts[2] == "*" {
        return Ok(format!(
            ">={major_num}.{minor_num}.0, <{major_num}.{}.0",
            minor_num + 1
        ));
    }
    Ok(raw.to_string())
}

fn warn(message: &str) {
    eprintln!("pnpm-rs warning: {message}");
}

fn write_modules_yaml(cwd: &Path, registry: &str) -> Result<()> {
    let path = cwd.join("node_modules").join(".modules.yaml");
    let store_dir = cwd.join("node_modules").join(".pnpm");
    let now = Utc::now().to_rfc2822();
    let contents = format!(
        "hoistPattern:\n  - '*'\nhoistedDependencies: {{}}\nincluded:\n  dependencies: true\n  devDependencies: true\n  optionalDependencies: true\ninjectedDeps: {{}}\nlayoutVersion: 5\nnodeLinker: isolated\npackageManager: pnpm-rs@{VERSION_STR}\npendingBuilds: []\nprunedAt: {now}\npublicHoistPattern: []\nregistries:\n  default: {registry}\nskipped: []\nstoreDir: {store}\nvirtualStoreDir: .pnpm\nvirtualStoreDirMaxLength: 120\n",
        store = store_dir.display()
    );
    fs::write(&path, contents).with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

fn extract_string_map(value: &JsonValue, context: &str) -> Option<BTreeMap<String, String>> {
    let obj = match value.as_object() {
        Some(obj) => obj,
        None => {
            warn(&format!("{context} is not an object; ignored"));
            return None;
        }
    };
    let mut out = BTreeMap::new();
    for (key, val) in obj {
        if let Some(s) = val.as_str() {
            out.insert(key.clone(), s.to_string());
        } else {
            warn(&format!("{context} has non-string value for {key}; ignored"));
        }
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

fn read_package_bin_entries(package_dir: &Path) -> Result<BTreeMap<String, PathBuf>> {
    let manifest_path = package_dir.join("package.json");
    if !manifest_path.exists() {
        return Ok(BTreeMap::new());
    }
    let raw = fs::read_to_string(&manifest_path)
        .with_context(|| format!("read {}", manifest_path.display()))?;
    let json: JsonValue = serde_json::from_str(&raw)
        .with_context(|| format!("parse {}", manifest_path.display()))?;
    let name = json.get("name").and_then(|v| v.as_str()).unwrap_or("");
    let bin_name = name.rsplit('/').next().unwrap_or(name);

    let mut entries = BTreeMap::new();
    match json.get("bin") {
        Some(JsonValue::String(s)) => {
            let path = PathBuf::from(s);
            if path.components().any(|c| matches!(c, Component::ParentDir)) {
                bail!("bin path contains ..: {s}");
            }
            entries.insert(bin_name.to_string(), package_dir.join(&path));
        }
        Some(JsonValue::Object(map)) => {
            for (key, val) in map {
                if let Some(s) = val.as_str() {
                    let path = PathBuf::from(s);
                    if path.components().any(|c| matches!(c, Component::ParentDir)) {
                        bail!("bin path contains ..: {s}");
                    }
                    entries.insert(key.clone(), package_dir.join(&path));
                }
            }
        }
        _ => {}
    }
    Ok(entries)
}

fn link_bin_entries(bin_dir: &Path, entries: &BTreeMap<String, PathBuf>) -> Result<()> {
    if entries.is_empty() {
        return Ok(());
    }
    fs::create_dir_all(bin_dir)
        .with_context(|| format!("create {}", bin_dir.display()))?;
    for (name, target) in entries {
        let link_path = bin_dir.join(name);
        remove_existing_path(&link_path)?;
        #[cfg(unix)]
        {
            symlink(target, &link_path)
                .with_context(|| format!("symlink bin {}", link_path.display()))?;
            use std::os::unix::fs::PermissionsExt;
            if target.exists() {
                let meta = fs::metadata(target)?;
                let mut perms = meta.permissions();
                let mode = perms.mode() | 0o111;
                perms.set_mode(mode);
                fs::set_permissions(target, perms)?;
            }
        }
    }
    Ok(())
}

fn link_root_bin_entries(cwd: &Path, root_resolved: &HashMap<String, String>) -> Result<()> {
    let bin_dir = cwd.join("node_modules").join(".bin");
    for (name, version) in root_resolved {
        let pkg_dir = store_package_path(cwd, name, version);
        let entries = read_package_bin_entries(&pkg_dir)?;
        link_bin_entries(&bin_dir, &entries)?;
    }
    Ok(())
}

fn link_nested_bin_entries(cwd: &Path, node: &ResolvedNode) -> Result<()> {
    let store_nm = store_package_root(cwd, &node.name, &node.version).join("node_modules");
    let bin_dir = store_nm.join(".bin");
    for (dep, dep_version) in node.dependencies.iter().chain(node.peer_dependencies.iter()) {
        let dep_pkg_dir = store_package_path(cwd, dep, dep_version);
        let entries = read_package_bin_entries(&dep_pkg_dir)?;
        link_bin_entries(&bin_dir, &entries)?;
    }
    Ok(())
}

fn install_with_resolution(cwd: &Path, resolve: &ResolveResult, debug: bool, registry: &str) -> Result<()> {
    let node_modules = cwd.join("node_modules");
    if !node_modules.exists() {
        fs::create_dir_all(&node_modules)
            .with_context(|| format!("create {}", node_modules.display()))?;
    }
    let store_root = node_modules.join(".pnpm");
    fs::create_dir_all(&store_root)
        .with_context(|| format!("create {}", store_root.display()))?;

    let custom_host = custom_registry_host(registry);
    let custom_host_ref = custom_host.as_deref();

    let mut node_keys: Vec<_> = resolve.nodes.keys().cloned().collect();
    node_keys.sort();
    for key in &node_keys {
        let node = resolve
            .nodes
            .get(key)
            .expect("node key exists");
        install_package(cwd, &node.name, &node.version, resolve, debug, custom_host_ref)?;
    }

    for key in &node_keys {
        let node = resolve
            .nodes
            .get(key)
            .expect("node key exists");
        link_package_deps(cwd, node)?;
    }

    let manifest = read_package_json(cwd)?;
    let (deps, dev_deps, optional_deps) = collect_manifest_deps(&manifest);
    for (name, _req) in deps
        .iter()
        .chain(dev_deps.iter())
        .chain(optional_deps.iter())
    {
        link_root_dep(cwd, name, &resolve.root_resolved)?;
    }

    // Link .bin entries for root dependencies (Change 10)
    link_root_bin_entries(cwd, &resolve.root_resolved)?;

    // Link .bin entries for nested dependencies
    for key in &node_keys {
        let node = resolve.nodes.get(key).expect("node key exists");
        link_nested_bin_entries(cwd, node)?;
    }

    write_lockfile(cwd, resolve)?;
    write_modules_yaml(cwd, registry)?;
    print_blocked_scripts_for_root(cwd)?;
    println!("Packages: +{}", node_keys.len());
    println!("Done");
    Ok(())
}

fn install_package(
    cwd: &Path,
    name: &str,
    version: &str,
    resolve: &ResolveResult,
    debug: bool,
    custom_host: Option<&str>,
) -> Result<()> {
    let meta = resolve
        .metadata
        .get(name)
        .ok_or_else(|| anyhow!("missing metadata for {name}"))?;
    let version_entry = meta
        .versions
        .get(version)
        .ok_or_else(|| anyhow!("missing metadata for {name}@{version}"))?;

    let tarball_url = &version_entry.dist.tarball;
    ensure_trusted_tarball_url(tarball_url, custom_host)?;
    println!("Downloading {name}@{version}");
    if debug {
        eprintln!("pnpm-rs debug: download {tarball_url}");
    }
    let tarball = download_tarball(tarball_url)?;
    verify_download_integrity(
        &tarball,
        version_entry.dist.integrity.as_deref(),
        version_entry.dist.shasum.as_deref(),
        &format!("{name}@{version}"),
    )?;

    let temp = TempDir::new().context("create temp dir")?;
    unpack_tarball(&tarball, temp.path())?;
    let package_dir = locate_package_dir(temp.path())
        .with_context(|| format!("tarball missing package/ directory for {name}@{version}"))?;

    let dest = store_package_path(cwd, name, version);
    let store_root = store_package_root(cwd, name, version);
    if store_root.exists() {
        fs::remove_dir_all(&store_root)
            .with_context(|| format!("remove {}", store_root.display()))?;
    }
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create {}", parent.display()))?;
    }
    println!("Installing {name}@{version}");
    match fs::rename(&package_dir, &dest) {
        Ok(()) => {}
        Err(err) if is_cross_device_error(&err) => {
            copy_dir_all(&package_dir, &dest)
                .with_context(|| format!("copy {}", dest.display()))?;
            fs::remove_dir_all(&package_dir)
                .with_context(|| format!("cleanup {}", package_dir.display()))?;
        }
        Err(err) => return Err(err).with_context(|| format!("move {}", dest.display())),
    }

    report_blocked_scripts(&dest)?;
    Ok(())
}

fn copy_dir_all(src: &Path, dst: &Path) -> Result<()> {
    if !dst.exists() {
        fs::create_dir_all(dst).with_context(|| format!("create {}", dst.display()))?;
    }
    for entry in fs::read_dir(src).with_context(|| format!("read {}", src.display()))? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        if file_type.is_dir() {
            copy_dir_all(&src_path, &dst_path)?;
        } else if file_type.is_file() {
            fs::copy(&src_path, &dst_path)
                .with_context(|| format!("copy {}", dst_path.display()))?;
        }
    }
    Ok(())
}

fn is_cross_device_error(err: &io::Error) -> bool {
    err.raw_os_error() == Some(18)
}

fn shasum_to_integrity(shasum: &str) -> Result<String> {
    let bytes = hex_to_bytes(shasum)?;
    let encoded = BASE64_STANDARD.encode(bytes);
    Ok(format!("sha1-{encoded}"))
}

fn hex_to_bytes(hex: &str) -> Result<Vec<u8>> {
    if hex.len() % 2 != 0 {
        bail!("invalid shasum length");
    }
    let mut out = Vec::with_capacity(hex.len() / 2);
    let chars: Vec<char> = hex.chars().collect();
    for idx in (0..chars.len()).step_by(2) {
        let pair = [chars[idx], chars[idx + 1]];
        let value = u8::from_str_radix(&pair.iter().collect::<String>(), 16)
            .with_context(|| "parse shasum")?;
        out.push(value);
    }
    Ok(out)
}

fn package_install_path(cwd: &Path, name: &str) -> PathBuf {
    if let Some((scope, pkg)) = name.split_once('/') {
        if scope.starts_with('@') {
            return cwd.join("node_modules").join(scope).join(pkg);
        }
    }
    cwd.join("node_modules").join(name)
}

fn store_package_root(cwd: &Path, name: &str, version: &str) -> PathBuf {
    cwd.join("node_modules")
        .join(".pnpm")
        .join(pnpm_dir_name(name, version))
}

fn store_package_path(cwd: &Path, name: &str, version: &str) -> PathBuf {
    store_package_root(cwd, name, version)
        .join("node_modules")
        .join(name)
}

fn pnpm_dir_name(name: &str, version: &str) -> String {
    let mut safe = name.replace('/', "+");
    safe.push('@');
    safe.push_str(version);
    safe
}

fn link_package_deps(cwd: &Path, node: &ResolvedNode) -> Result<()> {
    let all_deps = node.dependencies.iter()
        .chain(node.peer_dependencies.iter());
    let has_any = !node.dependencies.is_empty() || !node.peer_dependencies.is_empty();
    if !has_any {
        return Ok(());
    }
    let store_root = store_package_root(cwd, &node.name, &node.version).join("node_modules");
    fs::create_dir_all(&store_root)
        .with_context(|| format!("create {}", store_root.display()))?;
    for (dep, dep_version) in all_deps {
        let target = store_package_path(cwd, dep, dep_version);
        let link_path = store_root.join(dep);
        if let Some(parent) = link_path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("create {}", parent.display()))?;
        }
        remove_existing_path(&link_path)?;
        #[cfg(unix)]
        {
            symlink(&target, &link_path)
                .with_context(|| format!("symlink {}", link_path.display()))?;
        }
    }
    Ok(())
}

fn link_root_dep(
    cwd: &Path,
    name: &str,
    resolved: &HashMap<String, String>,
) -> Result<()> {
    let Some(version) = resolved.get(name) else { return Ok(()) };
    let target = store_package_path(cwd, name, version);
    let link_path = package_install_path(cwd, name);
    if let Some(parent) = link_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create {}", parent.display()))?;
    }
    remove_existing_path(&link_path)?;
    #[cfg(unix)]
    {
        symlink(&target, &link_path)
            .with_context(|| format!("symlink {}", link_path.display()))?;
    }
    Ok(())
}

fn remove_existing_path(path: &Path) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }
    let meta = fs::symlink_metadata(path)
        .with_context(|| format!("stat {}", path.display()))?;
    if meta.file_type().is_dir() && !meta.file_type().is_symlink() {
        fs::remove_dir_all(path).with_context(|| format!("remove {}", path.display()))?;
    } else {
        fs::remove_file(path).with_context(|| format!("remove {}", path.display()))?;
    }
    Ok(())
}

fn ensure_trusted_tarball_url(url: &str, custom_registry_host: Option<&str>) -> Result<()> {
    let parsed = reqwest::Url::parse(url).with_context(|| format!("parse tarball url {url}"))?;
    if parsed.scheme() != "https" {
        bail!("tarball URL must use https: {url}");
    }
    let Some(host) = parsed.host_str() else {
        bail!("tarball URL missing host: {url}");
    };
    if !is_allowed_tarball_host(host, custom_registry_host) {
        bail!("tarball URL host not allowed: {host}");
    }
    Ok(())
}

fn is_allowed_tarball_host(host: &str, custom_registry_host: Option<&str>) -> bool {
    if host == "registry.npmjs.org"
        || host == "npmjs.org"
        || host.ends_with(".npmjs.org")
        || host == "npmjs.com"
        || host.ends_with(".npmjs.com")
    {
        return true;
    }
    if let Some(custom) = custom_registry_host {
        return host == custom;
    }
    false
}

fn download_tarball(url: &str) -> Result<Vec<u8>> {
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .build()
        .context("build http client")?;
    let mut response = client
        .get(url)
        .header("User-Agent", "pnpm-rs")
        .send()
        .with_context(|| format!("download tarball {url}"))?;
    if !response.status().is_success() {
        bail!("tarball download failed: {}", response.status());
    }
    let mut buf = Vec::new();
    response
        .copy_to(&mut buf)
        .context("read tarball response")?;
    Ok(buf)
}

fn verify_download_integrity(
    bytes: &[u8],
    integrity: Option<&str>,
    shasum: Option<&str>,
    label: &str,
) -> Result<()> {
    if let Some(integrity) = integrity {
        match verify_integrity(bytes, integrity) {
            Ok(()) => return Ok(()),
            Err(err) => warn(&format!(
                "integrity mismatch for {label} ({integrity}): {err}; trying shasum fallback"
            )),
        }
    }
    if let Some(shasum) = shasum {
        verify_shasum(bytes, shasum)?;
        return Ok(());
    }
    bail!("no usable integrity metadata for {label}; refusing unverified tarball")
}

fn verify_shasum(bytes: &[u8], expected: &str) -> Result<()> {
    let mut hasher = Sha1::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let actual = format!("{:x}", digest);
    if actual != expected {
        bail!("tarball shasum mismatch: expected {expected}, got {actual}");
    }
    Ok(())
}

fn verify_integrity(bytes: &[u8], integrity: &str) -> Result<()> {
    for token in integrity.split_whitespace() {
        if let Some((algo, value)) = token.split_once('-') {
            let decoded = BASE64_STANDARD
                .decode(value)
                .with_context(|| "decode integrity")?;
            match algo {
                "sha512" => {
                    let mut hasher = Sha512::new();
                    hasher.update(bytes);
                    let digest = hasher.finalize();
                    if digest.as_slice() == decoded.as_slice() {
                        return Ok(());
                    }
                }
                "sha256" => {
                    let mut hasher = Sha256::new();
                    hasher.update(bytes);
                    let digest = hasher.finalize();
                    if digest.as_slice() == decoded.as_slice() {
                        return Ok(());
                    }
                }
                "sha1" => {
                    let mut hasher = Sha1::new();
                    hasher.update(bytes);
                    let digest = hasher.finalize();
                    if digest.as_slice() == decoded.as_slice() {
                        return Ok(());
                    }
                }
                _ => continue,
            }
        }
    }
    bail!("integrity verification failed")
}

fn unpack_tarball(bytes: &[u8], dest: &Path) -> Result<()> {
    let decoder = GzDecoder::new(bytes);
    let mut archive = Archive::new(decoder);

    for entry in archive.entries()? {
        let mut entry = entry?;
        let entry_type = entry.header().entry_type();
        if !matches!(entry_type, EntryType::Regular | EntryType::Directory) {
            continue;
        }
        let path = entry.path()?;
        let sanitized = sanitize_tar_path(&path)?;
        let full_path = dest.join(sanitized);
        if entry_type == EntryType::Directory {
            fs::create_dir_all(&full_path)
                .with_context(|| format!("create {}", full_path.display()))?;
            continue;
        }

        if let Some(parent) = full_path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("create {}", parent.display()))?;
        }
        let mut file = fs::File::create(&full_path)
            .with_context(|| format!("create {}", full_path.display()))?;
        io::copy(&mut entry, &mut file)
            .with_context(|| format!("write {}", full_path.display()))?;
    }

    Ok(())
}

fn sanitize_tar_path(path: &Path) -> Result<PathBuf> {
    let mut sanitized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => sanitized.push(part),
            Component::CurDir => continue,
            _ => bail!("invalid tarball path: {}", path.display()),
        }
    }
    Ok(sanitized)
}

fn locate_package_dir(temp: &Path) -> Result<PathBuf> {
    let package_dir = temp.join("package");
    if package_dir.exists() {
        return Ok(package_dir);
    }

    for entry in fs::read_dir(temp).with_context(|| format!("read {}", temp.display()))? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            let candidate = path.join("package");
            if candidate.exists() {
                return Ok(candidate);
            }
        }
    }

    for entry in fs::read_dir(temp).with_context(|| format!("read {}", temp.display()))? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() && path.join("package.json").exists() {
            return Ok(path);
        }
    }

    bail!("tarball missing package/ directory");
}

fn report_blocked_scripts(package_dir: &Path) -> Result<()> {
    let manifest_path = package_dir.join("package.json");
    if !manifest_path.exists() {
        return Ok(());
    }
    let raw = fs::read_to_string(&manifest_path)
        .with_context(|| format!("read {}", manifest_path.display()))?;
    let json: JsonValue = serde_json::from_str(&raw)
        .with_context(|| format!("parse {}", manifest_path.display()))?;

    let name = json.get("name").and_then(|v| v.as_str()).unwrap_or("<unknown>");
    let version = json
        .get("version")
        .and_then(|v| v.as_str())
        .unwrap_or("<unknown>");

    let scripts = match json.get("scripts").and_then(|v| v.as_object()) {
        Some(obj) => obj,
        None => return Ok(()),
    };

    for script_name in ["preinstall", "install", "postinstall", "prepare"] {
        if let Some(cmd) = scripts.get(script_name).and_then(|v| v.as_str()) {
            println!(
                "pnpm-rs: blocked {script_name} for {name}@{version}: {cmd} (run manually if required)"
            );
        }
    }

    Ok(())
}

fn print_blocked_scripts_for_root(cwd: &Path) -> Result<()> {
    let root_manifest = cwd.join("package.json");
    if root_manifest.exists() {
        report_blocked_scripts(cwd)?;
    }
    Ok(())
}

#[derive(Serialize)]
struct Lockfile {
    #[serde(rename = "lockfileVersion")]
    lockfile_version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    settings: Option<LockfileSettings>,
    importers: BTreeMap<String, Importer>,
    packages: BTreeMap<String, PackageSnapshot>,
    snapshots: BTreeMap<String, SnapshotOut>,
}

#[derive(Serialize)]
struct LockfileSettings {
    #[serde(rename = "autoInstallPeers")]
    auto_install_peers: bool,
    #[serde(rename = "excludeLinksFromLockfile")]
    exclude_links_from_lockfile: bool,
}

#[derive(Serialize)]
struct Importer {
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    dependencies: BTreeMap<String, ImporterDepOut>,
    #[serde(rename = "devDependencies", skip_serializing_if = "BTreeMap::is_empty")]
    dev_dependencies: BTreeMap<String, ImporterDepOut>,
    #[serde(rename = "optionalDependencies", skip_serializing_if = "BTreeMap::is_empty")]
    optional_dependencies: BTreeMap<String, ImporterDepOut>,
}

#[derive(Serialize)]
struct ImporterDepOut {
    specifier: String,
    version: String,
}

#[derive(Serialize)]
struct PackageSnapshot {
    resolution: Resolution,
    #[serde(skip_serializing_if = "Option::is_none")]
    dependencies: Option<BTreeMap<String, String>>,
    #[serde(rename = "optionalDependencies", skip_serializing_if = "Option::is_none")]
    optional_dependencies: Option<BTreeMap<String, String>>,
    #[serde(rename = "peerDependencies", skip_serializing_if = "Option::is_none")]
    peer_dependencies: Option<BTreeMap<String, String>>,
    #[serde(rename = "peerDependenciesMeta", skip_serializing_if = "Option::is_none")]
    peer_dependencies_meta: Option<BTreeMap<String, PeerDepMeta>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    engines: Option<BTreeMap<String, String>>,
    #[serde(rename = "hasBin", skip_serializing_if = "Option::is_none")]
    has_bin: Option<bool>,
}

#[derive(Serialize, Clone)]
struct SnapshotOut {
    #[serde(skip_serializing_if = "Option::is_none")]
    dependencies: Option<BTreeMap<String, String>>,
    #[serde(rename = "optionalDependencies", skip_serializing_if = "Option::is_none")]
    optional_dependencies: Option<BTreeMap<String, String>>,
    #[serde(rename = "peerDependencies", skip_serializing_if = "Option::is_none")]
    peer_dependencies: Option<BTreeMap<String, String>>,
}

#[derive(Serialize)]
struct Resolution {
    integrity: String,
}

fn write_lockfile(cwd: &Path, resolve: &ResolveResult) -> Result<()> {
    let manifest = read_package_json(cwd)?;
    let (deps, dev_deps, optional_deps) = collect_manifest_deps(&manifest);
    let mut dep_map = BTreeMap::new();
    let mut dev_map = BTreeMap::new();
    let mut optional_map = BTreeMap::new();
    for (name, req) in deps.iter() {
        if let Some(version) = resolve.root_resolved.get(name) {
            dep_map.insert(
                name.clone(),
                ImporterDepOut {
                    specifier: req.clone(),
                    version: version.clone(),
                },
            );
        }
    }
    for (name, req) in dev_deps.iter() {
        if let Some(version) = resolve.root_resolved.get(name) {
            dev_map.insert(
                name.clone(),
                ImporterDepOut {
                    specifier: req.clone(),
                    version: version.clone(),
                },
            );
        }
    }
    for (name, req) in optional_deps.iter() {
        if let Some(version) = resolve.root_resolved.get(name) {
            optional_map.insert(
                name.clone(),
                ImporterDepOut {
                    specifier: req.clone(),
                    version: version.clone(),
                },
            );
        }
    }

    let mut packages = BTreeMap::new();
    let mut snapshots = BTreeMap::new();
    for node in resolve.nodes.values() {
        let name = &node.name;
        let version = &node.version;
        let meta = resolve
            .metadata
            .get(name)
            .ok_or_else(|| anyhow!("missing metadata for {name}"))?;
        let entry = meta
            .versions
            .get(version)
            .ok_or_else(|| anyhow!("missing metadata for {name}@{version}"))?;
        let key = format!("{name}@{version}");
        let optional_deps = if node.optional_dependencies.is_empty() {
            None
        } else {
            Some(node.optional_dependencies.clone())
        };
        let peer_deps = entry.peer_dependencies.as_ref().map(|map| {
            map.iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect::<BTreeMap<_, _>>()
        });
        let peer_meta = entry.peer_dependencies_meta.as_ref().map(|map| {
            map.iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect::<BTreeMap<_, _>>()
        });
        let engines = entry
            .engines
            .as_ref()
            .and_then(|value| extract_string_map(value, &format!("{name}@{version} engines")));
        let integrity = entry
            .dist
            .integrity
            .clone()
            .or_else(|| {
                entry
                    .dist
                    .shasum
                    .as_ref()
                    .and_then(|s| shasum_to_integrity(s).ok())
            })
            .ok_or_else(|| anyhow!("no integrity metadata for {name}@{version}"))?;
        packages.insert(
            key.clone(),
            PackageSnapshot {
                resolution: Resolution {
                    integrity,
                },
                dependencies: None,
                optional_dependencies: None,
                peer_dependencies: peer_deps.clone(),
                peer_dependencies_meta: peer_meta,
                engines,
                has_bin: entry.has_bin,
            },
        );

        // Merge resolved peer deps into snapshot dependencies
        let mut snapshot_deps = node.dependencies.clone();
        for (k, v) in &node.peer_dependencies {
            snapshot_deps.entry(k.clone()).or_insert_with(|| v.clone());
        }
        let snapshot_deps_opt = if snapshot_deps.is_empty() { None } else { Some(snapshot_deps) };

        snapshots.insert(
            key,
            SnapshotOut {
                dependencies: snapshot_deps_opt,
                optional_dependencies: optional_deps,
                peer_dependencies: peer_deps,
            },
        );
    }

    let mut importers = BTreeMap::new();
    importers.insert(
        ".".to_string(),
        Importer {
            dependencies: dep_map,
            dev_dependencies: dev_map,
            optional_dependencies: optional_map,
        },
    );

    let lockfile = Lockfile {
        lockfile_version: "9.0".to_string(),
        settings: Some(LockfileSettings {
            auto_install_peers: true,
            exclude_links_from_lockfile: false,
        }),
        importers,
        packages,
        snapshots,
    };

    let contents = lockfile_to_yaml(&lockfile);
    let wanted_path = cwd.join("pnpm-lock.yaml");
    fs::write(&wanted_path, &contents).context("write pnpm-lock.yaml")?;
    let current_path = cwd.join("node_modules").join(".pnpm").join("lock.yaml");
    fs::write(&current_path, &contents)
        .with_context(|| format!("write {}", current_path.display()))?;
    Ok(())
}

fn lockfile_to_yaml(lockfile: &Lockfile) -> String {
    let mut out = String::new();
    out.push_str("lockfileVersion: '");
    out.push_str(&escape_yaml_scalar(&lockfile.lockfile_version));
    out.push_str("'\n");

    if let Some(settings) = &lockfile.settings {
        out.push_str("settings:\n");
        out.push_str("  autoInstallPeers: ");
        out.push_str(if settings.auto_install_peers { "true" } else { "false" });
        out.push('\n');
        out.push_str("  excludeLinksFromLockfile: ");
        out.push_str(if settings.exclude_links_from_lockfile { "true" } else { "false" });
        out.push('\n');
    }

    out.push_str("importers:\n");
    for (name, importer) in &lockfile.importers {
        out.push_str("  ");
        out.push_str(&escape_yaml_quoted(name));
        out.push_str(":\n");
        write_dependency_section_out(&mut out, "dependencies", &importer.dependencies);
        write_dependency_section_out(&mut out, "devDependencies", &importer.dev_dependencies);
        write_dependency_section_out(&mut out, "optionalDependencies", &importer.optional_dependencies);
    }

    out.push_str("packages:\n");
    for (key, pkg) in &lockfile.packages {
        out.push_str("  ");
        out.push_str(&escape_yaml_quoted(key));
        out.push_str(":\n");
        out.push_str("    resolution:\n");
        out.push_str("      integrity: ");
        out.push_str(&escape_yaml_quoted(&pkg.resolution.integrity));
        out.push('\n');
        if let Some(deps) = &pkg.peer_dependencies {
            write_dep_map(&mut out, 4, "peerDependencies", deps);
        }
        if let Some(meta) = &pkg.peer_dependencies_meta {
            if !meta.is_empty() {
                out.push_str("    peerDependenciesMeta:\n");
                for (dep, info) in meta {
                    out.push_str("      ");
                    out.push_str(&escape_yaml_quoted(dep));
                    out.push_str(":\n");
                    if let Some(optional) = info.optional {
                        out.push_str("        optional: ");
                        out.push_str(if optional { "true" } else { "false" });
                        out.push('\n');
                    }
                }
            }
        }
        if let Some(engines) = &pkg.engines {
            if !engines.is_empty() {
                out.push_str("    engines:\n");
                for (key, value) in engines {
                    out.push_str("      ");
                    out.push_str(&escape_yaml_quoted(key));
                    out.push_str(": ");
                    out.push_str(&escape_yaml_quoted(value));
                    out.push('\n');
                }
            }
        }
        if let Some(has_bin) = pkg.has_bin {
            out.push_str("    hasBin: ");
            out.push_str(if has_bin { "true" } else { "false" });
            out.push('\n');
        }
    }

    out.push_str("snapshots:\n");
    for (key, snapshot) in &lockfile.snapshots {
        out.push_str("  ");
        out.push_str(&escape_yaml_quoted(key));
        out.push_str(":\n");
        let mut wrote = write_dep_map_opt(&mut out, 4, "dependencies", &snapshot.dependencies);
        wrote |= write_dep_map_opt(&mut out, 4, "optionalDependencies", &snapshot.optional_dependencies);
        wrote |= write_dep_map_opt(&mut out, 4, "peerDependencies", &snapshot.peer_dependencies);
        if !wrote {
            out.push_str("    {}\n");
        }
    }

    out
}

fn write_dependency_section_out(
    out: &mut String,
    label: &str,
    resolved: &BTreeMap<String, ImporterDepOut>,
) {
    if resolved.is_empty() {
        return;
    }
    out.push_str("    ");
    out.push_str(label);
    out.push_str(":\n");
    for (name, dep) in resolved {
        out.push_str("      ");
        out.push_str(&escape_yaml_quoted(name));
        out.push_str(":\n");
        out.push_str("        specifier: ");
        out.push_str(&escape_yaml_quoted(&dep.specifier));
        out.push('\n');
        out.push_str("        version: ");
        out.push_str(&escape_yaml_quoted(&dep.version));
        out.push('\n');
    }
}

fn escape_yaml_quoted(value: &str) -> String {
    let escaped = value.replace('\'', "''");
    format!("'{escaped}'")
}

fn escape_yaml_scalar(value: &str) -> String {
    value.replace('\'', "''")
}

fn write_dep_map(out: &mut String, indent: usize, label: &str, deps: &BTreeMap<String, String>) {
    if deps.is_empty() {
        return;
    }
    out.push_str(&" ".repeat(indent));
    out.push_str(label);
    out.push_str(":\n");
    for (dep, version) in deps {
        out.push_str(&" ".repeat(indent + 2));
        out.push_str(&escape_yaml_quoted(dep));
        out.push_str(": ");
        out.push_str(&escape_yaml_quoted(version));
        out.push('\n');
    }
}

fn write_dep_map_opt(
    out: &mut String,
    indent: usize,
    label: &str,
    deps: &Option<BTreeMap<String, String>>,
) -> bool {
    if let Some(map) = deps {
        if !map.is_empty() {
            write_dep_map(out, indent, label, map);
            return true;
        }
    }
    false
}

#[derive(Deserialize)]
struct LockfileIn {
    importers: Option<HashMap<String, ImporterIn>>,
    packages: Option<HashMap<String, PackageSnapshotIn>>,
    snapshots: Option<HashMap<String, SnapshotIn>>,
}

#[derive(Deserialize)]
struct ImporterIn {
    dependencies: Option<HashMap<String, ImporterDepIn>>,
    #[serde(rename = "devDependencies")]
    dev_dependencies: Option<HashMap<String, ImporterDepIn>>,
    #[serde(rename = "optionalDependencies")]
    optional_dependencies: Option<HashMap<String, ImporterDepIn>>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum ImporterDepIn {
    String(String),
    Object {
        version: Option<String>,
    },
}

#[derive(Deserialize, Clone)]
struct ResolutionIn {
    integrity: Option<String>,
}

#[derive(Deserialize, Clone)]
struct PackageSnapshotIn {
    dependencies: Option<HashMap<String, String>>,
    #[serde(rename = "optionalDependencies")]
    optional_dependencies: Option<HashMap<String, String>>,
    #[serde(rename = "peerDependencies")]
    peer_dependencies: Option<HashMap<String, String>>,
    resolution: Option<ResolutionIn>,
}

#[derive(Deserialize, Clone)]
struct SnapshotIn {
    dependencies: Option<HashMap<String, String>>,
    #[serde(rename = "optionalDependencies")]
    optional_dependencies: Option<HashMap<String, String>>,
    #[serde(rename = "peerDependencies")]
    peer_dependencies: Option<HashMap<String, String>>,
}

fn read_lockfile(cwd: &Path) -> Result<Option<LockfileIn>> {
    let lockfile_path = cwd.join("pnpm-lock.yaml");
    if !lockfile_path.exists() {
        return Ok(None);
    }
    let raw = fs::read_to_string(&lockfile_path)
        .with_context(|| format!("read {}", lockfile_path.display()))?;
    let lockfile: LockfileIn = serde_yaml::from_str(&raw).context("parse pnpm-lock.yaml")?;
    Ok(Some(lockfile))
}

fn lockfile_satisfies_manifest(
    lockfile: &LockfileIn,
    deps: &HashMap<String, String>,
    dev_deps: &HashMap<String, String>,
    optional_deps: &HashMap<String, String>,
) -> bool {
    let Some(importers) = &lockfile.importers else { return false; };
    let Some(root) = importers.get(".") else { return false; };

    fn specifiers_match(
        lockfile_deps: &Option<HashMap<String, ImporterDepIn>>,
        manifest_deps: &HashMap<String, String>,
    ) -> bool {
        let lockfile_map = lockfile_deps.as_ref().map(|m| {
            m.iter().map(|(k, v)| {
                let spec = match v {
                    ImporterDepIn::String(s) => s.clone(),
                    ImporterDepIn::Object { version, .. } => version.clone().unwrap_or_default(),
                };
                (k.clone(), spec)
            }).collect::<HashMap<_, _>>()
        }).unwrap_or_default();

        if lockfile_map.len() != manifest_deps.len() {
            return false;
        }
        for (name, _spec) in manifest_deps {
            if !lockfile_map.contains_key(name) {
                return false;
            }
        }
        true
    }

    specifiers_match(&root.dependencies, deps)
        && specifiers_match(&root.dev_dependencies, dev_deps)
        && specifiers_match(&root.optional_dependencies, optional_deps)
}

fn install_from_lockfile(cwd: &Path, lockfile: &LockfileIn, _debug: bool, registry: &str) -> Result<()> {
    println!("Progress: installing from lockfile");
    let node_modules = cwd.join("node_modules");
    if !node_modules.exists() {
        fs::create_dir_all(&node_modules)
            .with_context(|| format!("create {}", node_modules.display()))?;
    }
    let store_root = node_modules.join(".pnpm");
    fs::create_dir_all(&store_root)
        .with_context(|| format!("create {}", store_root.display()))?;

    let custom_host = custom_registry_host(registry);
    let custom_host_ref = custom_host.as_deref();

    let packages = lockfile.packages.as_ref().cloned().unwrap_or_default();
    let snapshots = lockfile.snapshots.as_ref().cloned().unwrap_or_default();
    let mut installed_count = 0;

    // Install all packages from lockfile
    for (key, pkg_snapshot) in &packages {
        let Some((name, version)) = parse_lockfile_key(key) else { continue };
        let dest = store_package_path(cwd, &name, &version);
        if dest.exists() {
            // Already installed
            installed_count += 1;
            continue;
        }

        // We need to download this package
        let encoded = urlencoding::encode(&name);
        let url = format!("{registry}{encoded}");
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(60))
            .build()
            .context("build http client")?;
        println!("Fetching metadata: {name}");
        let response = client
            .get(&url)
            .header("User-Agent", "pnpm-rs")
            .send()
            .with_context(|| format!("fetch registry metadata {url}"))?;
        if !response.status().is_success() {
            bail!("registry lookup failed for {name}: {}", response.status());
        }
        let meta: RegistryPackage = response.json().context("parse registry json")?;
        let version_entry = meta
            .versions
            .get(&version)
            .ok_or_else(|| anyhow!("missing metadata for {name}@{version}"))?;

        let tarball_url = &version_entry.dist.tarball;
        ensure_trusted_tarball_url(tarball_url, custom_host_ref)?;
        println!("Downloading {name}@{version}");
        let tarball = download_tarball(tarball_url)?;

        // Use lockfile integrity if available, fall back to registry
        let lockfile_integrity = pkg_snapshot
            .resolution
            .as_ref()
            .and_then(|r| r.integrity.as_deref());
        verify_download_integrity(
            &tarball,
            lockfile_integrity.or(version_entry.dist.integrity.as_deref()),
            version_entry.dist.shasum.as_deref(),
            &format!("{name}@{version}"),
        )?;

        let temp = TempDir::new().context("create temp dir")?;
        unpack_tarball(&tarball, temp.path())?;
        let package_dir = locate_package_dir(temp.path())
            .with_context(|| format!("tarball missing package/ directory for {name}@{version}"))?;

        let store_pkg_root = store_package_root(cwd, &name, &version);
        if store_pkg_root.exists() {
            fs::remove_dir_all(&store_pkg_root)
                .with_context(|| format!("remove {}", store_pkg_root.display()))?;
        }
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("create {}", parent.display()))?;
        }
        println!("Installing {name}@{version}");
        match fs::rename(&package_dir, &dest) {
            Ok(()) => {}
            Err(err) if is_cross_device_error(&err) => {
                copy_dir_all(&package_dir, &dest)?;
                fs::remove_dir_all(&package_dir)?;
            }
            Err(err) => return Err(err).with_context(|| format!("move {}", dest.display())),
        }
        report_blocked_scripts(&dest)?;
        installed_count += 1;
    }

    // Link dependencies using snapshots
    for (key, snapshot) in &snapshots {
        let Some((name, version)) = parse_lockfile_key(key) else { continue };
        let all_deps = merge_dep_maps(
            snapshot.dependencies.clone(),
            None,
            snapshot.peer_dependencies.clone(),
        );
        if all_deps.is_empty() {
            continue;
        }
        let nm_root = store_package_root(cwd, &name, &version).join("node_modules");
        fs::create_dir_all(&nm_root)
            .with_context(|| format!("create {}", nm_root.display()))?;
        for (dep, dep_version) in &all_deps {
            let target = store_package_path(cwd, dep, dep_version);
            let link_path = nm_root.join(dep);
            if let Some(parent) = link_path.parent() {
                fs::create_dir_all(parent)?;
            }
            remove_existing_path(&link_path)?;
            #[cfg(unix)]
            {
                symlink(&target, &link_path)
                    .with_context(|| format!("symlink {}", link_path.display()))?;
            }
        }

        // Link nested .bin entries
        let bin_dir = nm_root.join(".bin");
        for (dep, dep_version) in &all_deps {
            let dep_pkg_dir = store_package_path(cwd, dep, dep_version);
            let entries = read_package_bin_entries(&dep_pkg_dir)?;
            link_bin_entries(&bin_dir, &entries)?;
        }
    }

    // Link root dependencies
    let manifest = read_package_json(cwd)?;
    let (deps, dev_deps, optional_deps) = collect_manifest_deps(&manifest);
    let mut root_resolved = HashMap::new();
    if let Some(importers) = &lockfile.importers {
        if let Some(root) = importers.get(".") {
            let all_lock_deps = [&root.dependencies, &root.dev_dependencies, &root.optional_dependencies];
            for lock_deps in &all_lock_deps {
                if let Some(map) = lock_deps {
                    for (name, dep) in map {
                        let version = match dep {
                            ImporterDepIn::String(v) => v.clone(),
                            ImporterDepIn::Object { version, .. } => version.clone().unwrap_or_default(),
                        };
                        root_resolved.insert(name.clone(), version);
                    }
                }
            }
        }
    }
    for (name, _req) in deps.iter().chain(dev_deps.iter()).chain(optional_deps.iter()) {
        link_root_dep(cwd, name, &root_resolved)?;
    }

    // Link root .bin entries
    link_root_bin_entries(cwd, &root_resolved)?;

    write_modules_yaml(cwd, registry)?;
    print_blocked_scripts_for_root(cwd)?;
    println!("Packages: +{installed_count}");
    println!("Done");
    Ok(())
}

fn why_packages(cwd: &Path, targets: &[String]) -> Result<()> {
    let lockfile_path = cwd.join("pnpm-lock.yaml");
    if !lockfile_path.exists() {
        bail!("pnpm-lock.yaml not found; run pnpm-rs install first");
    }

    let raw = fs::read_to_string(&lockfile_path)
        .with_context(|| format!("read {}", lockfile_path.display()))?;
    let lockfile: LockfileIn = serde_yaml::from_str(&raw).context("parse pnpm-lock.yaml")?;

    let mut reverse: HashMap<String, Vec<String>> = HashMap::new();
    let mut name_to_versions: HashMap<String, Vec<String>> = HashMap::new();

    if let Some(snapshots) = &lockfile.snapshots {
        for (key, snapshot) in snapshots {
            let Some((name, version)) = parse_lockfile_key(key) else { continue };
            name_to_versions
                .entry(name.clone())
                .or_default()
                .push(version);
            if let Some(deps) = &snapshot.dependencies {
                for dep in deps.keys() {
                    reverse.entry(dep.clone()).or_default().push(name.clone());
                }
            }
            if let Some(deps) = &snapshot.optional_dependencies {
                for dep in deps.keys() {
                    reverse.entry(dep.clone()).or_default().push(name.clone());
                }
            }
            if let Some(deps) = &snapshot.peer_dependencies {
                for dep in deps.keys() {
                    reverse.entry(dep.clone()).or_default().push(name.clone());
                }
            }
        }
    } else if let Some(packages) = &lockfile.packages {
        for (key, snapshot) in packages {
            let Some((name, version)) = parse_lockfile_key(key) else { continue };
            name_to_versions
                .entry(name.clone())
                .or_default()
                .push(version);
            if let Some(deps) = &snapshot.dependencies {
                for dep in deps.keys() {
                    reverse.entry(dep.clone()).or_default().push(name.clone());
                }
            }
            if let Some(deps) = &snapshot.optional_dependencies {
                for dep in deps.keys() {
                    reverse.entry(dep.clone()).or_default().push(name.clone());
                }
            }
            if let Some(deps) = &snapshot.peer_dependencies {
                for dep in deps.keys() {
                    reverse.entry(dep.clone()).or_default().push(name.clone());
                }
            }
        }
    }

    let mut root_deps = HashMap::new();
    if let Some(importers) = &lockfile.importers {
        if let Some(importer) = importers.get(".") {
            if let Some(deps) = &importer.dependencies {
                root_deps.extend(importer_dep_versions(deps));
            }
            if let Some(deps) = &importer.dev_dependencies {
                root_deps.extend(importer_dep_versions(deps));
            }
            if let Some(deps) = &importer.optional_dependencies {
                root_deps.extend(importer_dep_versions(deps));
            }
        }
    }
    for dep in root_deps.keys() {
        reverse
            .entry(dep.clone())
            .or_default()
            .push("<root>".to_string());
    }

    for target in targets {
        println!("pnpm-rs why {target}:");
        let mut found = false;
        if root_deps.contains_key(target) {
            println!("- direct dependency of root");
            found = true;
        }
        if let Some(parents) = reverse.get(target) {
            let mut listed = Vec::new();
            for parent in parents {
                if parent == "<root>" {
                    continue;
                }
                if let Some(versions) = name_to_versions.get(parent) {
                    let version = versions.first().map(|v| v.as_str()).unwrap_or("<unknown>");
                    listed.push(format!("{parent}@{version}"));
                } else {
                    listed.push(parent.clone());
                }
            }
            if !listed.is_empty() {
                listed.sort();
                listed.dedup();
                println!("- depended on by: {}", listed.join(", "));
                found = true;
            }
        }

        if let Some(path) = find_path_to_root(target, &reverse) {
            println!("- path: {}", path.join(" -> "));
            found = true;
        }

        if !found {
            println!("- not found in lockfile");
        }
    }

    Ok(())
}

fn parse_lockfile_key(key: &str) -> Option<(String, String)> {
    let trimmed = key.trim().trim_start_matches('/');
    if trimmed.is_empty() {
        return None;
    }
    let (name, rest) = if trimmed.starts_with('@') {
        let slash_idx = trimmed.find('/')?;
        let after = &trimmed[slash_idx + 1..];
        let at_idx = after.find('@')? + slash_idx + 1;
        (trimmed[..at_idx].to_string(), trimmed[at_idx + 1..].to_string())
    } else {
        let at_idx = trimmed.find('@')?;
        (trimmed[..at_idx].to_string(), trimmed[at_idx + 1..].to_string())
    };
    let version = rest.split('(').next().unwrap_or("").trim();
    if name.is_empty() || version.is_empty() {
        return None;
    }
    Some((name, version.to_string()))
}

fn find_path_to_root(
    target: &str,
    reverse: &HashMap<String, Vec<String>>,
) -> Option<Vec<String>> {
    let mut queue = VecDeque::new();
    let mut parent: HashMap<String, String> = HashMap::new();
    queue.push_back(target.to_string());

    while let Some(node) = queue.pop_front() {
        if let Some(parents) = reverse.get(&node) {
            for parent_name in parents {
                if parent_name == "<root>" {
                    parent.insert("<root>".to_string(), node.clone());
                    let mut path = Vec::new();
                    path.push("<root>".to_string());
                    let mut current = "<root>".to_string();
                    while let Some(next) = parent.get(&current) {
                        path.push(next.clone());
                        current = next.clone();
                        if current == *target {
                            break;
                        }
                    }
                    return Some(path);
                }
                if !parent.contains_key(parent_name) {
                    parent.insert(parent_name.clone(), node.clone());
                    if parent_name == target {
                        continue;
                    }
                    queue.push_back(parent_name.clone());
                }
            }
        }
    }
    None
}

fn importer_dep_versions(deps: &HashMap<String, ImporterDepIn>) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for (name, dep) in deps {
        match dep {
            ImporterDepIn::String(value) => {
                out.insert(name.clone(), value.clone());
            }
            ImporterDepIn::Object { version, .. } => {
                if let Some(ver) = version {
                    out.insert(name.clone(), ver.clone());
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha1::{Digest as Sha1Digest, Sha1};

    #[test]
    fn validate_package_name_rejects_path_like_values() {
        assert!(validate_package_name("../evil").is_err());
        assert!(validate_package_name("@scope/../evil").is_err());
        assert!(validate_package_name("evil\\name").is_err());
    }

    #[test]
    fn validate_package_name_accepts_common_npm_names() {
        assert!(validate_package_name("react").is_ok());
        assert!(validate_package_name("@types/node").is_ok());
        assert!(validate_package_name("left-pad").is_ok());
    }

    #[test]
    fn tarball_url_rejects_untrusted_or_insecure_hosts() {
        assert!(ensure_trusted_tarball_url("http://registry.npmjs.org/react/-/react-1.0.0.tgz", None).is_err());
        assert!(ensure_trusted_tarball_url("https://example.com/react.tgz", None).is_err());
    }

    #[test]
    fn tarball_url_accepts_npm_registry_hosts() {
        assert!(ensure_trusted_tarball_url(
            "https://registry.npmjs.org/react/-/react-19.0.0.tgz",
            None,
        )
        .is_ok());
    }

    #[test]
    fn tarball_url_accepts_custom_registry_host() {
        assert!(ensure_trusted_tarball_url(
            "https://npm.example.com/react/-/react-19.0.0.tgz",
            Some("npm.example.com"),
        )
        .is_ok());
        assert!(ensure_trusted_tarball_url(
            "https://npm.example.com/react/-/react-19.0.0.tgz",
            None,
        )
        .is_err());
    }

    #[test]
    fn verify_download_integrity_fails_without_metadata() {
        let data = b"abc";
        let err = verify_download_integrity(data, None, None, "pkg@1.0.0").unwrap_err();
        assert!(err.to_string().contains("refusing unverified tarball"));
    }

    #[test]
    fn verify_download_integrity_accepts_shasum_fallback() -> Result<()> {
        let data = b"abc";
        let mut hasher = Sha1::new();
        hasher.update(data);
        let shasum = format!("{:x}", hasher.finalize());
        verify_download_integrity(data, Some("sha512-bad=="), Some(&shasum), "pkg@1.0.0")
    }

    #[test]
    fn format_save_version_uses_caret_by_default() {
        assert_eq!(format_save_version(None, "1.2.3", false), "^1.2.3");
        assert_eq!(format_save_version(Some("19"), "19.0.0", false), "^19.0.0");
        assert_eq!(format_save_version(Some("react"), "19.0.0", false), "^19.0.0");
    }

    #[test]
    fn format_save_version_preserves_explicit_ranges() {
        assert_eq!(format_save_version(Some("^1.0.0"), "1.2.3", false), "^1.0.0");
        assert_eq!(format_save_version(Some("~1.0.0"), "1.0.5", false), "~1.0.0");
        assert_eq!(format_save_version(Some(">=1.0.0"), "1.2.3", false), ">=1.0.0");
        assert_eq!(format_save_version(Some("1.0.0 - 2.0.0"), "1.5.0", false), "1.0.0 - 2.0.0");
        assert_eq!(format_save_version(Some("^1.0.0 || ^2.0.0"), "2.1.0", false), "^1.0.0 || ^2.0.0");
    }

    #[test]
    fn format_save_version_exact_mode() {
        assert_eq!(format_save_version(None, "1.2.3", true), "1.2.3");
        assert_eq!(format_save_version(Some("^1.0.0"), "1.2.3", true), "1.2.3");
    }

    #[test]
    fn collect_requested_deps_shows_all_by_default() {
        let manifest = serde_json::json!({
            "dependencies": { "react": "^19.0.0" },
            "devDependencies": { "typescript": "^5.0.0" },
            "optionalDependencies": { "fsevents": "^2.0.0" }
        });
        let opts = ListOptions {
            json: false, long: false, parseable: false,
            prod: false, dev: false, optional: false,
            only: None, global: false, recursive: false,
            depth: None, packages: vec![],
        };
        let result = collect_requested_deps(&manifest, &opts).unwrap();
        let names: Vec<&str> = result.iter().map(|(n, _)| n.as_str()).collect();
        assert!(names.contains(&"react"));
        assert!(names.contains(&"typescript"));
        assert!(names.contains(&"fsevents"));
    }

    #[test]
    fn collect_requested_deps_filters_by_flag() {
        let manifest = serde_json::json!({
            "dependencies": { "react": "^19.0.0" },
            "devDependencies": { "typescript": "^5.0.0" },
            "optionalDependencies": { "fsevents": "^2.0.0" }
        });
        let opts = ListOptions {
            json: false, long: false, parseable: false,
            prod: true, dev: false, optional: false,
            only: None, global: false, recursive: false,
            depth: None, packages: vec![],
        };
        let result = collect_requested_deps(&manifest, &opts).unwrap();
        let names: Vec<&str> = result.iter().map(|(n, _)| n.as_str()).collect();
        assert!(names.contains(&"react"));
        assert!(!names.contains(&"typescript"));
        assert!(!names.contains(&"fsevents"));
    }

    #[test]
    fn read_overrides_parses_pnpm_overrides() {
        let manifest = serde_json::json!({
            "pnpm": {
                "overrides": {
                    "lodash": "4.17.21",
                    "glob": "^10.0.0"
                }
            }
        });
        let overrides = read_overrides(&manifest);
        assert_eq!(overrides.get("lodash").unwrap(), "4.17.21");
        assert_eq!(overrides.get("glob").unwrap(), "^10.0.0");
    }

    #[test]
    fn read_overrides_returns_empty_without_section() {
        let manifest = serde_json::json!({ "name": "test" });
        let overrides = read_overrides(&manifest);
        assert!(overrides.is_empty());
    }

    #[test]
    fn parse_npmrc_returns_none_for_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        let result = parse_npmrc(dir.path()).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn parse_npmrc_reads_registry_line() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(".npmrc"), "registry=https://npm.example.com/\n").unwrap();
        let result = parse_npmrc(dir.path()).unwrap();
        assert_eq!(result.unwrap(), "https://npm.example.com/");
    }

    #[test]
    fn parse_npmrc_ignores_comments() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(".npmrc"), "# registry=https://bad.com/\nregistry=https://good.com/\n").unwrap();
        let result = parse_npmrc(dir.path()).unwrap();
        assert_eq!(result.unwrap(), "https://good.com/");
    }

    #[test]
    fn read_package_bin_entries_handles_string_bin() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = serde_json::json!({
            "name": "my-tool",
            "bin": "./cli.js"
        });
        fs::write(dir.path().join("package.json"), serde_json::to_string(&manifest).unwrap()).unwrap();
        let entries = read_package_bin_entries(dir.path()).unwrap();
        assert_eq!(entries.len(), 1);
        assert!(entries.contains_key("my-tool"));
    }

    #[test]
    fn read_package_bin_entries_handles_object_bin() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = serde_json::json!({
            "name": "multi-tool",
            "bin": {
                "cmd1": "./bin/cmd1.js",
                "cmd2": "./bin/cmd2.js"
            }
        });
        fs::write(dir.path().join("package.json"), serde_json::to_string(&manifest).unwrap()).unwrap();
        let entries = read_package_bin_entries(dir.path()).unwrap();
        assert_eq!(entries.len(), 2);
        assert!(entries.contains_key("cmd1"));
        assert!(entries.contains_key("cmd2"));
    }

    #[test]
    fn read_package_bin_entries_rejects_parent_dir() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = serde_json::json!({
            "name": "evil",
            "bin": "../../../etc/passwd"
        });
        fs::write(dir.path().join("package.json"), serde_json::to_string(&manifest).unwrap()).unwrap();
        assert!(read_package_bin_entries(dir.path()).is_err());
    }

    #[test]
    fn ensure_safe_requirement_handles_npm_alias() {
        let result = ensure_safe_requirement("my-alias", "npm:real-pkg@^1.0.0").unwrap();
        let (real_name, real_req) = result.unwrap();
        assert_eq!(real_name, "real-pkg");
        assert_eq!(real_req, "^1.0.0");
    }

    #[test]
    fn ensure_safe_requirement_handles_npm_scoped_alias() {
        let result = ensure_safe_requirement("alias", "npm:@scope/pkg@^2.0.0").unwrap();
        let (real_name, real_req) = result.unwrap();
        assert_eq!(real_name, "@scope/pkg");
        assert_eq!(real_req, "^2.0.0");
    }

    #[test]
    fn ensure_safe_requirement_returns_none_for_normal_req() {
        let result = ensure_safe_requirement("react", "^19.0.0").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn parse_package_spec_strips_npm_prefix() {
        let spec = parse_package_spec("npm:react@19").unwrap();
        assert_eq!(spec.name, "react");
        assert_eq!(spec.requested.unwrap(), "19");
    }

    #[test]
    fn stub_command_returns_error() {
        let result = stub_command("run", &["test".to_string()]);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not implemented"));
    }
}
