use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use reqwest::blocking::Client;
use reqwest::Url;
use serde::Deserialize;
use tempfile::TempDir;

const NPM_REPLICATE_ALL_DOCS: &str = "https://replicate.npmjs.com/_all_docs";
const SCOPE_PAGE_SIZE: usize = 500;

#[derive(Parser, Debug)]
#[command(
    name = "pnpm-rs-pre-scan",
    about = "Scan a package before installing by using pnpm-rs in a temp project"
)]
struct Cli {
    package: String,
    #[arg(long)]
    yara: Option<String>,
    #[arg(long, default_value_t = 5)]
    older_than_years: i64,
    #[arg(long, default_value_t = false)]
    no_deps: bool,
    #[arg(long, default_value_t = false)]
    inspect_shell: bool,
    #[arg(long)]
    out_dir: Option<PathBuf>,
    #[arg(long, default_value_t = false)]
    debug: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let pnpm_rs = find_pnpm_rs()?;
    let packages = expand_scan_targets(&cli.package, cli.debug)?;
    let wildcard_mode = wildcard_scope_prefix(&cli.package).is_some();
    let many_packages = packages.len() > 1;

    if wildcard_mode {
        if !cli.no_deps {
            bail!("pnpm-rs-pre-scan: --no-deps is required for scope wildcard scans");
        }
        if cli.inspect_shell && packages.len() != 1 {
            bail!(
                "pnpm-rs-pre-scan: --inspect-shell requires exactly one expanded package, got {}",
                packages.len()
            );
        }
        eprintln!(
            "pnpm-rs-pre-scan: expanded {} to {} package(s)",
            cli.package,
            packages.len()
        );
    }

    let mut results = Vec::new();
    let mut failures = Vec::new();
    for (idx, package) in packages.iter().enumerate() {
        if many_packages {
            eprintln!(
                "pnpm-rs-pre-scan: [{}/{}] scanning {}",
                idx + 1,
                packages.len(),
                package
            );
        }
        match scan_one_package(&pnpm_rs, package, &cli) {
            Ok(result) => results.push(result),
            Err(err) => {
                eprintln!("pnpm-rs-pre-scan: scan failed for {package}: {err:#}");
                failures.push(package.clone());
            }
        }
    }

    if many_packages {
        print_multi_scan_summary(&cli.package, &results, &failures, cli.yara.is_some());
    }

    if failures.is_empty() {
        if many_packages {
            eprintln!(
                "pnpm-rs-pre-scan: completed {} package scan(s) successfully",
                packages.len()
            );
        }
        return Ok(());
    }

    bail!(
        "pnpm-rs-pre-scan: {} package scan(s) failed: {}",
        failures.len(),
        failures.join(", ")
    )
}

fn build_add_args(package: &str, no_deps: bool) -> Vec<String> {
    let mut args = vec!["add".to_string()];
    if no_deps {
        args.push("--no-deps".to_string());
    }
    args.push(package.to_string());
    args
}

fn find_pnpm_rs() -> Result<PathBuf> {
    if let Ok(current) = env::current_exe() {
        if let Some(dir) = current.parent() {
            let candidate = dir.join("pnpm-rs");
            if candidate.exists() {
                return Ok(candidate);
            }
        }
    }
    Ok(PathBuf::from("pnpm-rs"))
}

#[derive(Deserialize)]
struct AllDocsResponse {
    rows: Vec<AllDocsRow>,
}

#[derive(Deserialize)]
struct AllDocsRow {
    key: String,
}

#[derive(Debug, Deserialize, Default)]
struct SecurityScanSummary {
    packages_scanned: usize,
    workspace_importers_scanned: usize,
    packages_with_issues: usize,
    issues_found: usize,
    yara: Option<SecurityScanYaraSummary>,
}

#[derive(Debug, Deserialize, Default)]
struct SecurityScanYaraSummary {
    files_scanned: usize,
    rule_matches: usize,
    string_matches: usize,
    rules: Vec<String>,
    match_locations: Vec<SecurityScanYaraMatch>,
}

#[derive(Debug, Deserialize)]
struct SecurityScanYaraMatch {
    package: String,
    rule: String,
    path: String,
}

#[derive(Debug)]
struct PackageScanOutcome {
    package: String,
    summary: SecurityScanSummary,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct AggregatedMatchLocation {
    scanned_package: String,
    source_package: String,
    rule: String,
    path: String,
}

#[derive(Debug, Default)]
struct AggregateScanSummary {
    successful_scans: usize,
    failed_scans: usize,
    files_scanned: usize,
    rule_matches: usize,
    string_matches: usize,
    packages_scanned: usize,
    workspace_importers_scanned: usize,
    packages_with_issues: usize,
    issues_found: usize,
    rules_matched: Vec<String>,
    packages_with_matches: Vec<String>,
    matched_files: Vec<AggregatedMatchLocation>,
}

fn scan_one_package(bin: &PathBuf, package: &str, cli: &Cli) -> Result<PackageScanOutcome> {
    let temp = TempDir::new().context("create temp dir")?;

    run_cmd(bin, &["init"], temp.path(), cli.debug)?;
    let add_args = build_add_args(package, cli.no_deps);
    run_cmd_dynamic(bin, &add_args, temp.path(), cli.debug)?;

    let mut scan_args = vec!["security-scan".to_string()];
    scan_args.push(format!("--older-than-years={}", cli.older_than_years));
    if let Some(yara) = &cli.yara {
        scan_args.push("--yara".to_string());
        scan_args.push(yara.clone());
    }
    let summary_path = temp.path().join(".pnpm-rs-security-scan-summary.json");
    scan_args.push("--summary-json".to_string());
    scan_args.push(summary_path.display().to_string());
    run_cmd_dynamic(bin, &scan_args, temp.path(), cli.debug)?;
    let mut summary = read_scan_summary(&summary_path)?;
    normalize_scan_summary_paths(&mut summary, temp.path());

    if cli.inspect_shell {
        if let Some(out_dir) = &cli.out_dir {
            eprintln!(
                "pnpm-rs-pre-scan: artifacts will be copied to {} after you exit the inspection shell",
                out_dir.display()
            );
        }
        launch_inspection_shell(temp.path())?;
    }

    if let Some(out_dir) = &cli.out_dir {
        let saved_path = export_artifacts(temp.path(), out_dir, package)?;
        eprintln!(
            "pnpm-rs-pre-scan: saved analysis project to {}",
            saved_path.display()
        );
    }

    Ok(PackageScanOutcome {
        package: package.to_string(),
        summary,
    })
}

fn expand_scan_targets(spec: &str, debug: bool) -> Result<Vec<String>> {
    if wildcard_scope_prefix(spec).is_some() {
        return list_scoped_packages(spec, debug);
    }
    Ok(vec![spec.to_string()])
}

fn list_scoped_packages(spec: &str, debug: bool) -> Result<Vec<String>> {
    let prefix = wildcard_scope_prefix(spec)
        .ok_or_else(|| anyhow!("invalid scope wildcard spec: {spec}"))?;
    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .build()
        .context("build http client")?;

    let endkey = format!("{prefix}\u{fff0}");
    let mut packages = Vec::new();
    let mut next_key: Option<String> = None;

    loop {
        let mut url = Url::parse(NPM_REPLICATE_ALL_DOCS).context("parse replicate endpoint")?;
        {
            let mut query = url.query_pairs_mut();
            if let Some(last_key) = &next_key {
                query.append_pair("startkey", &json_scalar(last_key));
                query.append_pair("skip", "1");
            } else {
                query.append_pair("startkey", &json_scalar(&prefix));
            }
            query.append_pair("endkey", &json_scalar(&endkey));
            query.append_pair("limit", &SCOPE_PAGE_SIZE.to_string());
        }
        if debug {
            eprintln!("pnpm-rs-pre-scan debug: GET {url}");
        }
        let response = client
            .get(url)
            .header("User-Agent", "pnpm-rs-pre-scan")
            .send()
            .context("fetch scope package list")?;
        if !response.status().is_success() {
            bail!("scope package list query failed: {}", response.status());
        }
        let payload: AllDocsResponse = response.json().context("parse scope package list")?;
        if payload.rows.is_empty() {
            break;
        }

        let mut page_count = 0usize;
        for row in payload.rows {
            if !row.key.starts_with(&prefix) {
                continue;
            }
            next_key = Some(row.key.clone());
            packages.push(row.key);
            page_count += 1;
        }

        if page_count < SCOPE_PAGE_SIZE {
            break;
        }
    }

    packages.sort();
    packages.dedup();
    if packages.is_empty() {
        bail!("no packages found for scope wildcard {spec}");
    }
    Ok(packages)
}

fn wildcard_scope_prefix(spec: &str) -> Option<String> {
    let trimmed = spec.trim();
    let raw_scope = trimmed.strip_suffix("/*")?;
    if raw_scope.is_empty() {
        return None;
    }

    let normalized = if raw_scope.starts_with('@') {
        raw_scope.to_string()
    } else {
        format!("@{raw_scope}")
    };
    if !is_valid_scope_name(&normalized) {
        return None;
    }
    Some(format!("{normalized}/"))
}

fn is_valid_scope_name(scope: &str) -> bool {
    let Some(name) = scope.strip_prefix('@') else {
        return false;
    };
    if name.is_empty() || name.contains('/') || name.starts_with('.') || name.starts_with('_') {
        return false;
    }
    name.chars()
        .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || matches!(ch, '-' | '_' | '.'))
}

fn json_scalar(value: &str) -> String {
    serde_json::to_string(value).expect("json string literal")
}

fn read_scan_summary(path: &Path) -> Result<SecurityScanSummary> {
    let raw = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    serde_json::from_str(&raw).with_context(|| format!("parse {}", path.display()))
}

fn normalize_scan_summary_paths(summary: &mut SecurityScanSummary, root: &Path) {
    let Some(yara) = summary.yara.as_mut() else {
        return;
    };
    for entry in &mut yara.match_locations {
        if let Ok(relative) = Path::new(&entry.path).strip_prefix(root) {
            entry.path = relative.display().to_string();
        }
    }
}

fn aggregate_scan_results(
    results: &[PackageScanOutcome],
    failures: &[String],
) -> AggregateScanSummary {
    let mut summary = AggregateScanSummary {
        successful_scans: results.len(),
        failed_scans: failures.len(),
        ..AggregateScanSummary::default()
    };
    let mut rules_matched = BTreeSet::new();
    let mut packages_with_matches = BTreeSet::new();
    let mut matched_files = BTreeSet::new();

    for result in results {
        summary.packages_scanned += result.summary.packages_scanned;
        summary.workspace_importers_scanned += result.summary.workspace_importers_scanned;
        summary.packages_with_issues += result.summary.packages_with_issues;
        summary.issues_found += result.summary.issues_found;
        let Some(yara) = &result.summary.yara else {
            continue;
        };
        summary.files_scanned += yara.files_scanned;
        summary.rule_matches += yara.rule_matches;
        summary.string_matches += yara.string_matches;

        if !yara.match_locations.is_empty() {
            packages_with_matches.insert(result.package.clone());
        }
        for rule in &yara.rules {
            rules_matched.insert(rule.clone());
        }
        for entry in &yara.match_locations {
            matched_files.insert(AggregatedMatchLocation {
                scanned_package: result.package.clone(),
                source_package: entry.package.clone(),
                rule: entry.rule.clone(),
                path: entry.path.clone(),
            });
        }
    }

    summary.rules_matched = rules_matched.into_iter().collect();
    summary.packages_with_matches = packages_with_matches.into_iter().collect();
    summary.matched_files = matched_files.into_iter().collect();
    summary
}

fn print_multi_scan_summary(
    requested: &str,
    results: &[PackageScanOutcome],
    failures: &[String],
    yara_enabled: bool,
) {
    let summary = aggregate_scan_results(results, failures);
    println!();
    println!("pnpm-rs-pre-scan summary:");
    println!("- requested target: {requested}");
    println!("- package scans completed: {}", summary.successful_scans);
    println!("- package scans failed: {}", summary.failed_scans);
    println!("- packages scanned: {}", summary.packages_scanned);
    println!(
        "- workspace importers scanned: {}",
        summary.workspace_importers_scanned
    );
    println!("- packages with issues: {}", summary.packages_with_issues);
    println!("- issues found: {}", summary.issues_found);
    if !yara_enabled {
        println!("- YARA enabled: no");
        return;
    }
    println!("- YARA files scanned: {}", summary.files_scanned);
    println!("- YARA rule matches: {}", summary.rule_matches);
    println!("- YARA string matches: {}", summary.string_matches);
    println!(
        "- target packages with YARA matches: {}",
        summary.packages_with_matches.len()
    );
    println!("- matched files: {}", summary.matched_files.len());
    if !summary.rules_matched.is_empty() {
        println!("- matched rules: {}", summary.rules_matched.join(", "));
    }
    if !summary.packages_with_matches.is_empty() {
        println!("Target packages with YARA matches:");
        for package in &summary.packages_with_matches {
            println!("- {package}");
        }
    }
    if !summary.matched_files.is_empty() {
        println!("Matched files:");
        for entry in &summary.matched_files {
            println!(
                "- {} [{}] {} (rule {})",
                entry.scanned_package, entry.source_package, entry.path, entry.rule
            );
        }
    }
}

fn run_cmd(bin: &PathBuf, args: &[&str], cwd: &std::path::Path, debug: bool) -> Result<()> {
    let mut cmd = Command::new(bin);
    cmd.args(args)
        .current_dir(cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    if debug {
        cmd.arg("--debug");
    }
    let status = cmd
        .status()
        .with_context(|| format!("run {}", bin.display()))?;
    if !status.success() {
        return Err(anyhow!("command failed: {} {:?}", bin.display(), args));
    }
    Ok(())
}

fn run_cmd_dynamic(
    bin: &PathBuf,
    args: &[String],
    cwd: &std::path::Path,
    debug: bool,
) -> Result<()> {
    let mut cmd = Command::new(bin);
    cmd.args(args)
        .current_dir(cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    if debug {
        cmd.arg("--debug");
    }
    let status = cmd
        .status()
        .with_context(|| format!("run {}", bin.display()))?;
    if !status.success() {
        return Err(anyhow!("command failed: {} {:?}", bin.display(), args));
    }
    Ok(())
}

fn launch_inspection_shell(cwd: &std::path::Path) -> Result<()> {
    eprintln!(
        "pnpm-rs-pre-scan: opening inspection shell in {} (exit the shell to clean up the temp project)",
        cwd.display()
    );
    let mut cmd = Command::new("/bin/sh");
    cmd.current_dir(cwd)
        .env("PNPM_RS_SCAN_TEMP_DIR", cwd)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    let status = cmd.status().context("launch inspection shell")?;
    if !status.success() {
        return Err(anyhow!("inspection shell exited with status {status}"));
    }
    Ok(())
}

fn export_artifacts(
    source_dir: &std::path::Path,
    out_dir: &std::path::Path,
    package: &str,
) -> Result<PathBuf> {
    fs::create_dir_all(out_dir).with_context(|| format!("create {}", out_dir.display()))?;
    let destination = next_artifact_path(out_dir, package);
    copy_tree(source_dir, &destination)?;
    Ok(destination)
}

fn next_artifact_path(base_dir: &std::path::Path, package: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let prefix = artifact_dir_name(package, stamp);
    let mut candidate = base_dir.join(&prefix);
    let mut suffix = 1u32;
    while candidate.exists() {
        candidate = base_dir.join(format!("{prefix}-{suffix}"));
        suffix += 1;
    }
    candidate
}

fn artifact_dir_name(package: &str, stamp: u64) -> String {
    format!("scan-{}-{stamp}", sanitize_artifact_component(package))
}

fn sanitize_artifact_component(value: &str) -> String {
    let mut out = String::new();
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
        } else if matches!(ch, '@' | '/' | '.' | '-' | '_' | '+') {
            out.push('-');
        }
    }
    let trimmed = out.trim_matches('-');
    if trimmed.is_empty() {
        "package".to_string()
    } else {
        trimmed.to_string()
    }
}

fn copy_tree(src: &std::path::Path, dst: &std::path::Path) -> Result<()> {
    let metadata = fs::symlink_metadata(src).with_context(|| format!("stat {}", src.display()))?;
    if metadata.file_type().is_symlink() {
        copy_symlink(src, dst)?;
        return Ok(());
    }
    if metadata.is_dir() {
        fs::create_dir_all(dst).with_context(|| format!("create {}", dst.display()))?;
        for entry in fs::read_dir(src).with_context(|| format!("read {}", src.display()))? {
            let entry = entry?;
            let child_src = entry.path();
            let child_dst = dst.join(entry.file_name());
            copy_tree(&child_src, &child_dst)?;
        }
        return Ok(());
    }
    if metadata.is_file() {
        if let Some(parent) = dst.parent() {
            fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
        }
        fs::copy(src, dst)
            .with_context(|| format!("copy {} -> {}", src.display(), dst.display()))?;
        fs::set_permissions(dst, metadata.permissions())
            .with_context(|| format!("set permissions {}", dst.display()))?;
        return Ok(());
    }
    Ok(())
}

#[cfg(unix)]
fn copy_symlink(src: &std::path::Path, dst: &std::path::Path) -> Result<()> {
    use std::os::unix::fs::symlink;

    if let Some(parent) = dst.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    let target = fs::read_link(src).with_context(|| format!("read link {}", src.display()))?;
    symlink(&target, dst).with_context(|| format!("symlink {}", dst.display()))?;
    Ok(())
}

#[cfg(not(unix))]
fn copy_symlink(_src: &std::path::Path, _dst: &std::path::Path) -> Result<()> {
    Err(anyhow!("copying symlinks is only supported on unix"))
}

#[cfg(test)]
mod tests {
    use super::{
        aggregate_scan_results, artifact_dir_name, build_add_args, copy_tree,
        normalize_scan_summary_paths, sanitize_artifact_component, wildcard_scope_prefix,
        PackageScanOutcome, SecurityScanSummary, SecurityScanYaraMatch, SecurityScanYaraSummary,
    };
    use std::fs;
    use std::path::Path;

    #[test]
    fn build_add_args_includes_no_deps_flag() {
        assert_eq!(
            build_add_args("react@19", true),
            vec![
                "add".to_string(),
                "--no-deps".to_string(),
                "react@19".to_string()
            ]
        );
    }

    #[test]
    fn build_add_args_defaults_to_normal_add() {
        assert_eq!(
            build_add_args("react@19", false),
            vec!["add".to_string(), "react@19".to_string()]
        );
    }

    #[test]
    fn cli_accepts_inspect_shell_flag() {
        let cli = <super::Cli as clap::Parser>::parse_from([
            "pnpm-rs-pre-scan",
            "react@19",
            "--inspect-shell",
        ]);
        assert!(cli.inspect_shell);
        assert_eq!(cli.package, "react@19");
    }

    #[test]
    fn cli_accepts_out_dir_flag() {
        let cli = <super::Cli as clap::Parser>::parse_from([
            "pnpm-rs-pre-scan",
            "react@19",
            "--out-dir",
            "/out",
        ]);
        assert_eq!(cli.out_dir.unwrap(), std::path::PathBuf::from("/out"));
    }

    #[test]
    fn cli_accepts_scope_wildcard_with_no_deps() {
        let cli = <super::Cli as clap::Parser>::parse_from([
            "pnpm-rs-pre-scan",
            "@opengov/*",
            "--no-deps",
        ]);
        assert_eq!(cli.package, "@opengov/*");
        assert!(cli.no_deps);
    }

    #[test]
    fn sanitize_artifact_component_normalizes_package_name() {
        assert_eq!(
            sanitize_artifact_component("@Scope/pkg.name+beta"),
            "scope-pkg-name-beta"
        );
    }

    #[test]
    fn artifact_dir_name_includes_prefix_and_stamp() {
        assert_eq!(artifact_dir_name("react@19", 42), "scan-react-19-42");
    }

    #[test]
    fn copy_tree_preserves_symlinks() {
        let src = tempfile::tempdir().unwrap();
        let dst = tempfile::tempdir().unwrap();

        fs::create_dir_all(src.path().join("dir")).unwrap();
        fs::write(src.path().join("dir").join("file.txt"), "hello").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink("dir/file.txt", src.path().join("link.txt")).unwrap();

        copy_tree(src.path(), &dst.path().join("saved")).unwrap();

        assert!(dst
            .path()
            .join("saved")
            .join("dir")
            .join("file.txt")
            .exists());
        #[cfg(unix)]
        {
            let meta = fs::symlink_metadata(dst.path().join("saved").join("link.txt")).unwrap();
            assert!(meta.file_type().is_symlink());
        }
    }

    #[test]
    fn wildcard_scope_prefix_accepts_scoped_wildcard() {
        assert_eq!(
            wildcard_scope_prefix("@opengov/*").as_deref(),
            Some("@opengov/")
        );
    }

    #[test]
    fn wildcard_scope_prefix_accepts_unscoped_scope_shorthand() {
        assert_eq!(
            wildcard_scope_prefix("opengov/*").as_deref(),
            Some("@opengov/")
        );
    }

    #[test]
    fn wildcard_scope_prefix_rejects_non_wildcard_specs() {
        assert!(wildcard_scope_prefix("@opengov/pkg").is_none());
        assert!(wildcard_scope_prefix("react@19").is_none());
    }

    #[test]
    fn wildcard_scope_prefix_rejects_invalid_scope_names() {
        assert!(wildcard_scope_prefix("@OpenGov/*").is_none());
        assert!(wildcard_scope_prefix("@_hidden/*").is_none());
        assert!(wildcard_scope_prefix("@scope/name/*").is_none());
    }

    #[test]
    fn normalize_scan_summary_paths_makes_match_paths_relative() {
        let root = Path::new("/tmp/project");
        let mut summary = SecurityScanSummary {
            yara: Some(SecurityScanYaraSummary {
                match_locations: vec![SecurityScanYaraMatch {
                    package: "pkg@1.0.0".to_string(),
                    rule: "test_rule".to_string(),
                    path: "/tmp/project/node_modules/pkg/index.js".to_string(),
                }],
                ..SecurityScanYaraSummary::default()
            }),
            ..SecurityScanSummary::default()
        };

        normalize_scan_summary_paths(&mut summary, root);

        let yara = summary.yara.unwrap();
        assert_eq!(yara.match_locations[0].path, "node_modules/pkg/index.js");
    }

    #[test]
    fn aggregate_scan_results_summarizes_matches_across_packages() {
        let results = vec![
            PackageScanOutcome {
                package: "@scope/a".to_string(),
                summary: SecurityScanSummary {
                    packages_scanned: 1,
                    workspace_importers_scanned: 1,
                    packages_with_issues: 1,
                    issues_found: 2,
                    yara: Some(SecurityScanYaraSummary {
                        files_scanned: 10,
                        rule_matches: 2,
                        string_matches: 3,
                        rules: vec!["alpha".to_string(), "beta".to_string()],
                        match_locations: vec![
                            SecurityScanYaraMatch {
                                package: "workspace:.".to_string(),
                                rule: "alpha".to_string(),
                                path: "package.json".to_string(),
                            },
                            SecurityScanYaraMatch {
                                package: "@scope/a@1.0.0".to_string(),
                                rule: "beta".to_string(),
                                path: "node_modules/@scope/a/index.js".to_string(),
                            },
                        ],
                    }),
                },
            },
            PackageScanOutcome {
                package: "@scope/b".to_string(),
                summary: SecurityScanSummary {
                    packages_scanned: 1,
                    workspace_importers_scanned: 1,
                    packages_with_issues: 0,
                    issues_found: 0,
                    yara: Some(SecurityScanYaraSummary {
                        files_scanned: 4,
                        rule_matches: 0,
                        string_matches: 0,
                        rules: Vec::new(),
                        match_locations: Vec::new(),
                    }),
                },
            },
        ];

        let summary = aggregate_scan_results(&results, &["@scope/c".to_string()]);

        assert_eq!(summary.successful_scans, 2);
        assert_eq!(summary.failed_scans, 1);
        assert_eq!(summary.files_scanned, 14);
        assert_eq!(summary.rule_matches, 2);
        assert_eq!(summary.string_matches, 3);
        assert_eq!(summary.packages_scanned, 2);
        assert_eq!(summary.workspace_importers_scanned, 2);
        assert_eq!(summary.packages_with_issues, 1);
        assert_eq!(summary.issues_found, 2);
        assert_eq!(summary.rules_matched, vec!["alpha", "beta"]);
        assert_eq!(summary.packages_with_matches, vec!["@scope/a"]);
        assert_eq!(summary.matched_files.len(), 2);
    }
}
