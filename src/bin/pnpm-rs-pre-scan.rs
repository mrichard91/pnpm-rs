use std::collections::{BTreeSet, VecDeque};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use reqwest::blocking::Client;
use reqwest::Url;
use serde::Deserialize;
use tempfile::TempDir;

const NPM_REPLICATE_ALL_DOCS: &str = "https://replicate.npmjs.com/_all_docs";
const NPM_SEARCH_API: &str = "https://registry.npmjs.org/-/v1/search";
const SCOPE_PAGE_SIZE: usize = 500;
const SEARCH_PAGE_SIZE: usize = 250;

#[derive(Parser, Debug, Clone)]
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
    #[arg(long, default_value_t = 1)]
    jobs: usize,
    #[arg(long, default_value_t = false)]
    debug: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    if cli.jobs == 0 {
        bail!("pnpm-rs-pre-scan: --jobs must be at least 1");
    }
    let pnpm_rs = find_pnpm_rs()?;
    let packages = expand_scan_targets(&cli.package, cli.debug)?;
    let selector_mode = scan_selector_kind(&cli.package);
    let many_packages = packages.len() > 1;
    let jobs = cli.jobs.min(packages.len().max(1));

    if selector_mode.is_some() {
        if !cli.no_deps {
            bail!(
                "pnpm-rs-pre-scan: --no-deps is required for scope wildcard and maintainer scans"
            );
        }
        if cli.inspect_shell && packages.len() != 1 {
            bail!(
                "pnpm-rs-pre-scan: --inspect-shell requires exactly one expanded package, got {}",
                packages.len()
            );
        }
        println!(
            "[=] expanded {} to {} package(s)",
            cli.package,
            packages.len()
        );
        if jobs > 1 {
            println!("  [+] using {jobs} parallel worker(s)");
        }
    }

    let (results, failures) = if many_packages && jobs > 1 {
        run_parallel_scans(&pnpm_rs, &packages, &cli, jobs)
    } else {
        run_serial_scans(&pnpm_rs, &packages, &cli)
    };

    if many_packages {
        print_multi_scan_summary(&cli.package, &results, &failures, cli.yara.is_some());
    }

    if failures.is_empty() {
        if many_packages {
            println!(
                "[=] completed {} package scan(s) successfully",
                packages.len()
            );
        }
        return Ok(());
    }

    bail!("{}", format_failure_error(&failures))
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

#[derive(Deserialize)]
struct SearchResponse {
    objects: Vec<SearchObject>,
    total: usize,
}

#[derive(Deserialize)]
struct SearchObject {
    package: SearchPackage,
}

#[derive(Deserialize)]
struct SearchPackage {
    name: String,
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
    log: PackageLog,
}

#[derive(Debug)]
struct ScanFailure {
    package: String,
    error: String,
    log: PackageLog,
}

#[derive(Debug)]
enum WorkerScanResult {
    Success {
        index: usize,
        outcome: PackageScanOutcome,
    },
    Failure {
        index: usize,
        failure: ScanFailure,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ScanSelectorKind {
    ScopeWildcard,
    Maintainer,
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

#[derive(Debug, Clone, Copy)]
enum LogKind {
    Header,
    Info,
    Bad,
    Error,
}

impl LogKind {
    fn marker(self) -> &'static str {
        match self {
            Self::Header => "[=]",
            Self::Info => "[+]",
            Self::Bad => "[-]",
            Self::Error => "[*]",
        }
    }
}

#[derive(Debug)]
struct LogEntry {
    level: usize,
    kind: LogKind,
    message: String,
}

impl LogEntry {
    fn render(&self) -> String {
        let indent = "  ".repeat(self.level);
        format!("{indent}{} {}", self.kind.marker(), self.message)
    }
}

#[derive(Debug, Default)]
struct PackageLog {
    entries: Vec<LogEntry>,
}

impl PackageLog {
    fn scanning(package: &str) -> Self {
        let mut log = Self::default();
        log.header(&format!("scanning {package}"));
        log
    }

    fn header(&mut self, message: &str) {
        self.header_at(0, message);
    }

    fn header_at(&mut self, level: usize, message: &str) {
        self.push(level, LogKind::Header, message);
    }

    fn info(&mut self, message: &str) {
        self.info_at(1, message);
    }

    fn info_at(&mut self, level: usize, message: &str) {
        self.push(level, LogKind::Info, message);
    }

    fn bad(&mut self, message: &str) {
        self.bad_at(1, message);
    }

    fn bad_at(&mut self, level: usize, message: &str) {
        self.push(level, LogKind::Bad, message);
    }

    fn error(&mut self, message: &str) {
        self.error_at(1, message);
    }

    fn error_at(&mut self, level: usize, message: &str) {
        self.push(level, LogKind::Error, message);
    }

    fn push(&mut self, level: usize, kind: LogKind, message: &str) {
        self.entries.push(LogEntry {
            level,
            kind,
            message: message.to_string(),
        });
    }

    fn has_output(&self) -> bool {
        !self.entries.is_empty()
    }

    fn rendered_lines(&self) -> Vec<String> {
        self.entries.iter().map(LogEntry::render).collect()
    }
}

#[derive(Debug)]
struct CommandRunOutput {
    status: std::process::ExitStatus,
    stdout: String,
    stderr: String,
}

fn scan_one_package(
    bin: &PathBuf,
    package: &str,
    cli: &Cli,
) -> std::result::Result<PackageScanOutcome, ScanFailure> {
    let mut log = PackageLog::scanning(package);
    let temp = match TempDir::new().context("create temp dir") {
        Ok(temp) => temp,
        Err(err) => return Err(scan_failure_from_log(package, log, err)),
    };
    log.info(&format!(
        "created temp project at {}",
        temp.path().display()
    ));

    if let Err(err) = run_cmd(
        bin,
        &["init"],
        temp.path(),
        cli.debug,
        "initialize temp project",
        &mut log,
    ) {
        return Err(scan_failure_from_log(package, log, err));
    }
    let add_args = build_add_args(package, cli.no_deps);
    if let Err(err) = run_cmd_dynamic(
        bin,
        &add_args,
        temp.path(),
        cli.debug,
        "install target package",
        &mut log,
    ) {
        return Err(scan_failure_from_log(package, log, err));
    }

    let mut scan_args = vec!["security-scan".to_string()];
    scan_args.push(format!("--older-than-years={}", cli.older_than_years));
    if let Some(yara) = &cli.yara {
        scan_args.push("--yara".to_string());
        scan_args.push(yara.clone());
    }
    let summary_path = temp.path().join(".pnpm-rs-security-scan-summary.json");
    scan_args.push("--summary-json".to_string());
    scan_args.push(summary_path.display().to_string());
    if let Err(err) = run_cmd_dynamic(
        bin,
        &scan_args,
        temp.path(),
        cli.debug,
        "run security scan",
        &mut log,
    ) {
        return Err(scan_failure_from_log(package, log, err));
    }
    let mut summary = match read_scan_summary(&summary_path) {
        Ok(summary) => summary,
        Err(err) => return Err(scan_failure_from_log(package, log, err)),
    };
    normalize_scan_summary_paths(&mut summary, temp.path());
    log.info(&format!(
        "scan summary: packages={}, issues={}",
        summary.packages_scanned, summary.issues_found
    ));

    if cli.inspect_shell {
        if let Some(out_dir) = &cli.out_dir {
            log.info(&format!(
                "artifacts will be copied to {} after you exit the inspection shell",
                out_dir.display()
            ));
        }
        if let Err(err) = launch_inspection_shell(temp.path()) {
            return Err(scan_failure_from_log(package, log, err));
        }
        log.info("inspection shell exited");
    }

    if let Some(out_dir) = &cli.out_dir {
        let saved_path = match export_artifacts(temp.path(), out_dir, package) {
            Ok(saved_path) => saved_path,
            Err(err) => return Err(scan_failure_from_log(package, log, err)),
        };
        log.info(&format!(
            "saved analysis project to {}",
            saved_path.display()
        ));
    }

    Ok(PackageScanOutcome {
        package: package.to_string(),
        summary,
        log,
    })
}

fn run_serial_scans(
    pnpm_rs: &PathBuf,
    packages: &[String],
    cli: &Cli,
) -> (Vec<PackageScanOutcome>, Vec<ScanFailure>) {
    let mut results = Vec::new();
    let mut failures = Vec::new();
    for package in packages {
        match scan_one_package(pnpm_rs, package, cli) {
            Ok(result) => {
                print_package_log(&result.log);
                results.push(result);
            }
            Err(err) => {
                print_package_log(&err.log);
                failures.push(err);
            }
        }
    }
    (results, failures)
}

fn run_parallel_scans(
    pnpm_rs: &PathBuf,
    packages: &[String],
    cli: &Cli,
    jobs: usize,
) -> (Vec<PackageScanOutcome>, Vec<ScanFailure>) {
    let queue = Arc::new(Mutex::new(
        packages
            .iter()
            .cloned()
            .enumerate()
            .collect::<VecDeque<(usize, String)>>(),
    ));
    let (tx, rx) = mpsc::channel::<WorkerScanResult>();
    let total = packages.len();

    for _ in 0..jobs {
        let queue = Arc::clone(&queue);
        let tx = tx.clone();
        let pnpm_rs = pnpm_rs.clone();
        let cli = cli.clone();
        thread::spawn(move || {
            worker_loop(queue, tx, pnpm_rs, cli);
        });
    }
    drop(tx);

    let mut result_slots: Vec<Option<PackageScanOutcome>> =
        std::iter::repeat_with(|| None).take(total).collect();
    let mut failure_slots: Vec<Option<ScanFailure>> =
        std::iter::repeat_with(|| None).take(total).collect();

    for message in rx {
        match message {
            WorkerScanResult::Success { index, outcome } => {
                let mut outcome = outcome;
                outcome
                    .log
                    .info(&format!("completed package scan {}/{}", index + 1, total));
                print_package_log(&outcome.log);
                result_slots[index] = Some(outcome);
            }
            WorkerScanResult::Failure { index, failure } => {
                let mut failure = failure;
                failure.log.error(&format!(
                    "package scan failed at position {}/{}",
                    index + 1,
                    total
                ));
                print_package_log(&failure.log);
                failure_slots[index] = Some(failure);
            }
        }
    }

    let results = result_slots.into_iter().flatten().collect();
    let failures = failure_slots.into_iter().flatten().collect();
    (results, failures)
}

fn worker_loop(
    queue: Arc<Mutex<VecDeque<(usize, String)>>>,
    tx: mpsc::Sender<WorkerScanResult>,
    pnpm_rs: PathBuf,
    cli: Cli,
) {
    loop {
        let next = match queue.lock() {
            Ok(mut guard) => guard.pop_front(),
            Err(_) => return,
        };
        let Some((index, package)) = next else {
            return;
        };
        let message = match scan_one_package(&pnpm_rs, &package, &cli) {
            Ok(outcome) => WorkerScanResult::Success { index, outcome },
            Err(err) => WorkerScanResult::Failure {
                index,
                failure: err,
            },
        };
        if tx.send(message).is_err() {
            return;
        }
    }
}

fn expand_scan_targets(spec: &str, debug: bool) -> Result<Vec<String>> {
    match scan_selector_kind(spec) {
        Some(ScanSelectorKind::ScopeWildcard) => list_scoped_packages(spec, debug),
        Some(ScanSelectorKind::Maintainer) => list_maintainer_packages(spec, debug),
        None => Ok(vec![spec.to_string()]),
    }
}

fn scan_selector_kind(spec: &str) -> Option<ScanSelectorKind> {
    if wildcard_scope_prefix(spec).is_some() {
        return Some(ScanSelectorKind::ScopeWildcard);
    }
    if maintainer_selector(spec).is_some() {
        return Some(ScanSelectorKind::Maintainer);
    }
    None
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

fn list_maintainer_packages(spec: &str, debug: bool) -> Result<Vec<String>> {
    let maintainer =
        maintainer_selector(spec).ok_or_else(|| anyhow!("invalid maintainer selector: {spec}"))?;
    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .build()
        .context("build http client")?;

    let mut from = 0usize;
    let mut packages = Vec::new();
    loop {
        let mut url = Url::parse(NPM_SEARCH_API).context("parse search endpoint")?;
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("text", &format!("maintainer:{maintainer}"));
            query.append_pair("size", &SEARCH_PAGE_SIZE.to_string());
            query.append_pair("from", &from.to_string());
        }
        if debug {
            eprintln!("pnpm-rs-pre-scan debug: GET {url}");
        }
        let response = client
            .get(url)
            .header("User-Agent", "pnpm-rs-pre-scan")
            .send()
            .context("fetch maintainer package list")?;
        if !response.status().is_success() {
            bail!(
                "maintainer package list query failed: {}",
                response.status()
            );
        }
        let payload: SearchResponse = response.json().context("parse maintainer package list")?;
        if payload.objects.is_empty() {
            break;
        }
        let batch_len = payload.objects.len();
        for object in payload.objects {
            packages.push(object.package.name);
        }
        from += batch_len;
        if from >= payload.total || batch_len < SEARCH_PAGE_SIZE {
            break;
        }
    }

    packages.sort();
    packages.dedup();
    if packages.is_empty() {
        bail!("no packages found for maintainer selector {spec}");
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

fn maintainer_selector(spec: &str) -> Option<String> {
    let trimmed = spec.trim();
    if let Some(username) = trimmed.strip_prefix("maintainer:") {
        return normalize_maintainer_username(username);
    }
    if let Some(username) = trimmed.strip_prefix('~') {
        return normalize_maintainer_username(username);
    }
    let parsed = Url::parse(trimmed).ok()?;
    let host = parsed.host_str()?;
    if host != "www.npmjs.com" && host != "npmjs.com" {
        return None;
    }
    let username = parsed
        .path()
        .trim()
        .trim_end_matches('/')
        .strip_prefix("/~")?;
    if username.contains('/') {
        return None;
    }
    normalize_maintainer_username(username)
}

fn normalize_maintainer_username(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.starts_with('@') {
        return None;
    }
    if trimmed.starts_with('.') || trimmed.starts_with('_') {
        return None;
    }
    if !trimmed
        .chars()
        .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || matches!(ch, '-' | '_' | '.'))
    {
        return None;
    }
    Some(trimmed.to_string())
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
    failures: &[ScanFailure],
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
    failures: &[ScanFailure],
    yara_enabled: bool,
) {
    let summary = aggregate_scan_results(results, failures);
    let mut log = PackageLog::default();
    log.header("summary");
    log.info(&format!("requested target: {requested}"));
    log.info(&format!(
        "package scans completed: {}",
        summary.successful_scans
    ));
    log.info(&format!("package scans failed: {}", summary.failed_scans));
    log.info(&format!("packages scanned: {}", summary.packages_scanned));
    log.info(&format!(
        "workspace importers scanned: {}",
        summary.workspace_importers_scanned
    ));
    log.info(&format!(
        "packages with issues: {}",
        summary.packages_with_issues
    ));
    log.info(&format!("issues found: {}", summary.issues_found));
    if !failures.is_empty() {
        log.error("failed packages:");
        for failure in failures {
            log.error_at(2, &format!("{}: {}", failure.package, failure.error));
        }
    }
    if !yara_enabled {
        log.info("YARA enabled: no");
        println!();
        print_package_log(&log);
        return;
    }
    log.info(&format!("YARA files scanned: {}", summary.files_scanned));
    log.info(&format!("YARA rule matches: {}", summary.rule_matches));
    log.info(&format!("YARA string matches: {}", summary.string_matches));
    log.info(&format!(
        "target packages with YARA matches: {}",
        summary.packages_with_matches.len()
    ));
    log.info(&format!("matched files: {}", summary.matched_files.len()));
    if !summary.rules_matched.is_empty() {
        log.info(&format!(
            "matched rules: {}",
            summary.rules_matched.join(", ")
        ));
    }
    if !summary.packages_with_matches.is_empty() {
        log.bad("target packages with YARA matches:");
        for package in &summary.packages_with_matches {
            log.bad_at(2, package);
        }
    }
    if !summary.matched_files.is_empty() {
        log.bad("matched files:");
        for entry in &summary.matched_files {
            log.bad_at(
                2,
                &format!(
                    "{} [{}] {} (rule {})",
                    entry.scanned_package, entry.source_package, entry.path, entry.rule
                ),
            );
        }
    }
    println!();
    print_package_log(&log);
}

fn scan_failure_from_log(package: &str, mut log: PackageLog, err: anyhow::Error) -> ScanFailure {
    let rendered = format!("{err:#}");
    let error = rendered
        .lines()
        .find(|line| !line.trim().is_empty())
        .unwrap_or("scan failed")
        .to_string();
    for line in rendered.lines().filter(|line| !line.trim().is_empty()) {
        log.error_at(2, line.trim());
    }
    ScanFailure {
        package: package.to_string(),
        error,
        log,
    }
}

fn format_failure_error(failures: &[ScanFailure]) -> String {
    let mut message = format!(
        "pnpm-rs-pre-scan: {} package scan(s) failed",
        failures.len()
    );
    for failure in failures {
        message.push_str(&format!("\n- {}: {}", failure.package, failure.error));
    }
    message
}

fn print_package_log(log: &PackageLog) {
    if !log.has_output() {
        return;
    }
    for line in log.rendered_lines() {
        println!("{line}");
    }
}

fn emit_command_output(log: &mut PackageLog, step_label: &str, output: &CommandRunOutput) {
    for line in output
        .stdout
        .lines()
        .chain(output.stderr.lines())
        .filter(|line| !line.trim().is_empty())
    {
        classify_command_line(log, step_label, line);
    }
}

fn classify_command_line(log: &mut PackageLog, step_label: &str, raw_line: &str) {
    let trimmed = raw_line.trim_start();
    let leading_spaces = raw_line.len().saturating_sub(trimmed.len());
    let nested_level = 2 + (leading_spaces / 2);

    if step_label == "run security scan" {
        if trimmed == "Security scan report:" || trimmed == "YARA summary:" {
            log.info_at(nested_level, trimmed);
            return;
        }
        if trimmed == "No issues detected."
            || trimmed.starts_with("Selected package: ")
            || trimmed.starts_with("Fetching metadata: ")
        {
            log.info_at(nested_level, trimmed);
            return;
        }
        if let Some(detail) = trimmed.strip_prefix("- ") {
            let detail_trimmed = detail.trim_start();
            let detail_spaces = detail.len().saturating_sub(detail_trimmed.len());
            let detail_level = nested_level + 1 + (detail_spaces / 2);
            let lower = detail.to_ascii_lowercase();
            let counts_only = lower.starts_with("packages scanned:")
                || lower.starts_with("workspace importers scanned:")
                || lower.starts_with("packages with issues:")
                || lower.starts_with("issues found:")
                || lower.starts_with("files scanned:")
                || lower.starts_with("rule matches:")
                || lower.starts_with("string matches:")
                || lower.starts_with("rules matched:")
                || lower.starts_with("packages with matches:")
                || lower.starts_with("rule list:")
                || lower.starts_with("target packages with yara matches:")
                || lower.starts_with("matched files:");
            if counts_only {
                log.info_at(detail_level, detail_trimmed);
            } else {
                log.bad_at(detail_level, detail_trimmed);
            }
            return;
        }
        if trimmed.starts_with("warning:") || trimmed.starts_with("warn:") {
            log.error_at(nested_level, trimmed);
            return;
        }
        log.header_at(nested_level, trimmed);
        return;
    }

    if trimmed.starts_with("warning:") || trimmed.starts_with("warn:") {
        log.error_at(nested_level, trimmed);
    } else if trimmed.to_ascii_lowercase().contains("blocked")
        || trimmed.to_ascii_lowercase().contains("lifecycle script")
    {
        log.bad_at(nested_level, trimmed);
    } else {
        log.info_at(nested_level, trimmed);
    }
}

fn command_failure_message(step_label: &str, output: &CommandRunOutput) -> String {
    let suffix = output
        .stderr
        .lines()
        .chain(output.stdout.lines())
        .map(str::trim)
        .rev()
        .find(|line| !line.is_empty())
        .map(|line| format!(": {line}"))
        .unwrap_or_default();
    match output.status.code() {
        Some(code) => format!("{step_label} failed with exit code {code}{suffix}"),
        None => format!("{step_label} terminated by signal{suffix}"),
    }
}

fn run_cmd(
    bin: &PathBuf,
    args: &[&str],
    cwd: &std::path::Path,
    debug: bool,
    step_label: &str,
    log: &mut PackageLog,
) -> Result<()> {
    log.info(step_label);
    let output = run_cmd_capture(bin, args, cwd, debug)?;
    emit_command_output(log, step_label, &output);
    if !output.status.success() {
        let reason = command_failure_message(step_label, &output);
        log.error_at(2, &reason);
        return Err(anyhow!(reason));
    }
    Ok(())
}

fn run_cmd_capture(
    bin: &PathBuf,
    args: &[&str],
    cwd: &std::path::Path,
    debug: bool,
) -> Result<CommandRunOutput> {
    let mut cmd = Command::new(bin);
    cmd.args(args)
        .current_dir(cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if debug {
        cmd.arg("--debug");
    }
    let output = cmd
        .output()
        .with_context(|| format!("run {}", bin.display()))?;
    Ok(CommandRunOutput {
        status: output.status,
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    })
}

fn run_cmd_dynamic(
    bin: &PathBuf,
    args: &[String],
    cwd: &std::path::Path,
    debug: bool,
    step_label: &str,
    log: &mut PackageLog,
) -> Result<()> {
    log.info(step_label);
    let mut cmd = Command::new(bin);
    cmd.args(args)
        .current_dir(cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if debug {
        cmd.arg("--debug");
    }
    let output = cmd
        .output()
        .with_context(|| format!("run {}", bin.display()))?;
    let output = CommandRunOutput {
        status: output.status,
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    };
    emit_command_output(log, step_label, &output);
    if !output.status.success() {
        let reason = command_failure_message(step_label, &output);
        log.error_at(2, &reason);
        return Err(anyhow!(reason));
    }
    Ok(())
}

fn launch_inspection_shell(cwd: &std::path::Path) -> Result<()> {
    println!(
        "    [+] opening inspection shell in {} (exit the shell to clean up the temp project)",
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
    copy_tree_with_roots(src, dst, src, dst)
}

fn copy_tree_with_roots(
    src: &std::path::Path,
    dst: &std::path::Path,
    src_root: &std::path::Path,
    dst_root: &std::path::Path,
) -> Result<()> {
    let metadata = fs::symlink_metadata(src).with_context(|| format!("stat {}", src.display()))?;
    if metadata.file_type().is_symlink() {
        copy_symlink(src, dst, src_root, dst_root)?;
        return Ok(());
    }
    if metadata.is_dir() {
        fs::create_dir_all(dst).with_context(|| format!("create {}", dst.display()))?;
        for entry in fs::read_dir(src).with_context(|| format!("read {}", src.display()))? {
            let entry = entry?;
            let child_src = entry.path();
            let child_dst = dst.join(entry.file_name());
            copy_tree_with_roots(&child_src, &child_dst, src_root, dst_root)?;
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
fn copy_symlink(
    src: &std::path::Path,
    dst: &std::path::Path,
    src_root: &std::path::Path,
    dst_root: &std::path::Path,
) -> Result<()> {
    use std::os::unix::fs::symlink;

    if let Some(parent) = dst.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    let target = fs::read_link(src).with_context(|| format!("read link {}", src.display()))?;
    let target = rewrite_exported_symlink_target(&target, dst, src_root, dst_root);
    symlink(&target, dst).with_context(|| format!("symlink {}", dst.display()))?;
    Ok(())
}

#[cfg(not(unix))]
fn copy_symlink(
    _src: &std::path::Path,
    _dst: &std::path::Path,
    _src_root: &std::path::Path,
    _dst_root: &std::path::Path,
) -> Result<()> {
    Err(anyhow!("copying symlinks is only supported on unix"))
}

#[cfg(unix)]
fn rewrite_exported_symlink_target(
    target: &std::path::Path,
    dst: &std::path::Path,
    src_root: &std::path::Path,
    dst_root: &std::path::Path,
) -> PathBuf {
    if !target.is_absolute() {
        return target.to_path_buf();
    }
    let Ok(relative_target) = target.strip_prefix(src_root) else {
        return target.to_path_buf();
    };
    let remapped_target = dst_root.join(relative_target);
    let Some(dst_parent) = dst.parent() else {
        return remapped_target;
    };
    relative_path_between(dst_parent, &remapped_target).unwrap_or(remapped_target)
}

#[cfg(not(unix))]
fn rewrite_exported_symlink_target(
    target: &std::path::Path,
    _dst: &std::path::Path,
    _src_root: &std::path::Path,
    _dst_root: &std::path::Path,
) -> PathBuf {
    target.to_path_buf()
}

fn relative_path_between(from: &std::path::Path, to: &std::path::Path) -> Option<PathBuf> {
    use std::path::Component;

    let from_components = from.components().collect::<Vec<_>>();
    let to_components = to.components().collect::<Vec<_>>();

    if from_components.is_empty() || to_components.is_empty() {
        return None;
    }
    match (from_components.first(), to_components.first()) {
        (Some(Component::Prefix(left)), Some(Component::Prefix(right)))
            if left.kind() != right.kind() =>
        {
            return None;
        }
        (Some(Component::RootDir), Some(Component::RootDir)) => {}
        (Some(Component::Normal(_)), Some(Component::Normal(_))) => {}
        (left, right) if left != right => return None,
        _ => {}
    }

    let shared = from_components
        .iter()
        .zip(&to_components)
        .take_while(|(left, right)| left == right)
        .count();

    let mut out = PathBuf::new();
    for component in &from_components[shared..] {
        if matches!(component, Component::Normal(_)) {
            out.push("..");
        }
    }
    for component in &to_components[shared..] {
        out.push(component.as_os_str());
    }
    if out.as_os_str().is_empty() {
        out.push(".");
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::{
        aggregate_scan_results, artifact_dir_name, build_add_args, copy_tree, maintainer_selector,
        normalize_scan_summary_paths, relative_path_between, sanitize_artifact_component,
        wildcard_scope_prefix, PackageLog, PackageScanOutcome, ScanFailure, SecurityScanSummary,
        SecurityScanYaraMatch, SecurityScanYaraSummary,
    };
    use std::fs;
    use std::path::{Path, PathBuf};

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
    fn cli_accepts_jobs_flag() {
        let cli = <super::Cli as clap::Parser>::parse_from([
            "pnpm-rs-pre-scan",
            "@opengov/*",
            "--no-deps",
            "--jobs",
            "4",
        ]);
        assert_eq!(cli.package, "@opengov/*");
        assert!(cli.no_deps);
        assert_eq!(cli.jobs, 4);
    }

    #[test]
    fn maintainer_selector_accepts_prefixed_username() {
        assert_eq!(
            maintainer_selector("maintainer:opengov-superadmin").as_deref(),
            Some("opengov-superadmin")
        );
    }

    #[test]
    fn maintainer_selector_accepts_profile_shorthand_and_url() {
        assert_eq!(
            maintainer_selector("~opengov-superadmin").as_deref(),
            Some("opengov-superadmin")
        );
        assert_eq!(
            maintainer_selector("https://www.npmjs.com/~opengov-superadmin").as_deref(),
            Some("opengov-superadmin")
        );
        assert_eq!(
            maintainer_selector("https://www.npmjs.com/~opengov-superadmin/").as_deref(),
            Some("opengov-superadmin")
        );
    }

    #[test]
    fn maintainer_selector_rejects_invalid_values() {
        assert!(maintainer_selector("@opengov/*").is_none());
        assert!(maintainer_selector("maintainer:OpenGov").is_none());
        assert!(maintainer_selector("https://example.com/~opengov-superadmin").is_none());
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
    #[cfg(unix)]
    fn copy_tree_rewrites_absolute_in_tree_symlinks() {
        let src = tempfile::tempdir().unwrap();
        let dst = tempfile::tempdir().unwrap();

        fs::create_dir_all(src.path().join("dir")).unwrap();
        let target_file = src.path().join("dir").join("file.txt");
        fs::write(&target_file, "hello").unwrap();
        std::os::unix::fs::symlink(&target_file, src.path().join("abs-link.txt")).unwrap();

        let exported = dst.path().join("saved");
        copy_tree(src.path(), &exported).unwrap();

        let link_path = exported.join("abs-link.txt");
        let raw_target = fs::read_link(&link_path).unwrap();
        assert!(!raw_target.is_absolute());
        assert_eq!(fs::read_to_string(&link_path).unwrap(), "hello");
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
    fn relative_path_between_builds_expected_relative_target() {
        let from = PathBuf::from("/tmp/out/node_modules/@scope");
        let to = PathBuf::from("/tmp/out/node_modules/.pnpm/pkg/node_modules/@scope/pkg");
        assert_eq!(
            relative_path_between(&from, &to).unwrap(),
            PathBuf::from("../.pnpm/pkg/node_modules/@scope/pkg")
        );
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
    fn package_log_renders_nested_indentation() {
        let mut log = PackageLog::scanning("@scope/pkg");
        log.info("install target package");
        log.info_at(2, "Selected package: @scope/pkg@1.2.3");
        log.bad_at(3, "lifecycle script: prepare");
        assert_eq!(
            log.rendered_lines(),
            vec![
                "[=] scanning @scope/pkg".to_string(),
                "  [+] install target package".to_string(),
                "    [+] Selected package: @scope/pkg@1.2.3".to_string(),
                "      [-] lifecycle script: prepare".to_string(),
            ]
        );
    }

    #[test]
    fn security_scan_output_classifies_counts_and_findings_at_different_levels() {
        let mut log = PackageLog::default();
        super::classify_command_line(
            &mut log,
            "run security scan",
            "Fetching metadata: @scope/pkg",
        );
        super::classify_command_line(&mut log, "run security scan", "Security scan report:");
        super::classify_command_line(&mut log, "run security scan", "- packages scanned: 1");
        super::classify_command_line(&mut log, "run security scan", "@scope/pkg@1.2.3");
        super::classify_command_line(
            &mut log,
            "run security scan",
            "- lifecycle script blocked: prepare",
        );
        super::classify_command_line(
            &mut log,
            "run security scan",
            "-   starts by invoking the Node.js interpreter",
        );
        assert_eq!(
            log.rendered_lines(),
            vec![
                "    [+] Fetching metadata: @scope/pkg".to_string(),
                "    [+] Security scan report:".to_string(),
                "      [+] packages scanned: 1".to_string(),
                "    [=] @scope/pkg@1.2.3".to_string(),
                "      [-] lifecycle script blocked: prepare".to_string(),
                "        [-] starts by invoking the Node.js interpreter".to_string(),
            ]
        );
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
                log: PackageLog::default(),
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
                log: PackageLog::default(),
            },
        ];

        let summary = aggregate_scan_results(
            &results,
            &[ScanFailure {
                package: "@scope/c".to_string(),
                error: "install target package failed".to_string(),
                log: PackageLog::default(),
            }],
        );

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
