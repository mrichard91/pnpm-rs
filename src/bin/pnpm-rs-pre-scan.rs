use std::env;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use tempfile::TempDir;

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
    debug: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let temp = TempDir::new().context("create temp dir")?;

    let pnpm_rs = find_pnpm_rs()?;

    run_cmd(&pnpm_rs, &["init"], temp.path(), cli.debug)?;
    run_cmd(&pnpm_rs, &["add", &cli.package], temp.path(), cli.debug)?;

    let mut scan_args = vec!["security-scan".to_string()];
    scan_args.push(format!("--older-than-years={}", cli.older_than_years));
    if let Some(yara) = &cli.yara {
        scan_args.push("--yara".to_string());
        scan_args.push(yara.clone());
    }
    run_cmd_dynamic(&pnpm_rs, &scan_args, temp.path(), cli.debug)?;

    Ok(())
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
    let status = cmd.status().with_context(|| format!("run {}", bin.display()))?;
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
    let status = cmd.status().with_context(|| format!("run {}", bin.display()))?;
    if !status.success() {
        return Err(anyhow!("command failed: {} {:?}", bin.display(), args));
    }
    Ok(())
}
