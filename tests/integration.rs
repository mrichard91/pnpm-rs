use std::fs;
use anyhow::{Context, Result};
use assert_cmd::cargo::cargo_bin_cmd;
use assert_fs::TempDir;

#[test]
fn add_package_in_existing_project() -> Result<()> {
    let temp = TempDir::new()?;
    let package_json = serde_json::json!({
        "name": "existing-project",
        "version": "1.0.0",
        "private": true
    });
    fs::write(
        temp.path().join("package.json"),
        serde_json::to_string_pretty(&package_json)? + "\n",
    )?;

    let mut cmd = cargo_bin_cmd!("pnpm-rs");
    cmd.current_dir(temp.path()).arg("add").arg("react@19");
    cmd.assert().success();

    let react_manifest = temp.path().join("node_modules").join("react").join("package.json");
    assert!(react_manifest.exists(), "react package.json should exist");
    let pnpm_store = temp.path().join("node_modules").join(".pnpm");
    assert!(pnpm_store.exists(), ".pnpm store should exist");
    let react_link = temp.path().join("node_modules").join("react");
    let meta = fs::symlink_metadata(&react_link)?;
    assert!(meta.file_type().is_symlink(), "react should be a symlink");
    Ok(())
}

#[test]
fn init_and_add_package() -> Result<()> {
    let temp = TempDir::new()?;

    let mut init_cmd = cargo_bin_cmd!("pnpm-rs");
    init_cmd.current_dir(temp.path()).arg("init");
    init_cmd.assert().success();

    let package_json_path = temp.path().join("package.json");
    let contents = fs::read_to_string(&package_json_path)
        .with_context(|| format!("read {}", package_json_path.display()))?;
    assert!(contents.contains("\"name\""));

    let mut add_cmd = cargo_bin_cmd!("pnpm-rs");
    add_cmd
        .current_dir(temp.path())
        .arg("add")
        .arg("react@19");
    add_cmd.assert().success();

    let react_manifest = temp.path().join("node_modules").join("react").join("package.json");
    assert!(react_manifest.exists(), "react package.json should exist");
    Ok(())
}

#[test]
fn shows_version_with_v_and_long_flag() -> Result<()> {
    let mut cmd = cargo_bin_cmd!("pnpm-rs");
    cmd.arg("-v")
        .assert()
        .success()
        .stdout(predicates::str::contains("pnpm-rs 0.1"));

    let mut cmd = cargo_bin_cmd!("pnpm-rs");
    cmd.arg("--version")
        .assert()
        .success()
        .stdout(predicates::str::contains("pnpm-rs 0.1"));
    Ok(())
}

#[test]
fn why_reports_direct_dependency() -> Result<()> {
    let temp = TempDir::new()?;
    let package_json = serde_json::json!({
        "name": "why-project",
        "version": "1.0.0",
        "private": true
    });
    fs::write(
        temp.path().join("package.json"),
        serde_json::to_string_pretty(&package_json)? + "\n",
    )?;

    let mut add_cmd = cargo_bin_cmd!("pnpm-rs");
    add_cmd
        .current_dir(temp.path())
        .arg("add")
        .arg("react@19");
    add_cmd.assert().success();

    let mut why_cmd = cargo_bin_cmd!("pnpm-rs");
    why_cmd
        .current_dir(temp.path())
        .arg("why")
        .arg("react")
        .assert()
        .success()
        .stdout(predicates::str::contains("direct dependency"));

    Ok(())
}

#[test]
fn ls_aliases_list() -> Result<()> {
    let temp = TempDir::new()?;
    let package_json = serde_json::json!({
        "name": "ls-project",
        "version": "1.0.0",
        "private": true
    });
    fs::write(
        temp.path().join("package.json"),
        serde_json::to_string_pretty(&package_json)? + "\n",
    )?;

    let mut add_cmd = cargo_bin_cmd!("pnpm-rs");
    add_cmd
        .current_dir(temp.path())
        .arg("add")
        .arg("react@19");
    add_cmd.assert().success();

    let mut list_cmd = cargo_bin_cmd!("pnpm-rs");
    let list_out = list_cmd
        .current_dir(temp.path())
        .arg("list")
        .arg("--depth")
        .arg("0")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let mut ls_cmd = cargo_bin_cmd!("pnpm-rs");
    let ls_out = ls_cmd
        .current_dir(temp.path())
        .arg("ls")
        .arg("--depth")
        .arg("0")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    assert_eq!(list_out, ls_out);
    Ok(())
}
