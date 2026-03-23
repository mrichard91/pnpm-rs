use anyhow::{Context, Result};
use assert_cmd::cargo::cargo_bin_cmd;
use assert_fs::TempDir;
use std::fs;

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

    let react_manifest = temp
        .path()
        .join("node_modules")
        .join("react")
        .join("package.json");
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
    add_cmd.current_dir(temp.path()).arg("add").arg("react@19");
    add_cmd.assert().success();

    let react_manifest = temp
        .path()
        .join("node_modules")
        .join("react")
        .join("package.json");
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
    add_cmd.current_dir(temp.path()).arg("add").arg("react@19");
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
    add_cmd.current_dir(temp.path()).arg("add").arg("react@19");
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

#[test]
fn add_rejects_invalid_package_name() -> Result<()> {
    let temp = TempDir::new()?;
    let package_json = serde_json::json!({
        "name": "invalid-name-project",
        "version": "1.0.0",
        "private": true
    });
    fs::write(
        temp.path().join("package.json"),
        serde_json::to_string_pretty(&package_json)? + "\n",
    )?;

    let mut cmd = cargo_bin_cmd!("pnpm-rs");
    cmd.current_dir(temp.path()).arg("add").arg("../evil");
    cmd.assert()
        .failure()
        .stderr(predicates::str::contains("package name"));
    Ok(())
}

#[test]
fn install_rejects_invalid_manifest_dependency_name() -> Result<()> {
    let temp = TempDir::new()?;
    let package_json = serde_json::json!({
        "name": "invalid-manifest-project",
        "version": "1.0.0",
        "private": true,
        "dependencies": {
            "../evil": "1.0.0"
        }
    });
    fs::write(
        temp.path().join("package.json"),
        serde_json::to_string_pretty(&package_json)? + "\n",
    )?;

    let mut cmd = cargo_bin_cmd!("pnpm-rs");
    cmd.current_dir(temp.path()).arg("install");
    cmd.assert()
        .failure()
        .stderr(predicates::str::contains("package name"));
    Ok(())
}

#[test]
fn stubbed_commands_exit_nonzero() -> Result<()> {
    let mut cmd = cargo_bin_cmd!("pnpm-rs");
    cmd.arg("run").arg("test");
    cmd.assert()
        .failure()
        .stderr(predicates::str::contains("not implemented"));
    Ok(())
}

#[test]
fn add_writes_caret_range() -> Result<()> {
    let temp = TempDir::new()?;
    let package_json = serde_json::json!({
        "name": "caret-project",
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

    let contents = fs::read_to_string(temp.path().join("package.json"))?;
    let parsed: serde_json::Value = serde_json::from_str(&contents)?;
    let react_version = parsed["dependencies"]["react"].as_str().unwrap();
    assert!(
        react_version.starts_with('^'),
        "expected caret range, got {react_version}"
    );
    Ok(())
}

#[test]
fn add_save_exact_writes_plain_version() -> Result<()> {
    let temp = TempDir::new()?;
    let package_json = serde_json::json!({
        "name": "exact-project",
        "version": "1.0.0",
        "private": true
    });
    fs::write(
        temp.path().join("package.json"),
        serde_json::to_string_pretty(&package_json)? + "\n",
    )?;

    let mut cmd = cargo_bin_cmd!("pnpm-rs");
    cmd.current_dir(temp.path())
        .arg("add")
        .arg("--save-exact")
        .arg("react@19");
    cmd.assert().success();

    let contents = fs::read_to_string(temp.path().join("package.json"))?;
    let parsed: serde_json::Value = serde_json::from_str(&contents)?;
    let react_version = parsed["dependencies"]["react"].as_str().unwrap();
    assert!(
        !react_version.starts_with('^'),
        "expected exact version, got {react_version}"
    );
    Ok(())
}

#[test]
fn add_no_deps_rejects_existing_root_dependencies() -> Result<()> {
    let temp = TempDir::new()?;
    let package_json = serde_json::json!({
        "name": "analysis-project",
        "version": "1.0.0",
        "private": true,
        "dependencies": {
            "lodash": "^4.17.21"
        }
    });
    fs::write(
        temp.path().join("package.json"),
        serde_json::to_string_pretty(&package_json)? + "\n",
    )?;

    let mut cmd = cargo_bin_cmd!("pnpm-rs");
    cmd.current_dir(temp.path())
        .arg("add")
        .arg("--no-deps")
        .arg("react@19");
    cmd.assert().failure().stderr(predicates::str::contains(
        "--no-deps only supports isolated analysis projects",
    ));
    Ok(())
}

#[test]
fn add_save_dev_writes_to_dev_dependencies() -> Result<()> {
    let temp = TempDir::new()?;
    let package_json = serde_json::json!({
        "name": "dev-dep-project",
        "version": "1.0.0",
        "private": true
    });
    fs::write(
        temp.path().join("package.json"),
        serde_json::to_string_pretty(&package_json)? + "\n",
    )?;

    let mut cmd = cargo_bin_cmd!("pnpm-rs");
    cmd.current_dir(temp.path())
        .arg("add")
        .arg("--save-dev")
        .arg("react@19");
    cmd.assert().success();

    let contents = fs::read_to_string(temp.path().join("package.json"))?;
    let parsed: serde_json::Value = serde_json::from_str(&contents)?;
    assert!(
        parsed["devDependencies"]["react"].is_string(),
        "expected react in devDependencies"
    );
    assert!(
        parsed["dependencies"]["react"].is_null(),
        "expected react NOT in dependencies"
    );
    Ok(())
}

#[test]
fn frozen_lockfile_fails_without_lockfile() -> Result<()> {
    let temp = TempDir::new()?;
    let package_json = serde_json::json!({
        "name": "frozen-project",
        "version": "1.0.0",
        "private": true,
        "dependencies": { "react": "^19.0.0" }
    });
    fs::write(
        temp.path().join("package.json"),
        serde_json::to_string_pretty(&package_json)? + "\n",
    )?;

    let mut cmd = cargo_bin_cmd!("pnpm-rs");
    cmd.current_dir(temp.path())
        .arg("--frozen-lockfile")
        .arg("install");
    cmd.assert()
        .failure()
        .stderr(predicates::str::contains("no lockfile found"));
    Ok(())
}

#[test]
fn install_blocks_bin_links() -> Result<()> {
    let temp = TempDir::new()?;
    let package_json = serde_json::json!({
        "name": "bin-project",
        "version": "1.0.0",
        "private": true
    });
    fs::write(
        temp.path().join("package.json"),
        serde_json::to_string_pretty(&package_json)? + "\n",
    )?;

    // Add a package that has bin entries (semver has a bin)
    let mut cmd = cargo_bin_cmd!("pnpm-rs");
    cmd.current_dir(temp.path()).arg("add").arg("semver@7");
    cmd.assert().success();

    let bin_dir = temp.path().join("node_modules").join(".bin");
    assert!(
        !bin_dir.exists(),
        "safe mode should not create node_modules/.bin"
    );
    Ok(())
}

#[test]
fn install_rejects_workspace_mutation() -> Result<()> {
    let temp = TempDir::new()?;
    fs::write(
        temp.path().join("pnpm-workspace.yaml"),
        "packages:\n  - packages/*\n",
    )?;
    let package_json = serde_json::json!({
        "name": "workspace-root",
        "version": "1.0.0",
        "private": true
    });
    fs::write(
        temp.path().join("package.json"),
        serde_json::to_string_pretty(&package_json)? + "\n",
    )?;

    let mut cmd = cargo_bin_cmd!("pnpm-rs");
    cmd.current_dir(temp.path()).arg("install");
    cmd.assert().failure().stderr(predicates::str::contains(
        "mutating commands are disabled inside pnpm workspaces",
    ));
    Ok(())
}
