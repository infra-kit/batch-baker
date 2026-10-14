//! Client and guest sources must not spawn local processes.
//! Remote `sh`, `ssh-keygen`, and `systemctl` run only over SSH.

use std::fs;
use std::path::{Path, PathBuf};

#[test]
fn sources_do_not_spawn_processes() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace root");
    let mut offenders = Vec::new();
    visit(&root, &root, &mut offenders);
    assert!(
        offenders.is_empty(),
        "std::process::Command is not allowed:\n{}",
        offenders
            .iter()
            .map(|path| path.display().to_string())
            .collect::<Vec<_>>()
            .join("\n")
    );
}

fn visit(root: &Path, dir: &Path, offenders: &mut Vec<PathBuf>) {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name == "target" || name.starts_with('.') {
            continue;
        }
        if path.is_dir() {
            visit(root, &path, offenders);
            continue;
        }
        if !is_source(root, &path) {
            continue;
        }
        let text = fs::read_to_string(&path).unwrap_or_default();
        if text.contains("std::process::Command") || text.contains("Command::new") {
            offenders.push(path);
        }
    }
}

fn is_source(root: &Path, path: &Path) -> bool {
    let rel = path.strip_prefix(root).unwrap_or(path);
    let parts: Vec<_> = rel.components().collect();
    if parts.first().and_then(|part| part.as_os_str().to_str()) != Some("crates") {
        return false;
    }
    let name = path.file_name().and_then(|name| name.to_str()).unwrap_or("");
    if name == "build.rs" {
        return true;
    }
    parts.get(2).and_then(|part| part.as_os_str().to_str()) == Some("src")
        && path.extension().is_some_and(|ext| ext == "rs")
}
