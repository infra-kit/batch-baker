use std::fs;
use std::path::Path;

use globset::{Glob, GlobSet, GlobSetBuilder};

use crate::error::{Error, Result};

pub fn load(path: Option<&Path>) -> Result<GlobSet> {
    let mut builder = GlobSetBuilder::new();
    builder.add(Glob::new(".batch-baker").map_err(|err| Error::msg(err.to_string()))?);
    builder.add(Glob::new(".batch-baker/**").map_err(|err| Error::msg(err.to_string()))?);
    if let Some(path) = path {
        let text = fs::read_to_string(path).map_err(|err| Error::io(path, err))?;
        for (number, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let glob = Glob::new(line).map_err(|err| {
                Error::msg(format!("{}:{}: {err}", path.display(), number + 1))
            })?;
            builder.add(glob);
        }
    }
    builder
        .build()
        .map_err(|err| Error::msg(format!("excludes: {err}")))
}

pub fn is_excluded(set: &GlobSet, relative: &str) -> bool {
    set.is_match(relative) || relative.split('/').any(|part| set.is_match(part))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn honors_file_and_internal_journal_dir() {
        let dir = std::env::temp_dir().join(format!("bb-ex-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("excludes");
        fs::write(&path, "# comment\n*.log\nsecret/**\n").unwrap();
        let set = load(Some(&path)).unwrap();
        assert!(is_excluded(&set, "a.log"));
        assert!(is_excluded(&set, "secret/key"));
        assert!(is_excluded(&set, ".batch-baker/transfer.json"));
        assert!(!is_excluded(&set, "src/main.rs"));
        let _ = fs::remove_dir_all(&dir);
    }
}
