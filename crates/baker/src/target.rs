//! `{kernel}-{arch}-{os}-{provider}` target strings.

use crate::error::{Error, Result};

/// A parsed target. `kernel` is stored and not validated.
/// Arch and OS are checked later by the selected provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub kernel: String,
    pub arch: String,
    pub os: String,
    pub provider: String,
    pub raw: String,
}

impl Target {
    /// Split on `-` into exactly four fields.
    pub fn parse(raw: &str) -> Result<Self> {
        let parts: Vec<&str> = raw.split('-').collect();
        if parts.len() != 4 || parts.iter().any(|part| part.is_empty()) {
            return Err(Error::BadTarget(raw.to_string()));
        }
        Ok(Self {
            kernel: parts[0].to_string(),
            arch: parts[1].to_string(),
            os: parts[2].to_string(),
            provider: parts[3].to_string(),
            raw: raw.to_string(),
        })
    }
}

impl std::str::FromStr for Target {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Self::parse(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_four_fields() {
        let target = Target::parse("linux-amd64-ubuntu-digitalocean").unwrap();
        assert_eq!(target.kernel, "linux");
        assert_eq!(target.arch, "amd64");
        assert_eq!(target.os, "ubuntu");
        assert_eq!(target.provider, "digitalocean");
    }

    #[test]
    fn rejects_short_and_empty_fields() {
        assert!(Target::parse("linux-amd64-ubuntu").is_err());
        assert!(Target::parse("linux-amd64--digitalocean").is_err());
        assert!(Target::parse("linux-arm64-ubuntu-aws").is_ok());
    }
}
