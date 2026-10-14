//! Decide whether a presented host key matches the pin.

use crate::error::{Error, Result};

pub fn accept_host_key(host: &str, insecure: bool, pinned: Option<&str>, got: &str) -> Result<()> {
    if insecure {
        return Ok(());
    }
    let Some(pinned) = pinned else {
        return Err(Error::msg(format!(
            "no pinned host key for {host}. Refusing to continue."
        )));
    };
    if pinned != got {
        return Err(Error::Mitm {
            host: host.to_string(),
            pinned: pinned.to_string(),
            got: got.to_string(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mismatch_is_a_mitm_error() {
        let err = accept_host_key("vm", false, Some("SHA256:one"), "SHA256:two").unwrap_err();
        let message = err.to_string();
        assert!(message.contains("MITM"), "{message}");
        assert!(message.contains("SHA256:one"));
        assert!(message.contains("SHA256:two"));
    }

    #[test]
    fn insecure_accepts_any_key() {
        accept_host_key("vm", true, Some("SHA256:one"), "SHA256:other").unwrap();
    }
}
