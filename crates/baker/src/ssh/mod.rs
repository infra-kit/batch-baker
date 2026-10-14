//! SSH sessions. Production uses russh. Tests use an in-memory guest.

mod russh_client;
mod session;
mod verifier;

#[cfg(test)]
pub(crate) mod fake;

use std::time::Duration;

pub use russh_client::RusshFactory;
pub use session::{ByteChannel, ConnectSpec, ExecResult, SessionFactory, SshSession};

use crate::error::{Error, Result};
use tokio_util::sync::CancellationToken;

#[derive(Debug, Clone)]
pub struct ConnectPolicy {
    pub budget: Duration,
    pub initial: Duration,
    pub max_interval: Duration,
}

impl Default for ConnectPolicy {
    fn default() -> Self {
        Self {
            budget: Duration::from_secs(120),
            initial: Duration::from_secs(1),
            max_interval: Duration::from_secs(10),
        }
    }
}

/// Retry SSH until cloud-init has installed keys or the budget runs out.
pub async fn connect_retry(
    factory: &dyn SessionFactory,
    spec: &ConnectSpec,
    policy: ConnectPolicy,
    cancel: &CancellationToken,
) -> Result<Box<dyn SshSession>> {
    let started = std::time::Instant::now();
    let mut delay = policy.initial;
    let mut last;
    loop {
        if cancel.is_cancelled() {
            return Err(Error::Cancelled);
        }
        match factory.connect(spec).await {
            Ok(session) => return Ok(session),
            Err(err) => {
                if matches!(err, Error::Mitm { .. }) || err.to_string().contains("MITM") {
                    return Err(err);
                }
                last = err;
            }
        }
        if started.elapsed() >= policy.budget {
            return Err(Error::msg(format!(
                "ssh to {} did not become ready: {last}",
                spec.host
            )));
        }
        tokio::select! {
            _ = cancel.cancelled() => return Err(Error::Cancelled),
            _ = tokio::time::sleep(delay) => {}
        }
        delay = (delay * 2).min(policy.max_interval);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use std::sync::atomic::{AtomicU32, Ordering};

    struct Flaky {
        left: AtomicU32,
    }

    #[async_trait]
    impl SessionFactory for Flaky {
        async fn connect(&self, _spec: &ConnectSpec) -> Result<Box<dyn SshSession>> {
            let left = self.left.fetch_sub(1, Ordering::SeqCst);
            if left > 0 {
                Err(Error::msg("not yet"))
            } else {
                Err(Error::msg("stop"))
            }
        }
    }

    #[tokio::test]
    async fn retries_until_the_budget_is_spent() {
        let factory = Flaky {
            left: AtomicU32::new(5),
        };
        let spec = ConnectSpec {
            host: "203.0.113.10".into(),
            port: 22,
            username: "ubuntu".into(),
            client_key: crate::keys::generate("batch-baker").unwrap().private,
            insecure: true,
            pinned_fingerprint: None,
            host_label: "vm".into(),
        };
        let err = match connect_retry(
            &factory,
            &spec,
            ConnectPolicy {
                budget: Duration::from_millis(30),
                initial: Duration::from_millis(5),
                max_interval: Duration::from_millis(5),
            },
            &CancellationToken::new(),
        )
        .await
        {
            Err(err) => err,
            Ok(_) => panic!("flaky factory should fail"),
        };
        assert!(err.to_string().contains("did not become ready"), "{err}");
    }
}
