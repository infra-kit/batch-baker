//! Run one remote shell command and stream timestamped lines.

use crate::api::{Events, LogLine, Stream};
use crate::error::Result;
use crate::ssh::SshSession;

pub fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

pub fn shell_join(args: &[String]) -> String {
    args.iter()
        .map(|arg| {
            if arg.is_empty()
                || arg.chars().any(|ch| {
                    !ch.is_ascii_alphanumeric() && !matches!(ch, '-' | '_' | '/' | '.' | ',')
                })
            {
                shell_quote(arg)
            } else {
                arg.clone()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

pub fn remote_shell(command: &str) -> String {
    format!("sh -lc {}", shell_quote(command))
}

pub async fn run_command(
    session: &mut dyn SshSession,
    command: &str,
    events: &dyn Events,
) -> Result<i32> {
    let shell = remote_shell(command);
    let code = session
        .exec_streaming(&shell, &mut |stderr, line| {
            events.on_log_line(&LogLine {
                timestamp: crate::api::now_rfc3339(),
                stream: if stderr { Stream::Stderr } else { Stream::Stdout },
                text: line.to_string(),
            });
        })
        .await?;
    Ok(code)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quotes_spaces_and_single_quotes() {
        assert_eq!(shell_join(&["echo".into(), "hello world".into()]), "echo 'hello world'");
        assert_eq!(shell_quote("a'b"), "'a'\\''b'");
    }
}
