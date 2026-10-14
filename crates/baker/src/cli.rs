//! Map argv onto [`batch_baker::RunRequest`].

use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use batch_baker::{
    format_summary, Events, LogLine, RunRequest, SshMode, Stream, Target, TransferProgress,
};
use clap::Parser;
use tokio_util::sync::CancellationToken;

#[derive(Debug, Parser)]
#[command(name = "batch-baker", about = "Provision a VM, upload a directory, and run a command")]
struct Cli {
    /// kernel-arch-os-provider, for example linux-amd64-ubuntu-digitalocean
    target: String,
    /// Local directory to upload
    local_dir: PathBuf,
    /// Provider region. Default comes from the provider.
    #[arg(long)]
    region: Option<String>,
    /// Provider size. Default comes from the provider.
    #[arg(long)]
    size: Option<String>,
    /// Provider image. Default comes from the provider and the target OS.
    #[arg(long)]
    image: Option<String>,
    /// Remote username. Default comes from the provider.
    #[arg(long)]
    username: Option<String>,
    /// Delete the instance from this process when the run finishes.
    #[arg(long)]
    destroy: bool,
    /// Arm the guest agent to delete the instance after this duration (30m, 2h, 1d).
    #[arg(long)]
    ttl: Option<String>,
    /// File of glob patterns to skip during upload.
    #[arg(long)]
    excludes: Option<PathBuf>,
    /// Require the pinned host key. This is the default.
    #[arg(long, default_value_t = true)]
    safe_ssh: bool,
    /// Accept any host key.
    #[arg(long)]
    insecure_ssh: bool,
    /// Override the state directory.
    #[arg(long)]
    state_home: Option<PathBuf>,
    /// Create a new instance even when one is already recorded for this target.
    #[arg(long)]
    no_reuse: bool,
    /// Increase logging. Repeat for more detail.
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,
    /// Warnings and errors only.
    #[arg(short, long)]
    quiet: bool,
    /// Remote command. Pass it after `--`.
    #[arg(last = true)]
    remote: Vec<String>,
}

struct Printer {
    quiet: bool,
}

impl Events for Printer {
    fn on_phase(&self, name: &str) {
        if self.quiet {
            return;
        }
        emit(name);
    }

    fn on_log_line(&self, line: &LogLine) {
        let stream = match line.stream {
            Stream::Stdout => "stdout",
            Stream::Stderr => "stderr",
        };
        emit(&format!("{} {stream} | {}", line.timestamp, line.text));
    }

    fn on_transfer_progress(&self, progress: &TransferProgress) {
        if self.quiet {
            return;
        }
        eprintln!(
            "upload {} sent {} reused {} (total sent {} reused {})",
            progress.path,
            progress.bytes_sent,
            progress.bytes_reused,
            progress.bytes_sent_total,
            progress.bytes_reused_total
        );
    }

    fn on_ttl_armed(&self, deadline: std::time::SystemTime) {
        if self.quiet {
            return;
        }
        eprintln!(
            "TTL armed until {}",
            batch_baker::format_system_time(deadline)
        );
    }

    fn on_summary(&self, report: &batch_baker::RunReport) {
        if self.quiet {
            return;
        }
        emit(&format_summary(report));
    }
}

fn emit(text: &str) {
    println!("{text}");
    let _ = io::stdout().flush();
}

pub async fn run() -> ExitCode {
    let cli = Cli::parse();
    init_tracing(cli.verbose, cli.quiet);
    let token = match std::env::var("DIGITALOCEAN_TOKEN") {
        Ok(token) if !token.is_empty() => token,
        _ => {
            eprintln!("error: set DIGITALOCEAN_TOKEN");
            return ExitCode::from(1);
        }
    };
    let target = match Target::parse(&cli.target) {
        Ok(target) => target,
        Err(err) => {
            eprintln!("error: {err}");
            return ExitCode::from(1);
        }
    };
    let ttl = match cli.ttl.as_deref().map(parse_ttl).transpose() {
        Ok(ttl) => ttl,
        Err(err) => {
            eprintln!("error: {err}");
            return ExitCode::from(1);
        }
    };
    let cancel = CancellationToken::new();
    spawn_signals(cancel.clone());
    let baker = match batch_baker::Baker::open(cli.state_home) {
        Ok(baker) => baker,
        Err(err) => {
            eprintln!("error: {err}");
            return ExitCode::from(1);
        }
    };
    let mut req = RunRequest::new(target, cli.local_dir, token);
    req.region = cli.region;
    req.size = cli.size;
    req.image = cli.image;
    req.username = cli.username;
    req.destroy = cli.destroy;
    req.ttl = ttl;
    req.excludes = cli.excludes;
    req.ssh = if cli.insecure_ssh {
        SshMode::Insecure
    } else {
        SshMode::Safe
    };
    req.reuse = !cli.no_reuse;
    req.cancel = cancel;
    req.workdir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    if !cli.remote.is_empty() {
        req.remote_command = Some(batch_baker::shell_join(&cli.remote));
    }
    let events = Printer { quiet: cli.quiet };
    match baker.run(req, &events).await {
        Ok(report) => ExitCode::from(report.remote_exit.unwrap_or(0).clamp(0, 255) as u8),
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::from(1)
        }
    }
}

fn parse_ttl(text: &str) -> Result<Duration, String> {
    humantime::parse_duration(text).map_err(|err| format!("ttl `{text}`: {err}"))
}

fn init_tracing(verbose: u8, quiet: bool) {
    let filter = if quiet {
        "warn"
    } else {
        match verbose {
            0 => "info",
            1 => "debug",
            _ => "trace",
        }
    };
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .try_init();
}

fn spawn_signals(cancel: CancellationToken) {
    tokio::spawn(async move {
        let ctrl_c = tokio::signal::ctrl_c();
        #[cfg(unix)]
        {
            let mut term = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                Ok(term) => term,
                Err(_) => {
                    let _ = ctrl_c.await;
                    cancel.cancel();
                    return;
                }
            };
            tokio::select! {
                _ = ctrl_c => cancel.cancel(),
                _ = term.recv() => cancel.cancel(),
            }
        }
        #[cfg(not(unix))]
        {
            let _ = ctrl_c.await;
            cancel.cancel();
        }
    });
}
