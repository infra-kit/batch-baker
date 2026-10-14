//! Guest helper installed by batch-baker.
//!
//! * `apply` reads the delta protocol on stdin and writes the destination tree.
//! * `ttl` sleeps until the deadline in a root-only config file, then deletes
//!   that one instance through the provider API and powers the guest off.

mod destroy;

#[cfg(test)]
mod destroy_tests;

use std::env;
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use batch_baker_proto::serve_apply;
use destroy::{delete_instance, wait_until, Retry, TtlConfig};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            let _ = writeln!(io::stderr(), "batch-baker-agent: {err}");
            ExitCode::from(1)
        }
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args().skip(1);
    match args.next().as_deref() {
        Some("apply") => apply(args.collect()),
        Some("ttl") => ttl(args.collect()),
        _ => {
            eprintln!(
                "usage:\n  batch-baker-agent apply --dest DIR --journal FILE\n  batch-baker-agent ttl --config FILE"
            );
            Err("missing subcommand".into())
        }
    }
}

fn apply(args: Vec<String>) -> Result<(), Box<dyn std::error::Error>> {
    let dest = flag(&args, "--dest")?;
    let journal = flag(&args, "--journal")?;
    let stdin = io::stdin();
    let mut reader = stdin.lock();
    let stdout = io::stdout();
    let mut writer = stdout.lock();
    serve_apply(&mut reader, &mut writer, &dest, &journal)?;
    Ok(())
}

fn ttl(args: Vec<String>) -> Result<(), Box<dyn std::error::Error>> {
    let path = flag(&args, "--config")?;
    let mut file = File::open(&path)?;
    let mut body = String::new();
    file.read_to_string(&mut body)?;
    let config: TtlConfig = serde_json::from_str(&body)?;
    wait_until(&config.deadline)?;
    delete_instance(&config, Retry::default())?;
    destroy::poweroff();
    Ok(())
}

fn flag(args: &[String], name: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if arg == name {
            let value = iter
                .next()
                .ok_or_else(|| format!("{name} needs a value"))?;
            return Ok(PathBuf::from(value));
        }
    }
    Err(format!("missing {name}").into())
}
