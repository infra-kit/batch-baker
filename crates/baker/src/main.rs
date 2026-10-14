//! CLI adapter. Lifecycle lives in the `batch_baker` library.

mod cli;

#[tokio::main]
async fn main() -> std::process::ExitCode {
    cli::run().await
}
