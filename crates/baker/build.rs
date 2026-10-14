use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    let out = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));
    let dest = out.join("batch-baker-agent");
    let bytes = env::var_os("BATCH_BAKER_AGENT_BIN")
        .map(PathBuf::from)
        .filter(|path| path.is_file())
        .or_else(|| {
            let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap_or_default());
            let candidate = manifest
                .join("../..")
                .join("target/x86_64-unknown-linux-musl/release/batch-baker-agent");
            candidate.is_file().then_some(candidate)
        });
    match bytes {
        Some(path) => {
            fs::copy(&path, &dest).expect("copy agent binary");
            println!("cargo:rerun-if-changed={}", path.display());
        }
        None => {
            fs::write(&dest, []).expect("write empty agent stub");
        }
    }
    println!("cargo:rerun-if-env-changed=BATCH_BAKER_AGENT_BIN");
    println!("cargo:rerun-if-changed=build.rs");
}
