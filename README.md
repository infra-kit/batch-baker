# batch-baker

`batch-baker` provisions one VM, rotates the SSH keys it seeded, uploads a directory, and runs an optional remote command. The Rust library is the product. The `batch-baker` binary is a thin adapter over [`Baker::run`](crates/baker/src/lib.rs).

A run does this, in order:

1. Reuse the recorded instance for the target, or create one.
2. Wait until SSH accepts the seeded client key and the pinned host key.
3. Install `batch-baker-agent` on the guest.
4. When `--ttl` is set, arm a systemd unit that deletes that instance at the deadline.
5. Rotate the client key and the host key once. Later runs skip this step.
6. Upload the local directory through the agent. There is no tar transport.
7. Run the remote command, if one was given, and stream its output.
8. When `--destroy` is set, delete the instance from this process. A missing instance counts as success.

`--destroy` and `--ttl` can be combined. The guest timer is armed, and this process also deletes the instance when the run finishes. A run that returns an error leaves the instance running, including after SIGINT or SIGTERM.

## CLI

```text
batch-baker <target> <local_dir> [flags] [-- <remote command>]
```

The target is `kernel-arch-os-provider`. The kernel name is stored and not checked. DigitalOcean accepts `amd64` with `ubuntu` or `debian`.

```sh
export DIGITALOCEAN_TOKEN=...
batch-baker linux-amd64-ubuntu-digitalocean ./payload --destroy -- echo hello
```

| Flag | Meaning |
| --- | --- |
| `--region` | Provider region. DigitalOcean defaults to `ams3`. |
| `--size` | Provider size. DigitalOcean defaults to `s-1vcpu-1gb`. |
| `--image` | Provider image. Ubuntu defaults to `ubuntu-24-04-x64`, Debian to `debian-12-x64`. |
| `--username` | Remote user. DigitalOcean defaults to `ubuntu`. |
| `--destroy` | Delete the instance from this process when the run ends, including after a failed command. |
| `--ttl <duration>` | Arm the guest to delete the instance after this duration (`30m`, `2h`, `1d`). This process can exit. |
| `--excludes <file>` | Glob patterns to skip, one per line. `#` starts a comment. `.batch-baker` is always skipped. |
| `--safe-ssh` | Require the pinned host key. This is the default. |
| `--insecure-ssh` | Accept any host key. A mismatch in safe mode is reported as a possible MITM and is never accepted. |
| `--state-home <dir>` | Override the state directory. |
| `--no-reuse` | Create a new instance even when one is already recorded. The previous instance is left running. |
| `-v` / `-vv` | Raise logging to debug, then trace. |
| `-q` | Warnings and errors only. Remote log lines are still printed. |
| `--` | The remote command. Arguments are joined with POSIX single quotes and run as `sh -lc`. |

The process exit code is the remote command's status, clamped to 0–255. A provider or SSH failure exits 1. A non-zero remote command is still a successful library result.

## Artifacts and state

The working directory receives `./<target>/`:

- `private_key` (mode `0600`) and `private_key.pub` — the current client key
- `ssh-config` — OpenSSH config for the alias
- `known_hosts` — the pinned host key for the alias and `[ip]:22`
- `last_instance.json` — provider id and instance id

The host private key is not written here. After rotation the directory holds the new client key and the new host public key.

Canonical state is JSON plus an exclusive lock:

| OS | Default directory |
| --- | --- |
| macOS | `~/Library/Application Support/batch-baker` |
| Linux | `~/.local/share/batch-baker` |
| Windows | `%APPDATA%\batch-baker` |

Private key blobs in that directory are mode `0600`. Pins live in `pins/known_hosts.json`. Re-running a reused instance rewrites the TTL deadline and restarts the unit.

## Guest agent

Uploads and TTL both need the static agent embedded in the client. On macOS, build it with a musl cross toolchain:

```sh
cargo zigbuild -p batch-baker-agent --release --target x86_64-unknown-linux-musl
```

`cross` works the same way. `build.rs` copies `target/x86_64-unknown-linux-musl/release/batch-baker-agent`, or the file in `BATCH_BAKER_AGENT_BIN`, into the client. If neither exists, the client still compiles and `cargo test` does not need a cross toolchain. `upload` and `--ttl` then fail at runtime and print the `zigbuild` command.

The client installs the binary at `/usr/local/libexec/batch-baker-agent` (mode `0755`). `apply` is the only file writer. `ttl` sleeps until the deadline, sends one DELETE for that instance, and powers off only after the provider accepts the delete. HTTP 404 is success. Other errors retry for about five minutes and leave the machine running.

The TTL config is `/root/.batch-baker/ttl.json`, mode `0600`, written over SSH stdin. It is not in cloud-init and not in argv. The systemd unit `batch-baker-ttl.service` is enabled, so a reboot before the deadline starts it again. `/tmp` is not used.

A DigitalOcean token can delete every droplet on the account. The file is root-only and disappears with the droplet. Treat a TTL-armed droplet as holding that credential until it is destroyed.

## File transfer

The client runs `batch-baker-agent apply` on one SSH exec channel. Both sides speak protocol version 1: length-prefixed [postcard](https://docs.rs/postcard) frames on that channel's stdin and stdout. Each frame is flushed. A frame larger than 32MiB is rejected.

Files are written under the remote user's home. Paths are relative and use `/`. An absolute path or a path containing `..` is rejected. `.batch-baker` is never uploaded. The agent records finished files in `~/.batch-baker/transfer.json`.

1. The client sends `Hello`. The agent answers `Hello`.
2. The client sends `Begin` with each file's path, mode, length, and BLAKE3 digest. The agent answers `Plan` with the paths whose journal entry and on-disk digest already match. Those files are not sent again.
3. For every other file the client sends `SignaturesPlease`. The agent answers with one signature per existing block: a rolling Adler-32 weak hash, a BLAKE3 strong hash, and the block length. A full block is 4096 bytes. A shorter final block is not eligible for reuse. If the file on disk already has the announced digest, the agent marks it unchanged and returns no blocks.
4. The client sends `Delta`. `Reuse` names an existing block by index. `Literal` carries bytes that did not match. The agent rebuilds the file, checks the announced length and digest, writes it by renaming a temporary file into place, stores the digest in the journal, and answers `Applied`.
5. The client sends `Finish`. The agent answers `Done` with the byte totals.

A new file is sent entirely as literals. A later upload of the same bytes is skipped by the plan. A changed file sends only the spans that do not match a full block already on the guest, so an insert in the middle does not resend the tail. An `Error` frame ends the transfer. If the session drops, the next run continues after the last file recorded in the journal.

## Library

Depend on the library without the CLI stack:

```toml
[dependencies]
batch-baker = { version = "0.1.0", default-features = false }
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
```

```rust
use batch_baker::{Baker, NopEvents, RunRequest, Target};

#[tokio::main]
async fn main() -> batch_baker::Result<()> {
    let baker = Baker::open(None)?;
    let mut request = RunRequest::new(
        Target::parse("linux-amd64-ubuntu-digitalocean")?,
        "./payload".into(),
        std::env::var("DIGITALOCEAN_TOKEN").expect("token"),
    );
    request.remote_command = Some("echo hello".into());
    request.destroy = true;
    let report = baker.run(request, &NopEvents).await?;
    println!("{}", batch_baker::format_summary(&report));
    Ok(())
}
```

The same steps are available one at a time: `provision`, `rotate`, `upload`, `exec`, `destroy`, and `arm_ttl`. Each one closes its SSH session before returning. Pass a `CancellationToken` on the request to cancel; the library does not read argv, install signal handlers, or exit the process.

`Events` receives log lines, transfer progress, the TTL deadline, and the summary. `NopEvents` discards them. `-q` on the CLI still prints remote log lines.

## Adding a provider

Orchestration talks only to `ComputeProvider`. DigitalOcean is the only backend that returns `Ok`. `aws`, `gcp`, and any other id return `ProviderUnavailable` and name `crates/baker/src/provider/mod.rs`.

A new cloud is:

1. A module under `crates/baker/src/provider/` that implements `ComputeProvider`, including `guest_ttl_config`.
2. One arm in `open_provider`.
3. A matching arm in `batch-baker-agent` (`crates/agent/src/destroy.rs`) that deletes that one instance. `arm_ttl` fails before it reports success when the agent cannot delete the provider.

Defaults for region, size, username, and image live on the provider. Cloud-init is shared and does not contain the provider token.

## End-to-end test

`cargo test` does not create droplets. `scripts/e2e.sh` runs the DigitalOcean checklist when `DIGITALOCEAN_TOKEN` is set. It builds the musl agent, creates droplets tagged `batch-baker`, and deletes any droplet this run added.

```sh
export DIGITALOCEAN_TOKEN=...
./scripts/e2e.sh
```

The script checks:

- A first run rotates keys, writes `./<target>/`, leaves the payload at `/home/ubuntu/blob.bin`, and the remote command's exit code is the process exit code.
- After rotation, a different client key is rejected, the original host key files are gone, and one client key remains.
- `--insecure-ssh` connects when the pin would not match. Without it, a mismatch stops the run.
- `--ttl 2m` lets the client exit, and the guest deletes that droplet.
- A second run with the same target reuses the instance. `--no-reuse` creates another one, `--destroy` deletes that new one, and the first stays until the TTL run.
- A second upload of an unchanged tree reports reused bytes and sends less than the first upload.
