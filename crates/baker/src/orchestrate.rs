//! End-to-end run. Public methods on [`crate::Baker`] call into here.
//!
//! Manual checks against a real DigitalOcean account (not part of `cargo test`):
//! happy path with rotation, old keys rejected, `--insecure-ssh`, TTL delete from
//! the guest, reuse versus `--no-reuse`, and a second upload that sends fewer bytes.
//! See the README for the same list.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use tracing::instrument;

use crate::api::{
    format_summary, Events, InstanceHandle, ProvisionSpec, RotationReport, RunReport,
    RunRequest, SshMode, TransferStats, UploadSpec,
};
use crate::artifacts::write_client_and_config;
use crate::cloud_init;
use crate::command::run_command;
use crate::error::{Error, Result};
use crate::keys::{self, KeyMaterial};
use crate::provider::{
    open_provider, ComputeProvider, CreateInstance, InstanceStatus, ProviderContext,
};
use crate::ssh::{connect_retry, ConnectPolicy, ConnectSpec, RusshFactory, SessionFactory};
use crate::state::{instance_key, InstanceRecord, StateStore, TargetRecord};
use crate::transfer::{agent_apply_command, collect_files, load_excludes, upload_tree};
use crate::ttl::{self, deadline_from};
use crate::Baker;

struct Machine {
    handle: InstanceHandle,
    client: KeyMaterial,
    host_public: String,
}

impl Baker {
    /// Provision or reuse, install the agent, rotate keys, upload, run the command, then destroy or arm TTL.
    pub async fn run(&self, req: RunRequest, events: &dyn Events) -> Result<RunReport> {
        let provider = open_provider(
            &req.target.provider,
            ProviderContext {
                token: req.token.clone(),
                cancel: req.cancel.clone(),
            },
        )?;
        self.run_with(
            req,
            events,
            provider,
            Arc::new(RusshFactory),
            ConnectPolicy::default(),
        )
        .await
    }

    /// Create an instance, or reuse the recorded one unless `spec.reuse` is false.
    pub async fn provision(&self, spec: ProvisionSpec) -> Result<InstanceHandle> {
        let provider = open_provider(
            &spec.target.provider,
            ProviderContext {
                token: spec.token.clone(),
                cancel: spec.cancel.clone(),
            },
        )?;
        let machine = provision(self, &spec, provider.as_ref()).await?;
        Ok(machine.handle)
    }

    /// Upload `upload.local_dir` through the guest agent. The session is closed before return.
    pub async fn upload(
        &self,
        inst: &InstanceHandle,
        upload: UploadSpec,
        events: &dyn Events,
    ) -> Result<TransferStats> {
        let provider = open_provider(
            &inst.provider,
            ProviderContext {
                token: inst.token.clone(),
                cancel: upload.cancel.clone(),
            },
        )?;
        let _ = provider;
        let sessions = Arc::new(RusshFactory);
        let machine = load_machine(self, inst)?;
        let mut session = connect_machine(
            self.state_home(),
            &machine,
            sessions.as_ref(),
            &ConnectPolicy::default(),
            &upload.cancel,
        )
        .await?;
        install_agent(&mut *session, self.agent_bytes()).await?;
        transfer(&mut *session, &machine, &upload, events).await
    }

    /// Rotate the client key and the host key when this instance has not been rotated yet.
    pub async fn rotate(&self, inst: &InstanceHandle) -> Result<RotationReport> {
        let sessions = Arc::new(RusshFactory);
        let machine = load_machine(self, inst)?;
        let mut session = connect_machine(
            self.state_home(),
            &machine,
            sessions.as_ref(),
            &ConnectPolicy::default(),
            &tokio_util::sync::CancellationToken::new(),
        )
        .await?;
        let rotated = rotate_machine(self, &mut *session, sessions.as_ref(), &machine).await?;
        Ok(rotated.report)
    }

    /// Run `command` with `sh -lc` and forward each line to `events`.
    pub async fn exec(&self, inst: &InstanceHandle, command: &str, events: &dyn Events) -> Result<i32> {
        let sessions = Arc::new(RusshFactory);
        let machine = load_machine(self, inst)?;
        let mut session = connect_machine(
            self.state_home(),
            &machine,
            sessions.as_ref(),
            &ConnectPolicy::default(),
            &tokio_util::sync::CancellationToken::new(),
        )
        .await?;
        run_command(&mut *session, command, events).await
    }

    /// Delete the instance through the provider API. A missing instance is success.
    pub async fn destroy(&self, inst: &InstanceHandle) -> Result<()> {
        let provider = open_provider(
            &inst.provider,
            ProviderContext {
                token: inst.token.clone(),
                cancel: tokio_util::sync::CancellationToken::new(),
            },
        )?;
        destroy_instance(self, provider.as_ref(), inst).await
    }

    /// Install a systemd unit that deletes this instance at `until` and then powers off.
    pub async fn arm_ttl(&self, inst: &InstanceHandle, until: SystemTime) -> Result<()> {
        let provider = open_provider(
            &inst.provider,
            ProviderContext {
                token: inst.token.clone(),
                cancel: tokio_util::sync::CancellationToken::new(),
            },
        )?;
        let sessions = Arc::new(RusshFactory);
        let machine = load_machine(self, inst)?;
        let mut session = connect_machine(
            self.state_home(),
            &machine,
            sessions.as_ref(),
            &ConnectPolicy::default(),
            &tokio_util::sync::CancellationToken::new(),
        )
        .await?;
        install_agent(&mut *session, self.agent_bytes()).await?;
        let deadline = crate::api::system_time_rfc3339(until);
        ttl::arm(&mut *session, provider.as_ref(), &inst.instance_id, &deadline).await?;
        let store = StateStore::new(self.state_home());
        let mut lock = store.lock()?;
        if let Some(target) = lock.state.targets.get_mut(&inst.target) {
            target.ttl_until = Some(deadline);
            target.ttl_armed = true;
        }
        lock.save()?;
        Ok(())
    }
}

impl Baker {
    #[instrument(skip_all, fields(target = req.target.raw))]
    pub(crate) async fn run_with(
        &self,
        req: RunRequest,
        events: &dyn Events,
        provider: Box<dyn ComputeProvider>,
        sessions: Arc<dyn SessionFactory>,
        connect: ConnectPolicy,
    ) -> Result<RunReport> {
        self.run_body(&req, events, provider.as_ref(), sessions, connect)
            .await
    }

    async fn run_body(
        &self,
        req: &RunRequest,
        events: &dyn Events,
        provider: &dyn ComputeProvider,
        sessions: Arc<dyn SessionFactory>,
        connect: ConnectPolicy,
    ) -> Result<RunReport> {
        check_cancel(&req.cancel)?;
        events.on_phase("provision");
        let spec = ProvisionSpec {
            target: req.target.clone(),
            region: req.region.clone(),
            size: req.size.clone(),
            image: req.image.clone(),
            username: req.username.clone(),
            token: req.token.clone(),
            reuse: req.reuse,
            insecure: req.ssh == SshMode::Insecure,
            cancel: req.cancel.clone(),
            workdir: req.workdir.clone(),
        };
        let mut machine = provision(self, &spec, provider).await?;

        let mut session = connect_machine(self.state_home(), &machine, sessions.as_ref(), &connect, &req.cancel).await?;
        install_agent(&mut *session, self.agent_bytes()).await?;

        let mut ttl_until = None;
        if let Some(ttl) = req.ttl {
            let (until, text) = deadline_from(ttl);
            ttl::arm(&mut *session, provider, &machine.handle.instance_id, &text).await?;
            events.on_ttl_armed(until);
            ttl_until = Some(until);
            remember_ttl(self, &machine.handle.target, &text)?;
        }

        let rotation = if machine.handle.keys_rotated {
            None
        } else {
            events.on_phase("rotate");
            let rotated = rotate_machine(self, &mut *session, sessions.as_ref(), &machine).await?;
            machine.client = rotated.client;
            machine.host_public = rotated.host_public;
            machine.handle.client_key_fpr = machine.client.fingerprint.clone();
            machine.handle.host_key_fpr = rotated.report.host_new.clone();
            machine.handle.keys_rotated = true;
            refresh_artifacts(&machine)?;
            Some(rotated.report)
        };

        events.on_phase("upload");
        let upload = UploadSpec {
            local_dir: req.local_dir.clone(),
            excludes: req.excludes.clone(),
            cancel: req.cancel.clone(),
        };
        // sshd restart during rotation drops the session that installed the agent.
        let transfer = if rotation.is_some() {
            let mut upload_session =
                connect_machine(self.state_home(), &machine, sessions.as_ref(), &connect, &req.cancel).await?;
            transfer(&mut *upload_session, &machine, &upload, events).await?
        } else {
            transfer(&mut *session, &machine, &upload, events).await?
        };

        let remote_exit = if let Some(command) = &req.remote_command {
            events.on_phase("command");
            let mut command_session =
                connect_machine(self.state_home(), &machine, sessions.as_ref(), &connect, &req.cancel).await?;
            Some(run_command(&mut *command_session, command, events).await?)
        } else {
            None
        };

        let mut destroyed = false;
        if req.destroy {
            destroy_instance(self, provider, &machine.handle).await?;
            destroyed = true;
        }

        let paths = crate::artifacts::paths(&req.workdir, &req.target.raw);
        let report = RunReport {
            alias: req.target.raw.clone(),
            ip: machine.handle.ip.clone(),
            username: machine.handle.username.clone(),
            private_key: paths.private_key,
            ssh_config: paths.ssh_config,
            known_hosts: paths.known_hosts,
            transfer,
            rotation,
            remote_exit,
            ttl_until,
            destroyed,
        };
        events.on_summary(&report);
        tracing::info!("{}", format_summary(&report));
        Ok(report)
    }
}

#[instrument(skip_all)]
async fn provision(baker: &Baker, spec: &ProvisionSpec, provider: &dyn ComputeProvider) -> Result<Machine> {
    check_cancel(&spec.cancel)?;
    provider.ensure_supported(&spec.target.os, &spec.target.arch)?;
    let defaults = provider.defaults();
    let region = spec.region.clone().unwrap_or(defaults.region);
    let size = spec.size.clone().unwrap_or(defaults.size);
    let username = spec.username.clone().unwrap_or(defaults.username);
    validate_username(&username)?;
    let image = match &spec.image {
        Some(image) => image.clone(),
        None => provider.default_image(&spec.target.os, &spec.target.arch)?,
    };

    let store = StateStore::new(baker.state_home());
    if spec.reuse {
        let existing = {
            let lock = store.lock()?;
            lock.state.targets.get(&spec.target.raw).cloned()
        };
        if let Some(record) = existing {
            let info = provider.get_instance(&record.active_instance_id).await?;
            if info.status != InstanceStatus::Active || info.public_ipv4.is_none() {
                return Err(Error::InstanceUnavailable {
                    target: spec.target.raw.clone(),
                    id: record.active_instance_id,
                });
            }
            let client_path = keys::client_private_path(baker.state_home(), &record.client_key_fpr);
            let host_path = keys::host_public_path(baker.state_home(), &record.host_key_fpr);
            if !client_path.is_file() || !host_path.is_file() {
                return Err(Error::InconsistentKeys {
                    target: spec.target.raw.clone(),
                    detail: "key files are missing".into(),
                });
            }
            let client = keys::load_private(&client_path)?;
            let host_public = std::fs::read_to_string(&host_path).map_err(|err| Error::io(&host_path, err))?;
            let ip = info.public_ipv4.unwrap();
            let handle = handle_from(spec, &record, &ip, &client.fingerprint);
            let machine = Machine {
                handle,
                client,
                host_public,
            };
            refresh_artifacts(&machine)?;
            return Ok(machine);
        }
    }

    let client = keys::generate("batch-baker")?;
    let host = keys::generate("host@cloud-mvp")?;
    keys::store_client(baker.state_home(), &client)?;
    keys::store_host(baker.state_home(), &host)?;
    let user_data = cloud_init::render(&username, &client, &host);
    let created = provider
        .create_instance(CreateInstance {
            name: format!("{}-{}", spec.target.raw, name_suffix()),
            region: region.clone(),
            size: size.clone(),
            image: image.clone(),
            user_data,
            tags: vec!["batch-baker".into()],
        })
        .await?;
    let ready = provider
        .wait_instance_ready(&created.id, Duration::from_secs(300))
        .await?;
    let ip = ready.public_ipv4.ok_or_else(|| Error::msg("instance has no public IPv4"))?;
    let created_at = crate::api::now_rfc3339();
    let record = TargetRecord {
        active_instance_id: created.id.clone(),
        username: username.clone(),
        region: region.clone(),
        size,
        image,
        client_key_fpr: client.fingerprint.clone(),
        host_key_fpr: host.fingerprint.clone(),
        created_at: created_at.clone(),
        ttl_until: None,
        keys_rotated: false,
        ttl_armed: false,
    };
    let instance = InstanceRecord {
        target: spec.target.raw.clone(),
        ip: ip.clone(),
        status: "active".into(),
        created_at,
        destroy_at: None,
    };
    {
        let mut lock = store.lock()?;
        lock.state
            .provider
            .entry(provider.id().to_string())
            .or_default()
            .last_used_region = Some(region);
        lock.state.instances.insert(instance_key(provider.id(), &created.id), instance.clone());
        lock.write_instance_file(provider.id(), &created.id, &instance)?;
        lock.state.targets.insert(spec.target.raw.clone(), record.clone());
        lock.save()?;
    }
    {
        let mut pins = crate::state::KnownHosts::load(baker.state_home())?;
        pins.upsert(&spec.target.raw, 22, &host.fingerprint);
        pins.upsert(&ip, 22, &host.fingerprint);
        pins.save(baker.state_home())?;
    }
    let handle = handle_from(spec, &record, &ip, &client.fingerprint);
    let machine = Machine {
        handle,
        client,
        host_public: host.public_openssh,
    };
    refresh_artifacts(&machine)?;
    Ok(machine)
}

fn handle_from(spec: &ProvisionSpec, record: &TargetRecord, ip: &str, client_fpr: &str) -> InstanceHandle {
    InstanceHandle {
        provider: spec.target.provider.clone(),
        instance_id: record.active_instance_id.clone(),
        ip: ip.to_string(),
        username: record.username.clone(),
        target: spec.target.raw.clone(),
        client_key_fpr: client_fpr.to_string(),
        host_key_fpr: record.host_key_fpr.clone(),
        keys_rotated: record.keys_rotated,
        insecure: spec.insecure,
        token: spec.token.clone(),
        workdir: spec.workdir.clone(),
    }
}

async fn transfer(
    session: &mut dyn crate::ssh::SshSession,
    machine: &Machine,
    upload: &UploadSpec,
    events: &dyn Events,
) -> Result<TransferStats> {
    check_cancel(&upload.cancel)?;
    if !upload.local_dir.is_dir() {
        return Err(Error::msg(format!(
            "{} is not a directory",
            upload.local_dir.display()
        )));
    }
    let excludes = load_excludes(upload.excludes.as_deref())?;
    let files = collect_files(&upload.local_dir, &excludes)?;
    let mut channel = session
        .open_exec(&agent_apply_command(&machine.handle.username))
        .await?;
    let stats = upload_tree(channel.as_mut(), files, events, &upload.cancel).await?;
    channel.close_send().await?;
    Ok(stats)
}

async fn rotate_machine(
    baker: &Baker,
    session: &mut dyn crate::ssh::SshSession,
    sessions: &dyn SessionFactory,
    machine: &Machine,
) -> Result<crate::rotate::Rotated> {
    let rotated = crate::rotate::rotate(
        session,
        sessions,
        crate::rotate::RotationInput {
            state_root: baker.state_home(),
            username: &machine.handle.username,
            host: &machine.handle.ip,
            host_label: &machine.handle.target,
            c0: machine.client.clone(),
            h0_fingerprint: &machine.handle.host_key_fpr,
            insecure: machine.handle.insecure,
        },
    )
    .await?;
    keys::write_public(
        &keys::host_public_path(baker.state_home(), &rotated.report.host_new),
        &format!("{}\n", rotated.host_public.trim()),
    )?;
    let store = StateStore::new(baker.state_home());
    let mut lock = store.lock()?;
    if let Some(target) = lock.state.targets.get_mut(&machine.handle.target) {
        target.client_key_fpr = rotated.client.fingerprint.clone();
        target.host_key_fpr = rotated.report.host_new.clone();
        target.keys_rotated = true;
    }
    lock.save()?;
    Ok(rotated)
}

async fn destroy_instance(baker: &Baker, provider: &dyn ComputeProvider, inst: &InstanceHandle) -> Result<()> {
    provider.destroy_instance(&inst.instance_id).await?;
    let store = StateStore::new(baker.state_home());
    let mut lock = store.lock()?;
    let key = instance_key(&inst.provider, &inst.instance_id);
    if let Some(record) = lock.state.instances.get_mut(&key) {
        record.status = "destroyed".into();
        record.destroy_at = Some(crate::api::now_rfc3339());
    }
    if let Some(target) = lock.state.targets.get_mut(&inst.target) {
        if target.active_instance_id == inst.instance_id {
            target.ttl_armed = false;
        }
    }
    lock.save()?;
    Ok(())
}

fn remember_ttl(baker: &Baker, target: &str, deadline: &str) -> Result<()> {
    let store = StateStore::new(baker.state_home());
    let mut lock = store.lock()?;
    if let Some(record) = lock.state.targets.get_mut(target) {
        record.ttl_until = Some(deadline.to_string());
        record.ttl_armed = true;
    }
    lock.save()
}

fn refresh_artifacts(machine: &Machine) -> Result<()> {
    let record = InstanceRecord {
        target: machine.handle.target.clone(),
        ip: machine.handle.ip.clone(),
        status: "active".into(),
        created_at: crate::api::now_rfc3339(),
        destroy_at: None,
    };
    write_client_and_config(
        &machine.handle.workdir,
        &machine.handle.target,
        &machine.handle.username,
        &machine.handle.ip,
        &machine.client.private_openssh,
        &machine.client.public_openssh,
        &machine.host_public,
        if machine.handle.insecure {
            SshMode::Insecure
        } else {
            SshMode::Safe
        },
        &record,
    )?;
    Ok(())
}

async fn connect_machine(
    state_home: &std::path::Path,
    machine: &Machine,
    sessions: &dyn SessionFactory,
    policy: &ConnectPolicy,
    cancel: &tokio_util::sync::CancellationToken,
) -> Result<Box<dyn crate::ssh::SshSession>> {
    let pinned_fingerprint = if machine.handle.insecure {
        None
    } else {
        let pins = crate::state::KnownHosts::load(state_home)?;
        Some(
            pins.fingerprint_for(&machine.handle.target, 22)
                .or_else(|| pins.fingerprint_for(&machine.handle.ip, 22))
                .ok_or_else(|| {
                    Error::msg(format!(
                        "no pinned host key for {}",
                        machine.handle.target
                    ))
                })?
                .to_string(),
        )
    };
    let spec = ConnectSpec {
        host: machine.handle.ip.clone(),
        port: 22,
        username: machine.handle.username.clone(),
        client_key: machine.client.private.clone(),
        insecure: machine.handle.insecure,
        pinned_fingerprint,
        host_label: machine.handle.target.clone(),
    };
    connect_retry(sessions, &spec, policy.clone(), cancel).await
}

async fn install_agent(session: &mut dyn crate::ssh::SshSession, bytes: &[u8]) -> Result<()> {
    if bytes.is_empty() {
        return Err(Error::AgentMissing);
    }
    let mkdir = session.exec("sudo mkdir -p /usr/local/libexec").await?;
    if mkdir.status != 0 {
        return Err(Error::msg(format!("mkdir agent dir: {}", mkdir.stderr)));
    }
    let copied = session
        .exec_stdin(
            "sudo tee /usr/local/libexec/batch-baker-agent > /dev/null",
            bytes,
        )
        .await?;
    if copied.status != 0 {
        return Err(Error::msg(format!("install agent: {}", copied.stderr)));
    }
    let mode = session
        .exec("sudo chmod 0755 /usr/local/libexec/batch-baker-agent")
        .await?;
    if mode.status != 0 {
        return Err(Error::msg(format!("chmod agent: {}", mode.stderr)));
    }
    Ok(())
}

fn load_machine(baker: &Baker, inst: &InstanceHandle) -> Result<Machine> {
    let client = keys::load_private(&keys::client_private_path(
        baker.state_home(),
        &inst.client_key_fpr,
    ))?;
    let host_path = keys::host_public_path(baker.state_home(), &inst.host_key_fpr);
    let host_public = std::fs::read_to_string(&host_path).map_err(|err| Error::io(&host_path, err))?;
    Ok(Machine {
        handle: inst.clone_shallow(),
        client,
        host_public,
    })
}

fn validate_username(name: &str) -> Result<()> {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return Err(Error::msg("username is empty"));
    };
    if !(first.is_ascii_lowercase() || first == '_')
        || name.len() > 32
        || chars.any(|ch| !(ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_' || ch == '-'))
    {
        return Err(Error::msg(format!(
            "username `{name}` must match [a-z_][a-z0-9_-]{{0,31}}"
        )));
    }
    Ok(())
}

fn name_suffix() -> String {
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    format!("{nanos:08x}")
}

fn check_cancel(cancel: &tokio_util::sync::CancellationToken) -> Result<()> {
    if cancel.is_cancelled() {
        Err(Error::Cancelled)
    } else {
        Ok(())
    }
}

trait CloneHandle {
    fn clone_shallow(&self) -> InstanceHandle;
}

impl CloneHandle for InstanceHandle {
    fn clone_shallow(&self) -> InstanceHandle {
        InstanceHandle {
            provider: self.provider.clone(),
            instance_id: self.instance_id.clone(),
            ip: self.ip.clone(),
            username: self.username.clone(),
            target: self.target.clone(),
            client_key_fpr: self.client_key_fpr.clone(),
            host_key_fpr: self.host_key_fpr.clone(),
            keys_rotated: self.keys_rotated,
            insecure: self.insecure,
            token: self.token.clone(),
            workdir: self.workdir.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::{LogLine, NopEvents, RunRequest};
    use crate::provider::{
        CreateInstance, InstanceInfo, InstanceRef, InstanceStatus, ProviderDefaults,
    };
    use crate::ssh::fake::{FakeSessions, SharedGuest};
    use crate::target::Target;
    use async_trait::async_trait;
    use std::sync::Mutex;

    struct MemProvider {
        guest: SharedGuest,
        creates: Mutex<u32>,
    }

    #[async_trait]
    impl ComputeProvider for MemProvider {
        fn id(&self) -> &'static str {
            "digitalocean"
        }
        fn defaults(&self) -> ProviderDefaults {
            ProviderDefaults {
                region: "ams3".into(),
                size: "s-1vcpu-1gb".into(),
                username: "ubuntu".into(),
            }
        }
        fn default_image(&self, os: &str, arch: &str) -> Result<String> {
            DigitalOceanImage::image(os, arch)
        }
        fn ensure_supported(&self, os: &str, arch: &str) -> Result<()> {
            if arch == "amd64" && (os == "ubuntu" || os == "debian") {
                Ok(())
            } else {
                Err(Error::UnsupportedPlatform {
                    provider: "digitalocean".into(),
                    arch: arch.into(),
                    os: os.into(),
                })
            }
        }
        fn guest_ttl_config(&self, instance_id: &str, deadline_rfc3339: &str) -> Result<Vec<u8>> {
            Ok(serde_json::json!({
                "provider": "digitalocean",
                "instance_id": instance_id,
                "deadline": deadline_rfc3339,
                "api": "https://api.digitalocean.com",
                "token": "token",
            })
            .to_string()
            .into_bytes())
        }
        async fn create_instance(&self, req: CreateInstance) -> Result<InstanceRef> {
            self.guest.set_user_data(req.user_data);
            *self.creates.lock().unwrap() += 1;
            Ok(InstanceRef { id: "100".into() })
        }
        async fn wait_instance_ready(&self, id: &str, _: Duration) -> Result<InstanceInfo> {
            self.get_instance(id).await
        }
        async fn destroy_instance(&self, _: &str) -> Result<()> {
            self.guest.mark_destroyed();
            Ok(())
        }
        async fn get_instance(&self, id: &str) -> Result<InstanceInfo> {
            Ok(InstanceInfo {
                id: id.to_string(),
                provider: "digitalocean".into(),
                status: if self.guest.destroyed() {
                    InstanceStatus::Missing
                } else {
                    InstanceStatus::Active
                },
                public_ipv4: Some("203.0.113.10".into()),
            })
        }
    }

    struct DigitalOceanImage;
    impl DigitalOceanImage {
        fn image(os: &str, arch: &str) -> Result<String> {
            match (os, arch) {
                ("ubuntu", "amd64") => Ok("ubuntu-24-04-x64".into()),
                ("debian", "amd64") => Ok("debian-12-x64".into()),
                _ => Err(Error::msg("unsupported image")),
            }
        }
    }

    struct Collect {
        lines: Mutex<Vec<LogLine>>,
    }
    impl Events for Collect {
        fn on_log_line(&self, line: &LogLine) {
            self.lines.lock().unwrap().push(line.clone());
        }
    }

    #[tokio::test]
    async fn run_uploads_rotates_and_destroys() {
        let root = std::env::temp_dir().join(format!("bb-run-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(root.join("src/hello.txt"), b"hello").unwrap();
        let state = root.join("state");
        let work = root.join("work");
        std::fs::create_dir_all(&work).unwrap();
        let baker = Baker::with_agent_for_test(state, b"embedded-agent");
        let guest = SharedGuest::new();
        let provider = Box::new(MemProvider {
            guest: guest.clone(),
            creates: Mutex::new(0),
        });
        let sessions = Arc::new(FakeSessions::new(guest.clone()));
        let mut req = RunRequest::new(
            Target::parse("linux-amd64-ubuntu-digitalocean").unwrap(),
            root.join("src"),
            "token",
        );
        req.remote_command = Some("echo hello".into());
        req.destroy = true;
        req.workdir = work.clone();
        let events = Collect {
            lines: Mutex::new(Vec::new()),
        };
        let report = baker
            .run_with(req, &events, provider, sessions, ConnectPolicy {
                budget: Duration::from_secs(5),
                initial: Duration::from_millis(1),
                max_interval: Duration::from_millis(1),
            })
            .await
            .unwrap();
        assert_eq!(report.remote_exit, Some(0));
        assert!(report.destroyed);
        assert!(report.rotation.is_some());
        assert!(report.transfer.files >= 1);
        assert!(events.lines.lock().unwrap().iter().any(|line| line.text == "hello"));
        assert!(work
            .join("linux-amd64-ubuntu-digitalocean/ssh-config")
            .is_file());
        assert!(guest.destroyed());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn cancelled_request_fails_before_create() {
        let root = std::env::temp_dir().join(format!("bb-cancel-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("src")).unwrap();
        let baker = Baker::with_agent_for_test(root.join("state"), b"agent");
        let guest = SharedGuest::new();
        let provider = Box::new(MemProvider {
            guest: guest.clone(),
            creates: Mutex::new(0),
        });
        let sessions = Arc::new(FakeSessions::new(guest));
        let mut req = RunRequest::new(
            Target::parse("linux-amd64-ubuntu-digitalocean").unwrap(),
            root.join("src"),
            "token",
        );
        req.cancel.cancel();
        req.workdir = root.clone();
        let err = baker
            .run_with(
                req,
                &NopEvents,
                provider,
                sessions,
                ConnectPolicy::default(),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Cancelled));
        let _ = std::fs::remove_dir_all(&root);
    }
}
