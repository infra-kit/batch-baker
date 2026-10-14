//! DigitalOcean droplet backend.
//!
//! Auth is `ctx.token` or the token passed to [`DigitalOceanProvider::new`].
//! The account SSH-key API is not used; cloud-init installs the client key.

use std::time::{Duration, Instant};

use async_trait::async_trait;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;

use super::{
    ComputeProvider, CreateInstance, InstanceInfo, InstanceRef, InstanceStatus, ProviderDefaults,
};
use crate::error::{Error, Result};

pub struct DigitalOceanProvider {
    http: reqwest::Client,
    base: String,
    token: String,
    cancel: CancellationToken,
}

impl DigitalOceanProvider {
    pub fn new(base: String, token: String, cancel: CancellationToken) -> Result<Self> {
        if token.is_empty() {
            return Err(Error::msg(
                "DigitalOcean token is empty. Set DIGITALOCEAN_TOKEN or pass a token on the request.",
            ));
        }
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("batch-baker")
            .build()
            .map_err(|err| Error::msg(format!("http client: {err}")))?;
        Ok(Self {
            http,
            base: base.trim_end_matches('/').to_string(),
            token,
            cancel,
        })
    }
}

#[async_trait]
impl ComputeProvider for DigitalOceanProvider {
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

    fn default_image(&self, os: &str, _arch: &str) -> Result<String> {
        match os {
            "ubuntu" => Ok("ubuntu-24-04-x64".into()),
            "debian" => Ok("debian-12-x64".into()),
            other => Err(Error::UnsupportedPlatform {
                provider: "digitalocean".into(),
                arch: _arch.into(),
                os: other.into(),
            }),
        }
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
        let body = serde_json::json!({
            "provider": "digitalocean",
            "instance_id": instance_id,
            "deadline": deadline_rfc3339,
            "api": self.base,
            "token": self.token,
        });
        serde_json::to_vec_pretty(&body).map_err(|err| Error::msg(format!("ttl config: {err}")))
    }

    async fn create_instance(&self, req: CreateInstance) -> Result<InstanceRef> {
        self.check_cancel()?;
        #[derive(Serialize)]
        struct Body<'a> {
            name: &'a str,
            region: &'a str,
            size: &'a str,
            image: &'a str,
            user_data: &'a str,
            tags: &'a [String],
        }
        let response = self
            .http
            .post(format!("{}/v2/droplets", self.base))
            .header(AUTHORIZATION, format!("Bearer {}", self.token))
            .header(CONTENT_TYPE, "application/json")
            .json(&Body {
                name: &req.name,
                region: &req.region,
                size: &req.size,
                image: &req.image,
                user_data: &req.user_data,
                tags: &req.tags,
            })
            .send()
            .await
            .map_err(|err| Error::msg(format!("create droplet: {err}")))?;
        let status = response.status();
        let text = response.text().await.unwrap_or_default();
        if !status.is_success() {
            return Err(Error::msg(format!(
                "create droplet failed: HTTP {status}: {}",
                trim(&text)
            )));
        }
        let parsed: DropletResponse = serde_json::from_str(&text)
            .map_err(|err| Error::msg(format!("create droplet response: {err}: {}", trim(&text))))?;
        Ok(InstanceRef {
            id: parsed.droplet.id.to_string(),
        })
    }

    async fn wait_instance_ready(&self, id: &str, timeout: Duration) -> Result<InstanceInfo> {
        let deadline = Instant::now() + timeout;
        loop {
            self.check_cancel()?;
            let info = self.get_instance(id).await?;
            if info.status == InstanceStatus::Active && info.public_ipv4.is_some() {
                return Ok(info);
            }
            if Instant::now() >= deadline {
                return Err(Error::msg(format!(
                    "timed out waiting for droplet {id} to become active"
                )));
            }
            tokio::select! {
                _ = self.cancel.cancelled() => return Err(Error::Cancelled),
                _ = tokio::time::sleep(Duration::from_secs(2)) => {}
            }
        }
    }

    async fn destroy_instance(&self, id: &str) -> Result<()> {
        self.check_cancel()?;
        let response = self
            .http
            .delete(format!("{}/v2/droplets/{id}", self.base))
            .header(AUTHORIZATION, format!("Bearer {}", self.token))
            .send()
            .await
            .map_err(|err| Error::msg(format!("destroy droplet: {err}")))?;
        if response.status() == StatusCode::NOT_FOUND || response.status().is_success() {
            return Ok(());
        }
        let status = response.status();
        let text = response.text().await.unwrap_or_default();
        Err(Error::msg(format!(
            "destroy droplet failed: HTTP {status}: {}",
            trim(&text)
        )))
    }

    async fn get_instance(&self, id: &str) -> Result<InstanceInfo> {
        self.check_cancel()?;
        let response = self
            .http
            .get(format!("{}/v2/droplets/{id}", self.base))
            .header(AUTHORIZATION, format!("Bearer {}", self.token))
            .send()
            .await
            .map_err(|err| Error::msg(format!("get droplet: {err}")))?;
        if response.status() == StatusCode::NOT_FOUND {
            return Ok(InstanceInfo {
                id: id.to_string(),
                provider: "digitalocean".into(),
                status: InstanceStatus::Missing,
                public_ipv4: None,
            });
        }
        let status = response.status();
        let text = response.text().await.unwrap_or_default();
        if !status.is_success() {
            return Err(Error::msg(format!(
                "get droplet failed: HTTP {status}: {}",
                trim(&text)
            )));
        }
        let parsed: DropletResponse = serde_json::from_str(&text)
            .map_err(|err| Error::msg(format!("get droplet response: {err}: {}", trim(&text))))?;
        Ok(info_from_droplet(parsed.droplet))
    }
}

impl DigitalOceanProvider {
    fn check_cancel(&self) -> Result<()> {
        if self.cancel.is_cancelled() {
            Err(Error::Cancelled)
        } else {
            Ok(())
        }
    }
}

fn info_from_droplet(droplet: Droplet) -> InstanceInfo {
    let status = match droplet.status.as_str() {
        "active" => InstanceStatus::Active,
        "archive" | "off" => InstanceStatus::Destroyed,
        _ => InstanceStatus::Pending,
    };
    let public_ipv4 = droplet.networks.v4.into_iter().find_map(|net| {
        (net.kind == "public").then_some(net.ip_address)
    });
    InstanceInfo {
        id: droplet.id.to_string(),
        provider: "digitalocean".into(),
        status,
        public_ipv4,
    }
}

fn trim(body: &str) -> String {
    let mut text = body.trim().to_string();
    if text.len() > 2048 {
        text.truncate(2048);
    }
    text
}

#[derive(Debug, Deserialize)]
struct DropletResponse {
    droplet: Droplet,
}

#[derive(Debug, Deserialize)]
struct Droplet {
    id: u64,
    status: String,
    #[serde(default)]
    networks: Networks,
}

#[derive(Debug, Default, Deserialize)]
struct Networks {
    #[serde(default)]
    v4: Vec<NetV4>,
}

#[derive(Debug, Deserialize)]
struct NetV4 {
    ip_address: String,
    #[serde(rename = "type")]
    kind: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn droplet_json(status: &str, ip: Option<&str>) -> serde_json::Value {
        let v4 = match ip {
            Some(ip) => serde_json::json!([{ "ip_address": ip, "type": "public" }]),
            None => serde_json::json!([]),
        };
        serde_json::json!({
            "droplet": {
                "id": 42,
                "status": status,
                "networks": { "v4": v4 }
            }
        })
    }

    #[tokio::test]
    async fn create_poll_and_destroy() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v2/droplets"))
            .respond_with(ResponseTemplate::new(202).set_body_json(droplet_json("new", None)))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/v2/droplets/42"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(droplet_json("active", Some("203.0.113.10"))),
            )
            .mount(&server)
            .await;
        Mock::given(method("DELETE"))
            .and(path("/v2/droplets/42"))
            .respond_with(ResponseTemplate::new(204))
            .mount(&server)
            .await;

        let provider = DigitalOceanProvider::new(
            server.uri(),
            "token".into(),
            CancellationToken::new(),
        )
        .unwrap();
        let created = provider
            .create_instance(CreateInstance {
                name: "batch".into(),
                region: "ams3".into(),
                size: "s-1vcpu-1gb".into(),
                image: "ubuntu-24-04-x64".into(),
                user_data: "#cloud-config\nssh_authorized_keys:\n  - ssh-ed25519 AAAA batch-baker\n".into(),
                tags: vec!["batch-baker".into()],
            })
            .await
            .unwrap();
        assert_eq!(created.id, "42");
        let ready = provider
            .wait_instance_ready("42", Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(ready.public_ipv4.as_deref(), Some("203.0.113.10"));
        provider.destroy_instance("42").await.unwrap();
    }
}
