//! Fingerprinting avanzado de dispositivos aprovechando múltiples heurísticas.

use crate::domain::device::{DeviceIdentity, DeviceRecord, ServiceDetail};
use crate::infrastructure::network::nmap::{run_scan, HostResult};
use crate::infrastructure::network::signature::SignatureMatcher;
use crate::infrastructure::persistence::device_db::DeviceDatabase;
use anyhow::Result;
use chrono::Utc;
use dns_lookup::lookup_addr;
use regex::Regex;
use reqwest::Client;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::task;
use tokio::time::{timeout, Duration};

/// Servicio responsable de enriquecer los registros de dispositivos.
#[derive(Clone)]
pub struct Fingerprinter {
    db: Arc<DeviceDatabase>,
    matcher: SignatureMatcher,
    client: Client,
    http_title_regex: Regex,
    http_timeout: Duration,
}

impl Fingerprinter {
    /// Construye el servicio inicializando recursos compartidos.
    pub fn new(db: Arc<DeviceDatabase>) -> Result<Self> {
        let matcher = SignatureMatcher::new()?;
        let client = Client::builder()
            .danger_accept_invalid_certs(true)
            .timeout(Duration::from_secs(5))
            .user_agent("Expulsor-RS/1.0")
            .build()?;
        let http_title_regex = Regex::new(r"<title>(?P<title>.*?)</title>").unwrap();

        Ok(Self {
            db,
            matcher,
            client,
            http_title_regex,
            http_timeout: Duration::from_secs(4),
        })
    }

    /// Obtiene información detallada de un dispositivo concreto.
    pub async fn fingerprint(&self, identity: &DeviceIdentity) -> Result<DeviceRecord> {
        let mut record = if let Some(stored) = self.db.get_known_device(&identity.ip).await? {
            stored
        } else {
            DeviceRecord::new(identity.clone())
        };
        record.touch();

        if record.identity.mac.is_none() {
            record.identity.mac = identity.mac.clone();
        }

        if let Some(mac) = record.identity.mac.clone() {
            let (vendor, details) = self.db.get_vendor_info(&mac).await;
            if vendor != "Desconocido" {
                record.vendor = Some(vendor);
            }
            if !details.is_empty() {
                record.vendor_details = Some(details);
            }
        }

        let target = identity.ip.to_string();

        let nmap_future = run_scan(
            &target,
            &[
                "-sV",
                "-O",
                "-T4",
                "--max-retries",
                "2",
                "--host-timeout",
                "60s",
            ],
        );
        let hostname_future = resolve_hostname(identity.ip);
        let http_future = self.fetch_http_signature(identity.ip);

        let (nmap_result, hostname_result, http_signature) =
            tokio::join!(nmap_future, hostname_future, http_future);

        if let Ok(Some(hostname)) = hostname_result {
            record.hostname = Some(hostname);
        }

        if let Some(signature) = http_signature {
            record.http_signature = Some(signature);
        }

        if let Ok(hosts) = nmap_result {
            if let Some(host) = hosts.into_iter().next() {
                self.apply_nmap(host, &mut record);
            }
        }

        self.matcher.apply(&mut record);
        record.last_seen = Utc::now();
        self.db.save_record(&record).await?;
        Ok(record)
    }

    fn apply_nmap(&self, host: HostResult, record: &mut DeviceRecord) {
        if let Some(ip) = host.ip {
            if record.identity.ip.to_string() != ip {
                if let Some(identity) =
                    DeviceIdentity::from_strings(&ip, record.identity.mac.as_deref())
                {
                    record.identity = identity;
                }
            }
        }

        if record.identity.mac.is_none() {
            record.identity.mac = host.mac.clone();
        }

        if record.vendor.is_none() {
            record.vendor = host.vendor.clone();
        }

        if record.hostname.is_none() {
            record.hostname = host.hostname.clone();
        }

        if let Some(os) = host.os_match {
            record.operating_system = Some(os);
        }

        if !host.ports.is_empty() {
            record.open_ports = host.ports.iter().map(|port| port.port).collect();
            record.service_details.clear();
            for port in host.ports {
                let mut detail = ServiceDetail::empty();
                detail.name = port.service_name;
                detail.product = port.product;
                detail.version = port.version;
                detail.extrainfo = port.extrainfo;
                record.service_details.insert(port.port, detail);
            }
        }
    }

    async fn fetch_http_signature(&self, ip: IpAddr) -> Option<String> {
        let host = match ip {
            IpAddr::V4(addr) => addr.to_string(),
            IpAddr::V6(addr) => format!("[{addr}]"),
        };

        let candidates = [
            format!("http://{}", host),
            format!("http://{}:8080", host),
            format!("https://{}", host),
        ];

        for url in candidates {
            let request = self.client.get(&url);
            if let Ok(Ok(resp)) = timeout(self.http_timeout, request.send()).await {
                if let Ok(text) = resp.text().await {
                    if let Some(capture) = self.http_title_regex.captures(&text) {
                        if let Some(title) = capture.name("title") {
                            return Some(format!("{} | {}", url, title.as_str().trim()));
                        }
                    }
                }
            }
        }
        None
    }
}

async fn resolve_hostname(ip: IpAddr) -> Result<Option<String>> {
    match task::spawn_blocking(move || lookup_addr(&ip)).await {
        Ok(Ok(name)) => Ok(Some(name)),
        _ => Ok(None),
    }
}
