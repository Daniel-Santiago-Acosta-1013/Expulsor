//! Integración con la herramienta externa Nmap para escaneo de puertos y servicios.

use anyhow::{Context, Result};
use quick_xml::de::from_reader;
use serde::Deserialize;
use std::process::Stdio;
use tokio::process::Command;

/// Representa la información relevante extraída de la salida XML de Nmap.
#[derive(Debug, Clone)]
pub struct HostResult {
    pub ip: Option<String>,
    pub mac: Option<String>,
    pub vendor: Option<String>,
    pub hostname: Option<String>,
    pub ports: Vec<PortResult>,
    pub os_match: Option<String>,
}

/// Resultado de un puerto individual encontrado por Nmap.
#[derive(Debug, Clone)]
pub struct PortResult {
    pub port: u16,
    pub service_name: Option<String>,
    pub product: Option<String>,
    pub version: Option<String>,
    pub extrainfo: Option<String>,
}

/// Ejecuta Nmap con los argumentos especificados y devuelve los hosts detectados.
pub async fn run_scan(target: &str, arguments: &[&str]) -> Result<Vec<HostResult>> {
    let mut command = Command::new("nmap");
    command.arg("-oX").arg("-");
    command.args(arguments);
    command.arg(target);
    command.stdout(Stdio::piped());
    command.stderr(Stdio::piped());

    let output = command.output().await.context("Error al ejecutar nmap")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("nmap retornó un estado no exitoso: {}", stderr.trim());
    }

    let scan: NmapRun =
        from_reader(&output.stdout[..]).context("No se pudo parsear la salida XML de nmap")?;

    let hosts = scan
        .hosts
        .into_iter()
        .map(|host| HostResult {
            ip: host.primary_ipv4(),
            mac: host.mac_address(),
            vendor: host.mac_vendor(),
            hostname: host.hostname(),
            ports: host
                .ports
                .unwrap_or_default()
                .ports
                .into_iter()
                .filter(|port| port.state.as_ref().map(|s| s.state.as_str()) == Some("open"))
                .map(|port| PortResult {
                    port: port.portid,
                    service_name: port.service.as_ref().and_then(|s| s.name.clone()),
                    product: port.service.as_ref().and_then(|s| s.product.clone()),
                    version: port.service.as_ref().and_then(|s| s.version.clone()),
                    extrainfo: port.service.as_ref().and_then(|s| s.extrainfo.clone()),
                })
                .collect(),
            os_match: host.os.and_then(|os| os.best_match()),
        })
        .collect();

    Ok(hosts)
}

#[derive(Debug, Deserialize)]
struct NmapRun {
    #[serde(default, rename = "host")]
    hosts: Vec<Host>,
}

#[derive(Debug, Deserialize)]
struct Host {
    #[serde(default, rename = "address")]
    addresses: Vec<Address>,
    #[serde(default, rename = "hostnames")]
    hostnames: Vec<Hostnames>,
    #[serde(default, rename = "ports")]
    ports: Option<Ports>,
    #[serde(default, rename = "os")]
    os: Option<Os>,
}

impl Host {
    fn primary_ipv4(&self) -> Option<String> {
        self.addresses
            .iter()
            .find(|addr| addr.addrtype == "ipv4")
            .map(|addr| addr.addr.clone())
    }

    fn mac_address(&self) -> Option<String> {
        self.addresses
            .iter()
            .find(|addr| addr.addrtype == "mac")
            .map(|addr| addr.addr.clone())
    }

    fn mac_vendor(&self) -> Option<String> {
        self.addresses
            .iter()
            .find(|addr| addr.addrtype == "mac")
            .and_then(|addr| addr.vendor.clone())
    }

    fn hostname(&self) -> Option<String> {
        self.hostnames
            .iter()
            .flat_map(|h| h.hostname.iter())
            .find(|hn| hn.typ.as_deref() != Some("PTR"))
            .and_then(|hn| hn.name.clone())
    }
}

#[derive(Debug, Deserialize)]
struct Address {
    #[serde(rename = "@addr")]
    addr: String,
    #[serde(rename = "@addrtype")]
    addrtype: String,
    #[serde(rename = "@vendor")]
    vendor: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Hostnames {
    #[serde(default, rename = "hostname")]
    hostname: Vec<Hostname>,
}

#[derive(Debug, Deserialize)]
struct Hostname {
    #[serde(rename = "@name")]
    name: Option<String>,
    #[serde(rename = "@type")]
    typ: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
struct Ports {
    #[serde(default, rename = "port")]
    ports: Vec<Port>,
}

#[derive(Debug, Deserialize)]
struct Port {
    #[serde(rename = "@portid")]
    portid: u16,
    #[serde(default, rename = "state")]
    state: Option<PortState>,
    #[serde(default, rename = "service")]
    service: Option<Service>,
}

#[derive(Debug, Deserialize)]
struct PortState {
    #[serde(rename = "@state")]
    state: String,
}

#[derive(Debug, Deserialize, Clone)]
struct Service {
    #[serde(rename = "@name")]
    name: Option<String>,
    #[serde(rename = "@product")]
    product: Option<String>,
    #[serde(rename = "@version")]
    version: Option<String>,
    #[serde(rename = "@extrainfo")]
    extrainfo: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Os {
    #[serde(default, rename = "osmatch")]
    matches: Vec<OsMatch>,
}

impl Os {
    fn best_match(&self) -> Option<String> {
        self.matches
            .iter()
            .max_by_key(|m| m.accuracy.parse::<u8>().unwrap_or(0))
            .map(|m| m.name.clone())
    }
}

#[derive(Debug, Deserialize)]
struct OsMatch {
    #[serde(rename = "@name")]
    name: String,
    #[serde(rename = "@accuracy")]
    accuracy: String,
}
