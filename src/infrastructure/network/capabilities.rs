//! Detección heurística de las capacidades del entorno para bloquear dispositivos.

use crate::domain::capabilities::{BlockStrategy, CapabilityReport};
use anyhow::{anyhow, Context, Result};
use default_net::get_default_interface;
use default_net::interface::InterfaceType;
use pnet_datalink::{self, Channel::Ethernet, Config as DatalinkConfig};
use std::net::IpAddr;
use tokio::process::Command;

/// Ejecuta una colección de pruebas para determinar qué tan viable es bloquear
/// dispositivos desde este host.
pub async fn evaluate() -> CapabilityReport {
    let mut report = CapabilityReport::default();
    let mut diagnostics = Vec::new();

    match get_default_interface() {
        Ok(interface) => {
            report.interface_name = interface.name.clone();
            report.interface_kind = interface.if_type.name().to_string();
            if let Some(gateway) = interface.gateway.and_then(|g| match g.ip_addr {
                IpAddr::V4(ip) => Some(ip),
                _ => None,
            }) {
                report.gateway_ip = Some(gateway);
            }

            if interface.if_type == InterfaceType::Wireless80211 {
                diagnostics.push(
                    "Interfaz Wi-Fi detectada; algunos routers filtran ARP spoofing".to_string(),
                );
            }
        }
        Err(err) => {
            diagnostics.push(format!(
                "No se pudo determinar la interfaz predeterminada: {}",
                err
            ));
        }
    }

    report.supports_firewall = check_pf().await.unwrap_or_else(|err| {
        diagnostics.push(format!("pfctl no disponible: {}", err));
        false
    });

    report.supports_datalink = check_datalink_channel(&report.interface_name)
        .await
        .unwrap_or_else(|err| {
            diagnostics.push(format!("Enlace Ethernet sin acceso crudo: {}", err));
            false
        });

    report.recommended = recommend_strategy(&report);

    diagnostics.extend(strategy_notes(&report));
    report.diagnostics = diagnostics;

    report
}

async fn check_pf() -> Result<bool> {
    let status = Command::new("pfctl")
        .args(["-s", "info"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .await
        .context("pfctl no respondió")?;
    Ok(status.success())
}

async fn check_datalink_channel(interface_name: &str) -> Result<bool> {
    if interface_name.is_empty() {
        return Ok(false);
    }

    let interfaces = pnet_datalink::interfaces();
    let iface = interfaces
        .into_iter()
        .find(|iface| iface.name == interface_name)
        .ok_or_else(|| anyhow!("No se encontró la interfaz {}", interface_name))?;

    let result = tokio::task::spawn_blocking(move || {
        let mut config = DatalinkConfig::default();
        config.write_buffer_size = 512;
        match pnet_datalink::channel(&iface, config) {
            Ok(Ethernet(_tx, _rx)) => Ok(true),
            Ok(_) => Err(anyhow!("Tipo de canal no soportado")),
            Err(err) => Err(anyhow!(err)),
        }
    })
    .await
    .context("Error al crear canal de datos")??;

    Ok(result)
}

fn recommend_strategy(report: &CapabilityReport) -> BlockStrategy {
    let kind_lower = report.interface_kind.to_ascii_lowercase();
    let is_wifi = kind_lower.contains("802.11") || kind_lower.contains("wifi");

    match (report.supports_firewall, report.supports_datalink, is_wifi) {
        (false, false, _) => BlockStrategy::Unsupported,
        (true, false, _) => BlockStrategy::FirewallOnly,
        (true, true, true) => BlockStrategy::BalancedArp,
        (true, true, false) => BlockStrategy::AggressiveArp,
        (false, true, _) => BlockStrategy::BalancedArp,
    }
}

fn strategy_notes(report: &CapabilityReport) -> Vec<String> {
    match report.recommended {
        BlockStrategy::Unsupported => vec![
            "No se encontraron capacidades suficientes para expulsar dispositivos desde este host"
                .to_string(),
        ],
        BlockStrategy::FirewallOnly => vec![
            "Se utilizará solamente pf; el tráfico puede restablecerse si el router ignora el gateway falso"
                .to_string(),
        ],
        BlockStrategy::BalancedArp => vec![
            "ARP disponible pero con cautela: se empleará refuerzo moderado para evitar bloqueos del router"
                .to_string(),
        ],
        BlockStrategy::AggressiveArp => vec![
            "Se permitirá ARP agresivo junto con firewall"
                .to_string(),
        ],
    }
}
