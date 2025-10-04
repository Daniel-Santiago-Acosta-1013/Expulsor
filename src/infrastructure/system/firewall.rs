//! Configuración de reglas de firewall específicas por plataforma.

use anyhow::{anyhow, Context, Result};
use futures::future::BoxFuture;
#[cfg(target_os = "macos")]
use std::process::Stdio;
use tokio::process::Command;

/// Controlador abstracto de firewall para permitir pruebas y distintas plataformas.
pub trait FirewallDriver: Send + Sync {
    fn ensure_ready(&self) -> BoxFuture<'_, Result<()>>;
    fn block(&self, ip: &str) -> BoxFuture<'_, Result<()>>;
    fn unblock(&self, ip: &str) -> BoxFuture<'_, Result<()>>;
}

/// Implementación basada en las utilidades del sistema.
#[derive(Clone, Debug, Default)]
pub struct SystemFirewall;

impl FirewallDriver for SystemFirewall {
    fn ensure_ready(&self) -> BoxFuture<'_, Result<()>> {
        Box::pin(async { ensure_ready().await })
    }

    fn block(&self, ip: &str) -> BoxFuture<'_, Result<()>> {
        let ip = ip.to_string();
        Box::pin(async move { add_rule(&ip).await })
    }

    fn unblock(&self, ip: &str) -> BoxFuture<'_, Result<()>> {
        let ip = ip.to_string();
        Box::pin(async move { remove_rule(&ip).await })
    }
}

/// Agrega reglas para bloquear un dispositivo por su dirección IP.
pub async fn add_rule(ip: &str) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        if !check_rule_linux(ip).await? {
            Command::new("iptables")
                .args(["-A", "FORWARD", "-s", ip, "-j", "DROP"])
                .status()
                .await
                .context("Error al ejecutar iptables -A")?;
        }
        return Ok(());
    }

    #[cfg(target_os = "macos")]
    {
        add_rule_macos(ip).await
    }

    #[cfg(target_os = "windows")]
    {
        Command::new("netsh")
            .args([
                "advfirewall",
                "firewall",
                "add",
                "rule",
                &format!("name=ExpulsorBlock{}", ip.replace('.', "_")),
                "dir=out",
                "action=block",
                &format!("remoteip={}", ip),
            ])
            .status()
            .await
            .context("Error al ejecutar netsh")?;
        return Ok(());
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        let _ = ip;
        Ok(())
    }
}

/// Elimina las reglas relacionadas con el dispositivo indicado.
pub async fn remove_rule(ip: &str) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        while check_rule_linux(ip).await? {
            Command::new("iptables")
                .args(["-D", "FORWARD", "-s", ip, "-j", "DROP"])
                .status()
                .await
                .context("Error al ejecutar iptables -D")?;
        }
        return Ok(());
    }

    #[cfg(target_os = "macos")]
    {
        remove_rule_macos(ip).await
    }

    #[cfg(target_os = "windows")]
    {
        Command::new("netsh")
            .args([
                "advfirewall",
                "firewall",
                "delete",
                "rule",
                &format!("name=ExpulsorBlock{}", ip.replace('.', "_")),
            ])
            .status()
            .await
            .context("Error al ejecutar netsh delete")?;
        return Ok(());
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        let _ = ip;
        Ok(())
    }
}

#[cfg(target_os = "linux")]
async fn check_rule_linux(ip: &str) -> Result<bool> {
    let status = Command::new("iptables")
        .args(["-C", "FORWARD", "-s", ip, "-j", "DROP"])
        .status()
        .await
        .context("Error al comprobar reglas iptables")?;
    Ok(status.success())
}

async fn ensure_ready() -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        ensure_ready_macos().await?;
    }
    #[cfg(target_os = "linux")]
    {
        // Linux no requiere preparación especial si iptables está disponible.
    }
    #[cfg(target_os = "windows")]
    {
        // Netsh no necesita configuración previa.
    }
    Ok(())
}

#[cfg(target_os = "macos")]
async fn ensure_ready_macos() -> Result<()> {
    use tokio::io::AsyncWriteExt;

    // Activar pf si está deshabilitado.
    let status = Command::new("pfctl")
        .args(["-s", "info"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
        .context("No se pudo consultar el estado de pfctl")?;
    if !status.success() {
        return Err(anyhow!("pfctl no está disponible"));
    }

    let enabled = Command::new("pfctl")
        .args(["-s", "info"])
        .stderr(Stdio::null())
        .output()
        .await
        .context("No se pudo obtener información de pfctl")?;
    let info = String::from_utf8_lossy(&enabled.stdout);
    if !info.contains("Status: Enabled") {
        Command::new("pfctl")
            .arg("-E")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await
            .context("No se pudo habilitar pf")?;
    }

    // Cargar ancla y tabla en com.apple/expulsor para aprovechar el include por defecto.
    let rules = b"table <expulsor_blocklist> persist\nblock drop quick from <expulsor_blocklist> to any\nblock drop quick from any to <expulsor_blocklist>\n";
    let mut child = Command::new("pfctl")
        .args(["-q", "-a", "com.apple/expulsor", "-f", "-"])
        .stdin(std::process::Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("No se pudo preparar el anchor expulsor")?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(rules)
            .await
            .context("No se pudo cargar las reglas base")?;
    }
    child
        .wait()
        .await
        .context("pfctl no pudo cargar las reglas base")?;

    Ok(())
}

#[cfg(target_os = "macos")]
async fn add_rule_macos(ip: &str) -> Result<()> {
    ensure_ready_macos().await?;

    let status = Command::new("pfctl")
        .args(["-q", "-t", "expulsor_blocklist", "-T", "add", ip])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
        .context("No se pudo actualizar la tabla expulsor_blocklist")?;
    if !status.success() {
        return Err(anyhow!("pfctl devolvió error al agregar {}", ip));
    }

    // Limpia estados existentes para la IP restringida.
    Command::new("pfctl")
        .args(["-k", ip])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
        .ok();
    Ok(())
}

#[cfg(target_os = "macos")]
async fn remove_rule_macos(ip: &str) -> Result<()> {
    ensure_ready_macos().await?;

    let status = Command::new("pfctl")
        .args(["-q", "-t", "expulsor_blocklist", "-T", "delete", ip])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
        .context("No se pudo eliminar la IP de expulsor_blocklist")?;
    if !status.success() {
        return Err(anyhow!("pfctl devolvió error al eliminar {}", ip));
    }
    Ok(())
}
