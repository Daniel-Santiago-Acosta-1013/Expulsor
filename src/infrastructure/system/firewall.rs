//! Configuración de reglas de firewall específicas por plataforma.

use anyhow::{Context, Result};
use tokio::process::Command;

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
        use tokio::io::AsyncWriteExt;
        let rule = format!("block drop from {} to any", ip);
        let mut child = Command::new("pfctl")
            .args(["-a", "com.expulsor", "-f", "-"])
            .stdin(std::process::Stdio::piped())
            .spawn()
            .context("No se pudo invocar pfctl")?;
        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(
                    format!(
                        "{}
",
                        rule
                    )
                    .as_bytes(),
                )
                .await
                .context("No se pudo enviar la regla a pfctl")?;
        }
        child.wait().await.context("pfctl finalizó con error")?;
        return Ok(());
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
        use tokio::io::AsyncWriteExt;
        let _ = ip;
        let mut child = Command::new("pfctl")
            .args(["-a", "com.expulsor", "-f", "-"])
            .stdin(std::process::Stdio::piped())
            .spawn()
            .context("No se pudo reiniciar pfctl")?;
        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(
                    b"
",
                )
                .await
                .ok();
        }
        child.wait().await.ok();
        return Ok(());
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
