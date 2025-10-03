//! Habilita o deshabilita el reenvío de paquetes IP cuando es necesario.

use anyhow::{Context, Result};
use tokio::process::Command;
#[cfg(target_os = "linux")]
use tokio::task;

/// Activa el reenvío IP en la plataforma actual devolviendo el estado anterior.
pub async fn enable() -> Result<Option<String>> {
    #[cfg(target_os = "linux")]
    {
        let previous = read_linux_forward().await?;
        if previous.trim() != "1" {
            write_linux_forward("1").await?;
        }
        return Ok(Some(previous));
    }

    #[cfg(target_os = "macos")]
    {
        let status = Command::new("sysctl")
            .args(["-n", "net.inet.ip.forwarding"])
            .output()
            .await
            .context("No se pudo leer sysctl net.inet.ip.forwarding")?;
        let previous = String::from_utf8_lossy(&status.stdout).trim().to_string();
        Command::new("sysctl")
            .args(["-w", "net.inet.ip.forwarding=1"])
            .status()
            .await
            .context("No se pudo habilitar ip forwarding")?;
        return Ok(Some(previous));
    }

    #[cfg(target_os = "windows")]
    {
        // Windows gestiona el reenvío desde el registro. No se aplica en esta versión.
        return Ok(None);
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        Ok(None)
    }
}

/// Restaura el estado de reenvío IP previo.
pub async fn restore(previous: Option<String>) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        if let Some(state) = previous {
            write_linux_forward(state.trim()).await?;
        }
        return Ok(());
    }

    #[cfg(target_os = "macos")]
    {
        if let Some(state) = previous {
            Command::new("sysctl")
                .args(["-w", &format!("net.inet.ip.forwarding={}", state.trim())])
                .status()
                .await
                .context("No se pudo restaurar ip forwarding")?;
        }
        return Ok(());
    }

    #[cfg(target_os = "windows")]
    {
        let _ = previous;
        return Ok(());
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        let _ = previous;
        Ok(())
    }
}

#[cfg(target_os = "linux")]
async fn read_linux_forward() -> Result<String> {
    let content =
        task::spawn_blocking(|| std::fs::read_to_string("/proc/sys/net/ipv4/ip_forward")).await??;
    Ok(content)
}

#[cfg(target_os = "linux")]
async fn write_linux_forward(value: &str) -> Result<()> {
    task::spawn_blocking(move || std::fs::write("/proc/sys/net/ipv4/ip_forward", value.as_bytes()))
        .await??;
    Ok(())
}
