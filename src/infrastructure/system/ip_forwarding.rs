//! Habilita o deshabilita el reenvío de paquetes IP cuando es necesario.

#[cfg(not(test))]
use anyhow::Context;
use anyhow::Result;
#[cfg(all(not(test), target_os = "macos"))]
use std::process::Stdio;
#[cfg(not(test))]
use tokio::process::Command;
#[cfg(all(not(test), target_os = "linux"))]
use tokio::task;

#[cfg(not(test))]
/// Desactiva el reenvío IP en la plataforma actual devolviendo el estado anterior.
pub async fn disable() -> Result<Option<String>> {
    #[cfg(target_os = "linux")]
    {
        let previous = read_linux_forward().await?;
        if previous.trim() != "0" {
            write_linux_forward("0").await?;
        }
        Ok(Some(previous))
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
            .args(["-w", "net.inet.ip.forwarding=0"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await
            .context("No se pudo deshabilitar ip forwarding")?;
        Ok(Some(previous))
    }

    #[cfg(target_os = "windows")]
    {
        // Windows gestiona el reenvío desde el registro. No se aplica en esta versión.
        Ok(None)
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        Ok(None)
    }
}

#[cfg(not(test))]
/// Restaura el estado de reenvío IP previo.
pub async fn restore(previous: Option<String>) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        if let Some(state) = previous {
            write_linux_forward(state.trim()).await?;
        }
        Ok(())
    }

    #[cfg(target_os = "macos")]
    {
        if let Some(state) = previous {
            Command::new("sysctl")
                .args(["-w", &format!("net.inet.ip.forwarding={}", state.trim())])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .await
                .context("No se pudo restaurar ip forwarding")?;
        }
        Ok(())
    }

    #[cfg(target_os = "windows")]
    {
        let _ = previous;
        Ok(())
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

#[cfg(test)]
use once_cell::sync::Lazy;
#[cfg(test)]
use std::sync::Mutex;

#[cfg(test)]
static FORWARDING_STATE: Lazy<Mutex<bool>> = Lazy::new(|| Mutex::new(false));

#[cfg(test)]
pub async fn restore(previous: Option<String>) -> Result<()> {
    let mut guard = FORWARDING_STATE.lock().unwrap();
    *guard = previous.as_deref() == Some("1");
    Ok(())
}

#[cfg(test)]
pub async fn disable() -> Result<Option<String>> {
    let mut guard = FORWARDING_STATE.lock().unwrap();
    let previous = if *guard {
        Some("1".to_string())
    } else {
        Some("0".to_string())
    };
    *guard = false;
    Ok(previous)
}
