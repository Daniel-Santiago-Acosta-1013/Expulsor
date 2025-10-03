//! Descubrimiento de interfaces y parámetros IP de la máquina local.

use anyhow::Result;
use default_net::{self, Interface};
use std::net::IpAddr;

/// Información básica de la interfaz de red activa.
#[derive(Debug, Clone)]
pub struct InterfaceInfo {
    pub ip: IpAddr,
    pub netmask: Option<IpAddr>,
}

/// Obtiene la interfaz predeterminada empleada para la salida a Internet.
pub fn default_interface() -> Result<Option<InterfaceInfo>> {
    match default_net::get_default_interface() {
        Ok(interface) => Ok(convert_interface(&interface)?),
        Err(_) => Ok(None),
    }
}

fn convert_interface(interface: &Interface) -> Result<Option<InterfaceInfo>> {
    let ipv4 = interface
        .ipv4
        .first()
        .map(|net| (IpAddr::V4(net.addr), IpAddr::V4(net.netmask())));

    let info = if let Some((ip, netmask)) = ipv4 {
        InterfaceInfo {
            ip,
            netmask: Some(netmask),
        }
    } else if let Some(ipv6) = interface.ipv6.first() {
        InterfaceInfo {
            ip: IpAddr::V6(ipv6.addr),
            netmask: None,
        }
    } else {
        return Ok(None);
    };

    Ok(Some(info))
}
