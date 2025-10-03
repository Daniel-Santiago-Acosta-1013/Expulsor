//! Tipos de datos que representan dispositivos de red y sus atributos.

use chrono::{DateTime, Utc};
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// Identidad mínima que permite referenciar a un dispositivo.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DeviceIdentity {
    /// Dirección IP asociada al dispositivo.
    pub ip: IpAddr,
    /// Dirección MAC en formato hexadecimal si se conoce.
    pub mac: Option<String>,
}

impl DeviceIdentity {
    /// Construye una representación a partir de cadenas de texto.
    pub fn from_strings(ip: &str, mac: Option<&str>) -> Option<Self> {
        let ip: IpAddr = ip.parse().ok()?;
        let mac = mac.map(|value| value.to_owned());
        Some(Self { ip, mac })
    }
}

/// Estado operativo del dispositivo dentro de la red monitorizada.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeviceStatus {
    /// El dispositivo respondió recientemente y se encuentra activo.
    Active,
    /// El dispositivo lleva más de un umbral sin actividad observable.
    Inactive,
    /// Hubo un problema al intentar obtener información reciente.
    Error,
}

impl Default for DeviceStatus {
    fn default() -> Self {
        Self::Active
    }
}

/// Detalle específico de un servicio identificado en un puerto determinado.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceDetail {
    pub name: Option<String>,
    pub product: Option<String>,
    pub version: Option<String>,
    pub extrainfo: Option<String>,
    pub scripts: Vec<String>,
}

impl ServiceDetail {
    /// Crea una instancia sin datos detallados.
    pub fn empty() -> Self {
        Self {
            name: None,
            product: None,
            version: None,
            extrainfo: None,
            scripts: Vec::new(),
        }
    }
}

/// Registro completo empleado por la interfaz de usuario.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceRecord {
    pub identity: DeviceIdentity,
    pub hostname: Option<String>,
    pub vendor: Option<String>,
    pub vendor_details: Option<String>,
    pub device_type: Option<String>,
    pub model: Option<String>,
    pub operating_system: Option<String>,
    pub open_ports: Vec<u16>,
    pub service_details: IndexMap<u16, ServiceDetail>,
    pub http_signature: Option<String>,
    pub last_seen: DateTime<Utc>,
    pub status: DeviceStatus,
    pub blocked: bool,
    pub detailed_scan_time: Option<DateTime<Utc>>,
}

impl DeviceRecord {
    /// Construye un registro a partir de la identidad básica.
    pub fn new(identity: DeviceIdentity) -> Self {
        Self {
            identity,
            hostname: None,
            vendor: None,
            vendor_details: None,
            device_type: None,
            model: None,
            operating_system: None,
            open_ports: Vec::new(),
            service_details: IndexMap::new(),
            http_signature: None,
            last_seen: Utc::now(),
            status: DeviceStatus::Active,
            blocked: false,
            detailed_scan_time: None,
        }
    }

    /// Actualiza el timestamp de última observación.
    pub fn touch(&mut self) {
        self.last_seen = Utc::now();
        self.status = DeviceStatus::Active;
    }
}
