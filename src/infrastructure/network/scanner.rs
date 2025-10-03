//! Combina técnicas de ARP y Nmap para detectar dispositivos en la red local.

use crate::domain::device::{DeviceIdentity, DeviceRecord, DeviceStatus};
use crate::infrastructure::network::fingerprint::Fingerprinter;
use crate::infrastructure::network::interfaces::{default_interface, InterfaceInfo};
use crate::infrastructure::persistence::device_db::DeviceDatabase;
use anyhow::Result;
use futures::stream::{FuturesUnordered, StreamExt};
use ipnetwork::Ipv4Network;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

/// Resultado de escaneo agrupado por IP.
pub type ScanMap = HashMap<String, DeviceRecord>;

/// Escáner principal utilizado para descubrir dispositivos de red.
pub struct NetworkScanner {
    interface: Option<InterfaceInfo>,
    db: Arc<DeviceDatabase>,
    fingerprinter: Fingerprinter,
}

impl NetworkScanner {
    /// Construye un escáner listo para iniciar operaciones.
    pub fn new(db: Arc<DeviceDatabase>, fingerprinter: Fingerprinter) -> Result<Self> {
        let interface = default_interface().unwrap_or(None);
        Ok(Self {
            interface,
            db,
            fingerprinter,
        })
    }

    /// Realiza un recorrido rápido de la red empleando Nmap en modo ping.
    pub async fn quick_scan(&self) -> Result<ScanMap> {
        let network = self
            .network_cidr()
            .unwrap_or_else(|| "192.168.1.0/24".to_string());

        let hosts =
            crate::infrastructure::network::nmap::run_scan(&network, &["-sn", "-PR", "-T4"])
                .await?;
        let mut map = HashMap::new();

        for host in hosts {
            let ip_str = match host.ip.clone() {
                Some(value) => value,
                None => continue,
            };

            let Some(identity) = DeviceIdentity::from_strings(&ip_str, host.mac.as_deref()) else {
                continue;
            };

            let mut record = if let Some(stored) = self.db.get_known_device(&identity.ip).await? {
                stored
            } else {
                DeviceRecord::new(identity.clone())
            };

            record.identity = identity;
            record.touch();

            if record.vendor.is_none() {
                record.vendor = host.vendor.clone();
            }

            if record.hostname.is_none() {
                record.hostname = host.hostname.clone();
            }

            map.insert(ip_str, record);
        }

        Ok(map)
    }

    /// Ejecuta un escaneo profundo, incluyendo fingerprinting detallado.
    pub async fn deep_scan(&self) -> Result<ScanMap> {
        let quick = self.quick_scan().await?;
        let mut tasks = FuturesUnordered::new();

        for (ip, device) in quick.into_iter() {
            let fp = self.fingerprinter.clone();
            tasks.push(async move {
                match fp.fingerprint(&device.identity).await {
                    Ok(mut detailed) => {
                        detailed.touch();
                        Ok((ip, detailed))
                    }
                    Err(error) => {
                        tracing::warn!(
                            ?error,
                            "Error realizando fingerprint de {}",
                            device.identity.ip
                        );
                        let mut fallback = device;
                        fallback.status = DeviceStatus::Error;
                        Err((ip, fallback))
                    }
                }
            });
        }

        let mut result = HashMap::new();
        while let Some(entry) = tasks.next().await {
            match entry {
                Ok((ip, record)) => {
                    result.insert(ip, record);
                }
                Err((ip, fallback)) => {
                    result.insert(ip, fallback);
                }
            }
        }

        Ok(result)
    }

    /// Ejecuta un escaneo individual detallado.
    pub async fn scan_device(&self, identity: &DeviceIdentity) -> Result<DeviceRecord> {
        let record = self.fingerprinter.fingerprint(identity).await?;
        Ok(record)
    }

    fn network_cidr(&self) -> Option<String> {
        let info = self.interface.as_ref()?;
        match (info.ip, info.netmask) {
            (IpAddr::V4(ip), Some(IpAddr::V4(mask))) => {
                let network = Ipv4Network::with_netmask(ip, mask).ok()?;
                Some(network.to_string())
            }
            _ => None,
        }
    }
}
