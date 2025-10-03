//! Motor de coincidencia de firmas que ayuda a clasificar dispositivos.

use crate::domain::device::DeviceRecord;
use anyhow::{Context, Result};
use regex::Regex;
use serde::Deserialize;
use std::collections::HashMap;

/// Intérprete de patrones reutilizados para estimar tipo y modelo de dispositivos.
#[derive(Clone)]
pub struct SignatureMatcher {
    ports: Vec<PortSignature>,
    hostname: Vec<RegexSignature>,
    http: Vec<RegexSignature>,
    services: HashMap<String, Vec<RegexSignature>>,
}

impl SignatureMatcher {
    /// Carga las firmas desde el archivo JSON embebido en los recursos.
    pub fn new() -> Result<Self> {
        let json = include_str!("../../../assets/device_signatures.json");
        let raw: SignaturePayload =
            serde_json::from_str(json).context("No se pudo parsear device_signatures.json")?;

        let ports = raw
            .ports
            .into_iter()
            .map(|entry| PortSignature {
                ports: entry.ports,
                labels: entry.labels,
            })
            .collect();

        let hostname = compile_patterns(raw.hostname)?;
        let http = compile_patterns(raw.http_signature)?;
        let services = raw
            .service_signature
            .into_iter()
            .map(|(service, entries)| Ok((service, compile_patterns(entries)?)))
            .collect::<Result<HashMap<_, _>>>()?;

        Ok(Self {
            ports,
            hostname,
            http,
            services,
        })
    }

    /// Intenta enriquecer el registro con información adicional basada en firmas.
    pub fn apply(&self, record: &mut DeviceRecord) {
        if let Some(device_type) = self.match_ports(&record.open_ports) {
            if record.device_type.is_none() {
                record.device_type = Some(device_type)
            }
        }

        if let Some(hostname) = record.hostname.clone() {
            if let Some(label) = self.match_regex_list(&self.hostname, &hostname) {
                record.device_type = Some(label);
            }
        }

        if let Some(signature) = record.http_signature.clone() {
            if let Some(label) = self.match_regex_list(&self.http, &signature) {
                record.device_type = Some(label);
            }
        }

        for details in record.service_details.values() {
            let mut blob = String::new();
            if let Some(name) = &details.name {
                blob.push_str(name);
                blob.push(' ');
            }
            if let Some(product) = &details.product {
                blob.push_str(product);
                blob.push(' ');
            }
            if let Some(version) = &details.version {
                blob.push_str(version);
                blob.push(' ');
            }
            for script in &details.scripts {
                blob.push_str(script);
                blob.push(' ');
            }
            if let Some(label) = self.match_service_patterns(&blob) {
                record.device_type = Some(label);
                break;
            }
        }
    }

    fn match_ports(&self, open_ports: &[u16]) -> Option<String> {
        if open_ports.is_empty() {
            return None;
        }
        let set: Vec<u16> = open_ports.iter().cloned().collect();
        let mut best_label: Option<(String, f32)> = None;
        for signature in &self.ports {
            if signature.ports.is_empty() {
                continue;
            }
            let matched = signature
                .ports
                .iter()
                .filter(|port| set.contains(port))
                .count();
            if matched == 0 {
                continue;
            }
            let score = matched as f32 / signature.ports.len() as f32;
            if let Some((_, best_score)) = &best_label {
                if &score <= best_score {
                    continue;
                }
            }
            if let Some(label) = signature.labels.first() {
                best_label = Some((label.clone(), score));
            }
        }
        best_label.map(|(label, _)| label)
    }

    fn match_service_patterns(&self, payload: &str) -> Option<String> {
        for patterns in self.services.values() {
            if let Some(label) = self.match_regex_list(patterns, payload) {
                return Some(label);
            }
        }
        None
    }

    fn match_regex_list(&self, patterns: &[RegexSignature], payload: &str) -> Option<String> {
        for entry in patterns {
            if entry.regex.is_match(payload) {
                return Some(entry.label.clone());
            }
        }
        None
    }
}

fn compile_patterns(entries: Vec<PatternEntry>) -> Result<Vec<RegexSignature>> {
    entries
        .into_iter()
        .map(|entry| {
            let regex = Regex::new(&entry.pattern)
                .with_context(|| format!("Expresión regular inválida: {}", entry.pattern))?;
            Ok(RegexSignature {
                regex,
                label: entry.label,
            })
        })
        .collect()
}

#[derive(Debug, Deserialize)]
struct SignaturePayload {
    #[serde(default)]
    ports: Vec<PortEntry>,
    #[serde(default)]
    hostname: Vec<PatternEntry>,
    #[serde(default)]
    http_signature: Vec<PatternEntry>,
    #[serde(default)]
    service_signature: HashMap<String, Vec<PatternEntry>>,
}

#[derive(Debug, Deserialize)]
struct PortEntry {
    ports: Vec<u16>,
    labels: Vec<String>,
}

#[derive(Clone)]
struct PortSignature {
    ports: Vec<u16>,
    labels: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct PatternEntry {
    pattern: String,
    label: String,
}

#[derive(Clone)]
struct RegexSignature {
    regex: Regex,
    label: String,
}
