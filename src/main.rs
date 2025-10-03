//! Punto de entrada del binario principal de Expulsor reimplementado en Rust.

mod app;
mod domain;
mod infrastructure;
mod presentation;
mod utils;

use anyhow::Result;
use app::application::ExpulsorApp;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install().expect("error iniciando color-eyre");

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_target(false)
        .compact()
        .init();

    // La aplicación no acepta argumentos de línea de comandos por diseño.
    let mut app = ExpulsorApp::initialize().await?;
    app.run().await
}
