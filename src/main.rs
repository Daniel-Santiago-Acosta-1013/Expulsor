//! Punto de entrada del binario principal de Expulsor reimplementado en Rust.

mod app;
mod domain;
mod infrastructure;
mod presentation;
mod utils;

use anyhow::Result;
use app::application::ExpulsorApp;
use tracing_subscriber::EnvFilter;

fn check_privileges() {
    #[cfg(unix)]
    unsafe {
        if libc::geteuid() != 0 {
            use crossterm::style::Stylize;
            eprintln!(
                "\n{} {}\n",
                "✕ Error Crítico:".red().bold(),
                "Expulsor requiere permisos de administrador.".red()
            );
            eprintln!(
                "  Por favor, ejecuta la aplicación con {}:",
                "sudo".yellow().bold()
            );
            eprintln!("      sudo ./target/debug/expulsor\n");
            std::process::exit(1);
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    check_privileges();
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
