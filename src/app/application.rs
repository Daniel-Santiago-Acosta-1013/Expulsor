//! Implementa la orquestación principal del ciclo de vida de la aplicación.

use crate::app::commands::CommandDispatcher;
use crate::app::state::AppState;
use crate::domain::actions::AppAction;
use crate::domain::settings::ScanKind;
use crate::presentation::tui::Tui;
use crate::utils::shutdown::ShutdownSignal;
use anyhow::Result;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Administrador principal de Expulsor.
///
/// Encapsula el estado compartido, los canales de comunicación y la
/// inicialización de los servicios de infraestructura.
pub struct ExpulsorApp {
    dispatcher: CommandDispatcher,
    tui: Tui,
}

impl ExpulsorApp {
    /// Crea la aplicación inicializando las dependencias de infraestructura
    /// y cargando el estado persistente necesario para operar.
    pub async fn initialize() -> Result<Self> {
        let state = Arc::new(Mutex::new(AppState::load().await?));
        let shutdown = ShutdownSignal::default();
        let dispatcher = CommandDispatcher::new(state.clone(), shutdown.clone())?;
        let tui = Tui::new(state.clone(), dispatcher.clone(), shutdown.clone())?;

        Ok(Self { dispatcher, tui })
    }

    /// Ejecuta el bucle principal hasta que el usuario solicite salir.
    pub async fn run(&mut self) -> Result<()> {
        self.dispatcher
            .submit(AppAction::ScanNetwork {
                mode: ScanKind::Quick,
            })
            .await?;
        self.dispatcher.spawn_background_tasks().await?;
        self.tui.run().await
    }
}
