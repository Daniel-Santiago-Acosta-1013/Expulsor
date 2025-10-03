//! Gestiona la cola de comandos y operaciones asincrónicas de Expulsor.

use crate::app::state::AppState;
use crate::domain::actions::AppAction;
use crate::infrastructure::services::ServiceRegistry;
use crate::utils::shutdown::ShutdownSignal;
use anyhow::Result;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use tokio::task::JoinHandle;

/// Capacidad predeterminada para la cola de comandos.
const COMMAND_BUFFER: usize = 64;

/// Componente responsable de ejecutar acciones solicitadas por la interfaz.
#[derive(Clone)]
pub struct CommandDispatcher {
    sender: mpsc::Sender<AppAction>,
    registry: Arc<ServiceRegistry>,
    state: Arc<Mutex<AppState>>,
    shutdown: ShutdownSignal,
}

impl CommandDispatcher {
    /// Construye un nuevo despachador y sus servicios asociados.
    pub fn new(state: Arc<Mutex<AppState>>, shutdown: ShutdownSignal) -> Result<Self> {
        let (sender, receiver) = mpsc::channel(COMMAND_BUFFER);
        let registry = Arc::new(ServiceRegistry::new()?);
        ServiceRegistry::spawn_executor(
            registry.clone(),
            state.clone(),
            receiver,
            shutdown.clone(),
        );

        Ok(Self {
            sender,
            registry,
            state,
            shutdown,
        })
    }

    /// Encola una acción para su ejecución asíncrona.
    pub async fn submit(&self, action: AppAction) -> Result<()> {
        self.sender.send(action).await.map_err(|err| err.into())
    }

    /// Activa las tareas en segundo plano propias del registro de servicios.
    pub async fn spawn_background_tasks(&self) -> Result<Vec<JoinHandle<()>>> {
        self.registry
            .spawn_background_tasks(self.state.clone(), self.shutdown.clone())
            .await
    }
}
