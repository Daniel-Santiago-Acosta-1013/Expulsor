//! Sincronización ligera para notificar el cierre de la aplicación.

use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

/// Señal compartida que permite conocer cuándo se ha solicitado finalizar el programa.
#[derive(Clone, Default)]
pub struct ShutdownSignal {
    inner: Arc<AtomicBool>,
}

impl ShutdownSignal {
    /// Activa la señal de cierre.
    pub fn trigger(&self) {
        self.inner.store(true, Ordering::SeqCst);
    }

    /// Comprueba si la señal ya fue activada.
    pub fn is_triggered(&self) -> bool {
        self.inner.load(Ordering::SeqCst)
    }
}
