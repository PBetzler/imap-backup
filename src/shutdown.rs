//! Graceful shutdown signaling for cooperative cancellation.
//!
//! Uses a [`tokio::sync::watch`] channel to broadcast a shutdown request
//! from the [`ShutdownController`] to all [`ShutdownSignal`] holders.
//! Signal handlers for SIGTERM and SIGINT are registered via
//! [`spawn_signal_handler`].

/// Receives shutdown notifications.
///
/// Cheaply cloneable — every async task that needs to check for shutdown
/// should hold its own `ShutdownSignal`.
#[derive(Clone)]
pub struct ShutdownSignal {
    /// Watch receiver that transitions from `false` to `true` on shutdown.
    receiver: tokio::sync::watch::Receiver<bool>,
}

impl ShutdownSignal {
    /// Check whether a shutdown has been requested.
    pub fn is_shutdown_requested(&self) -> bool {
        *self.receiver.borrow()
    }
}

/// Sends the shutdown notification to all [`ShutdownSignal`] holders.
pub struct ShutdownController {
    /// Watch sender that broadcasts the shutdown flag.
    sender: tokio::sync::watch::Sender<bool>,
}

impl ShutdownController {
    /// Create a new controller/signal pair.
    ///
    /// Returns `(controller, signal)` where the controller is used to
    /// trigger shutdown and the signal is polled by worker tasks.
    pub fn new() -> (Self, ShutdownSignal) {
        let (sender, receiver) = tokio::sync::watch::channel(false);
        let controller = Self { sender };
        let signal = ShutdownSignal { receiver };
        (controller, signal)
    }

    /// Request a graceful shutdown.
    ///
    /// All [`ShutdownSignal`] holders will observe `is_shutdown_requested() == true`
    /// after this call.
    pub fn request_shutdown(&self) {
        // send() only fails if all receivers are dropped, which is harmless.
        let _ = self.sender.send(true);
    }
}

/// Spawn a background task that listens for SIGTERM and SIGINT, then
/// triggers the given controller.
///
/// Logs a warning and returns an error description if signal registration
/// fails, but does not prevent the application from running.
pub fn spawn_signal_handler(controller: ShutdownController) {
    tokio::spawn(async move {
        if let Err(reason) = wait_for_signal().await {
            tracing::warn!(reason, "failed to register signal handlers");
            return;
        }
        tracing::info!("received shutdown signal, initiating graceful shutdown");
        controller.request_shutdown();
    });
}

/// Wait for either SIGTERM or SIGINT.
///
/// Returns `Ok(())` when a signal is received, or `Err` with a description
/// if signal registration fails.
async fn wait_for_signal() -> Result<(), String> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};

        let mut sigterm =
            signal(SignalKind::terminate()).map_err(|e| format!("SIGTERM handler: {e}"))?;
        let mut sigint =
            signal(SignalKind::interrupt()).map_err(|e| format!("SIGINT handler: {e}"))?;

        tokio::select! {
            _ = sigterm.recv() => {},
            _ = sigint.recv() => {},
        }

        Ok(())
    }

    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c()
            .await
            .map_err(|e| format!("Ctrl-C handler: {e}"))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signal_not_requested_initially() {
        let (_controller, signal) = ShutdownController::new();
        assert!(!signal.is_shutdown_requested());
    }

    #[test]
    fn signal_requested_after_shutdown() {
        let (controller, signal) = ShutdownController::new();
        controller.request_shutdown();
        assert!(signal.is_shutdown_requested());
    }

    #[test]
    fn cloned_signal_observes_shutdown() {
        let (controller, signal) = ShutdownController::new();
        let signal2 = signal.clone();
        controller.request_shutdown();
        assert!(signal.is_shutdown_requested());
        assert!(signal2.is_shutdown_requested());
    }

    #[test]
    fn request_shutdown_is_idempotent() {
        let (controller, signal) = ShutdownController::new();
        controller.request_shutdown();
        controller.request_shutdown();
        assert!(signal.is_shutdown_requested());
    }

    #[test]
    fn request_shutdown_after_signal_dropped_does_not_panic() {
        let (controller, signal) = ShutdownController::new();
        drop(signal);
        // Should not panic even though the receiver is gone.
        controller.request_shutdown();
    }
}
