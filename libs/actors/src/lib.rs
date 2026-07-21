use tokio::{
    signal::unix::{signal, SignalKind},
    sync::broadcast,
};
use tracing::*;

pub trait SignalHandler {
    fn terminate(&mut self) -> impl std::future::Future<Output = ()> + Send {
        async {
            trace!("terminate");
        }
    }

    fn interrupt(&mut self) -> impl std::future::Future<Output = ()> + Send {
        async {
            trace!("interrupt");
        }
    }

    fn hangup(&mut self) -> impl std::future::Future<Output = ()> + Send {
        async {
            trace!("hangup");
        }
    }

    fn user_defined1(&mut self) -> impl std::future::Future<Output = ()> + Send {
        async {
            trace!("user_defined1");
        }
    }

    fn user_defined2(&mut self) -> impl std::future::Future<Output = ()> + Send {
        async {
            trace!("user_defined2");
        }
    }

    fn alarm(&mut self) -> impl std::future::Future<Output = ()> + Send {
        async {
            trace!("alarm");
        }
    }
}

pub struct Runtime<H> {
    signal_handler: H,
}

impl<H> Runtime<H>
where
    H: SignalHandler,
{
    pub fn new(signal_handler: H) -> Self {
        Self { signal_handler }
    }

    pub async fn exec(mut self) -> Result<(), Box<dyn std::error::Error>> {
        let mut sigterm_stream = signal(SignalKind::terminate())?;
        let mut sigint_stream = signal(SignalKind::interrupt())?;
        let mut sighup_stream = signal(SignalKind::hangup())?;
        let mut siguser1_stream = signal(SignalKind::user_defined1())?;
        let mut siguser2_stream = signal(SignalKind::user_defined2())?;
        let mut sigalarm_stream = signal(SignalKind::alarm())?;

        // also need the handle to join on.

        // let stop_tx, stop_rx =

        loop {
            tokio::select! {
                _ = sigterm_stream.recv() => {
                    self.signal_handler.terminate().await;
                    break
                }

                _ = sigint_stream.recv() => {
                    self.signal_handler.interrupt().await;
                    break
                }

                _ = sighup_stream.recv() => {
                    self.signal_handler.hangup().await;
                }

                _ = siguser1_stream.recv() => {
                    self.signal_handler.user_defined1().await;
                }

                _ = siguser2_stream.recv() => {
                    self.signal_handler.user_defined2().await;
                }

                _ = sigalarm_stream.recv() => {
                    self.signal_handler.alarm().await;
                }
            }
        }

        Ok(())
    }
}

/*
pub struct Supervisor {
    hosted_fn:
}

impl Supervisor {
    async fn host() -> Result<(), ()> {

    }
}

*/

#[cfg(test)]
mod tests {
    use super::{Runtime, SignalHandler};
    use tracing::*;

    struct Handler {}

    impl SignalHandler for Handler {}

    #[tokio::test]
    async fn basic_test() {
        let _ = tracing_subscriber::fmt::try_init();

        trace!("It works");

        let rt = Runtime::new(Handler {});

        rt.exec().await;
    }
}
