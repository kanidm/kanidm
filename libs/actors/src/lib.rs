use std::collections::BTreeMap;
use std::future::Future;
use std::sync::Arc;
use tokio::{
    signal::unix::{signal, SignalKind},
    sync::{broadcast, mpsc, Mutex},
    task::{self, JoinHandle},
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

pub trait RuntimeSetup {
    type Error;

    fn setup(
        supervisor: &mut Supervisor,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send;
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

    pub async fn exec<S>(
        mut self,
        // rt_setup: S
    ) -> Result<(), Box<dyn std::error::Error>>
    where
        S: RuntimeSetup,
    {
        let mut sigterm_stream = signal(SignalKind::terminate())?;
        let mut sigint_stream = signal(SignalKind::interrupt())?;
        let mut sighup_stream = signal(SignalKind::hangup())?;
        let mut siguser1_stream = signal(SignalKind::user_defined1())?;
        let mut siguser2_stream = signal(SignalKind::user_defined2())?;
        let mut sigalarm_stream = signal(SignalKind::alarm())?;

        // also need the handle to join on.

        let (ctrl_tx, ctrl_rx) = broadcast::channel(1);

        let (mut supervisor, mut supervisor_handle) = Supervisor::primary(ctrl_rx);

        // Run the setup function to allow registration of tasks to the supervisor.
        S::setup(&mut supervisor).await;

        loop {
            tokio::select! {
                _ = &mut supervisor_handle => {
                    break
                }

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

        if ctrl_tx.send(()).is_err() {
            error!(
                "Unable to communicate with primary supervisor, unclean shutdown will now occur."
            );
        }

        if !supervisor_handle.is_finished() {
            supervisor_handle.await;
        }
        debug!("Runtime has stopped.");

        Ok(())
    }
}

enum SupervisorMessage {
    Stop,
}

// This is what actually hosts and drives the child tasks to completion.
struct SupervisorTask {
    // Receive messages from the parent supervisor
    parent_ctrl_rx: broadcast::Receiver<()>,

    mbox_rx: mpsc::Receiver<SupervisorMessage>,

    // Send messages to subordinate supervisors.
    ctrl_tx: broadcast::Sender<()>,
}

impl SupervisorTask {
    async fn run(&mut self) -> () {
        loop {
            tokio::select! {
                status = self.parent_ctrl_rx.recv() => {
                    if status.is_err() {
                        warn!("Parent supervisor has stopped, stopping down all subordinates.");
                    };

                    break
                }
                msg = self.mbox_rx.recv() => {
                    match msg {
                        Some(SupervisorMessage::Stop) => break,
                        None => {
                            // Do we care if this closes?
                        }
                    }
                }

                // Listen on incoming new tasks.

            }
        }

        debug!("Stopping supervisor ...");

        // If we haven't registered a subordinate, we don't want to error/alert
        let _ = self.ctrl_tx.send(());

        // Wait on all subordinates to stop.
        self.ctrl_tx.closed().await;

        trace!("SupervisorTask stopped");
    }
}

pub struct Supervisor {
    ctrl_tx: broadcast::Sender<()>,

    mbox_tx: mpsc::Sender<SupervisorMessage>,
}

impl Supervisor {
    fn build(parent_ctrl_rx: broadcast::Receiver<()>) -> (Self, JoinHandle<()>) {
        let (ctrl_tx, ctrl_rx) = broadcast::channel(1);
        let (mbox_tx, mbox_rx) = mpsc::channel(4);

        let exec_handle = {
            let ctrl_tx = ctrl_tx.clone();

            task::spawn(async move {
                let mut supervisor_task = SupervisorTask {
                    parent_ctrl_rx,
                    mbox_rx,
                    ctrl_tx,
                };

                supervisor_task.run().await;
            })
        };

        (Self { ctrl_tx, mbox_tx }, exec_handle)
    }

    fn primary(parent_ctrl_rx: broadcast::Receiver<()>) -> (Self, JoinHandle<()>) {
        Self::build(parent_ctrl_rx)
    }

    /// Build a subordinate supervisor. This allows you to group tasks together for clean
    /// shutdowns without affecting parent or sibiling supervised tasks.
    pub async fn subordinate(&mut self) -> Result<Self, ()> {
        let parent_ctrl_rx = self.ctrl_tx.subscribe();

        let (supervisor, handle) = Self::build(parent_ctrl_rx);

        Ok(supervisor)
    }

    /// Stop this supervisor and all it's hosted tasks.
    pub async fn stop(self) {
        self.mbox_tx.send(SupervisorMessage::Stop).await;

        // Wait for the task to stop
        debug!("Waiting for stop");
        self.mbox_tx.closed().await;
    }

    pub fn spawn<A>(&mut self, actor: A)
    where
        A: Actor + Send + 'static,
    {
        // From the point we subscribe to the tx, this causes
        // the task to be owned by the supervisor, and it will now wait
        // for this rx to stop during a shutdown event.
        let parent_ctrl_rx = self.ctrl_tx.subscribe();

        let mut supervised_actor = SupervisedActor::build(parent_ctrl_rx, actor);

        let _actor_handle = tokio::spawn(async move { supervised_actor.run().await });
    }
}

struct SupervisedActor<A> {
    parent_ctrl_rx: broadcast::Receiver<()>,
    a: A,
}

impl<A> SupervisedActor<A>
where
    A: Actor + Send + 'static,
{
    fn build(parent_ctrl_rx: broadcast::Receiver<()>, a: A) -> Self {
        Self { parent_ctrl_rx, a }
    }

    async fn run(&mut self) {
        debug!("starting actor");

        // Setup.
        self.a.setup().await;

        // Loop + Select on shutdown.
        loop {
            tokio::select! {
                status = self.parent_ctrl_rx.recv() => {
                    if status.is_err() {
                        warn!("Parent supervisor has stopped.");
                    };

                    break
                }
                _ = self.a.run() => {
                    // Let the actor run.
                }
            }
        }

        debug!("stopping actor");

        self.a.stop().await;
    }
}

pub trait Actor {
    fn setup(&mut self) -> impl std::future::Future<Output = ()> + Send {
        async {}
    }

    // Loop/run
    fn run(&mut self) -> impl std::future::Future<Output = ()> + Send {
        async {}
    }

    fn stop(&mut self) -> impl std::future::Future<Output = ()> + Send {
        async {}
    }
}

#[cfg(test)]
mod tests {
    use super::{Actor, Runtime, RuntimeSetup, SignalHandler, Supervisor};
    use tokio::time::{sleep, Duration};
    use tracing::*;

    struct Handler {}

    impl SignalHandler for Handler {}

    struct RTSetup {}

    impl RuntimeSetup for RTSetup {
        type Error = ();

        fn setup(
            supervisor: &mut Supervisor,
        ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send {
            async {
                info!("It Runs!");

                let super_1 = supervisor.subordinate().await.unwrap();

                let mut super_2 = supervisor.subordinate().await.unwrap();

                super_1.stop().await;

                super_2.spawn(TestActor {});

                Ok(())
            }
        }
    }

    struct TestActor {}

    impl Actor for TestActor {
        fn setup(&mut self) -> impl std::future::Future<Output = ()> + Send {
            async {
                debug!("setup!");
            }
        }

        // Loop/run
        fn run(&mut self) -> impl std::future::Future<Output = ()> + Send {
            async {
                sleep(Duration::from_millis(100)).await;
                println!("100 ms have elapsed");
            }
        }

        fn stop(&mut self) -> impl std::future::Future<Output = ()> + Send {
            async {
                debug!("stop");
            }
        }
    }

    #[tokio::test]
    async fn basic_test() {
        let _ = tracing_subscriber::fmt::try_init();

        trace!("It works");

        let rt = Runtime::new(Handler {});

        rt.exec::<RTSetup>().await;
    }
}
