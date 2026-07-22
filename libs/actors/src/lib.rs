use std::future::Future;
use tokio::{
    signal::unix::{signal, SignalKind},
    sync::{broadcast, mpsc, Mutex},
    task::{self, JoinHandle},
};
use tracing::*;
use std::collections::BTreeMap;

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

// This is what actually hosts and drives the child tasks to completion.
struct SupervisorTask {
    // Receive messages from the parent supervisor
    parent_ctrl_rx: broadcast::Receiver<()>,
    // Send messages to subordinate supervisors.
    ctrl_tx: broadcast::Sender<()>,

    // We probably need a way for subordinates to indicate they have stopped.
    signal_rx: mpsc::Receiver<u64>,

    // A registry of the join handles we own.
    registry: Arc<Mutex<
        Option<
            BTreeMap<
                u64,
                JoinHandle<()>
            >
        >
    >>,
}

impl SupervisorTask {
    async fn drive(&mut self) -> () {
        loop {
            tokio::select! {
                status = self.parent_ctrl_rx.recv() => {
                    if status.is_err() {
                        warn!("Parent supervisor has stopped, stopping down all subordinates.");
                    } else {
                        debug!("Stopping supervisor ...");
                    };

                    break
                }
            }
        }

        // If we haven't registered a subordinate, we don't want to error/alert
        let _ = self.ctrl_tx.send(());

        // Wait on all subordinates to stop.
        self.ctrl_tx.closed().await;

        // Tell our parent we are complete.

        trace!("SupervisorTask stopped");
    }
}

pub struct Supervisor {
    // My ID from the parent.
    id: u64,

    id_alloc: u64,

    // exec_handle: JoinHandle<()>,
    // Broadcast tx/rx
    ctrl_tx: broadcast::Sender<()>,

    signal_tx: mpsc::Sender<u64>,

    // A registry of the join handles we own.
    registry: Arc<Mutex<
        Option<
            BTreeMap<
                u64,
                JoinHandle<()>
            >
        >
    >>,
}

impl Supervisor {
    fn build(
        id: u64,
        parent_ctrl_rx: broadcast::Receiver<()>,
        parent_signal_tx: mpsc::Sender<u64>,
    ) -> (Self, JoinHandle<()>) {
        // Starts the first/primary supervisor.
        let id_alloc = 0;

        let (ctrl_tx, ctrl_rx) = broadcast::channel(1);
        let (signal_tx, signal_rx) = mpsc::channel(8);

        let registry = Default::default();

        let exec_handle = {
            let ctrl_tx = ctrl_tx.clone();
            let registry = registry.clone();

            task::spawn(async move {
                let mut supervisor_task = SupervisorTask {
                    parent_signal_tx,
                    parent_ctrl_rx,
                    ctrl_tx,
                    signal_rx,
                    registry,
                };

                supervisor_task.drive().await;
            })
        };

        (Self {
            id,
            id_alloc,
            ctrl_tx,
            signal_tx,
            registry,
        }, exec_handle)
    }

    fn primary(parent_ctrl_rx: broadcast::Receiver<()>) -> (Self, JoinHandle<()>) {
        self.build(0, parent_ctrl_rx)
    }

    /// Build a subordinate supervisor. This allows you to group tasks together for clean
    /// shutdowns without affecting parent or sibiling supervised tasks.
    pub async fn subordinate(
        &mut self,
    ) -> Result<Self, ()> {

        self.id_alloc += 1;
        id = self.id_alloc;

        let parent_ctrl_rx = self.ctrl_tx.subscribe();


        let (supervisor, handle) = self.build(id, parent_ctrl_rx);

        let mut registry_guard = self.registry.lock().await;



        supervisor
    }

    /*
    /// Stop this supervisor and all it's hosted tasks.
    pub fn stop(
        &self
    ) {
        // 
    }
    */

    /*
    pub fn spawn<A>(actor: A)
        where A: Actor
    {

        let supervised_actor = SupervisedActor::from(actor);

        // spawn it
        // send the handle to the supervisor task to take care of it.




    }
    */
}

/*
struct SupervisedActor<A> {
    a: A
}

impl<A> From<A> for SupervisedActor<A> {
    fn from(a: A) -> Self {
        Self { a }
    }
}

impl<A> SupervisedActor<A> {
    async fn drive(&mut self) -> () {

    }
}

trait Actor {




}
*/

#[cfg(test)]
mod tests {
    use super::{Runtime, RuntimeSetup, SignalHandler, Supervisor};
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
                Ok(())
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

