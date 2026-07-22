use std::future::Future;
use tokio::{
    signal::unix::{self, signal, SignalKind},
    sync::{broadcast, mpsc},
    task::{self, JoinHandle},
};
use tracing::*;

pub trait SignalHandler {
    fn terminate(&mut self) -> impl Future<Output = ()> + Send {
        async {
            trace!("terminate");
        }
    }

    fn interrupt(&mut self) -> impl Future<Output = ()> + Send {
        async {
            trace!("interrupt");
        }
    }

    fn hangup(&mut self) -> impl Future<Output = ()> + Send {
        async {
            trace!("hangup");
        }
    }

    fn user_defined1(&mut self) -> impl Future<Output = ()> + Send {
        async {
            trace!("user_defined1");
        }
    }

    fn user_defined2(&mut self) -> impl Future<Output = ()> + Send {
        async {
            trace!("user_defined2");
        }
    }

    fn alarm(&mut self) -> impl Future<Output = ()> + Send {
        async {
            trace!("alarm");
        }
    }
}

pub enum Signal {
    Terminate,
    Interrupt,
    Hangup,
    UserDefined1,
    UserDefined2,
    Alarm,
}

pub trait SignalSource {
    fn recv(&mut self) -> impl Future<Output = Signal> + Send;
}

pub struct UnixSignalSource {
    sigterm_stream: unix::Signal,
    sigint_stream: unix::Signal,
    sighup_stream: unix::Signal,
    siguser1_stream: unix::Signal,
    siguser2_stream: unix::Signal,
    sigalarm_stream: unix::Signal,
}

impl UnixSignalSource {
    pub fn new() -> Result<Self, std::io::Error> {
        let sigterm_stream = signal(SignalKind::terminate())?;
        let sigint_stream = signal(SignalKind::interrupt())?;
        let sighup_stream = signal(SignalKind::hangup())?;
        let siguser1_stream = signal(SignalKind::user_defined1())?;
        let siguser2_stream = signal(SignalKind::user_defined2())?;
        let sigalarm_stream = signal(SignalKind::alarm())?;

        Ok(Self {
            sigterm_stream,
            sigint_stream,
            sighup_stream,
            siguser1_stream,
            siguser2_stream,
            sigalarm_stream,
        })
    }
}

impl SignalSource for UnixSignalSource {
    fn recv(&mut self) -> impl Future<Output = Signal> + Send {
        async {
            tokio::select! {
                _ = self.sigterm_stream.recv() => {
                    Signal::Terminate
                }
                _ = self.sigint_stream.recv() => {
                    Signal::Interrupt
                }
                _ = self.sighup_stream.recv() => {
                    Signal::Hangup
                }
                _ = self.siguser1_stream.recv() => {
                    Signal::UserDefined1
                }
                _ = self.siguser2_stream.recv() => {
                    Signal::UserDefined2
                }
                _ = self.sigalarm_stream.recv() => {
                    Signal::Alarm
                }
            }
        }
    }
}

pub struct SoftwareSignalSource {
    rx: mpsc::Receiver<Signal>,
}

impl SoftwareSignalSource {
    pub fn new() -> (Self, mpsc::Sender<Signal>) {
        let (tx, rx) = mpsc::channel(4);

        (Self { rx }, tx)
    }
}

impl SignalSource for SoftwareSignalSource {
    fn recv(&mut self) -> impl Future<Output = Signal> + Send {
        async { self.rx.recv().await.unwrap_or(Signal::Terminate) }
    }
}

pub trait RuntimeSetup {
    type Error;

    fn setup(
        self,
        supervisor: &mut Supervisor,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;
}

pub struct Runtime {}

impl Runtime {
    pub fn new() -> Self {
        Self {}
    }

    pub async fn exec<H, T, S>(
        self,
        context: S,
        mut signal_handler: H,
        mut signal_source: T,
    ) -> Result<(), S::Error>
    where
        H: SignalHandler,
        T: SignalSource,
        S: RuntimeSetup,
    {
        let (ctrl_tx, ctrl_rx) = broadcast::channel(1);

        let (mut supervisor, mut supervisor_handle) = Supervisor::primary(ctrl_rx);

        // Run the setup function to allow registration of tasks to the supervisor.
        context.setup(&mut supervisor).await?;

        loop {
            tokio::select! {
                _ = &mut supervisor_handle => {
                    // This occurs if the primary supervisor stops prematurely.
                    break
                }

                signal_event = signal_source.recv() => {
                    match signal_event {
                        Signal::Terminate => {
                            signal_handler.terminate().await;
                            break
                        }
                        Signal::Interrupt => {
                            signal_handler.interrupt().await;
                            break
                        }
                        Signal::Hangup => {
                            signal_handler.hangup().await;
                        }
                        Signal::UserDefined1 => {
                            signal_handler.user_defined1().await;
                        }
                        Signal::UserDefined2 => {
                            signal_handler.user_defined2().await;
                        }
                        Signal::Alarm => {
                            signal_handler.alarm().await;
                        }
                    }
                }
            }
        }

        if ctrl_tx.send(()).is_err() {
            error!(
                "Unable to communicate with primary supervisor, unclean shutdown will now occur."
            );
        }

        if !supervisor_handle.is_finished() {
            if supervisor_handle.await.is_err() {
                error!("Failed to stop primary supervisor.");
            } else {
                debug!("Runtime has stopped.");
            }
        }

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
        let (ctrl_tx, _ctrl_rx) = broadcast::channel(1);
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
    pub async fn subordinate(&mut self) -> Self {
        let parent_ctrl_rx = self.ctrl_tx.subscribe();

        let (supervisor, _handle) = Self::build(parent_ctrl_rx);

        supervisor
    }

    pub fn subordinate_count(&self) -> usize {
        self.ctrl_tx.receiver_count()
    }

    /// Stop this supervisor and all it's hosted tasks.
    pub async fn stop(self) {
        let send_result = self.mbox_tx.send(SupervisorMessage::Stop).await;
        if send_result.is_err() {
            error!("Failed to communicate with supervisor task.");
        }

        // Wait for the task to stop
        debug!("Waiting for stop");
        self.mbox_tx.closed().await;
    }

    pub fn spawn<A>(&mut self, actor: A) -> JoinHandle<()>
    where
        A: Actor + Send + 'static,
    {
        // From the point we subscribe to the tx, this causes
        // the task to be owned by the supervisor, and it will now wait
        // for this rx to stop during a shutdown event.
        let parent_ctrl_rx = self.ctrl_tx.subscribe();

        let mut supervised_actor = SupervisedActor::build(parent_ctrl_rx, actor);

        tokio::spawn(async move { supervised_actor.run().await })
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
        // Setup.
        self.a.setup().await;

        tokio::select! {
            status = self.parent_ctrl_rx.recv() => {
                if status.is_err() {
                    warn!("Parent supervisor has stopped.");
                };
            }
            // Future - if we need to protect critical sections during run, we can
            // pass in a mutex that the receiver can lock to prevent shutdown
            // completing until they release the guard.
            _ = self.a.run() => {
                // Let the actor run.
            }
        }

        self.a.stop().await;
    }
}

pub trait Actor {
    fn setup(&mut self) -> impl Future<Output = ()> + Send {
        async {}
    }

    fn run(&mut self) -> impl Future<Output = ()> + Send {
        async {}
    }

    fn stop(&mut self) -> impl Future<Output = ()> + Send {
        async {}
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Actor, Runtime, RuntimeSetup, Signal, SignalHandler, SoftwareSignalSource, Supervisor,
    };
    use std::future::Future;
    use tokio::sync::mpsc;
    use tokio::task;
    use tracing::*;

    #[tokio::test]
    async fn signal_propagation_test() {
        struct Handler {
            notify_tx: mpsc::Sender<()>,
        }

        impl SignalHandler for Handler {
            fn hangup(&mut self) -> impl Future<Output = ()> + Send {
                async {
                    trace!("hangup");
                    self.notify_tx.send(()).await.unwrap();
                }
            }

            fn user_defined1(&mut self) -> impl Future<Output = ()> + Send {
                async {
                    trace!("user_defined1");
                    self.notify_tx.send(()).await.unwrap();
                }
            }

            fn user_defined2(&mut self) -> impl Future<Output = ()> + Send {
                async {
                    trace!("user_defined2");
                    self.notify_tx.send(()).await.unwrap();
                }
            }
        }

        struct RTContext {}

        impl RuntimeSetup for RTContext {
            type Error = ();

            fn setup(
                self,
                _supervisor: &mut Supervisor,
            ) -> impl Future<Output = Result<(), Self::Error>> + Send {
                async {
                    // Do nothing, really well.
                    Ok(())
                }
            }
        }

        // ============================================================

        let _ = tracing_subscriber::fmt::try_init();

        let (signal_source, signal_tx) = SoftwareSignalSource::new();

        let context = RTContext {};

        let rt = Runtime::new();

        let (notify_tx, mut notify_rx) = mpsc::channel(4);

        let signal_handler = Handler { notify_tx };

        let handle =
            task::spawn(async move { rt.exec(context, signal_handler, signal_source).await });

        assert_eq!(notify_rx.len(), 0);

        signal_tx.send(Signal::Hangup).await.unwrap();
        signal_tx.send(Signal::UserDefined1).await.unwrap();
        signal_tx.send(Signal::UserDefined2).await.unwrap();

        notify_rx.recv().await;

        // We took one message from the queue, there are two more at least.
        assert_eq!(notify_rx.len(), 2);

        signal_tx.send(Signal::Terminate).await.unwrap();
        let result = handle.await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn supervisor_test() {
        struct Handler {}

        impl SignalHandler for Handler {}

        struct TestActor {
            setup_run: bool,
            stop_run: bool,
            rx: mpsc::Receiver<()>,
        }

        impl TestActor {
            fn new(rx: mpsc::Receiver<()>) -> Self {
                Self {
                    setup_run: false,
                    stop_run: false,
                    rx,
                }
            }
        }

        impl Drop for TestActor {
            fn drop(&mut self) {
                debug_assert!(self.setup_run);
                debug_assert!(self.stop_run);
            }
        }

        impl Actor for TestActor {
            fn setup(&mut self) -> impl Future<Output = ()> + Send {
                async {
                    self.setup_run = true;
                }
            }

            fn run(&mut self) -> impl Future<Output = ()> + Send {
                async {
                    self.rx.recv().await;
                    trace!("oneshot message received!");
                }
            }

            fn stop(&mut self) -> impl Future<Output = ()> + Send {
                async {
                    self.stop_run = true;
                }
            }
        }

        struct RTContext {
            signal_tx: mpsc::Sender<Signal>,
        }

        impl RuntimeSetup for RTContext {
            type Error = ();

            fn setup(
                self,
                supervisor: &mut Supervisor,
            ) -> impl Future<Output = Result<(), Self::Error>> + Send {
                async {
                    let RTContext { signal_tx } = self;

                    // This sets up the test coordinator, which actually does all the work.
                    let test_supervisor = supervisor.subordinate().await;

                    let test_coordinator = TestCoordinator {
                        signal_tx,
                        test_supervisor,
                    };

                    supervisor.spawn(test_coordinator);

                    Ok(())
                }
            }
        }

        struct TestCoordinator {
            // The software signal transmit, so we can stop the test from within
            // the actual process ourself.
            signal_tx: mpsc::Sender<Signal>,
            test_supervisor: Supervisor,
        }

        impl Actor for TestCoordinator {
            fn run(&mut self) -> impl Future<Output = ()> + Send {
                async {
                    // It's time to test
                    trace!("Starting task supervision test");

                    // First - we have no hosted tasks or supervisors.
                    assert_eq!(self.test_supervisor.subordinate_count(), 0);

                    // Create a task on the test_supervisor.
                    let (task_1_tx, rx) = mpsc::channel(1);
                    let task_1_handle = self.test_supervisor.spawn(TestActor::new(rx));
                    assert_eq!(self.test_supervisor.subordinate_count(), 1);

                    // Now we can message the oneshote and it will cause the task to stop due to how
                    // we have configured it.
                    task_1_tx.send(()).await.unwrap();
                    task_1_handle.await.unwrap();

                    // Now there are no hosted tasks.
                    assert_eq!(self.test_supervisor.subordinate_count(), 0);

                    // Okay, start a supervisor, and give it some child tasks.
                    let mut supervisor = self.test_supervisor.subordinate().await;

                    let (_task_2_tx, rx) = mpsc::channel(1);
                    let task_2_handle = supervisor.spawn(TestActor::new(rx));

                    let (_task_3_tx, rx) = mpsc::channel(1);
                    let task_3_handle = supervisor.spawn(TestActor::new(rx));

                    // We are hosting the supervisor.
                    assert_eq!(self.test_supervisor.subordinate_count(), 1);
                    // And it's hosting it's tasks.
                    assert_eq!(supervisor.subordinate_count(), 2);

                    // Now tell it to stop.
                    supervisor.stop().await;
                    // Once it's done, we can tell the tasks stopped as the task handles
                    // will join automatically for us
                    task_2_handle.await.unwrap();
                    task_3_handle.await.unwrap();

                    // And we are back to no hosted tasks.
                    assert_eq!(self.test_supervisor.subordinate_count(), 0);

                    // Now stop the supervisor - all it's children will stop!

                    // We are now complete, stop everything!
                    self.signal_tx.send(Signal::Terminate).await.unwrap();
                }
            }
        }

        // ============================================================

        let _ = tracing_subscriber::fmt::try_init();

        let signal_handler = Handler {};
        let (signal_source, signal_tx) = SoftwareSignalSource::new();

        let context = {
            let signal_tx = signal_tx.clone();
            RTContext { signal_tx }
        };

        let rt = Runtime::new();

        let handle =
            task::spawn(async move { rt.exec(context, signal_handler, signal_source).await });

        let result = handle.await;
        assert!(result.is_ok());
    }
}
