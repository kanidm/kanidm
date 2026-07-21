use tokio::{
    signal::unix::{signal, SignalKind},
    sync::{broadcast, mpsc},
    task::{spawn, JoinHandle},
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

// This is what actually hosts and drives the child tasks to completion.
struct SupervisorTask {

    // Receive messages from the parent supervisor
    parent_ctrl_tx: broadcast::Receiver<()>,
    // Send messages to subordinate supervisors.
    ctrl_tx: broadcast::Sender<()>,

    // Receive new task handles.
    // register_rx: mpsc::Receiver<JoinHandle<()>>,

    // handles: ()
}

impl SupervisorTask {
    async fn drive(&mut self) -> () {

        loop {
            tokio::select! {
                status = parent_ctrl_tx.recv() => {
                    if status.is_err() {
                        warn!("Parent supervisor has stopped, stopping down all children.");
                    } else {
                        debug!("Stopping supervisor");
                    };
                    ctrl_tx.send(()).await;
                    break
                }
            }
        }

    }
}

pub struct Supervisor {
    // exec_handle: JoinHandle<()>,
    // Broadcast tx/rx
    ctrl_tx: broadcast::Sender<()>,

    // register_tx: mpsc::Sender<JoinHandle<()>>,

}

impl Supervisor {
    fn primary(
        parent_ctrl_rx: broadcast::Receiver<()>,
    ) -> (
        Self,
        JoinHandle<()>
    ) {
        // Starts the first/primary supervisor.
        let (ctrl_tx, ctrl_rx) = broadcast::channel(1);

        let exec_handle = task::spawn(async move {
            let supervisor_task = SupervisorTask {
                parent_ctrl_rx,
                ctrl_tx,
            };

            supervisor_task.drive();
        })





    }


    /*

    // Create a child-supervisor.
    pub fn new(
        &self,
    ) -> Self {

        let exec_handle = task::spawn(async move {
            let supervisor_task = SupervisorTask {
            };

            supervisor_task.drive();
        })
        
        Self {
            
        }
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


