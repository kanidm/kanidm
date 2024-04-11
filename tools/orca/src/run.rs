use crate::error::Error;
use crate::model::ActorRole;
use crate::state::*;
use crate::stats::{BasicStatistics, TestPhase};

use std::sync::Arc;

use rand::seq::SliceRandom;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;

use crossbeam::queue::{ArrayQueue, SegQueue};

use kanidm_client::{KanidmClient, KanidmClientBuilder};

use tokio::sync::broadcast;

use std::time::{Duration, Instant};

async fn actor_person(
    client: KanidmClient,
    person: Person,
    stats_queue: Arc<SegQueue<EventRecord>>,
    mut actor_rx: broadcast::Receiver<Signal>,
) -> Result<(), Error> {
    let mut model = person.model.as_dyn_object()?;

    while let Err(broadcast::error::TryRecvError::Empty) = actor_rx.try_recv() {
        let event = model.transition(&client, &person).await?;

        stats_queue.push(event);
    }

    debug!("Stopped person {}", person.username);
    Ok(())
}

pub struct EventRecord {
    pub start: Instant,
    pub duration: Duration,
    pub details: EventDetail,
}

pub enum EventDetail {
    Authentication,
    Logout,
    PersonGet,
    PersonSet,
    Error,
}

impl From<ActorRole> for EventDetail {
    fn from(value: ActorRole) -> Self {
        match value {
            ActorRole::ReadAttribute => EventDetail::PersonGet,
            ActorRole::WriteAttribute => EventDetail::PersonSet,
        }
    }
}

#[derive(Clone, Debug)]
pub enum Signal {
    Stop,
}

async fn execute_inner(
    warmup: Duration,
    test_time: Option<Duration>,
    mut control_rx: broadcast::Receiver<Signal>,
    stat_ctrl: Arc<ArrayQueue<TestPhase>>,
) -> Result<(), Error> {
    // Delay for warmup time.
    tokio::select! {
        _ = tokio::time::sleep(warmup) => {
            // continue.
        }
        _ = control_rx.recv() => {
            // Until we add other signal types, any event is
            // either Ok(Signal::Stop) or Err(_), both of which indicate
            // we need to stop immediately.
            return Err(Error::Interrupt);
        }
    }

    let start = Instant::now();
    if let Err(crossbeam_err) = stat_ctrl.push(TestPhase::Start(start)) {
        error!(
            ?crossbeam_err,
            "Unable to signal statistics collector to start"
        );
        return Err(Error::Crossbeam);
    }

    if let Some(test_time) = test_time {
        let sleep = tokio::time::sleep(test_time);
        tokio::pin!(sleep);
        let recv = (control_rx).recv();
        tokio::pin!(recv);

        // Wait for some condition (signal, or time).
        tokio::select! {
            _ = sleep => {
                // continue.
            }
            _ = recv => {
                // Until we add other signal types, any event is
                // either Ok(Signal::Stop) or Err(_), both of which indicate
                // we need to stop immediately.
                return Err(Error::Interrupt);
            }
        }
    } else {
        let _ = control_rx.recv().await;
    }

    let end = Instant::now();
    if let Err(crossbeam_err) = stat_ctrl.push(TestPhase::End(end)) {
        error!(
            ?crossbeam_err,
            "Unable to signal statistics collector to start"
        );
        return Err(Error::Crossbeam);
    }

    Ok(())
}

pub async fn execute(state: State, control_rx: broadcast::Receiver<Signal>) -> Result<(), Error> {
    // Create a statistics queue.
    let stats_queue = Arc::new(SegQueue::new());
    let stats_ctrl = Arc::new(ArrayQueue::new(4));

    // Spawn the stats aggregator
    let c_stats_queue = stats_queue.clone();
    let c_stats_ctrl = stats_ctrl.clone();

    let mut dyn_data_collector = BasicStatistics::new();

    let stats_task =
        tokio::task::spawn_blocking(move || dyn_data_collector.run(c_stats_queue, c_stats_ctrl));

    // Create clients. Note, we actually seed these deterministically too, so that
    // or persons are spread over the clients that exist, in a way that is also
    // deterministic.
    let mut seeded_rng = ChaCha8Rng::seed_from_u64(state.profile.seed());

    let clients = std::iter::once(state.profile.control_uri().to_string())
        .chain(state.profile.extra_uris().iter().cloned())
        .map(|uri| {
            KanidmClientBuilder::new()
                .address(uri)
                .danger_accept_invalid_hostnames(true)
                .danger_accept_invalid_certs(true)
                .build()
                .map_err(|err| {
                    error!(?err, "Unable to create kanidm client");
                    Error::KanidmClient
                })
        })
        .collect::<Result<Vec<_>, _>>()?;

    let (actor_tx, _actor_rx) = broadcast::channel(1);

    // Start the actors
    let mut tasks = Vec::with_capacity(state.persons.len());
    for person in state.persons.into_iter() {
        let client = clients
            .choose(&mut seeded_rng)
            .expect("Invalid client set")
            .new_session()
            .map_err(|err| {
                error!(?err, "Unable to create kanidm client");
                Error::KanidmClient
            })?;

        let c_stats_queue = stats_queue.clone();

        let c_actor_rx = actor_tx.subscribe();

        tasks.push(tokio::spawn(actor_person(
            client,
            person,
            c_stats_queue,
            c_actor_rx,
        )))
    }

    let warmup = state.profile.warmup_time();
    let test_time = state.profile.test_time();

    // We run a separate test inner so we don't have to worry about
    // task spawn/join within our logic.
    let c_stats_ctrl = stats_ctrl.clone();
    // Don't ? this, we want to stash the result so we cleanly stop all the workers
    // before returning the inner test result.
    let test_result = execute_inner(warmup, test_time, control_rx, c_stats_ctrl).await;

    info!("stopping stats");

    // The statistics collector has been working in the BG, and was likely told
    // to end by now, but if not (due to an error) send a signal to stop immediately.
    if let Err(crossbeam_err) = stats_ctrl.push(TestPhase::StopNow) {
        error!(
            ?crossbeam_err,
            "Unable to signal statistics collector to stop"
        );
        return Err(Error::Crossbeam);
    }

    info!("stopping workers");

    // Test workers to stop
    actor_tx.send(Signal::Stop).map_err(|broadcast_err| {
        error!(?broadcast_err, "Unable to signal workers to stop");
        Error::Tokio
    })?;

    info!("joining workers");

    // Join all the tasks.
    for task in tasks {
        task.await.map_err(|tokio_err| {
            error!(?tokio_err, "Failed to join task");
            Error::Tokio
        })??;
        // The double ? isn't a mistake, it's because this is Result<Result<T, E>, E>
        // and flatten is nightly.
    }

    // By this point the stats task should have been told to halt and rejoin.
    stats_task.await.map_err(|tokio_err| {
        error!(?tokio_err, "Failed to join statistics task");
        Error::Tokio
    })??;
    // Not an error, two ? to handle the inner data collector error.

    // Complete!

    test_result
}
