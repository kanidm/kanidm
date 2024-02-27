use crate::error::Error;
use crate::state::*;

use std::sync::Arc;

use rand::seq::SliceRandom;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;

use crossbeam::queue::SegQueue;

use kanidm_client::{KanidmClient, KanidmClientBuilder};

use tokio::sync::broadcast;

use std::time::{Duration, Instant};

async fn actor_person(
    client: KanidmClient,
    person: Person,
    stats_queue: Arc<SegQueue<EventRecord>>,
) -> Result<(), Error> {
    let model = person.model.into_dyn_object();


    // let transition, delay = determine_next_state

    // From the person, what model did they request?

    // let next_state =

    // Setup their initial state from that model.

    // Execute any delay, loop

    // Select on the broadcast too.

    // Submit stats as we go.

    Ok(())
}

pub enum EventRecord {}

#[derive(Clone, Debug)]
pub enum Signal {
    Stop,
}

async fn execute_inner(
    warmup: Duration,
    test_time: Option<Duration>,
    mut control_rx: broadcast::Receiver<Signal>,
) -> Result<(Instant, Instant), Error> {
    // Delay for warmup time.
    // TODO: Read warmup time from profile.
    tokio::select! {
        _ = tokio::time::sleep(warmup) => {
            // continue.
        }
        _ = control_rx.recv() => {
            // Untill we add other signal types, any event is
            // either Ok(Signal::Stop) or Err(_), both of which indicate
            // we need to stop immediately.
            return Err(Error::Interupt);
        }
    }

    let start = Instant::now();

    if let Some(test_time) = test_time {
        // Wait for some condition (signal, or time).
        tokio::select! {
            _ = tokio::time::sleep(test_time) => {
                // continue.
            }
            _ = control_rx.recv() => {
                // Untill we add other signal types, any event is
                // either Ok(Signal::Stop) or Err(_), both of which indicate
                // we need to stop immediately.
                return Err(Error::Interupt);
            }
        }
    } else {
        let _ = control_rx.recv().await;
    }

    let end = Instant::now();

    return Ok((start, end))
}

pub async fn execute(state: State, control_rx: broadcast::Receiver<Signal>) -> Result<(), Error> {
    // Create a statistics queue.
    let stats_queue = Arc::new(SegQueue::new());

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

        tasks.push(tokio::spawn(actor_person(client, person, c_stats_queue)))
    }

    // TODO: warmup/testtime should be from profile.
    let warmup = Duration::from_secs(10);
    let testtime = None;

    // We run a seperate test inner so we don't have to worry about
    // task spawn/join within our logic.
    execute_inner(
        warmup, testtime, control_rx
    ).await;

    // Join all the tasks.

    for task in tasks {
        let _ = task.await.map_err(|tokio_err| {
            error!(?tokio_err, "Failed to join task");
            Error::Tokio
        })??;
        // The double ? isn't a mistake, it's because this is Result<Result<T, E>, E>
        // and flatten is nightly.
    }

    // Write the time we ended.

    // Process the statistics that occured within the time window.

    // How should we emit the stats? Cool to make a csv that can turn into graphs I guess?

    Ok(())
}
