use crate::state::*;
use crate::error::Error;

use rand::SeedableRng;
use rand::seq::SliceRandom;
use rand_chacha::ChaCha8Rng;

use kanidm_client::{KanidmClient, KanidmClientBuilder};


async fn actor_person(
    client: KanidmClient,
    person: Person,
) -> Result<(), Error> {
    // From the person, what model did they request?

    // Setup their initial state from that model.

    // Execute any delay, loop

    // Select on the broadcast too.

    // Submit stats as we go.


    Ok(())
}



pub async fn execute(
    state: State,
) -> Result<(), Error> {

    // Create a statistics queue.
    // let stats_queue = crossbeam::queue::SegQueue;

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
        .collect::<
            Result<Vec<_>, _>
        >()?;

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

        tasks.push(tokio::spawn(
            actor_person(client, person)
        ))
    }

    // Delay for warmup time.

    // Write the time we started. 

    // Wait for some condition (signal, or time).
    for task in tasks {
        let _ = task.await
            .map_err(|tokio_err| {
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
