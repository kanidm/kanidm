use crate::error::Error;
use crate::kani;
use crate::state::*;
use std::collections::VecDeque;

use std::sync::atomic::{AtomicU32, Ordering};
use tokio::sync::Mutex;

use std::sync::Arc;

async fn apply_flags(client: Arc<kani::KanidmOrcaClient>, flags: &[Flag]) -> Result<(), Error> {
    for flag in flags {
        match flag {
            Flag::DisableAllPersonsMFAPolicy => client.disable_mfa_requirement().await?,
        }
    }
    Ok(())
}

async fn preflight_person(
    client: Arc<kani::KanidmOrcaClient>,
    person: Person,
) -> Result<(), Error> {
    debug!(?person);

    if client.person_exists(&person.username).await? {
        // Do nothing? Do we need to reset them later?
        return Ok(());
    } else {
        client
            .person_create(&person.username, &person.display_name)
            .await?;
    }

    match &person.credential {
        Credential::Password { plain } => {
            client
                .person_set_primary_password_only(&person.username, plain)
                .await?;
        }
    }

    // For each role we are part of, did we have other permissions required to fufil that?
    for role in &person.roles {
        if let Some(need_groups) = role.requires_membership_to() {
            for group_name in need_groups {
                client
                    .group_add_members(group_name, &[person.username.as_str()])
                    .await?;
            }
        }
    }

    Ok(())
}

async fn preflight_group(client: Arc<kani::KanidmOrcaClient>, group: Group) -> Result<(), Error> {
    if client.group_exists(group.name.as_str()).await? {
        // Do nothing? Do we need to reset them later?
    } else {
        client.group_create(group.name.as_str()).await?;
    }

    // We can submit all the members in one go.

    let members = group.members.iter().map(|s| s.as_str()).collect::<Vec<_>>();

    client
        .group_set_members(group.name.as_str(), members.as_slice())
        .await?;

    Ok(())
}

pub async fn preflight(state: State) -> Result<(), Error> {
    // Get the admin client.
    let client = Arc::new(kani::KanidmOrcaClient::new(&state.profile).await?);

    // Apply any flags if they exist.
    apply_flags(client.clone(), state.preflight_flags.as_slice()).await?;

    let state_persons_len = state.persons.len();
    let mut tasks = VecDeque::with_capacity(state_persons_len);

    // Create persons.
    for person in state.persons.into_iter() {
        let c = client.clone();
        // While writes are single threaded in Kanidm, searches (such as .exists)
        // and credential updates are concurrent / parallel. So these parts can be
        // called in parallel, so we divide up into workers.
        tasks.push_back(preflight_person(c, person))
    }

    let tasks = Arc::new(Mutex::new(tasks));
    let counter = Arc::new(AtomicU32::new(0));
    let par = std::thread::available_parallelism().unwrap();

    let handles: Vec<_> = (0..par.into())
        .map(|_| {
            let tasks_q = tasks.clone();
            let counter_c = counter.clone();
            tokio::spawn(async move {
                loop {
                    let maybe_task = async {
                        let mut guard = tasks_q.lock().await;
                        guard.pop_front()
                    }
                    .await;

                    if let Some(t) = maybe_task {
                        let _ = t.await;
                        let was = counter_c.fetch_add(1, Ordering::Relaxed);
                        if was % 1000 == 999 {
                            let order = was + 1;
                            eprint!("{}", order);
                        } else if was % 100 == 99 {
                            // Since we just added one, this just rolled over.
                            eprint!(".");
                        }
                    } else {
                        // queue drained.
                        break;
                    }
                }
            })
        })
        .collect();

    for handle in handles {
        handle.await.map_err(|tokio_err| {
            error!(?tokio_err, "Failed to join task");
            Error::Tokio
        })?;
    }

    eprintln!("done");

    // Create groups.
    let counter = Arc::new(AtomicU32::new(0));
    let mut tasks = Vec::with_capacity(state.groups.len());

    for group in state.groups.into_iter() {
        let c = client.clone();
        // Write operations are single threaded in Kanidm, so we don't need to attempt
        // to parallelise that here.
        // tasks.push(tokio::spawn(preflight_group(c, group)))
        tasks.push(preflight_group(c, group))
    }

    for task in tasks {
        task.await?;
        let was = counter.fetch_add(1, Ordering::Relaxed);
        if was % 1000 == 999 {
            let order = was + 1;
            eprint!("{}", order);
        } else if was % 100 == 99 {
            // Since we just added one, this just rolled over.
            eprint!(".");
        }
    }

    eprintln!("done");

    // Create integrations.

    info!("Ready to 🛫");
    Ok(())
}
