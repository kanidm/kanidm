use crate::error::Error;
use crate::kani;
use crate::state::*;

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
    } else {
        client
            .person_create(&person.username, &person.display_name)
            .await?;
    }

    match &person.credential {
        Credential::Password { plain } => {
            client
                .person_set_pirmary_password_only(&person.username, plain)
                .await?;
        }
    }

    Ok(())
}

pub async fn preflight(state: State) -> Result<(), Error> {
    // Get the admin client.
    let client = Arc::new(kani::KanidmOrcaClient::new(&state.profile).await?);

    // Apply any flags if they exist.
    apply_flags(client.clone(), state.preflight_flags.as_slice()).await?;

    // Create persons.
    let mut tasks = Vec::with_capacity(state.persons.len());
    for person in state.persons.into_iter() {
        let c = client.clone();
        tasks.push(tokio::spawn(preflight_person(c, person)))
    }

    for task in tasks {
        task.await.map_err(|tokio_err| {
            error!(?tokio_err, "Failed to join task");
            Error::Tokio
        })??;
        // The double ? isn't a mistake, it's because this is Result<Result<T, E>, E>
        // and flatten is nightly.
    }

    // Create groups.

    // Create integrations.

    info!("Ready to 🛫");
    Ok(())
}
