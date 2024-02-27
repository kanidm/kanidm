use crate::error::Error;
use crate::kani::KanidmOrcaClient;
use crate::profile::Profile;
use crate::state::{Credential, Flag, Model, Person, PreflightState, State};
use rand::distributions::{Alphanumeric, DistString};
use rand::seq::SliceRandom;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;

use std::collections::{BTreeMap, BTreeSet};

const PEOPLE_PREFIX: &str = "person";

#[derive(Debug)]
pub struct PartialGroup {
    pub name: String,
    pub members: BTreeSet<String>,
}

fn random_name(prefix: &str, rng: &mut ChaCha8Rng) -> String {
    let suffix = Alphanumeric.sample_string(rng, 8).to_lowercase();
    format!("{}_{}", prefix, suffix)
}

fn random_password(rng: &mut ChaCha8Rng) -> String {
    Alphanumeric.sample_string(rng, 24)
}

pub async fn populate(client: &KanidmOrcaClient, profile: Profile) -> Result<State, Error> {
    // IMPORTANT: We have to perform these steps in order so that the RNG is deterministic between
    // multiple invocations.
    let mut seeded_rng = ChaCha8Rng::seed_from_u64(profile.seed());

    let female_given_names = std::include_str!("../names-dataset/dataset/Female_given_names.txt");
    let male_given_names = std::include_str!("../names-dataset/dataset/Male_given_names.txt");

    let given_names = female_given_names
        .split('\n')
        .chain(male_given_names.split('\n'))
        .collect::<Vec<_>>();

    let surnames = std::include_str!("../names-dataset/dataset/Surnames.txt");

    let surnames = surnames.split('\n').collect::<Vec<_>>();

    debug!(
        "name pool: given: {} - family: {}",
        given_names.len(),
        surnames.len()
    );

    // PHASE 0 - For now, set require MFA off.
    let mut preflight_flags = Vec::new();

    preflight_flags.push(Flag::DisableAllPersonsMFAPolicy);

    // PHASE 1 - generate a pool of persons that are not-yet created for future import.
    // todo! may need a random username vec for later stuff

    // PHASE 2 - generate persons
    //         - assign them credentials of various types.
    let mut persons = Vec::with_capacity(profile.person_count() as usize);
    let mut person_names = BTreeSet::new();

    for _ in 0..profile.person_count() {
        let given_name = given_names
            .choose(&mut seeded_rng)
            .expect("name set corrupted");
        let surname = surnames
            .choose(&mut seeded_rng)
            .expect("name set corrupted");

        let display_name = format!("{} {}", given_name, surname);

        let username = display_name
            .chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .collect::<String>()
            .to_lowercase();

        let mut username = if username.is_empty() {
            random_name(PEOPLE_PREFIX, &mut seeded_rng)
        } else {
            username
        };

        while person_names.contains(&username) {
            username = random_name(PEOPLE_PREFIX, &mut seeded_rng);
        }

        let password = random_password(&mut seeded_rng);

        // TODO: Add more and different "models" to each person for their actions.
        let model = Model::Basic;

        // =======
        // Data is ready, make changes to the server. These should be idempotent if possible.

        let p = Person {
            preflight_state: PreflightState::Present,
            username: username.clone(),
            display_name,
            member_of: BTreeSet::default(),
            credential: Credential::Password { plain: password },
            model,
        };

        debug!(?p);

        person_names.insert(username.clone());
        persons.push(p);
    }

    // PHASE 3 - generate groups for integration access, assign persons.

    // PHASE 4 - generate groups for user modification rights

    // PHASE 5 - generate excess groups with nesting. Randomly assign persons.

    // PHASE 6 - generate integrations -

    // PHASE 7 - given the intergariotns and groupings,

    // Return the state.

    let state = State {
        profile,
        // ---------------
        preflight_flags,
        persons,
    };

    Ok(state)
}
