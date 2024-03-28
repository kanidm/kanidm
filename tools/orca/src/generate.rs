use crate::error::Error;
use crate::kani::KanidmOrcaClient;
use crate::model::ActorRole;
use crate::profile::Profile;
use crate::state::{Credential, Flag, Group, Model, Person, PreflightState, State};
use rand::distributions::{Alphanumeric, DistString};
use rand::seq::SliceRandom;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;

use std::borrow::Borrow;
use std::collections::BTreeSet;

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

pub async fn populate(_client: &KanidmOrcaClient, profile: Profile) -> Result<State, Error> {
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
    let preflight_flags = vec![Flag::DisableAllPersonsMFAPolicy];

    // PHASE 1 - generate a pool of persons that are not-yet created for future import.
    // todo! may need a random username vec for later stuff

    // PHASE 2 - generate groups for integration access, assign roles to groups
    // actually these are just groups to decide what each person is supposed to do with their life
    let groups = vec![
        Group::new(
            ActorRole::AttributeReader,
            BTreeSet::from(["idm_people_pii_read".to_string()]),
        ),
        Group::new(
            ActorRole::AttributeWriter,
            BTreeSet::from(["idm_people_self_write_mail".to_string()]),
        ),
    ];

    // PHASE 3 - generate persons
    //         - assign them credentials of various types.
    let mut persons = Vec::with_capacity(profile.person_count() as usize);
    let mut person_usernames = BTreeSet::new();

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

        while person_usernames.contains(&username) {
            username = random_name(PEOPLE_PREFIX, &mut seeded_rng);
        }

        let password = random_password(&mut seeded_rng);

        // //God forbid me but I didn't want to bother with matrixes as input
        // // Bare in mind that actually these probabilities are not so random: the first 4 represent the
        // // prob of each transition if we are in the Unauthenticated state, so we obv will have 0 prob to unauthenticate ourselves,
        // // and also 0 prob to update our account.
        // // The last 4 values refer to the authenticated scenario: here we will have 0 prob to authenticate, since we already did that, but we have some
        // // non-0 prob of doing everything else.
        // let model = Model::Markov {
        //     distributions_matrix: [0.5, 0., 0.5, 0., 0., 0.5, 0.25, 0.25],
        //     rng_seed: None,
        //     normal_dist_mean_and_std_dev: None,
        // };

        let mut member_of = BTreeSet::new();

        let number_of_groups_to_add = seeded_rng.gen_range(0..groups.len());

        for group in groups.choose_multiple(&mut seeded_rng, number_of_groups_to_add) {
            member_of.insert(String::from(Into::<&'static str>::into(
                group.name.borrow(),
            )));
        }

        let model = Model::ConditionalReadWriteAttr {
            member_of: member_of.clone(),
        };
        // =======
        // Data is ready, make changes to the server. These should be idempotent if possible.

        let p = Person {
            preflight_state: PreflightState::Present,
            username: username.clone(),
            display_name,
            member_of,
            credential: Credential::Password { plain: password },
            model,
        };

        debug!(?p);

        person_usernames.insert(username.clone());
        persons.push(p);
    }

    // PHASE 4 - generate groups for user modification rights

    // PHASE 5 - generate excess groups with nesting. Randomly assign persons.

    // PHASE 6 - generate integrations -

    // PHASE 7 - given the integrations and groupings,

    // Return the state.

    let state = State {
        profile,
        // ---------------
        groups,
        preflight_flags,
        persons,
    };

    Ok(state)
}
