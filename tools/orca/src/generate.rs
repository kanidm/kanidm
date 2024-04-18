use crate::error::Error;
use crate::kani::KanidmOrcaClient;
use crate::model::ActorRole;
use crate::profile::Profile;
use crate::state::{Credential, Flag, Group, Model, Person, PreflightState, State};
use rand::distributions::{Alphanumeric, DistString, Uniform};
use rand::seq::{index, SliceRandom};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;

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

    // PHASE 2 - generate groups for integration access, assign roles to groups.
    // These decide what each person is supposed to do with their life.
    let mut groups = vec![
        Group {
            name: "role_people_pii_reader".to_string(),
            role: ActorRole::PeoplePiiReader,
            ..Default::default()
        },
        Group {
            name: "role_people_self_write_mail".to_string(),
            role: ActorRole::PeopleSelfWriteMail,
            ..Default::default()
        },
        Group {
            name: "role_people_self_read_account".to_string(),
            role: ActorRole::PeopleSelfReadProfile,
            ..Default::default()
        },
        Group {
            name: "role_people_self_read_memberof".to_string(),
            role: ActorRole::PeopleSelfReadMemberOf,
            ..Default::default()
        },
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

        let roles = BTreeSet::new();

        let model = Model::Basic;

        // Data is ready, make changes to the server. These should be idempotent if possible.
        let p = Person {
            preflight_state: PreflightState::Present,
            username: username.clone(),
            display_name,
            roles,
            credential: Credential::Password { plain: password },
            model,
        };

        debug!(?p);

        person_usernames.insert(username.clone());
        persons.push(p);
    }

    // Now, assign persons to roles.
    //
    // We do this by iterating through our roles, and then assigning
    // them a baseline of required accounts with some variation. This
    // way in each test it's guaranteed that *at least* one person
    // to each role always will exist and be operational.

    for group in groups.iter_mut() {
        // For now, our baseline is 20%. We can adjust this in future per
        // role for example.
        let baseline = persons.len() / 5;
        let inverse = persons.len() - baseline;
        // Randomly add extra from the inverse
        let extra = Uniform::new(0, inverse);
        let persons_to_choose = baseline + seeded_rng.sample(extra);

        assert!(persons_to_choose <= persons.len());

        debug!(?persons_to_choose);

        let person_index = index::sample(&mut seeded_rng, persons.len(), persons_to_choose);

        // Order doesn't matter, lets optimise for linear lookup.
        let mut person_index = person_index.into_vec();
        person_index.sort_unstable();

        for p_idx in person_index {
            let person = persons.get_mut(p_idx).unwrap();

            // Add the person to the group.
            group.members.insert(person.username.clone());

            // Add the reverse links, this allows the person in the test
            // to know their roles
            person.roles.insert(group.role.clone());
        }
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
