use std::{
    iter,
    str::FromStr,
    time::{Duration, Instant},
};

use async_trait::async_trait;
use idlset::v2::IDLBitRange;

use hashbrown::HashMap;
use kanidm_client::KanidmClient;
use rand::Rng;
use rand_chacha::ChaCha8Rng;

use crate::{
    error::Error,
    model::{self, ActorModel, TransitionResult},
    run::{EventDetail, EventRecord},
    state::Person,
};

pub enum TransitionAction {
    Login,
    PrivilegeReauth,
    CreatePersonalGroup,
    CreateGroup,
    AddCreatedGroupToPersonalGroup,
    CheckPersonalGroupReplicationStatus,
}

// Is this the right way? Should transitions/delay be part of the actor model? Should
// they be responsible.
pub struct Transition {
    pub delay: Option<Duration>,
    pub action: TransitionAction,
}

impl Transition {
    #[allow(dead_code)]
    pub fn delay(&self) -> Option<Duration> {
        self.delay
    }
}

enum State {
    Unauthenticated,
    Authenticated,
    AuthenticatedWithReauth,
    CreatedPersonalGroup,
    CreatedGroup,
    AddedCreatedGroupToPersonalGroup,
    CheckedPersonalGroupReplicationStatus,
}

pub struct ActorLatencyMeasurer {
    state: State,
    randomised_backoff_time: Duration,
    additional_clients: Vec<KanidmClient>,
    group_index: u64,
    personal_group_name: String,
    groups_creation_time: HashMap<u64, Instant>,
    unreplicated_groups_by_client: Vec<IDLBitRange>,
}

impl ActorLatencyMeasurer {
    pub fn new(
        mut cha_rng: ChaCha8Rng,
        additional_clients: Vec<KanidmClient>,
        person_name: &str,
        warmup_time_ms: u64,
    ) -> Result<Self, Error> {
        if additional_clients.is_empty() {
            return Err(Error::InvalidState);
        };
        let additional_clients_len = additional_clients.len();

        let max_backoff_time_in_ms = 2 * warmup_time_ms / 3;
        let randomised_backoff_time =
            Duration::from_millis(cha_rng.gen_range(0..max_backoff_time_in_ms));
        Ok(ActorLatencyMeasurer {
            state: State::Unauthenticated,
            randomised_backoff_time,
            additional_clients,
            group_index: 0,
            personal_group_name: format!("{person_name}-personal-group"),
            groups_creation_time: HashMap::new(),
            unreplicated_groups_by_client: vec![IDLBitRange::new(); additional_clients_len],
        })
    }
}

#[async_trait]
impl ActorModel for ActorLatencyMeasurer {
    async fn transition(
        &mut self,
        client: &KanidmClient,
        person: &Person,
    ) -> Result<Vec<EventRecord>, Error> {
        let transition = self.next_transition();

        if let Some(delay) = transition.delay {
            tokio::time::sleep(delay).await;
        }

        let (result, event) = match transition.action {
            TransitionAction::Login => {
                let mut event_records = Vec::new();
                let mut final_res = TransitionResult::Ok;

                // We need to login on all the instances. Every time one of the login fails, we abort
                for client in iter::once(client).chain(self.additional_clients.iter()) {
                    let (res, more_records) = model::login(client, person).await?;
                    final_res = res;
                    event_records.extend(more_records);
                    if let TransitionResult::Error = final_res {
                        break;
                    }
                }
                Ok((final_res, event_records))
            }
            // PrivilegeReauth is only useful to create new groups, so we just need it on our main client
            TransitionAction::PrivilegeReauth => model::privilege_reauth(client, person).await,
            TransitionAction::CreatePersonalGroup => {
                model::person_create_group(client, &self.personal_group_name).await
            }
            TransitionAction::CreateGroup => {
                self.generate_new_group_name();
                let outcome = model::person_create_group(client, &self.get_group_name()).await;
                // We need to check if the group was successfully created or not, and act accordingly!
                if let Ok((transition_result, _)) = &outcome {
                    if let TransitionResult::Error = transition_result {
                        self.rollback_new_group_name()
                    } else {
                        self.commit_new_group_name()
                    }
                }
                outcome
            }
            TransitionAction::AddCreatedGroupToPersonalGroup => {
                model::person_add_group_members(
                    client,
                    &self.personal_group_name,
                    &[&self.get_group_name()],
                )
                .await
            }
            TransitionAction::CheckPersonalGroupReplicationStatus => {
                let mut event_records = Vec::new();
                let clients_number = self.additional_clients.len();
                for client_index in 0..clients_number {
                    match self.get_replicated_groups_by_client(client_index).await {
                        Ok(replicated_groups) => {
                            let groups_read_time = Instant::now();
                            let repl_event_records = self
                                .parse_replicated_groups_into_replication_event_records(
                                    &replicated_groups,
                                    client_index,
                                    groups_read_time,
                                );
                            event_records.extend(repl_event_records);
                        }
                        Err(event_record) => event_records.push(event_record),
                    };
                }
                // Note for the future folks ending up here: we MUST always return TransitionResult::Ok otherwise we will loop here forever (believe me
                // I know from personal experience). If we loop here we never do TransitionAction::CreateGroup, which is basically the only transition we care
                // about in this model. If you really need to change this then you also need to change the `next_state` function below
                Ok((TransitionResult::Ok, event_records))
            }
        }?;

        self.next_state(transition.action, result);

        Ok(event)
    }
}

impl ActorLatencyMeasurer {
    fn generate_new_group_name(&mut self) {
        self.group_index += 1;
    }

    fn commit_new_group_name(&mut self) {
        self.groups_creation_time
            .insert(self.group_index, Instant::now());
        self.unreplicated_groups_by_client
            .iter_mut()
            .for_each(|c| c.insert_id(self.group_index))
    }

    fn rollback_new_group_name(&mut self) {
        self.group_index -= 1;
    }

    fn get_group_name(&self) -> String {
        format!("{}-{}", &self.personal_group_name, self.group_index)
    }

    async fn get_replicated_groups_by_client(
        &self,
        client_index: usize,
    ) -> Result<Vec<String>, EventRecord> {
        let start = Instant::now();
        let replicated_groups = self.additional_clients[client_index]
            .idm_group_get_members(&self.personal_group_name)
            .await;
        let duration = Instant::now().duration_since(start);

        match replicated_groups {
            Err(client_err) => {
                debug!(?client_err);
                Err(EventRecord {
                    start,
                    duration,
                    details: EventDetail::Error,
                })
            }
            Ok(maybe_replicated_groups) => Ok(maybe_replicated_groups.unwrap_or_default()),
        }
    }

    fn parse_replicated_groups_into_replication_event_records(
        &mut self,
        replicated_group_names: &[String],
        client_index: usize,
        groups_read_time: Instant,
    ) -> Vec<EventRecord> {
        let group_id_from_group_name =
            |group_name: &String| u64::from_str(group_name.split(&['-', '@']).nth(3)?).ok();

        let replicated_group_ids: Vec<u64> = replicated_group_names
            .iter()
            .filter_map(group_id_from_group_name)
            .collect();
        // We just create a more efficient set to store the replicated group ids. This will be useful later
        let replicated_group_ids_set = IDLBitRange::from_iter(replicated_group_ids);

        // The newly_replicated_groups contains all replicated groups that have been spotted for the first time in the given client (determined by client_index);
        // It is the union of the set of groups we created and up to this point assumed were unreplicated (which is stored in unreplicated_groups_by_client) and
        // the set of groups we have just observed to be replicated, stored in replicated_group_names.
        let newly_replicated_groups =
            &replicated_group_ids_set & &self.unreplicated_groups_by_client[client_index];

        // Once we have these newly replicated groups, we remove them from the unreplicated_groups_by_client, as we now know they have indeed been replicated,
        // and therefore have no place in unreplicated_groups_by_client.
        for group_id in newly_replicated_groups.into_iter() {
            self.unreplicated_groups_by_client[client_index].remove_id(group_id)
        }

        newly_replicated_groups
            .into_iter()
            .filter_map(|group| {
                Some(self.create_replication_delay_event_record(
                    *self.groups_creation_time.get(&group)?,
                    groups_read_time,
                ))
            })
            .collect()
    }

    fn create_replication_delay_event_record(
        &self,
        creation_time: Instant,
        read_time: Instant,
    ) -> EventRecord {
        EventRecord {
            start: creation_time,
            duration: read_time.duration_since(creation_time),
            details: EventDetail::GroupReplicationDelay,
        }
    }

    fn next_transition(&mut self) -> Transition {
        match self.state {
            State::Unauthenticated => Transition {
                delay: Some(self.randomised_backoff_time),
                action: TransitionAction::Login,
            },
            State::Authenticated => Transition {
                delay: Some(Duration::from_secs(2)),
                action: TransitionAction::PrivilegeReauth,
            },
            State::AuthenticatedWithReauth => Transition {
                delay: Some(Duration::from_secs(1)),
                action: TransitionAction::CreatePersonalGroup,
            },
            State::CreatedPersonalGroup => Transition {
                delay: Some(Duration::from_secs(1)),
                action: TransitionAction::CreateGroup,
            },
            State::CreatedGroup => Transition {
                delay: None,
                action: TransitionAction::AddCreatedGroupToPersonalGroup,
            },
            State::AddedCreatedGroupToPersonalGroup => Transition {
                delay: None,
                action: TransitionAction::CheckPersonalGroupReplicationStatus,
            },
            State::CheckedPersonalGroupReplicationStatus => Transition {
                delay: Some(Duration::from_secs(1)),
                action: TransitionAction::CreateGroup,
            },
        }
    }

    fn next_state(&mut self, action: TransitionAction, result: TransitionResult) {
        // Is this a design flaw? We probably need to know what the state was that we
        // requested to move to?
        match (&self.state, action, result) {
            (State::Unauthenticated, TransitionAction::Login, TransitionResult::Ok) => {
                self.state = State::Authenticated;
            }
            (State::Authenticated, TransitionAction::PrivilegeReauth, TransitionResult::Ok) => {
                self.state = State::AuthenticatedWithReauth;
            }
            (
                State::AuthenticatedWithReauth,
                TransitionAction::CreatePersonalGroup,
                TransitionResult::Ok,
            ) => self.state = State::CreatedPersonalGroup,
            (State::CreatedPersonalGroup, TransitionAction::CreateGroup, TransitionResult::Ok) => {
                self.state = State::CreatedGroup
            }
            (
                State::CreatedGroup,
                TransitionAction::AddCreatedGroupToPersonalGroup,
                TransitionResult::Ok,
            ) => self.state = State::AddedCreatedGroupToPersonalGroup,
            (
                State::AddedCreatedGroupToPersonalGroup,
                TransitionAction::CheckPersonalGroupReplicationStatus,
                TransitionResult::Ok,
            ) => self.state = State::CheckedPersonalGroupReplicationStatus,
            (
                State::CheckedPersonalGroupReplicationStatus,
                TransitionAction::CreateGroup,
                TransitionResult::Ok,
            ) => self.state = State::CreatedGroup,

            #[allow(clippy::unreachable)]
            (_, _, TransitionResult::Ok) => {
                unreachable!();
            }
            (_, _, TransitionResult::Error) => {
                // If an error occurred we don't do anything, aka we remain on the same state we were before and we try again
            }
        }
    }
}
