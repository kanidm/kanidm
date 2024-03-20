use crate::model::{self, ActorModel, ActorRole, Transition, TransitionAction, TransitionResult};

use crate::error::Error;
use crate::run::EventRecord;
use crate::state::*;
use kanidm_client::KanidmClient;

use async_trait::async_trait;

use std::collections::BTreeSet;
use std::str::FromStr;
use std::time::Duration;

enum State {
    Unauthenticated,
    Authenticated,
    ReadAttribute,
    WroteAttribute,
}

pub struct ActorConditionalReadWrite {
    state: State,
    roles: Vec<ActorRole>,
    role_index: Option<usize>,
}

impl ActorConditionalReadWrite {
    pub fn new(member_of: BTreeSet<String>) -> Self {
        let roles = member_of
            .iter()
            .filter_map(|member| ActorRole::from_str(&member).ok())
            .collect::<Vec<ActorRole>>();
        let role_index = if roles.is_empty() { None } else { Some(0) };
        ActorConditionalReadWrite {
            state: State::Unauthenticated,
            roles,
            role_index,
        }
    }
}

#[async_trait]
impl ActorModel for ActorConditionalReadWrite {
    async fn transition(
        &mut self,
        client: &KanidmClient,
        person: &Person,
    ) -> Result<EventRecord, Error> {
        let transition = self.next_transition();

        if let Some(delay) = transition.delay {
            tokio::time::sleep(delay).await;
        }

        // Once we get to here, we want the transition to go ahead.
        let (result, event) = match transition.action {
            TransitionAction::Login => model::login(client, person).await,
            TransitionAction::ReadAttribute => model::person_get(client, person).await,
            TransitionAction::WriteAttribute => model::person_set(client, person).await,
            TransitionAction::Logout => model::logout(client, person).await,
        }?;

        self.next_state(result);

        Ok(event)
    }
}

impl ActorConditionalReadWrite {
    fn next_transition(&mut self) -> Transition {
        match self.state {
            State::Unauthenticated => Transition {
                delay: None,
                action: TransitionAction::Login,
            },
            State::Authenticated | State::WroteAttribute | State::ReadAttribute => {
                let action = match self.role_index {
                    Some(role_index) => match self.roles[role_index] {
                        ActorRole::ReadAttribute => TransitionAction::ReadAttribute,
                        ActorRole::WriteAttribute => TransitionAction::WriteAttribute,
                    },
                    None => TransitionAction::Logout,
                };

                Transition {
                    delay: Some(Duration::from_millis(100)),
                    action,
                }
            }
        }
    }

    fn next_state(&mut self, result: TransitionResult) {
        // Is this a design flaw? We probably need to know what the state was that we
        // requested to move to?
        match (&self.state, result) {
            (State::Unauthenticated, TransitionResult::Ok) => {
                self.state = State::Authenticated;
            }
            (
                State::Authenticated | State::ReadAttribute | State::WroteAttribute,
                TransitionResult::Ok,
            ) => {
                self.state = match self.role_index {
                    Some(role_index) => match self.roles[role_index] {
                        ActorRole::ReadAttribute => State::ReadAttribute,
                        ActorRole::WriteAttribute => State::WroteAttribute,
                    },
                    None => State::Unauthenticated,
                };
                // only after successfully transitioning to the new state we update the role index
                self.update_role_index();
            }
            (_, TransitionResult::Error) => {
                // do nothing in case of error
            }
        }
    }

    // for the time being this is somewhat contorted, but I believe we won't need this specific function with the probabilistic approach
    // so I'll you leave this here for now
    fn update_role_index(&mut self) {
        //* */ if there are no roles for this actor our index will always be 0!!
        if self.roles.is_empty() {
            return;
        }

        let roles_len = self.roles.len();
        // otherwise what we do is iterate through all the possible roles this person has, and when we get to the last
        // one (that is index roles_len - 1), we assign 'None' to role_index which is interpreted by the transition function
        // as: "nothing to do here, log out". This way each actor cycles through all their duties and then they log out.
        // Once they log out we repeat everything again, so we go from "None" to "Some(0)", which means "do the role at index 0".
        match self.role_index.as_mut() {
            Some(index) => {
                if index == &(roles_len - 1) {
                    self.role_index = None
                } else {
                    *index += 1;
                    *index %= roles_len;
                }
            }
            None => self.role_index = Some(0),
        }
    }
}
