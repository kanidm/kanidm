use crate::model::{self, ActorModel, ActorRole, Transition, TransitionAction, TransitionResult};

use crate::error::Error;
use crate::run::EventRecord;
use crate::state::*;
use kanidm_client::KanidmClient;

use async_trait::async_trait;

use std::collections::{BTreeSet, VecDeque};
use std::iter;
use std::str::FromStr;
use std::time::Duration;

enum State {
    Unauthenticated,
    AuthenticatedUnpriv,
    AuthenticatedPriv,
    ReadAttribute,
    WroteAttribute,
}

pub struct ActorConditionalReadWrite {
    state: State,
    roles: VecDeque<ActorRole>,
    // ! beware that it MUST NOT contain duplicates otherwise it messes with the state machine, this is currently ensured by the BTreeSet from which
    // ! it's created
}

impl ActorConditionalReadWrite {
    pub fn new(member_of: &BTreeSet<String>) -> Self {
        let roles = member_of
            .iter()
            .filter_map(|member| ActorRole::from_str(member).ok())
            .chain(iter::once(ActorRole::LazyActor))
            // we can add the LazyActor at the end as it can't be already in the list since serialization is disabled for this variant
            .collect::<VecDeque<ActorRole>>();
        ActorConditionalReadWrite {
            state: State::Unauthenticated,
            roles,
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
            TransitionAction::PrivilegeReauth => model::privilege_reauth(client, person).await,
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
            State::AuthenticatedUnpriv | State::WroteAttribute | State::ReadAttribute => {
                let action = match self.roles.front() {
                    Some(actor_role) => match actor_role {
                        ActorRole::AttributeReader => TransitionAction::ReadAttribute,
                        ActorRole::AttributeWriter => TransitionAction::PrivilegeReauth,
                        ActorRole::LazyActor => TransitionAction::Logout,
                    },
                    None => TransitionAction::Logout,
                };

                Transition {
                    delay: Some(Duration::from_millis(100)),
                    action,
                }
            }
            State::AuthenticatedPriv => Transition {
                delay: Some(Duration::from_millis(100)),
                action: TransitionAction::WriteAttribute,
            },
        }
    }

    fn next_state(&mut self, result: TransitionResult) {
        match (&self.state, result) {
            (State::Unauthenticated, TransitionResult::Ok) => {
                self.state = State::AuthenticatedUnpriv;
            }
            (
                State::AuthenticatedUnpriv | State::ReadAttribute | State::WroteAttribute,
                TransitionResult::Ok,
            ) => {
                self.state = match self.roles.front() {
                    Some(role) => match role {
                        ActorRole::AttributeReader => State::ReadAttribute,
                        ActorRole::AttributeWriter => State::AuthenticatedPriv,
                        ActorRole::LazyActor => State::Unauthenticated,
                    },
                    None => State::Unauthenticated,
                };
                self.roles.rotate_right(1); // we rotate the roles queue
            }
            (State::AuthenticatedPriv, TransitionResult::Ok) => self.state = State::WroteAttribute,
            (_, TransitionResult::Error) => {
                // do nothing in case of error
            }
        }
    }
}
