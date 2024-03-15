use crate::model::{self, ActorModel, ActorRole, Transition, TransitionAction, TransitionResult};

use crate::error::Error;
use crate::run::EventRecord;
use crate::state::*;
use kanidm_client::KanidmClient;

use async_trait::async_trait;

use std::time::Duration;

enum State {
    Unauthenticated,
    Authenticated,
    ReadAttribute,
    WroteAttribute,
}

pub struct ActorConditionalReadWrite {
    state: State,
    role: ActorRole,
}

impl ActorConditionalReadWrite {
    pub fn new(role: ActorRole) -> Self {
        ActorConditionalReadWrite {
            state: State::Unauthenticated,
            role,
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
            _ => Err(Error::InvalidState),
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
            State::Authenticated => {
                let action = match self.role {
                    ActorRole::ReadAttribute => TransitionAction::ReadAttribute,
                    ActorRole::WriteAttribute => TransitionAction::WriteAttribute,
                };
                Transition {
                    delay: Some(Duration::from_millis(100)),
                    action,
                }
            }
            State::WroteAttribute | State::ReadAttribute => Transition {
                delay: Some(Duration::from_millis(500)),
                action: TransitionAction::Logout,
            },
        }
    }

    fn next_state(&mut self, result: TransitionResult) {
        // Is this a design flaw? We probably need to know what the state was that we
        // requested to move to?
        match (&self.state, result) {
            (State::Unauthenticated, TransitionResult::Ok) => {
                self.state = State::Authenticated;
            }
            (State::Unauthenticated, TransitionResult::Error) => {
                self.state = State::Unauthenticated;
            }
            (State::Authenticated, TransitionResult::Ok) => {
                self.state = match self.role {
                    ActorRole::ReadAttribute => State::ReadAttribute,
                    ActorRole::WriteAttribute => State::WroteAttribute,
                }
            }
            (State::Authenticated, TransitionResult::Error) => {
                self.state = State::Authenticated;
            }
            (State::ReadAttribute, TransitionResult::Ok) => self.state = State::Unauthenticated,
            (State::ReadAttribute, TransitionResult::Error) => self.state = State::ReadAttribute,
            (State::WroteAttribute, TransitionResult::Ok) => self.state = State::Unauthenticated,
            (State::WroteAttribute, TransitionResult::Error) => self.state = State::WroteAttribute,
            _ => {}
        }
    }
}
