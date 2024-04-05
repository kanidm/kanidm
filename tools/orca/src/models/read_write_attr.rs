use crate::model::{self, ActorModel, Transition, TransitionAction, TransitionResult};

use crate::error::Error;
use crate::run::EventRecord;
use crate::state::*;
use kanidm_client::KanidmClient;

use async_trait::async_trait;

use std::time::Duration;

enum State {
    Unauthenticated,
    AuthenticatedUnpriv,
    ReadAttribute,
    AuthenticatedPriv,
    WroteAttribute,
}

pub struct ActorReadWrite {
    state: State,
}

impl ActorReadWrite {
    pub fn new() -> Self {
        ActorReadWrite {
            state: State::Unauthenticated,
        }
    }
}

#[async_trait]
impl ActorModel for ActorReadWrite {
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
            TransitionAction::PrivilegeReauth => model::privilege_reauth(client, person).await,
            TransitionAction::WriteAttribute => model::person_set(client, person).await,
            TransitionAction::Logout => model::logout(client, person).await,
        }?;

        // Given the result, make a choice about what text.
        self.next_state(result);

        Ok(event)
    }
}

impl ActorReadWrite {
    fn next_transition(&mut self) -> Transition {
        match self.state {
            State::Unauthenticated => Transition {
                delay: None,
                action: TransitionAction::Login,
            },
            State::AuthenticatedUnpriv => Transition {
                delay: Some(Duration::from_millis(100)),
                action: TransitionAction::ReadAttribute,
            },
            State::ReadAttribute => Transition {
                delay: None,
                action: TransitionAction::PrivilegeReauth,
            },
            State::AuthenticatedPriv => Transition {
                delay: None,
                action: TransitionAction::WriteAttribute,
            },
            State::WroteAttribute => Transition {
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
                self.state = State::AuthenticatedUnpriv;
            }

            (State::AuthenticatedUnpriv, TransitionResult::Ok) => {
                self.state = State::ReadAttribute;
            }
            (State::ReadAttribute, TransitionResult::Ok) => self.state = State::AuthenticatedPriv,
            (State::AuthenticatedPriv, TransitionResult::Ok) => self.state = State::WroteAttribute,
            (State::WroteAttribute, TransitionResult::Ok) => self.state = State::Unauthenticated,
            (_, TransitionResult::Error) => self.state = State::WroteAttribute,
        }
    }
}
