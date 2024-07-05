use crate::model::{self, ActorModel, Transition, TransitionAction, TransitionResult};

use crate::error::Error;
use crate::run::EventRecord;
use crate::state::*;
use kanidm_client::KanidmClient;

use async_trait::async_trait;

use std::time::Duration;

enum State {
    Unauthenticated,
    Authenticated,
}

pub struct ActorAuthOnly {
    state: State,
}

impl ActorAuthOnly {
    pub fn new() -> Self {
        ActorAuthOnly {
            state: State::Unauthenticated,
        }
    }
}

#[async_trait]
impl ActorModel for ActorAuthOnly {
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
            TransitionAction::Logout => model::logout(client, person).await,
            _ => Err(Error::InvalidState),
        }?;

        self.next_state(transition.action, result);

        Ok(event)
    }
}

impl ActorAuthOnly {
    fn next_transition(&mut self) -> Transition {
        match self.state {
            State::Unauthenticated => Transition {
                delay: None,
                action: TransitionAction::Login,
            },
            State::Authenticated => Transition {
                delay: Some(Duration::from_millis(100)),
                action: TransitionAction::Logout,
            },
        }
    }

    fn next_state(&mut self, action: TransitionAction, result: TransitionResult) {
        match (&self.state, action, result) {
            (State::Unauthenticated, TransitionAction::Login, TransitionResult::Ok) => {
                self.state = State::Authenticated;
            }
            (State::Authenticated, TransitionAction::Logout, TransitionResult::Ok) => {
                self.state = State::Unauthenticated;
            }
            // Shouldn't be reachable?
            #[allow(clippy::unreachable)]
            (_, _, TransitionResult::Ok) => {
                unreachable!();
            }
            (_, _, TransitionResult::Error) => {
                self.state = State::Unauthenticated;
            }
        }
    }
}
