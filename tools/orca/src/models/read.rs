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

pub struct ActorReader {
    state: State,
}

impl ActorReader {
    pub fn new() -> Self {
        ActorReader {
            state: State::Unauthenticated,
        }
    }
}

#[async_trait]
impl ActorModel for ActorReader {
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
            TransitionAction::PrivilegeReauth
            | TransitionAction::WriteAttributePersonMail
            | TransitionAction::ReadSelfAccount
            | TransitionAction::WriteSelfPassword => return Err(Error::InvalidState),
            TransitionAction::ReadSelfMemberOf => {
                model::person_get_self_memberof(client, person).await
            }
        }?;

        self.next_state(transition.action, result);

        Ok(event)
    }
}

impl ActorReader {
    fn next_transition(&mut self) -> Transition {
        match self.state {
            State::Unauthenticated => Transition {
                delay: Some(Duration::from_secs(2)),
                action: TransitionAction::Login,
            },
            State::Authenticated => Transition {
                delay: Some(Duration::from_secs(3)),
                action: TransitionAction::ReadSelfMemberOf,
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
            (State::Authenticated, TransitionAction::ReadSelfMemberOf, TransitionResult::Ok) => {
                self.state = State::Authenticated;
            }
            (_, _, TransitionResult::Ok) => unreachable!(),

            (_, _, TransitionResult::Error) => {
                self.state = State::Unauthenticated;
            }
        }
    }
}
