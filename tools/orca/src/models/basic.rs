use crate::model::{self, ActorModel, ActorRole, Transition, TransitionAction, TransitionResult};

use crate::error::Error;
use crate::run::EventRecord;
use crate::state::*;
use kanidm_client::KanidmClient;

use async_trait::async_trait;

use std::collections::BTreeSet;
use std::time::Duration;

enum State {
    Unauthenticated,
    Authenticated,
    AuthenticatedWithReauth,
}

pub struct ActorBasic {
    state: State,
}

impl ActorBasic {
    pub fn new() -> Self {
        ActorBasic {
            state: State::Unauthenticated,
        }
    }
}

#[async_trait]
impl ActorModel for ActorBasic {
    async fn transition(
        &mut self,
        client: &KanidmClient,
        person: &Person,
    ) -> Result<EventRecord, Error> {
        let transition = self.next_transition(&person.roles);

        if let Some(delay) = transition.delay {
            tokio::time::sleep(delay).await;
        }

        // Once we get to here, we want the transition to go ahead.
        let (result, event) = match transition.action {
            TransitionAction::Login => model::login(client, person).await,
            TransitionAction::Logout => model::logout(client, person).await,
            TransitionAction::PrivilegeReauth => model::privilege_reauth(client, person).await,
            TransitionAction::WriteAttributePersonMail => {
                let mail = format!("{}@example.com", person.username);
                let values = &[mail.as_str()];
                model::person_set_self_mail(client, person, values).await
            }
        }?;

        self.next_state(transition.action, result);

        Ok(event)
    }
}

impl ActorBasic {
    fn next_transition(&mut self, roles: &BTreeSet<ActorRole>) -> Transition {
        match self.state {
            State::Unauthenticated => Transition {
                delay: None,
                action: TransitionAction::Login,
            },
            State::Authenticated => Transition {
                delay: Some(Duration::from_millis(100)),
                action: TransitionAction::PrivilegeReauth,
            },
            State::AuthenticatedWithReauth => {
                if roles.contains(&ActorRole::PeopleSelfWriteMail) {
                    Transition {
                        delay: Some(Duration::from_millis(200)),
                        action: TransitionAction::WriteAttributePersonMail,
                    }
                } else {
                    Transition {
                        delay: Some(Duration::from_secs(5)),
                        action: TransitionAction::Logout,
                    }
                }
            }
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
                TransitionAction::WriteAttributePersonMail,
                TransitionResult::Ok,
            ) => {
                self.state = State::AuthenticatedWithReauth;
            }
            (_, TransitionAction::Logout, TransitionResult::Ok) => {
                self.state = State::Unauthenticated;
            }
            (_, _, TransitionResult::Ok) => {
                unreachable!();
            }
            (_, _, TransitionResult::Error) => {
                self.state = State::Unauthenticated;
            }
        }
    }
}
