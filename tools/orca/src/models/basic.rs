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
    ) -> Result<Vec<EventRecord>, Error> {
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
            TransitionAction::ReadSelfAccount => {
                model::person_get_self_account(client, person).await
            }
            TransitionAction::ReadSelfMemberOf => {
                model::person_get_self_memberof(client, person).await
            }
            TransitionAction::WriteSelfPassword => {
                // I know it's dumb but here we just re-set the same password because it's the simplest thing to do
                let Credential::Password { plain } = &person.credential;
                model::person_set_self_password(client, person, plain).await
            }
        }?;

        self.next_state(transition.action, result);

        Ok(event)
    }
}

impl ActorBasic {
    fn next_transition(&mut self, roles: &BTreeSet<ActorRole>) -> Transition {
        let logout_transition = Transition {
            delay: Some(Duration::from_secs(5)),
            action: TransitionAction::Logout,
        };
        match self.state {
            State::Unauthenticated => Transition {
                delay: Some(Duration::from_secs(15)),
                action: TransitionAction::Login,
            },
            State::Authenticated => Transition {
                delay: Some(Duration::from_secs(10)),
                action: TransitionAction::PrivilegeReauth,
            },
            // Since this is the basic model we don't want to get too fancy and do too many things, but since the struct Person
            // already comes with a BTreeSet of roles we don't want to change that, so we arbitrarily choose to use just the first role
            // (which is always deterministic thanks to the rng seed used to choose the roles)
            State::AuthenticatedWithReauth => match roles.first() {
                Some(role) => match role {
                    ActorRole::PeopleSelfMailWrite => Transition {
                        delay: Some(Duration::from_secs(5)),
                        action: TransitionAction::WriteAttributePersonMail,
                    },
                    ActorRole::PeopleSelfReadProfile => Transition {
                        delay: Some(Duration::from_secs(2)),
                        action: TransitionAction::ReadSelfAccount,
                    },
                    ActorRole::PeopleSelfReadMemberOf => Transition {
                        delay: Some(Duration::from_secs(1)),
                        action: TransitionAction::ReadSelfMemberOf,
                    },
                    ActorRole::PeopleSelfSetPassword => Transition {
                        delay: Some(Duration::from_secs(3)),
                        action: TransitionAction::WriteSelfPassword,
                    },
                    ActorRole::PeoplePiiReader | ActorRole::PeopleGroupAdmin | ActorRole::None => {
                        logout_transition
                    }
                },
                None => logout_transition,
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
                TransitionAction::WriteAttributePersonMail
                | TransitionAction::ReadSelfAccount
                | TransitionAction::ReadSelfMemberOf
                | TransitionAction::WriteSelfPassword,
                TransitionResult::Ok,
            ) => {
                self.state = State::AuthenticatedWithReauth;
            }
            (_, TransitionAction::Logout, TransitionResult::Ok) => {
                self.state = State::Unauthenticated;
            }
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
