use crate::model::{self, ActorModel, Transition, TransitionAction, TransitionResult};

use crate::error::Error;
use crate::run::EventRecord;
use crate::state::*;
use kanidm_client::KanidmClient;

use async_trait::async_trait;
use rand::Rng;
use rand_chacha::ChaCha8Rng;

use std::time::Duration;

enum State {
    Unauthenticated,
    Authenticated,
    AuthenticatedWithReauth,
}

pub struct ActorWriter {
    state: State,
    randomised_backoff_time: Duration,
}

impl ActorWriter {
    pub fn new(mut cha_rng: ChaCha8Rng, warmup_time_ms: u64) -> Self {
        let max_backoff_time_in_ms = 2 * warmup_time_ms / 3;
        let randomised_backoff_time =
            Duration::from_millis(cha_rng.random_range(0..max_backoff_time_in_ms));
        ActorWriter {
            state: State::Unauthenticated,
            randomised_backoff_time,
        }
    }
}

#[async_trait]
impl ActorModel for ActorWriter {
    async fn transition(
        &mut self,
        client: &KanidmClient,
        person: &Person,
    ) -> Result<Vec<EventRecord>, Error> {
        let transition = self.next_transition();

        if let Some(delay) = transition.delay {
            tokio::time::sleep(delay).await;
        }

        // Once we get to here, we want the transition to go ahead.
        let (result, event) = match transition.action {
            TransitionAction::Login => model::login(client, person).await,
            TransitionAction::Logout => model::logout(client, person).await,
            TransitionAction::PrivilegeReauth => model::privilege_reauth(client, person).await,
            TransitionAction::ReadSelfMemberOf
            | TransitionAction::ReadSelfAccount
            | TransitionAction::WriteSelfPassword => return Err(Error::InvalidState),
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

impl ActorWriter {
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
                action: TransitionAction::WriteAttributePersonMail,
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
                TransitionAction::WriteAttributePersonMail,
                TransitionResult::Ok,
            ) => self.state = State::AuthenticatedWithReauth,

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
