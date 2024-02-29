use crate::error::Error;
use crate::run::{EventDetail, EventRecord};
use crate::state::*;
use std::time::{Duration, Instant};

use kanidm_client::KanidmClient;

use async_trait::async_trait;

use tokio::sync::oneshot;

pub enum TransitionAction {
    Login,
    Logout,
}

// Is this the right way? Should transitions/delay be part of the actor model? Should
// they be responsible.
pub struct Transition {
    pub delay: Option<Duration>,
    pub action: TransitionAction,
}

impl Transition {
    pub fn delay(&self) -> Option<Duration> {
        self.delay
    }
}

pub enum TransitionResult {
    // Success
    Ok,
    // We need to re-authenticate, the session expired.
    // AuthenticationNeeded,
    // An error occured.
    Error,
}

#[async_trait]
pub trait ActorModel {
    async fn transition(
        &mut self,
        client: &KanidmClient,
        person: &Person,
    ) -> Result<EventRecord, Error>;
}

pub async fn login(
    client: &KanidmClient,
    person: &Person,
) -> Result<(TransitionResult, EventRecord), Error> {
    // Should we measure the time of each call rather than the time with multiple calls?
    let start = Instant::now();
    let result = match &person.credential {
        Credential::Password { plain } => {
            client
                .auth_simple_password(person.username.as_str(), plain.as_str())
                .await
        }
    };
    let end = Instant::now();

    let duration = end.duration_since(start);

    match result {
        Ok(_) => Ok((
            TransitionResult::Ok,
            EventRecord {
                start,
                duration,
                details: EventDetail::Authentication,
            },
        )),
        Err(client_err) => {
            debug!(?client_err);
            Ok((
                TransitionResult::Error,
                EventRecord {
                    start,
                    duration,
                    details: EventDetail::Error,
                },
            ))
        }
    }
}

pub async fn logout(
    client: &KanidmClient,
    person: &Person,
) -> Result<(TransitionResult, EventRecord), Error> {
    let start = Instant::now();
    let result = client.logout().await;
    let end = Instant::now();

    let duration = end.duration_since(start);

    match result {
        Ok(_) => Ok((
            TransitionResult::Ok,
            EventRecord {
                start,
                duration,
                details: EventDetail::Logout,
            },
        )),
        Err(client_err) => {
            debug!(?client_err);
            Ok((
                TransitionResult::Error,
                EventRecord {
                    start,
                    duration,
                    details: EventDetail::Error,
                },
            ))
        }
    }
}
