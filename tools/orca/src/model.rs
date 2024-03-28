use crate::error::Error;
use crate::run::{EventDetail, EventRecord, EventRecords};
use crate::state::*;
use std::time::{Duration, Instant};

use kanidm_client::{ClientError, KanidmClient};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use strum::{EnumString, IntoStaticStr};

// #[derive(EnumCount)]
pub enum TransitionAction {
    Login = 0,
    Logout = 1,
    ReadAttribute = 2,
    WriteAttribute = 3,
}

// impl TryFrom<i32> for TransitionAction {
//     type Error = ();
//     // TODO: avoid future tech debt with this simple trick: don't write each entry manually
//     fn try_from(v: i32) -> Result<Self, Self::Error> {
//         match v {
//             x if x == TransitionAction::Login as i32 => Ok(TransitionAction::Login),
//             x if x == TransitionAction::Logout as i32 => Ok(TransitionAction::Logout),
//             x if x == TransitionAction::ReadAttribute as i32 => Ok(TransitionAction::ReadAttribute),
//             x if x == TransitionAction::WriteAttribute as i32 => {
//                 Ok(TransitionAction::WriteAttribute)
//             }
//             _ => Err(()),
//         }
//     }
// }

// Is this the right way? Should transitions/delay be part of the actor model? Should
// they be responsible.
pub struct Transition {
    pub delay: Option<Duration>,
    pub action: TransitionAction,
}

impl Transition {
    #[allow(dead_code)]
    pub fn delay(&self) -> Option<Duration> {
        self.delay
    }
}

pub enum TransitionResult {
    // Success
    Ok,
    // We need to re-authenticate, the session expired.
    // AuthenticationNeeded,
    // An error occurred.
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize, EnumString, IntoStaticStr)]
pub enum ActorRole {
    AttributeReader,
    AttributeWriter,
}

#[async_trait]
pub trait ActorModel {
    async fn transition(
        &mut self,
        client: &KanidmClient,
        person: &Person,
    ) -> Result<EventRecords, Error>;
}

pub async fn login(
    client: &KanidmClient,
    person: &Person,
) -> Result<(TransitionResult, EventRecords), Error> {
    // Should we measure the time of each call rather than the time with multiple calls?
    let start = Instant::now();
    let result = match &person.credential {
        Credential::Password { plain } => {
            client
                .auth_simple_password(person.username.as_str(), plain.as_str())
                .await
        }
    };
    Ok(parse_call_result_into_transition_result_and_event_records(
        result,
        EventDetail::Login,
        start,
        None,
    ))
}

pub async fn person_get(
    client: &KanidmClient,
    _person: &Person,
) -> Result<(TransitionResult, EventRecords), Error> {
    // Should we measure the time of each call rather than the time with multiple calls?
    let start = Instant::now();
    let result = client.idm_person_account_get("idm_admin").await;
    Ok(parse_call_result_into_transition_result_and_event_records(
        result,
        EventDetail::PersonGet,
        start,
        None,
    ))
}

pub async fn person_set(
    client: &KanidmClient,
    person: &Person,
) -> Result<(TransitionResult, EventRecords), Error> {
    // Should we measure the time of each call rather than the time with multiple calls?
    let start = Instant::now();
    let person_username = person.username.as_str();

    let result = match &person.credential {
        Credential::Password { plain } => client.reauth_simple_password(plain.as_str()).await,
    };

    let first_parsed_result = parse_call_result_into_transition_result_and_event_records(
        result,
        EventDetail::PersonReauth,
        start,
        None,
    );

    if let TransitionResult::Error = first_parsed_result.0 {
        return Ok(first_parsed_result);
    };

    let start = Instant::now();
    let result = client
        .idm_person_account_set_attr(
            person_username,
            "mail",
            &[&format!("{person_username}@localhost.it")],
        )
        .await;

    let final_outcome = parse_call_result_into_transition_result_and_event_records(
        result,
        EventDetail::PersonSet,
        start,
        Some(first_parsed_result.1),
    );

    Ok(final_outcome)
}

pub async fn logout(
    client: &KanidmClient,
    _person: &Person,
) -> Result<(TransitionResult, EventRecords), Error> {
    let start = Instant::now();
    let result = client.logout().await;

    Ok(parse_call_result_into_transition_result_and_event_records(
        result,
        EventDetail::Logout,
        start,
        None,
    ))
}

fn parse_call_result_into_transition_result_and_event_records<T>(
    result: Result<T, ClientError>,
    details: EventDetail,
    start: Instant,
    previous_records: Option<EventRecords>,
) -> (TransitionResult, EventRecords) {
    let get_new_event_records = |new_record: EventRecord| match previous_records {
        None => EventRecords::SingleEvent(new_record),
        Some(previous_records) => {
            let records_vec = match previous_records {
                EventRecords::SingleEvent(previous_record) => vec![previous_record, new_record],
                EventRecords::MultipleEvents(mut previous_records) => {
                    previous_records.push(new_record);
                    previous_records
                }
            };
            EventRecords::MultipleEvents(records_vec)
        }
    };
    let duration = Instant::now().duration_since(start);

    match result {
        Ok(_) => (
            TransitionResult::Ok,
            get_new_event_records(EventRecord {
                start,
                duration,
                details,
            }),
        ),
        Err(client_err) => {
            debug!(?client_err);
            (
                TransitionResult::Error,
                get_new_event_records(EventRecord {
                    start,
                    duration,
                    details: EventDetail::Error,
                }),
            )
        }
    }
}
// pub async fn fetch_next_action(
//     client: &KanidmClient,
//     person: &Person,
// ) -> Result<(TransitionResult, EventRecord), Error> {
//     let start = Instant::now();
//     let result = client
//         .idm_person_account_get_attr(&person.username, "memberof")
//         .await;
//     let end = Instant::now();

//     let duration = end.duration_since(start);

//     match result {
//         Ok(res) => Ok(if let Some(groups) = res {
//             let (transition_result, details) =
//                 parse_groups_into_transition_result_and_event_details(&groups);
//             (
//                 transition_result,
//                 EventRecord {
//                     start,
//                     duration,
//                     details,
//                 },
//             )
//         } else {
//             (
//                 TransitionResult::Error,
//                 EventRecord {
//                     start,
//                     duration,
//                     details: EventDetail::Error,
//                 },
//             )
//         }),
//         Err(client_err) => {
//             debug!(?client_err);
//             Ok((
//                 TransitionResult::Error,
//                 EventRecord {
//                     start,
//                     duration,
//                     details: EventDetail::Error,
//                 },
//             ))
//         }
//     }
// }

// fn parse_groups_into_transition_result_and_event_details(
//     groups: &Vec<String>,
// ) -> (TransitionResult, EventDetail) {
//     for group in groups {
//         if let Ok(role) = ActorRole::from_str(group) {
//             return (
//                 TransitionResult::OkWithRole(role.clone()),
//                 EventDetail::from(role),
//             );
//         };
//     }
//     return (TransitionResult::Error, EventDetail::Error);
// }

// #[cfg(test)]
// mod test {
//     use super::TransitionAction;
//     use strum::EnumCount;

//     #[test]
//     fn transition_action_try_from_test() {
//         for i in 0..TransitionAction::COUNT {
//             let transition_action = TransitionAction::try_from(i as i32);
//             assert!(transition_action.is_ok());
//             assert_eq!(transition_action.unwrap() as usize, i);
//         }
//     }
// }
