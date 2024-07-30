use crate::error::Error;
use crate::run::{EventDetail, EventRecord};
use crate::state::*;
use std::time::{Duration, Instant};

use kanidm_client::{ClientError, KanidmClient};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

pub enum TransitionAction {
    Login,
    Logout,
    PrivilegeReauth,
    WriteAttributePersonMail,
    ReadSelfAccount,
    ReadSelfMemberOf,
    WriteSelfPassword,
}

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

#[derive(Debug, Clone, Default, Serialize, Deserialize, Eq, PartialEq, Ord, PartialOrd)]
pub enum ActorRole {
    #[default]
    None,
    PeoplePiiReader,
    PeopleSelfMailWrite,
    PeopleSelfReadProfile,
    PeopleSelfReadMemberOf,
    PeopleSelfSetPassword,
    PeopleGroupAdmin,
}

impl ActorRole {
    pub fn requires_membership_to(&self) -> Option<&[&str]> {
        match self {
            ActorRole::None
            | ActorRole::PeopleSelfReadProfile
            | ActorRole::PeopleSelfReadMemberOf
            | ActorRole::PeopleSelfSetPassword => None,
            ActorRole::PeoplePiiReader => Some(&["idm_people_pii_read"]),
            ActorRole::PeopleSelfMailWrite => Some(&["idm_people_self_mail_write"]),
            ActorRole::PeopleGroupAdmin => Some(&["idm_group_admins"]),
        }
    }
}

#[async_trait]
pub trait ActorModel {
    async fn transition(
        &mut self,
        client: &KanidmClient,
        person: &Person,
    ) -> Result<Vec<EventRecord>, Error>;
}

pub async fn login(
    client: &KanidmClient,
    person: &Person,
) -> Result<(TransitionResult, Vec<EventRecord>), Error> {
    // Should we measure the time of each call rather than the time with multiple calls?
    let start = Instant::now();
    let result = match &person.credential {
        Credential::Password { plain } => {
            client
                .auth_simple_password(person.username.as_str(), plain.as_str())
                .await
        }
    };

    let duration = Instant::now().duration_since(start);
    Ok(parse_call_result_into_transition_result_and_event_record(
        result,
        EventDetail::Login,
        start,
        duration,
    ))
}

pub async fn person_set_self_mail(
    client: &KanidmClient,
    person: &Person,
    values: &[&str],
) -> Result<(TransitionResult, Vec<EventRecord>), Error> {
    // Should we measure the time of each call rather than the time with multiple calls?
    let person_username = person.username.as_str();

    let start = Instant::now();
    let result = client
        .idm_person_account_set_attr(person_username, "mail", values)
        .await;

    let duration = Instant::now().duration_since(start);
    let parsed_result = parse_call_result_into_transition_result_and_event_record(
        result,
        EventDetail::PersonSetSelfMail,
        start,
        duration,
    );

    Ok(parsed_result)
}

pub async fn person_create_group(
    client: &KanidmClient,
    group_name: &str,
) -> Result<(TransitionResult, Vec<EventRecord>), Error> {
    let start = Instant::now();
    let result = client.idm_group_create(group_name, None).await;

    let duration = Instant::now().duration_since(start);
    let parsed_result = parse_call_result_into_transition_result_and_event_record(
        result,
        EventDetail::PersonCreateGroup,
        start,
        duration,
    );

    Ok(parsed_result)
}

pub async fn person_add_group_members(
    client: &KanidmClient,
    group_name: &str,
    group_members: &[&str],
) -> Result<(TransitionResult, Vec<EventRecord>), Error> {
    let start = Instant::now();
    let result = client
        .idm_group_add_members(group_name, group_members)
        .await;

    let duration = Instant::now().duration_since(start);
    let parsed_result = parse_call_result_into_transition_result_and_event_record(
        result,
        EventDetail::PersonAddGroupMembers,
        start,
        duration,
    );

    Ok(parsed_result)
}

pub async fn person_set_self_password(
    client: &KanidmClient,
    person: &Person,
    pw: &str,
) -> Result<(TransitionResult, Vec<EventRecord>), Error> {
    // Should we measure the time of each call rather than the time with multiple calls?
    let person_username = person.username.as_str();

    let start = Instant::now();
    let result = client
        .idm_person_account_primary_credential_set_password(person_username, pw)
        .await;

    let duration = Instant::now().duration_since(start);
    let parsed_result = parse_call_result_into_transition_result_and_event_record(
        result,
        EventDetail::PersonSetSelfPassword,
        start,
        duration,
    );

    Ok(parsed_result)
}

pub async fn privilege_reauth(
    client: &KanidmClient,
    person: &Person,
) -> Result<(TransitionResult, Vec<EventRecord>), Error> {
    let start = Instant::now();

    let result = match &person.credential {
        Credential::Password { plain } => client.reauth_simple_password(plain.as_str()).await,
    };

    let duration = Instant::now().duration_since(start);

    let parsed_result = parse_call_result_into_transition_result_and_event_record(
        result,
        EventDetail::PersonReauth,
        start,
        duration,
    );
    Ok(parsed_result)
}

pub async fn logout(
    client: &KanidmClient,
    _person: &Person,
) -> Result<(TransitionResult, Vec<EventRecord>), Error> {
    let start = Instant::now();
    let result = client.logout().await;
    let duration = Instant::now().duration_since(start);

    Ok(parse_call_result_into_transition_result_and_event_record(
        result,
        EventDetail::Logout,
        start,
        duration,
    ))
}

pub async fn person_get_self_account(
    client: &KanidmClient,
    person: &Person,
) -> Result<(TransitionResult, Vec<EventRecord>), Error> {
    let start = Instant::now();
    let result = client.idm_person_account_get(&person.username).await;
    let duration = Instant::now().duration_since(start);
    Ok(parse_call_result_into_transition_result_and_event_record(
        result,
        EventDetail::PersonGetSelfAccount,
        start,
        duration,
    ))
}

pub async fn person_get_self_memberof(
    client: &KanidmClient,
    person: &Person,
) -> Result<(TransitionResult, Vec<EventRecord>), Error> {
    let start = Instant::now();
    let result = client
        .idm_person_account_get_attr(&person.username, "memberof")
        .await;
    let duration = Instant::now().duration_since(start);
    Ok(parse_call_result_into_transition_result_and_event_record(
        result,
        EventDetail::PersonGetSelfMemberOf,
        start,
        duration,
    ))
}

fn parse_call_result_into_transition_result_and_event_record<T>(
    result: Result<T, ClientError>,
    details: EventDetail,
    start: Instant,
    duration: Duration,
) -> (TransitionResult, Vec<EventRecord>) {
    match result {
        Ok(_) => (
            TransitionResult::Ok,
            vec![EventRecord {
                start,
                duration,
                details,
            }],
        ),
        Err(client_err) => {
            debug!(?client_err);
            (
                TransitionResult::Error,
                vec![EventRecord {
                    start,
                    duration,
                    details: EventDetail::Error,
                }],
            )
        }
    }
}
