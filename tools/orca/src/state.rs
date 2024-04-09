use crate::error::Error;
use crate::model::{ActorModel, ActorRole};
use crate::models;
use crate::profile::Profile;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::Path;
/// A serialisable state representing the content of a kanidm database and potential
/// test content that can be created and modified.
///
/// This is all generated ahead of time before the test so that during the test
/// as minimal calculation as possible is required.
#[derive(Debug, Serialize, Deserialize)]
pub struct State {
    pub profile: Profile,
    // ----------------------------
    pub preflight_flags: Vec<Flag>,
    pub persons: Vec<Person>,
    pub groups: Vec<Group>,
    // oauth_clients: Vec<Oauth2Clients>,
}

impl State {
    pub fn write_to_path(&self, path: &Path) -> Result<(), Error> {
        let output = std::fs::File::create(path).map_err(|io_err| {
            error!(?io_err);
            Error::Io
        })?;

        serde_json::to_writer(output, self).map_err(|json_err| {
            error!(?json_err);
            Error::SerdeJson
        })
    }
}

impl TryFrom<&Path> for State {
    type Error = Error;

    fn try_from(path: &Path) -> Result<Self, Self::Error> {
        let input = std::fs::File::open(path).map_err(|io_err| {
            error!(?io_err);
            Error::Io
        })?;

        serde_json::from_reader(input).map_err(|json_err| {
            error!(?json_err);
            Error::SerdeJson
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Flag {
    DisableAllPersonsMFAPolicy,
}

#[derive(Default, Debug, Serialize, Deserialize)]
pub enum PreflightState {
    #[default]
    Present,
    Absent,
}

/// A model defines *how* an actors makes it's choices. For example the choices
/// could be purely random, they could be a linear pattern, or they could have
/// some set of weights related to choices they make.
///
/// Some models can *restrict* the set of choices that an actor may make.
///
/// This compliments ActorRoles, which define the extended actions an Actor may
/// choose to perform. If ActorRoles are present, the model MAY choose to use
/// these roles to perform extended operations.
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub enum Model {
    /// This is a "hardcoded" model that just authenticates and searches
    AuthOnly,
    /// A simple linear executor that does actions in a loop.
    #[default]
    Basic,
}

impl Model {
    pub fn as_dyn_object(&self) -> Result<Box<dyn ActorModel + Send>, Error> {
        Ok(match self {
            Model::AuthOnly => Box::new(models::auth_only::ActorAuthOnly::new()),
            Model::Basic => Box::new(models::basic::ActorBasic::new()),
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Credential {
    Password { plain: String },
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Person {
    pub preflight_state: PreflightState,
    pub username: String,
    pub display_name: String,
    pub member_of: BTreeSet<String>,
    pub roles: BTreeSet<ActorRole>,
    pub credential: Credential,
    pub model: Model,
}

#[derive(Default, Debug, Serialize, Deserialize)]
pub struct Group {
    pub name: String,
    pub preflight_state: PreflightState,
    pub role: ActorRole,
    pub members: BTreeSet<String>,
}
