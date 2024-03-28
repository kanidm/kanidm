use crate::error::Error;
use crate::model::{ActorModel, ActorRole};
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

#[derive(Debug, Serialize, Deserialize)]
pub enum PreflightState {
    Present,
    Absent,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub enum Model {
    /// This is a "hardcoded" model that just authenticates and searches
    #[default]
    Basic,
    // Markov {
    //     distributions_matrix: [f64; DISTR_MATRIX_SIZE],
    //     rng_seed: Option<u64>,
    //     normal_dist_mean_and_std_dev: Option<(f64, f64)>,
    // },
    ReadWriteAttr,
    ConditionalReadWriteAttr {
        member_of: BTreeSet<String>,
    },
}

impl Model {
    pub fn as_dyn_object(&self) -> Result<Box<dyn ActorModel + Send>, Error> {
        Ok(match self {
            Model::Basic => Box::new(crate::models::basic::ActorBasic::new()),
            // Model::Markov {
            //     distributions_matrix,
            //     rng_seed,
            //     normal_dist_mean_and_std_dev,
            // } => Box::new(crate::models::markov::ActorMarkov::new(
            //     distributions_matrix,
            //     rng_seed,
            //     normal_dist_mean_and_std_dev,
            // )?),
            Model::ReadWriteAttr => Box::new(crate::models::read_write_attr::ActorReadWrite::new()),
            Model::ConditionalReadWriteAttr { member_of } => Box::new(
                crate::models::conditional_read_write_attr::ActorConditionalReadWrite::new(
                    member_of,
                ),
            ),
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
    pub credential: Credential,
    pub model: Model,
}

#[derive(Debug, Serialize, Deserialize)]

pub struct Group {
    pub name: ActorRole,
    pub member_of: BTreeSet<String>,
}

impl Group {
    pub fn new(name: ActorRole, member_of: BTreeSet<String>) -> Self {
        Group { name, member_of }
    }
}
