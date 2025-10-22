use crate::{KanidmClientParser, OutputMode, RawOpt};
use kanidm_proto::cli::OpType;
use kanidm_proto::scim_v1::{
    client::{ScimEntryPostGeneric, ScimEntryPutGeneric},
    ScimEntryGetQuery,
};
use serde::de::DeserializeOwned;
use std::error::Error;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;

fn read_file<T: DeserializeOwned, P: AsRef<Path>>(path: P) -> Result<T, Box<dyn Error>> {
    let f = File::open(path)?;
    let r = BufReader::new(f);

    Ok(serde_json::from_reader(r)?)
}

impl RawOpt {
    pub async fn exec(&self, opt: KanidmClientParser) {
        match self {
            RawOpt::Search { filter } => {
                let client = opt.to_client(OpType::Read).await;

                let query = ScimEntryGetQuery {
                    // attributes,
                    // ext_access_check
                    // count
                    // start_index
                    filter: Some(filter.clone()),
                    ..Default::default()
                };

                match client.scim_v1_entry_query(query).await {
                    Ok(rset) => match opt.output_mode {
                        #[allow(clippy::expect_used)]
                        OutputMode::Json => {
                            println!(
                                "{}",
                                serde_json::to_string(&rset).expect("Failed to serialize entry!")
                            )
                        }
                        OutputMode::Text => {
                            println!(
                                "{}",
                                serde_json::to_string_pretty(&rset)
                                    .expect("Failed to serialize entry!")
                            )
                        }
                    },
                    Err(e) => error!("Error -> {:?}", e),
                }
            }
            RawOpt::Create { file } => {
                let client = opt.to_client(OpType::Write).await;
                // Read the file?
                let entry: ScimEntryPostGeneric = match read_file(file) {
                    Ok(r) => r,
                    Err(e) => {
                        error!("Error -> {:?}", e);
                        return;
                    }
                };

                if let Err(e) = client.scim_v1_entry_create(entry).await {
                    error!("Error -> {:?}", e);
                }
            }
            RawOpt::Update { file } => {
                let client = opt.to_client(OpType::Write).await;

                let entry: ScimEntryPutGeneric = match read_file(file) {
                    Ok(r) => r,
                    Err(e) => {
                        error!("Error -> {:?}", e);
                        return;
                    }
                };

                if let Err(e) = client.scim_v1_entry_update(entry).await {
                    error!("Error -> {:?}", e);
                }
            }
            RawOpt::Delete { id } => {
                let client = opt.to_client(OpType::Write).await;

                if let Err(e) = client.scim_v1_entry_delete(id).await {
                    error!("Error -> {:?}", e);
                }
            }
        }
    }
}
