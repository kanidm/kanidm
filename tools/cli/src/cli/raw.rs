use kanidm_proto::cli::OpType;
use std::collections::BTreeMap;
use std::error::Error;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use kanidm_proto::scim_v1::ScimEntryGetQuery;
use kanidm_proto::internal::{Filter, Modify, ModifyList};
use kanidm_proto::v1::Entry;
use serde::de::DeserializeOwned;

use crate::{KanidmClientParser, OutputMode, RawOpt};

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
                                serde_json::to_string_pretty(&rset).expect("Failed to serialize entry!")
                            )
                        }
                    },
                    Err(e) => error!("Error -> {:?}", e),
                }
            }
            RawOpt::Create(copt) => {
                let client = opt.to_client(OpType::Write).await;
                // Read the file?
                let r_entries: Vec<BTreeMap<String, Vec<String>>> = match read_file(&copt.file) {
                    Ok(r) => r,
                    Err(e) => {
                        error!("Error -> {:?}", e);
                        return;
                    }
                };

                let entries = r_entries.into_iter().map(|b| Entry { attrs: b }).collect();

                if let Err(e) = client.create(entries).await {
                    error!("Error -> {:?}", e);
                }
            }
            RawOpt::Modify(mopt) => {
                let client = opt.to_client(OpType::Write).await;
                // Read the file?
                let filter: Filter = match serde_json::from_str(mopt.filter.as_str()) {
                    Ok(f) => f,
                    Err(e) => {
                        error!("Error -> {:?}", e);
                        return;
                    }
                };

                let r_list: Vec<Modify> = match read_file(&mopt.file) {
                    Ok(r) => r,
                    Err(e) => {
                        error!("Error -> {:?}", e);
                        return;
                    }
                };

                let modlist = ModifyList::new_list(r_list);
                if let Err(e) = client.modify(filter, modlist).await {
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
