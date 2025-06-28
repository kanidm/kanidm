use crate::common::OpType;
use std::collections::BTreeMap;
use std::error::Error;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;

use kanidm_proto::internal::{Filter, Modify, ModifyList};
use kanidm_proto::v1::Entry;
use serde::de::DeserializeOwned;

use crate::{OutputMode, RawOpt};

fn read_file<T: DeserializeOwned, P: AsRef<Path>>(path: P) -> Result<T, Box<dyn Error>> {
    let f = File::open(path)?;
    let r = BufReader::new(f);

    Ok(serde_json::from_reader(r)?)
}

impl RawOpt {
    pub fn debug(&self) -> bool {
        match self {
            RawOpt::Search(sopt) => sopt.commonopts.debug,
            RawOpt::Create(copt) => copt.commonopts.debug,
            RawOpt::Modify(mopt) => mopt.commonopts.debug,
            RawOpt::Delete(dopt) => dopt.commonopts.debug,
        }
    }

    pub async fn exec(&self) {
        match self {
            RawOpt::Search(sopt) => {
                let client = sopt.commonopts.to_client(OpType::Read).await;

                let filter: Filter = match serde_json::from_str(sopt.filter.as_str()) {
                    Ok(f) => f,
                    Err(e) => {
                        error!("Error parsing filter -> {:?}", e);
                        return;
                    }
                };

                match client.search(filter).await {
                    Ok(rset) => match sopt.commonopts.output_mode {
                        #[allow(clippy::expect_used)]
                        OutputMode::Json => {
                            println!(
                                "{}",
                                serde_json::to_string(&rset).expect("Failed to serialize entry!")
                            )
                        }
                        OutputMode::Text => {
                            rset.iter().for_each(|e| println!("{e}"));
                        }
                    },
                    Err(e) => error!("Error -> {:?}", e),
                }
            }
            RawOpt::Create(copt) => {
                let client = copt.commonopts.to_client(OpType::Write).await;
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
                let client = mopt.commonopts.to_client(OpType::Write).await;
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
            RawOpt::Delete(dopt) => {
                let client = dopt.commonopts.to_client(OpType::Write).await;
                let filter: Filter = match serde_json::from_str(dopt.filter.as_str()) {
                    Ok(f) => f,
                    Err(e) => {
                        error!("Error -> {:?}", e);
                        return;
                    }
                };

                if let Err(e) = client.delete(filter).await {
                    error!("Error -> {:?}", e);
                }
            }
        }
    }
}
