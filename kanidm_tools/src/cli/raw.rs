use crate::RawOpt;
use kanidm_proto::v1::{Entry, Filter, Modify, ModifyList};
use std::collections::BTreeMap;

use std::error::Error;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;

use serde::de::DeserializeOwned;

fn read_file<T: DeserializeOwned, P: AsRef<Path>>(path: P) -> Result<T, Box<dyn Error>> {
    let f = File::open(path)?;
    let r = BufReader::new(f);

    let t: T = serde_json::from_reader(r)?;
    Ok(t)
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

    pub fn exec(&self) {
        match self {
            RawOpt::Search(sopt) => {
                let client = sopt.commonopts.to_client();

                let filter: Filter = match serde_json::from_str(sopt.filter.as_str()) {
                    Ok(f) => f,
                    Err(e) => {
                        eprintln!("Error -> {:?}", e);
                        return;
                    }
                };

                match client.search(filter) {
                    Ok(rset) => rset.iter().for_each(|e| println!("{}", e)),
                    Err(e) => {
                        eprintln!("Error -> {:?}", e);
                    }
                }
            }
            RawOpt::Create(copt) => {
                let client = copt.commonopts.to_client();
                // Read the file?
                let r_entries: Vec<BTreeMap<String, Vec<String>>> = match read_file(&copt.file) {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!("Error -> {:?}", e);
                        return;
                    }
                };

                let entries = r_entries.into_iter().map(|b| Entry { attrs: b }).collect();

                if let Err(e) = client.create(entries) {
                    eprintln!("Error -> {:?}", e);
                }
            }
            RawOpt::Modify(mopt) => {
                let client = mopt.commonopts.to_client();
                // Read the file?
                let filter: Filter = match serde_json::from_str(mopt.filter.as_str()) {
                    Ok(f) => f,
                    Err(e) => {
                        eprintln!("Error -> {:?}", e);
                        return;
                    }
                };

                let r_list: Vec<Modify> = match read_file(&mopt.file) {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!("Error -> {:?}", e);
                        return;
                    }
                };

                let modlist = ModifyList::new_list(r_list);
                if let Err(e) = client.modify(filter, modlist) {
                    eprintln!("Error -> {:?}", e);
                }
            }
            RawOpt::Delete(dopt) => {
                let client = dopt.commonopts.to_client();
                let filter: Filter = match serde_json::from_str(dopt.filter.as_str()) {
                    Ok(f) => f,
                    Err(e) => {
                        eprintln!("Error -> {:?}", e);
                        return;
                    }
                };

                if let Err(e) = client.delete(filter) {
                    eprintln!("Error -> {:?}", e);
                }
            }
        }
    }
}
