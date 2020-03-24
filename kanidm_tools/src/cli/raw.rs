use std::collections::BTreeMap;

#[derive(Debug, StructOpt)]
pub struct FilterOpt {
    #[structopt()]
    filter: String,
    #[structopt(flatten)]
    commonopts: CommonOpt,
}

#[derive(Debug, StructOpt)]
pub struct CreateOpt {
    #[structopt(parse(from_os_str))]
    file: Option<PathBuf>,
    #[structopt(flatten)]
    commonopts: CommonOpt,
}

#[derive(Debug, StructOpt)]
pub struct ModifyOpt {
    #[structopt(flatten)]
    commonopts: CommonOpt,
    #[structopt()]
    filter: String,
    #[structopt(parse(from_os_str))]
    file: Option<PathBuf>,
}

#[derive(Debug, StructOpt)]
pub enum RawOpt {
    #[structopt(name = "search")]
    Search(FilterOpt),
    #[structopt(name = "create")]
    Create(CreateOpt),
    #[structopt(name = "modify")]
    Modify(ModifyOpt),
    #[structopt(name = "delete")]
    Delete(FilterOpt),
}

impl RawOpt {
    pub fn exec(&self) -> () {
        match self {
            RawOpt::Search(sopt) => {
                let client = sopt.commonopts.to_client();

                let filter: Filter = serde_json::from_str(sopt.filter.as_str()).unwrap();
                let rset = client.search(filter).unwrap();

                rset.iter().for_each(|e| {
                    println!("{:?}", e);
                });
            }
            RawOpt::Create(copt) => {
                let client = copt.commonopts.to_client();
                // Read the file?
                match copt.file {
                    Some(p) => {
                        let r_entries: Vec<BTreeMap<String, Vec<String>>> = read_file(p).unwrap();
                        let entries = r_entries.into_iter().map(|b| Entry { attrs: b }).collect();
                        client.create(entries).unwrap()
                    }
                    None => {
                        println!("Must provide a file");
                    }
                }
            }
            RawOpt::Modify(mopt) => {
                let client = mopt.commonopts.to_client();
                // Read the file?
                match mopt.file {
                    Some(p) => {
                        let filter: Filter = serde_json::from_str(mopt.filter.as_str()).unwrap();
                        let r_list: Vec<Modify> = read_file(p).unwrap();
                        let modlist = ModifyList::new_list(r_list);
                        client.modify(filter, modlist).unwrap()
                    }
                    None => {
                        println!("Must provide a file");
                    }
                }
            }
            RawOpt::Delete(dopt) => {
                let client = dopt.commonopts.to_client();
                let filter: Filter = serde_json::from_str(dopt.filter.as_str()).unwrap();
                client.delete(filter).unwrap();
            }
        }
    }
}

