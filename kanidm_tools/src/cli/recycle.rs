use crate::RecycleOpt;

impl RecycleOpt {
    pub fn debug(&self) -> bool {
        match self {
            RecycleOpt::List(copt) => copt.debug,
            RecycleOpt::Get(nopt) => nopt.copt.debug,
            RecycleOpt::Revive(nopt) => nopt.copt.debug,
        }
    }

    pub fn exec(&self) {
        match self {
            RecycleOpt::List(copt) => {
                let client = copt.to_client();
                match client.recycle_bin_list() {
                    Ok(r) => r.iter().for_each(|e| println!("{}", e)),
                    Err(e) => {
                        eprintln!("Error -> {:?}", e);
                    }
                }
            }
            RecycleOpt::Get(nopt) => {
                let client = nopt.copt.to_client();
                match client.recycle_bin_get(nopt.name.as_str()) {
                    Ok(Some(e)) => println!("{}", e),
                    Ok(None) => println!("No matching entries"),
                    Err(e) => {
                        eprintln!("Error -> {:?}", e);
                    }
                }
            }
            RecycleOpt::Revive(nopt) => {
                let client = nopt.copt.to_client();
                if let Err(e) = client.recycle_bin_revive(nopt.name.as_str()) {
                    eprintln!("Error -> {:?}", e);
                }
            }
        }
    }
}
