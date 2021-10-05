use crate::Oauth2Opt;

impl Oauth2Opt {
    pub fn debug(&self) -> bool {
        match self {
            Oauth2Opt::List(copt) => copt.debug,
            Oauth2Opt::Get(nopt) => nopt.copt.debug,
            Oauth2Opt::CreateBasic(cbopt) => cbopt.nopt.copt.debug,
            Oauth2Opt::Delete(nopt) => nopt.copt.debug,
        }
    }

    pub fn exec(&self) {
        match self {
            Oauth2Opt::List(copt) => {
                let client = copt.to_client();
                match client.idm_oauth2_rs_list() {
                    Ok(r) => r.iter().for_each(|ent| println!("{}", ent)),
                    Err(e) => eprintln!("Error -> {:?}", e),
                }
            }
            Oauth2Opt::Get(nopt) => {
                let client = nopt.copt.to_client();
                match client.idm_oauth2_rs_get(nopt.name.as_str()) {
                    Ok(Some(e)) => println!("{}", e),
                    Ok(None) => println!("No matching entries"),
                    Err(e) => eprintln!("Error -> {:?}", e),
                }
            }
            Oauth2Opt::CreateBasic(cbopt) => {
                let _client = cbopt.nopt.copt.to_client();
                unimplemented!();
                /*
                match client
                    .idm_oauth2_rs_basic_create(cbopt.nopt.name.as_str(), cbopt.origin.as_str())
                {
                    Ok(_) => println!("Success"),
                    Err(e) => eprintln!("Error -> {:?}", e),
                }
                */
            }
            Oauth2Opt::Delete(nopt) => {
                let client = nopt.copt.to_client();
                match client.idm_oauth2_rs_delete(nopt.name.as_str()) {
                    Ok(_) => println!("Success"),
                    Err(e) => eprintln!("Error -> {:?}", e),
                }
            }
        }
    }
}
