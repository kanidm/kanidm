use crate::Oauth2Opt;

impl Oauth2Opt {
    pub fn debug(&self) -> bool {
        match self {
            Oauth2Opt::List(copt) => copt.debug,
            Oauth2Opt::Get(nopt) => nopt.copt.debug,
            Oauth2Opt::CreateBasic(cbopt) => cbopt.nopt.copt.debug,
            Oauth2Opt::SetImplictScopes(cbopt) => cbopt.nopt.copt.debug,
            Oauth2Opt::CreateScopeMap(cbopt) => cbopt.nopt.copt.debug,
            Oauth2Opt::DeleteScopeMap(cbopt) => cbopt.nopt.copt.debug,
            Oauth2Opt::ResetSecrets(cbopt) => cbopt.copt.debug,
            Oauth2Opt::Delete(nopt) => nopt.copt.debug,
            Oauth2Opt::EnablePkce(nopt) => nopt.copt.debug,
            Oauth2Opt::DisablePkce(nopt) => nopt.copt.debug,
            Oauth2Opt::EnableLegacyCrypto(nopt) => nopt.copt.debug,
            Oauth2Opt::DisableLegacyCrypto(nopt) => nopt.copt.debug,
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
                let client = cbopt.nopt.copt.to_client();
                match client.idm_oauth2_rs_basic_create(
                    cbopt.nopt.name.as_str(),
                    cbopt.displayname.as_str(),
                    cbopt.origin.as_str(),
                ) {
                    Ok(_) => println!("Success"),
                    Err(e) => eprintln!("Error -> {:?}", e),
                }
            }
            Oauth2Opt::SetImplictScopes(cbopt) => {
                let client = cbopt.nopt.copt.to_client();
                match client.idm_oauth2_rs_update(
                    cbopt.nopt.name.as_str(),
                    None,
                    None,
                    None,
                    Some(cbopt.scopes.iter().map(|s| s.as_str()).collect()),
                    false,
                    false,
                    false,
                ) {
                    Ok(_) => println!("Success"),
                    Err(e) => eprintln!("Error -> {:?}", e),
                }
            }
            Oauth2Opt::CreateScopeMap(cbopt) => {
                let client = cbopt.nopt.copt.to_client();
                match client.idm_oauth2_rs_create_scope_map(
                    cbopt.nopt.name.as_str(),
                    cbopt.group.as_str(),
                    cbopt.scopes.iter().map(|s| s.as_str()).collect(),
                ) {
                    Ok(_) => println!("Success"),
                    Err(e) => eprintln!("Error -> {:?}", e),
                }
            }
            Oauth2Opt::DeleteScopeMap(cbopt) => {
                let client = cbopt.nopt.copt.to_client();
                match client
                    .idm_oauth2_rs_delete_scope_map(cbopt.nopt.name.as_str(), cbopt.group.as_str())
                {
                    Ok(_) => println!("Success"),
                    Err(e) => eprintln!("Error -> {:?}", e),
                }
            }
            Oauth2Opt::ResetSecrets(cbopt) => {
                let client = cbopt.copt.to_client();
                match client.idm_oauth2_rs_update(
                    cbopt.name.as_str(),
                    None,
                    None,
                    None,
                    None,
                    true,
                    true,
                    true,
                ) {
                    Ok(_) => println!("Success"),
                    Err(e) => eprintln!("Error -> {:?}", e),
                }
            }
            Oauth2Opt::Delete(nopt) => {
                let client = nopt.copt.to_client();
                match client.idm_oauth2_rs_delete(nopt.name.as_str()) {
                    Ok(_) => println!("Success"),
                    Err(e) => eprintln!("Error -> {:?}", e),
                }
            }
            Oauth2Opt::EnablePkce(nopt) => {
                let client = nopt.copt.to_client();
                match client.idm_oauth2_rs_enable_pkce(nopt.name.as_str()) {
                    Ok(_) => println!("Success"),
                    Err(e) => eprintln!("Error -> {:?}", e),
                }
            }
            Oauth2Opt::DisablePkce(nopt) => {
                let client = nopt.copt.to_client();
                match client.idm_oauth2_rs_disable_pkce(nopt.name.as_str()) {
                    Ok(_) => println!("Success"),
                    Err(e) => eprintln!("Error -> {:?}", e),
                }
            }
            Oauth2Opt::EnableLegacyCrypto(nopt) => {
                let client = nopt.copt.to_client();
                match client.idm_oauth2_rs_enable_legacy_crypto(nopt.name.as_str()) {
                    Ok(_) => println!("Success"),
                    Err(e) => eprintln!("Error -> {:?}", e),
                }
            }
            Oauth2Opt::DisableLegacyCrypto(nopt) => {
                let client = nopt.copt.to_client();
                match client.idm_oauth2_rs_disable_legacy_crypto(nopt.name.as_str()) {
                    Ok(_) => println!("Success"),
                    Err(e) => eprintln!("Error -> {:?}", e),
                }
            }
        }
    }
}
