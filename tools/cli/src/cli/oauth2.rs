use std::process::exit;

use crate::common::OpType;
use crate::{handle_client_error, Oauth2Opt, OutputMode};

use crate::Oauth2ClaimMapJoin;
use kanidm_proto::internal::Oauth2ClaimMapJoin as ProtoOauth2ClaimMapJoin;

impl Oauth2Opt {
    pub fn debug(&self) -> bool {
        match self {
            Oauth2Opt::List(copt) => copt.debug,
            Oauth2Opt::Get(nopt) => nopt.copt.debug,
            Oauth2Opt::UpdateScopeMap(cbopt) => cbopt.nopt.copt.debug,
            Oauth2Opt::DeleteScopeMap(cbopt) => cbopt.nopt.copt.debug,
            Oauth2Opt::UpdateSupScopeMap(cbopt) => cbopt.nopt.copt.debug,
            Oauth2Opt::DeleteSupScopeMap(cbopt) => cbopt.nopt.copt.debug,
            Oauth2Opt::ResetSecrets(cbopt) => cbopt.copt.debug,
            // Should this be renamed to show client id? client secrets?
            Oauth2Opt::ShowBasicSecret(nopt) => nopt.copt.debug,
            Oauth2Opt::Delete(nopt) => nopt.copt.debug,
            Oauth2Opt::SetDisplayname(cbopt) => cbopt.nopt.copt.debug,
            Oauth2Opt::SetName { nopt, .. } => nopt.copt.debug,
            Oauth2Opt::SetLandingUrl { nopt, .. } => nopt.copt.debug,
            Oauth2Opt::EnablePkce(nopt) => nopt.copt.debug,
            Oauth2Opt::DisablePkce(nopt) => nopt.copt.debug,
            Oauth2Opt::EnableLegacyCrypto(nopt) => nopt.copt.debug,
            Oauth2Opt::DisableLegacyCrypto(nopt) => nopt.copt.debug,
            Oauth2Opt::PreferShortUsername(nopt) => nopt.copt.debug,
            Oauth2Opt::PreferSPNUsername(nopt) => nopt.copt.debug,
            Oauth2Opt::CreateBasic { copt, .. }
            | Oauth2Opt::CreatePublic { copt, .. }
            | Oauth2Opt::UpdateClaimMap { copt, .. }
            | Oauth2Opt::UpdateClaimMapJoin { copt, .. }
            | Oauth2Opt::DeleteClaimMap { copt, .. }
            | Oauth2Opt::EnablePublicLocalhost { copt, .. }
            | Oauth2Opt::DisablePublicLocalhost { copt, .. } => copt.debug,
            // Oauth2Opt::SetOrigin { nopt, .. } => nopt.copt.debug,
        }
    }

    pub async fn exec(&self) {
        match self {
            Oauth2Opt::List(copt) => {
                let client = copt.to_client(OpType::Read).await;
                match client.idm_oauth2_rs_list().await {
                    Ok(r) => match copt.output_mode {
                        OutputMode::Json => {
                            let r_attrs: Vec<_> = r.iter().map(|entry| &entry.attrs).collect();
                            println!(
                                "{}",
                                serde_json::to_string(&r_attrs).expect("Failed to serialise json")
                            );
                        }
                        OutputMode::Text => r.iter().for_each(|ent| println!("{}", ent)),
                    },
                    Err(e) => handle_client_error(e, copt.output_mode),
                }
            }
            Oauth2Opt::Get(nopt) => {
                let client = nopt.copt.to_client(OpType::Read).await;
                match client.idm_oauth2_rs_get(nopt.name.as_str()).await {
                    Ok(Some(e)) => println!("{}", e),
                    Ok(None) => println!("No matching entries"),
                    Err(e) => handle_client_error(e, nopt.copt.output_mode),
                }
            }
            Oauth2Opt::CreateBasic {
                name,
                displayname,
                origin,
                copt,
            } => {
                let client = copt.to_client(OpType::Write).await;
                match client
                    .idm_oauth2_rs_basic_create(
                        name.as_str(),
                        displayname.as_str(),
                        origin.as_str(),
                    )
                    .await
                {
                    Ok(_) => println!("Success"),
                    Err(e) => handle_client_error(e, copt.output_mode),
                }
            }
            Oauth2Opt::CreatePublic {
                name,
                displayname,
                origin,
                copt,
            } => {
                let client = copt.to_client(OpType::Write).await;
                match client
                    .idm_oauth2_rs_public_create(
                        name.as_str(),
                        displayname.as_str(),
                        origin.as_str(),
                    )
                    .await
                {
                    Ok(_) => println!("Success"),
                    Err(e) => handle_client_error(e, copt.output_mode),
                }
            }
            Oauth2Opt::UpdateScopeMap(cbopt) => {
                let client = cbopt.nopt.copt.to_client(OpType::Write).await;
                match client
                    .idm_oauth2_rs_update_scope_map(
                        cbopt.nopt.name.as_str(),
                        cbopt.group.as_str(),
                        cbopt.scopes.iter().map(|s| s.as_str()).collect(),
                    )
                    .await
                {
                    Ok(_) => println!("Success"),
                    Err(e) => handle_client_error(e, cbopt.nopt.copt.output_mode),
                }
            }
            Oauth2Opt::DeleteScopeMap(cbopt) => {
                let client = cbopt.nopt.copt.to_client(OpType::Write).await;
                match client
                    .idm_oauth2_rs_delete_scope_map(cbopt.nopt.name.as_str(), cbopt.group.as_str())
                    .await
                {
                    Ok(_) => println!("Success"),
                    Err(e) => handle_client_error(e, cbopt.nopt.copt.output_mode),
                }
            }
            Oauth2Opt::UpdateSupScopeMap(cbopt) => {
                let client = cbopt.nopt.copt.to_client(OpType::Write).await;
                match client
                    .idm_oauth2_rs_update_sup_scope_map(
                        cbopt.nopt.name.as_str(),
                        cbopt.group.as_str(),
                        cbopt.scopes.iter().map(|s| s.as_str()).collect(),
                    )
                    .await
                {
                    Ok(_) => println!("Success"),
                    Err(e) => {
                        error!("Error -> {:?}", e);
                        exit(1)
                    }
                }
            }
            Oauth2Opt::DeleteSupScopeMap(cbopt) => {
                let client = cbopt.nopt.copt.to_client(OpType::Write).await;
                match client
                    .idm_oauth2_rs_delete_sup_scope_map(
                        cbopt.nopt.name.as_str(),
                        cbopt.group.as_str(),
                    )
                    .await
                {
                    Ok(_) => println!("Success"),
                    Err(e) => handle_client_error(e, cbopt.nopt.copt.output_mode),
                }
            }
            Oauth2Opt::ResetSecrets(cbopt) => {
                let client = cbopt.copt.to_client(OpType::Write).await;
                match client
                    .idm_oauth2_rs_update(cbopt.name.as_str(), None, None, None, true, true, true)
                    .await
                {
                    Ok(_) => println!("Success"),
                    Err(e) => handle_client_error(e, cbopt.copt.output_mode),
                }
            }
            Oauth2Opt::ShowBasicSecret(nopt) => {
                let client = nopt.copt.to_client(OpType::Read).await;
                match client
                    .idm_oauth2_rs_get_basic_secret(nopt.name.as_str())
                    .await
                {
                    Ok(Some(secret)) => {
                        match nopt.copt.output_mode {
                            OutputMode::Text => println!("{}", secret),
                            OutputMode::Json => println!("{{\"secret\": \"{}\"}}", secret),
                        }
                        eprintln!("Success");
                    }
                    Ok(None) => {
                        eprintln!("No secret configured");
                    }
                    Err(e) => handle_client_error(e, nopt.copt.output_mode),
                }
            }
            Oauth2Opt::Delete(nopt) => {
                let client = nopt.copt.to_client(OpType::Write).await;
                match client.idm_oauth2_rs_delete(nopt.name.as_str()).await {
                    Ok(_) => println!("Success"),
                    Err(e) => handle_client_error(e, nopt.copt.output_mode),
                }
            }
            Oauth2Opt::SetDisplayname(cbopt) => {
                let client = cbopt.nopt.copt.to_client(OpType::Write).await;
                match client
                    .idm_oauth2_rs_update(
                        cbopt.nopt.name.as_str(),
                        None,
                        Some(cbopt.displayname.as_str()),
                        None,
                        false,
                        false,
                        false,
                    )
                    .await
                {
                    Ok(_) => println!("Success"),
                    Err(e) => handle_client_error(e, cbopt.nopt.copt.output_mode),
                }
            }
            Oauth2Opt::SetName { nopt, name } => {
                let client = nopt.copt.to_client(OpType::Write).await;
                match client
                    .idm_oauth2_rs_update(
                        nopt.name.as_str(),
                        Some(name.as_str()),
                        None,
                        None,
                        false,
                        false,
                        false,
                    )
                    .await
                {
                    Ok(_) => println!("Success"),
                    Err(e) => handle_client_error(e, nopt.copt.output_mode),
                }
            }
            Oauth2Opt::SetLandingUrl { nopt, url } => {
                let client = nopt.copt.to_client(OpType::Write).await;
                match client
                    .idm_oauth2_rs_update(
                        nopt.name.as_str(),
                        None,
                        None,
                        Some(url),
                        false,
                        false,
                        false,
                    )
                    .await
                {
                    Ok(_) => println!("Success"),
                    Err(e) => handle_client_error(e, nopt.copt.output_mode),
                }
            }
            Oauth2Opt::EnablePkce(nopt) => {
                let client = nopt.copt.to_client(OpType::Write).await;
                match client.idm_oauth2_rs_enable_pkce(nopt.name.as_str()).await {
                    Ok(_) => println!("Success"),
                    Err(e) => handle_client_error(e, nopt.copt.output_mode),
                }
            }
            Oauth2Opt::DisablePkce(nopt) => {
                let client = nopt.copt.to_client(OpType::Write).await;
                match client.idm_oauth2_rs_disable_pkce(nopt.name.as_str()).await {
                    Ok(_) => println!("Success"),
                    Err(e) => handle_client_error(e, nopt.copt.output_mode),
                }
            }
            Oauth2Opt::EnableLegacyCrypto(nopt) => {
                let client = nopt.copt.to_client(OpType::Write).await;
                match client
                    .idm_oauth2_rs_enable_legacy_crypto(nopt.name.as_str())
                    .await
                {
                    Ok(_) => println!("Success"),
                    Err(e) => handle_client_error(e, nopt.copt.output_mode),
                }
            }
            Oauth2Opt::DisableLegacyCrypto(nopt) => {
                let client = nopt.copt.to_client(OpType::Write).await;
                match client
                    .idm_oauth2_rs_disable_legacy_crypto(nopt.name.as_str())
                    .await
                {
                    Ok(_) => println!("Success"),
                    Err(e) => handle_client_error(e, nopt.copt.output_mode),
                }
            }
            Oauth2Opt::PreferShortUsername(nopt) => {
                let client = nopt.copt.to_client(OpType::Write).await;
                match client
                    .idm_oauth2_rs_prefer_short_username(nopt.name.as_str())
                    .await
                {
                    Ok(_) => println!("Success"),
                    Err(e) => handle_client_error(e, nopt.copt.output_mode),
                }
            }
            Oauth2Opt::PreferSPNUsername(nopt) => {
                let client = nopt.copt.to_client(OpType::Write).await;
                match client
                    .idm_oauth2_rs_prefer_spn_username(nopt.name.as_str())
                    .await
                {
                    Ok(_) => println!("Success"),
                    Err(e) => handle_client_error(e, nopt.copt.output_mode),
                }
            }
            /*
            Oauth2Opt::SetOrigin { nopt, origin } => {
                let client = nopt.copt.to_client(OpType::Write).await;
                match client
                    .idm_oauth2_rs_update(
                        &nopt.name,
                        None,
                        None,
                        Some(origin),
                        None,
                        false,
                        false,
                        false,
                    )
                    .await
                {
                    Ok(_) => println!("Success"),
                    Err(e) => handle_client_error(e, nopt.copt.output_mode),
                }
            }
            */
            Oauth2Opt::UpdateClaimMap {
                copt,
                name,
                group,
                claim_name,
                values,
            } => {
                let client = copt.to_client(OpType::Write).await;
                match client
                    .idm_oauth2_rs_update_claim_map(
                        name.as_str(),
                        claim_name.as_str(),
                        group.as_str(),
                        values,
                    )
                    .await
                {
                    Ok(_) => println!("Success"),
                    Err(e) => handle_client_error(e, copt.output_mode),
                }
            }
            Oauth2Opt::UpdateClaimMapJoin {
                copt,
                name,
                claim_name,
                join,
            } => {
                let client = copt.to_client(OpType::Write).await;

                let join = match join {
                    Oauth2ClaimMapJoin::Csv => ProtoOauth2ClaimMapJoin::Csv,
                    Oauth2ClaimMapJoin::Ssv => ProtoOauth2ClaimMapJoin::Ssv,
                    Oauth2ClaimMapJoin::Array => ProtoOauth2ClaimMapJoin::Array,
                };

                match client
                    .idm_oauth2_rs_update_claim_map_join(name.as_str(), claim_name.as_str(), join)
                    .await
                {
                    Ok(_) => println!("Success"),
                    Err(e) => handle_client_error(e, copt.output_mode),
                }
            }
            Oauth2Opt::DeleteClaimMap {
                copt,
                name,
                claim_name,
                group,
            } => {
                let client = copt.to_client(OpType::Write).await;
                match client
                    .idm_oauth2_rs_delete_claim_map(
                        name.as_str(),
                        claim_name.as_str(),
                        group.as_str(),
                    )
                    .await
                {
                    Ok(_) => println!("Success"),
                    Err(e) => handle_client_error(e, copt.output_mode),
                }
            }

            Oauth2Opt::EnablePublicLocalhost { copt, name } => {
                let client = copt.to_client(OpType::Write).await;
                match client
                    .idm_oauth2_rs_enable_public_localhost_redirect(name.as_str())
                    .await
                {
                    Ok(_) => println!("Success"),
                    Err(e) => handle_client_error(e, copt.output_mode),
                }
            }

            Oauth2Opt::DisablePublicLocalhost { copt, name } => {
                let client = copt.to_client(OpType::Write).await;
                match client
                    .idm_oauth2_rs_disable_public_localhost_redirect(name.as_str())
                    .await
                {
                    Ok(_) => println!("Success"),
                    Err(e) => handle_client_error(e, copt.output_mode),
                }
            }
        }
    }
}
