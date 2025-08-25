use crate::{handle_client_error, DomainOpt, KanidmClientParser};
use anyhow::{Context, Error};
use kanidm_proto::{cli::OpType, internal::ImageValue};
use std::fs::read;

impl DomainOpt {
    pub async fn exec(&self, opt: KanidmClientParser) {
        match self {
            DomainOpt::SetDisplayname(dopt) => {
                eprintln!(
                    "Attempting to set the domain's display name to: {:?}",
                    dopt.new_display_name
                );
                let client = opt.to_client(OpType::Write).await;
                match client
                    .idm_domain_set_display_name(&dopt.new_display_name)
                    .await
                {
                    Ok(_) => println!("Success"),
                    Err(e) => handle_client_error(e, opt.output_mode),
                }
            }
            DomainOpt::SetLdapMaxQueryableAttrs {
                new_max_queryable_attrs,
            } => {
                eprintln!(
                    "Attempting to set the maximum number of queryable LDAP attributes to: {new_max_queryable_attrs:?}"
                );
                let client = opt.to_client(OpType::Write).await;
                match client
                    .idm_domain_set_ldap_max_queryable_attrs(*new_max_queryable_attrs)
                    .await
                {
                    Ok(_) => println!("Success"),
                    Err(e) => handle_client_error(e, opt.output_mode),
                }
            }
            DomainOpt::SetLdapBasedn { new_basedn } => {
                eprintln!("Attempting to set the domain's ldap basedn to: {new_basedn:?}");
                let client = opt.to_client(OpType::Write).await;
                match client.idm_domain_set_ldap_basedn(new_basedn).await {
                    Ok(_) => println!("Success"),
                    Err(e) => handle_client_error(e, opt.output_mode),
                }
            }
            DomainOpt::SetLdapAllowUnixPasswordBind { enable } => {
                let client = opt.to_client(OpType::Write).await;
                match client.idm_set_ldap_allow_unix_password_bind(*enable).await {
                    Ok(_) => println!("Success"),
                    Err(e) => handle_client_error(e, opt.output_mode),
                }
            }
            DomainOpt::SetAllowEasterEggs { enable } => {
                let client = opt.to_client(OpType::Write).await;
                match client.idm_set_domain_allow_easter_eggs(*enable).await {
                    Ok(_) => {
                        if *enable {
                            println!("Success 🎉 🥚 🎉")
                        } else {
                            println!("Success")
                        }
                    }
                    Err(e) => handle_client_error(e, opt.output_mode),
                }
            }
            DomainOpt::Show => {
                let client = opt.to_client(OpType::Read).await;
                match client.idm_domain_get().await {
                    Ok(e) => println!("{e}"),
                    Err(e) => handle_client_error(e, opt.output_mode),
                }
            }
            DomainOpt::RevokeKey { key_id } => {
                let client = opt.to_client(OpType::Write).await;
                match client.idm_domain_revoke_key(key_id).await {
                    Ok(_) => println!("Success"),
                    Err(e) => handle_client_error(e, opt.output_mode),
                }
            }
            DomainOpt::SetImage { path, image_type } => {
                let client = opt.to_client(OpType::Write).await;
                let img_res: Result<ImageValue, Error> = (move || {
                    let file_name = path
                        .file_name()
                        .context("Please pass a file")?
                        .to_str()
                        .context("Path contains non utf-8")?
                        .to_string();

                    let image_type = match image_type {
                        Some(val) => val.clone(),
                        None => {
                        path
                            .extension().context("Path has no extension so we can't infer the imageType, or you could pass the optional imageType argument yourself.")?
                            .to_str().context("Path contains invalid utf-8")?
                            .try_into()
                            .map_err(Error::msg)?
                        }
                    };

                    let read_res = read(path);
                    match read_res {
                        Ok(data) => Ok(ImageValue::new(file_name, image_type, data)),
                        Err(err) => {
                            if opt.debug {
                                eprintln!(
                                    "{}",
                                    kanidm_lib_file_permissions::diagnose_path(path.as_ref())
                                );
                            }
                            Err(err).context(format!("Failed to read file at '{}'", path.display()))
                        }
                    }
                })();

                let img = match img_res {
                    Ok(img) => img,
                    Err(err) => {
                        eprintln!("{err}");
                        return;
                    }
                };

                match client.idm_domain_update_image(img).await {
                    Ok(_) => println!("Success"),
                    Err(e) => handle_client_error(e, opt.output_mode),
                }
            }
            DomainOpt::RemoveImage => {
                let client = opt.to_client(OpType::Write).await;

                match client.idm_domain_delete_image().await {
                    Ok(_) => println!("Success"),
                    Err(e) => handle_client_error(e, opt.output_mode),
                }
            }
        }
    }
}
