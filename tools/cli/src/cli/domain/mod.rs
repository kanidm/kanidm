use crate::common::OpType;
use crate::{handle_client_error, DomainOpt};
use anyhow::{Context, Error};
use kanidm_proto::internal::ImageValue;
use std::fs::read;

impl DomainOpt {
    pub fn debug(&self) -> bool {
        match self {
            DomainOpt::SetDisplayName(copt) => copt.copt.debug,
            DomainOpt::SetLdapBasedn { copt, .. }
            | DomainOpt::SetImage { copt, .. }
            | DomainOpt::RemoveImage { copt }
            | DomainOpt::SetLdapAllowUnixPasswordBind { copt, .. }
            | DomainOpt::RevokeKey { copt, .. }
            | DomainOpt::Show(copt) => copt.debug,
        }
    }

    pub async fn exec(&self) {
        match self {
            DomainOpt::SetDisplayName(opt) => {
                eprintln!(
                    "Attempting to set the domain's display name to: {:?}",
                    opt.new_display_name
                );
                let client = opt.copt.to_client(OpType::Write).await;
                match client
                    .idm_domain_set_display_name(&opt.new_display_name)
                    .await
                {
                    Ok(_) => println!("Success"),
                    Err(e) => handle_client_error(e, opt.copt.output_mode),
                }
            }
            DomainOpt::SetLdapBasedn { copt, new_basedn } => {
                eprintln!(
                    "Attempting to set the domain's ldap basedn to: {:?}",
                    new_basedn
                );
                let client = copt.to_client(OpType::Write).await;
                match client.idm_domain_set_ldap_basedn(new_basedn).await {
                    Ok(_) => println!("Success"),
                    Err(e) => handle_client_error(e, copt.output_mode),
                }
            }
            DomainOpt::SetLdapAllowUnixPasswordBind { copt, enable } => {
                let client = copt.to_client(OpType::Write).await;
                match client.idm_set_ldap_allow_unix_password_bind(*enable).await {
                    Ok(_) => println!("Success"),
                    Err(e) => handle_client_error(e, copt.output_mode),
                }
            }
            DomainOpt::Show(copt) => {
                let client = copt.to_client(OpType::Read).await;
                match client.idm_domain_get().await {
                    Ok(e) => println!("{}", e),
                    Err(e) => handle_client_error(e, copt.output_mode),
                }
            }
            DomainOpt::RevokeKey { copt, key_id } => {
                let client = copt.to_client(OpType::Write).await;
                match client.idm_domain_revoke_key(key_id).await {
                    Ok(_) => println!("Success"),
                    Err(e) => handle_client_error(e, copt.output_mode),
                }
            }
            DomainOpt::SetImage {
                copt,
                path,
                image_type,
            } => {
                let client = copt.to_client(OpType::Write).await;
                let img_res: Result<ImageValue, Error> = (move || {
                    let file_name = path
                        .file_name()
                        .context("Please pass a file")?
                        .to_str()
                        .context("Path contains non utf-8")?
                        .to_string();

                    let image_type = if let Some(image_type) = image_type {
                        image_type.as_str().try_into().map_err(Error::msg)?
                    } else {
                        path
                            .extension().context("Path has no extension so we can't infer the imageType, or you could pass the optional imageType argument yourself.")?
                            .to_str().context("Path contains invalid utf-8")?
                            .try_into()
                            .map_err(Error::msg)?
                    };

                    let read_res = read(path);
                    match read_res {
                        Ok(data) => Ok(ImageValue::new(file_name, image_type, data)),
                        Err(err) => Err(err).context("Reading error"),
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
                    Err(e) => handle_client_error(e, copt.output_mode),
                }
            }
            DomainOpt::RemoveImage { copt } => {
                let client = copt.to_client(OpType::Write).await;

                match client.idm_domain_delete_image().await {
                    Ok(_) => println!("Success"),
                    Err(e) => handle_client_error(e, copt.output_mode),
                }
            }
        }
    }
}
