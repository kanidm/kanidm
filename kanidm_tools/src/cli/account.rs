use crate::common::CommonOpt;
use crate::password_prompt;
use qrcode::render::unicode;
use qrcode::QrCode;
use std::io;
use structopt::StructOpt;
use time::OffsetDateTime;

use webauthn_authenticator_rs::{u2fhid::U2FHid, WebauthnAuthenticator};

#[derive(Debug, StructOpt)]
pub struct AccountCommonOpt {
    #[structopt()]
    account_id: String,
}

#[derive(Debug, StructOpt)]
pub struct AccountCredentialSet {
    #[structopt(flatten)]
    aopts: AccountCommonOpt,
    #[structopt(flatten)]
    copt: CommonOpt,
}

#[derive(Debug, StructOpt)]
pub struct AccountNamedOpt {
    #[structopt(flatten)]
    aopts: AccountCommonOpt,
    #[structopt(flatten)]
    copt: CommonOpt,
}

#[derive(Debug, StructOpt)]
pub struct AccountNamedExpireDateTimeOpt {
    #[structopt(flatten)]
    aopts: AccountCommonOpt,
    #[structopt(flatten)]
    copt: CommonOpt,
    #[structopt(name = "datetime")]
    /// An rfc3339 time of the format "YYYY-MM-DDTHH:MM:SS+TZ", "2020-09-25T11:22:02+10:00"
    /// or the word "never", "clear" to remove account expiry.
    datetime: String,
}

#[derive(Debug, StructOpt)]
pub struct AccountNamedValidDateTimeOpt {
    #[structopt(flatten)]
    aopts: AccountCommonOpt,
    #[structopt(flatten)]
    copt: CommonOpt,
    #[structopt(name = "datetime")]
    /// An rfc3339 time of the format "YYYY-MM-DDTHH:MM:SS+TZ", "2020-09-25T11:22:02+10:00"
    /// or the word "any", "clear" to remove valid from enforcement.
    datetime: String,
}

#[derive(Debug, StructOpt)]
pub struct AccountNamedTagOpt {
    #[structopt(flatten)]
    aopts: AccountCommonOpt,
    #[structopt(flatten)]
    copt: CommonOpt,
    #[structopt(name = "tag")]
    tag: String,
}

#[derive(Debug, StructOpt)]
pub struct AccountNamedTagPKOpt {
    #[structopt(flatten)]
    aopts: AccountCommonOpt,
    #[structopt(flatten)]
    copt: CommonOpt,
    #[structopt(name = "tag")]
    tag: String,
    #[structopt(name = "pubkey")]
    pubkey: String,
}

#[derive(Debug, StructOpt)]
pub struct AccountCreateOpt {
    #[structopt(flatten)]
    aopts: AccountCommonOpt,
    #[structopt(name = "display_name")]
    display_name: String,
    #[structopt(flatten)]
    copt: CommonOpt,
}

#[derive(Debug, StructOpt)]
pub enum AccountCredential {
    #[structopt(name = "set_password")]
    SetPassword(AccountCredentialSet),
    #[structopt(name = "generate_password")]
    GeneratePassword(AccountCredentialSet),
    #[structopt(name = "register_webauthn")]
    RegisterWebauthn(AccountNamedTagOpt),
    /// Set the TOTP credential of the account. If a TOTP already exists, on a successful
    /// registration, this will replace it.
    #[structopt(name = "set_totp")]
    RegisterTOTP(AccountNamedTagOpt),
    /// Remove TOTP from the account. If no TOTP exists, no action is taken.
    #[structopt(name = "remove_totp")]
    RemoveTOTP(AccountNamedOpt),
}

#[derive(Debug, StructOpt)]
pub enum AccountRadius {
    #[structopt(name = "show_secret")]
    Show(AccountNamedOpt),
    #[structopt(name = "generate_secret")]
    Generate(AccountNamedOpt),
    #[structopt(name = "delete_secret")]
    Delete(AccountNamedOpt),
}

#[derive(Debug, StructOpt)]
pub struct AccountPosixOpt {
    #[structopt(flatten)]
    aopts: AccountCommonOpt,
    #[structopt(long = "gidnumber")]
    gidnumber: Option<u32>,
    #[structopt(long = "shell")]
    shell: Option<String>,
    #[structopt(flatten)]
    copt: CommonOpt,
}

#[derive(Debug, StructOpt)]
pub enum AccountPosix {
    #[structopt(name = "show")]
    Show(AccountNamedOpt),
    #[structopt(name = "set")]
    Set(AccountPosixOpt),
    #[structopt(name = "set_password")]
    SetPassword(AccountNamedOpt),
}

#[derive(Debug, StructOpt)]
pub enum AccountSsh {
    #[structopt(name = "list_publickeys")]
    List(AccountNamedOpt),
    #[structopt(name = "add_publickey")]
    Add(AccountNamedTagPKOpt),
    #[structopt(name = "delete_publickey")]
    Delete(AccountNamedTagOpt),
}

#[derive(Debug, StructOpt)]
pub enum AccountValidity {
    #[structopt(name = "show")]
    Show(AccountNamedOpt),
    #[structopt(name = "expire_at")]
    ExpireAt(AccountNamedExpireDateTimeOpt),
    #[structopt(name = "begin_from")]
    BeginFrom(AccountNamedValidDateTimeOpt),
}

#[derive(Debug, StructOpt)]
pub enum AccountOpt {
    #[structopt(name = "credential")]
    Credential(AccountCredential),
    #[structopt(name = "radius")]
    Radius(AccountRadius),
    #[structopt(name = "posix")]
    Posix(AccountPosix),
    #[structopt(name = "ssh")]
    Ssh(AccountSsh),
    #[structopt(name = "list")]
    List(CommonOpt),
    #[structopt(name = "get")]
    Get(AccountNamedOpt),
    #[structopt(name = "create")]
    Create(AccountCreateOpt),
    #[structopt(name = "delete")]
    Delete(AccountNamedOpt),
    #[structopt(name = "validity")]
    Validity(AccountValidity),
}

impl AccountOpt {
    pub fn debug(&self) -> bool {
        match self {
            AccountOpt::Credential(acopt) => match acopt {
                AccountCredential::SetPassword(acs) => acs.copt.debug,
                AccountCredential::GeneratePassword(acs) => acs.copt.debug,
                AccountCredential::RegisterWebauthn(acs) => acs.copt.debug,
                AccountCredential::RegisterTOTP(acs) => acs.copt.debug,
                AccountCredential::RemoveTOTP(acs) => acs.copt.debug,
            },
            AccountOpt::Radius(acopt) => match acopt {
                AccountRadius::Show(aro) => aro.copt.debug,
                AccountRadius::Generate(aro) => aro.copt.debug,
                AccountRadius::Delete(aro) => aro.copt.debug,
            },
            AccountOpt::Posix(apopt) => match apopt {
                AccountPosix::Show(apo) => apo.copt.debug,
                AccountPosix::Set(apo) => apo.copt.debug,
                AccountPosix::SetPassword(apo) => apo.copt.debug,
            },
            AccountOpt::Ssh(asopt) => match asopt {
                AccountSsh::List(ano) => ano.copt.debug,
                AccountSsh::Add(ano) => ano.copt.debug,
                AccountSsh::Delete(ano) => ano.copt.debug,
            },
            AccountOpt::List(copt) => copt.debug,
            AccountOpt::Get(aopt) => aopt.copt.debug,
            AccountOpt::Delete(aopt) => aopt.copt.debug,
            AccountOpt::Create(aopt) => aopt.copt.debug,
            AccountOpt::Validity(avopt) => match avopt {
                AccountValidity::Show(ano) => ano.copt.debug,
                AccountValidity::ExpireAt(ano) => ano.copt.debug,
                AccountValidity::BeginFrom(ano) => ano.copt.debug,
            },
        }
    }

    pub fn exec(&self) {
        match self {
            // id/cred/primary/set
            AccountOpt::Credential(acopt) => match acopt {
                AccountCredential::SetPassword(acsopt) => {
                    let client = acsopt.copt.to_client();
                    let password = match password_prompt(
                        format!("Enter new password for {}: ", acsopt.aopts.account_id).as_str(),
                    ) {
                        Some(v) => v,
                        None => {
                            println!("Passwords do not match");
                            return;
                        }
                    };

                    if let Err(e) = client.idm_account_primary_credential_set_password(
                        acsopt.aopts.account_id.as_str(),
                        password.as_str(),
                    ) {
                        eprintln!("Error -> {:?}", e);
                    }
                }
                AccountCredential::GeneratePassword(acsopt) => {
                    let client = acsopt.copt.to_client();

                    match client.idm_account_primary_credential_set_generated(
                        acsopt.aopts.account_id.as_str(),
                    ) {
                        Ok(npw) => {
                            println!(
                                "Generated password for {}: {}",
                                acsopt.aopts.account_id, npw
                            );
                        }
                        Err(e) => {
                            eprintln!("Error -> {:?}", e);
                        }
                    }
                }
                AccountCredential::RegisterWebauthn(acsopt) => {
                    let client = acsopt.copt.to_client();

                    let (session, chal) = match client
                        .idm_account_primary_credential_register_webauthn(
                            acsopt.aopts.account_id.as_str(),
                            acsopt.tag.as_str(),
                        ) {
                        Ok(v) => v,
                        Err(e) => {
                            eprintln!("Error Starting Registration -> {:?}", e);
                            return;
                        }
                    };

                    let mut wa = WebauthnAuthenticator::new(U2FHid::new());

                    eprintln!("Your authenticator will now flash for you to interact with.");

                    let rego = match wa.do_registration(client.get_origin(), chal) {
                        Ok(rego) => rego,
                        Err(e) => {
                            eprintln!("Error Signing -> {:?}", e);
                            return;
                        }
                    };

                    match client.idm_account_primary_credential_complete_webuthn_registration(
                        acsopt.aopts.account_id.as_str(),
                        rego,
                        session,
                    ) {
                        Ok(()) => {
                            println!("Webauthn token registration success.");
                        }
                        Err(e) => {
                            eprintln!("Error Completing -> {:?}", e);
                        }
                    }
                }
                AccountCredential::RegisterTOTP(acsopt) => {
                    let client = acsopt.copt.to_client();
                    let (session, tok) = match client.idm_account_primary_credential_generate_totp(
                        acsopt.aopts.account_id.as_str(),
                        acsopt.tag.as_str(),
                    ) {
                        Ok(v) => v,
                        Err(e) => {
                            eprintln!("Error Starting Registration -> {:?}", e);
                            return;
                        }
                    };

                    // display the tok.
                    eprintln!("You should scan the follow QR code with your OTP App.");

                    let code = match QrCode::new(tok.to_uri().as_str()) {
                        Ok(c) => c,
                        Err(e) => {
                            eprintln!("Failed to generate QR code -> {:?}", e);
                            return;
                        }
                    };
                    let image = code
                        .render::<unicode::Dense1x2>()
                        .dark_color(unicode::Dense1x2::Light)
                        .light_color(unicode::Dense1x2::Dark)
                        .build();
                    eprintln!("{}", image);

                    eprintln!("Alternately, you can manually enter the following OTP details:");
                    println!("Account Name: {}", tok.accountname);
                    println!("Issuer: {}", tok.issuer);
                    println!("Algorithm: {}", tok.algo.to_string());
                    println!("Period/Step: {}", tok.step);
                    println!("Secret: {}", tok.get_secret());

                    // prompt for the totp.
                    eprintln!("--------------------------------------------------------------");
                    eprint!(
                        "Enter a TOTP from your authenticator to complete registration: \nTOTP: "
                    );

                    let mut totp_input = String::new();
                    if let Err(e) = io::stdin().read_line(&mut totp_input) {
                        eprintln!("Failed to read from stdin -> {:?}", e);
                        return;
                    };

                    // Convert to a u32.
                    let totp = match u32::from_str_radix(totp_input.trim(), 10) {
                        Ok(v) => v,
                        Err(e) => {
                            eprintln!("Invalid TOTP -> {:?}", e);
                            return;
                        }
                    };

                    match client.idm_account_primary_credential_verify_totp(
                        acsopt.aopts.account_id.as_str(),
                        totp,
                        session,
                    ) {
                        Ok(_) => {
                            println!("TOTP registration success.");
                        }
                        Err(e) => {
                            eprintln!("Error Completing -> {:?}", e);
                        }
                    }
                }
                AccountCredential::RemoveTOTP(acsopt) => {
                    let client = acsopt.copt.to_client();
                    match client.idm_account_primary_credential_remove_totp(
                        acsopt.aopts.account_id.as_str(),
                    ) {
                        Ok(_) => {
                            println!("TOTP removal success.");
                        }
                        Err(e) => {
                            eprintln!("Error Removing TOTP from account -> {:?}", e);
                        }
                    }
                }
            }, // end AccountOpt::Credential
            AccountOpt::Radius(aropt) => match aropt {
                AccountRadius::Show(aopt) => {
                    let client = aopt.copt.to_client();

                    let rcred =
                        client.idm_account_radius_credential_get(aopt.aopts.account_id.as_str());

                    match rcred {
                        Ok(Some(s)) => println!("Radius secret: {}", s),
                        Ok(None) => println!("NO Radius secret"),
                        Err(e) => {
                            eprintln!("Error -> {:?}", e);
                        }
                    }
                }
                AccountRadius::Generate(aopt) => {
                    let client = aopt.copt.to_client();
                    if let Err(e) = client
                        .idm_account_radius_credential_regenerate(aopt.aopts.account_id.as_str())
                    {
                        eprintln!("Error -> {:?}", e);
                    }
                }
                AccountRadius::Delete(aopt) => {
                    let client = aopt.copt.to_client();
                    if let Err(e) =
                        client.idm_account_radius_credential_delete(aopt.aopts.account_id.as_str())
                    {
                        eprintln!("Error -> {:?}", e);
                    }
                }
            }, // end AccountOpt::Radius
            AccountOpt::Posix(apopt) => match apopt {
                AccountPosix::Show(aopt) => {
                    let client = aopt.copt.to_client();
                    match client.idm_account_unix_token_get(aopt.aopts.account_id.as_str()) {
                        Ok(token) => println!("{}", token),
                        Err(e) => {
                            eprintln!("Error -> {:?}", e);
                        }
                    }
                }
                AccountPosix::Set(aopt) => {
                    let client = aopt.copt.to_client();
                    if let Err(e) = client.idm_account_unix_extend(
                        aopt.aopts.account_id.as_str(),
                        aopt.gidnumber,
                        aopt.shell.as_deref(),
                    ) {
                        eprintln!("Error -> {:?}", e);
                    }
                }
                AccountPosix::SetPassword(aopt) => {
                    let client = aopt.copt.to_client();
                    let password = match password_prompt("Enter new unit (sudo) password: ") {
                        Some(v) => v,
                        None => {
                            println!("Passwords do not match");
                            return;
                        }
                    };

                    if let Err(e) = client.idm_account_unix_cred_put(
                        aopt.aopts.account_id.as_str(),
                        password.as_str(),
                    ) {
                        eprintln!("Error -> {:?}", e);
                    }
                }
            }, // end AccountOpt::Posix
            AccountOpt::Ssh(asopt) => match asopt {
                AccountSsh::List(aopt) => {
                    let client = aopt.copt.to_client();

                    match client.idm_account_get_ssh_pubkeys(aopt.aopts.account_id.as_str()) {
                        Ok(pkeys) => pkeys.iter().for_each(|pkey| println!("{}", pkey)),
                        Err(e) => {
                            eprintln!("Error -> {:?}", e);
                        }
                    }
                }
                AccountSsh::Add(aopt) => {
                    let client = aopt.copt.to_client();
                    if let Err(e) = client.idm_account_post_ssh_pubkey(
                        aopt.aopts.account_id.as_str(),
                        aopt.tag.as_str(),
                        aopt.pubkey.as_str(),
                    ) {
                        eprintln!("Error -> {:?}", e);
                    }
                }
                AccountSsh::Delete(aopt) => {
                    let client = aopt.copt.to_client();
                    if let Err(e) = client.idm_account_delete_ssh_pubkey(
                        aopt.aopts.account_id.as_str(),
                        aopt.tag.as_str(),
                    ) {
                        eprintln!("Error -> {:?}", e);
                    }
                }
            }, // end AccountOpt::Ssh
            AccountOpt::List(copt) => {
                let client = copt.to_client();
                match client.idm_account_list() {
                    Ok(r) => r.iter().for_each(|ent| println!("{}", ent)),
                    Err(e) => eprintln!("Error -> {:?}", e),
                }
            }
            AccountOpt::Get(aopt) => {
                let client = aopt.copt.to_client();
                match client.idm_account_get(aopt.aopts.account_id.as_str()) {
                    Ok(Some(e)) => println!("{}", e),
                    Ok(None) => println!("No matching entries"),
                    Err(e) => eprintln!("Error -> {:?}", e),
                }
            }
            AccountOpt::Delete(aopt) => {
                let client = aopt.copt.to_client();
                if let Err(e) = client.idm_account_delete(aopt.aopts.account_id.as_str()) {
                    eprintln!("Error -> {:?}", e)
                }
            }
            AccountOpt::Create(acopt) => {
                let client = acopt.copt.to_client();
                if let Err(e) = client.idm_account_create(
                    acopt.aopts.account_id.as_str(),
                    acopt.display_name.as_str(),
                ) {
                    eprintln!("Error -> {:?}", e)
                }
            }
            AccountOpt::Validity(avopt) => match avopt {
                AccountValidity::Show(ano) => {
                    let client = ano.copt.to_client();

                    let r = client
                        .idm_account_get_attr(ano.aopts.account_id.as_str(), "account_expire")
                        .and_then(|v1| {
                            client
                                .idm_account_get_attr(
                                    ano.aopts.account_id.as_str(),
                                    "account_valid_from",
                                )
                                .map(|v2| (v1, v2))
                        });

                    match r {
                        Ok((ex, vf)) => {
                            if let Some(t) = vf {
                                // Convert the time to local timezone.
                                let t = OffsetDateTime::parse(&t[0], time::Format::Rfc3339)
                                    .map(|odt| {
                                        odt.to_offset(
                                            time::UtcOffset::try_current_local_offset()
                                                .unwrap_or(time::UtcOffset::UTC),
                                        )
                                        .format(time::Format::Rfc3339)
                                    })
                                    .unwrap_or_else(|_| "invalid timestamp".to_string());

                                println!("valid after: {}", t);
                            } else {
                                println!("valid after: any time");
                            }

                            if let Some(t) = ex {
                                let t = OffsetDateTime::parse(&t[0], time::Format::Rfc3339)
                                    .map(|odt| {
                                        odt.to_offset(
                                            time::UtcOffset::try_current_local_offset()
                                                .unwrap_or(time::UtcOffset::UTC),
                                        )
                                        .format(time::Format::Rfc3339)
                                    })
                                    .unwrap_or_else(|_| "invalid timestamp".to_string());
                                println!("expire: {}", t);
                            } else {
                                println!("expire: never");
                            }
                        }
                        Err(e) => eprintln!("Error -> {:?}", e),
                    }
                }
                AccountValidity::ExpireAt(ano) => {
                    let client = ano.copt.to_client();
                    if ano.datetime == "never" || ano.datetime == "clear" {
                        // Unset the value
                        if let Err(e) = client
                            .idm_account_purge_attr(ano.aopts.account_id.as_str(), "account_expire")
                        {
                            eprintln!("Error -> {:?}", e)
                        } else {
                            println!("Success")
                        }
                    } else {
                        if let Err(e) =
                            OffsetDateTime::parse(ano.datetime.as_str(), time::Format::Rfc3339)
                        {
                            eprintln!("Error -> {:?}", e);
                            return;
                        }

                        if let Err(e) = client.idm_account_set_attr(
                            ano.aopts.account_id.as_str(),
                            "account_expire",
                            &[ano.datetime.as_str()],
                        ) {
                            eprintln!("Error -> {:?}", e);
                        } else {
                            println!("Success")
                        }
                    }
                }
                AccountValidity::BeginFrom(ano) => {
                    let client = ano.copt.to_client();
                    if ano.datetime == "any"
                        || ano.datetime == "clear"
                        || ano.datetime == "whenever"
                    {
                        // Unset the value
                        if let Err(e) = client.idm_account_purge_attr(
                            ano.aopts.account_id.as_str(),
                            "account_valid_from",
                        ) {
                            eprintln!("Error -> {:?}", e)
                        } else {
                            println!("Success")
                        }
                    } else {
                        // Attempt to parse and set
                        if let Err(e) =
                            OffsetDateTime::parse(ano.datetime.as_str(), time::Format::Rfc3339)
                        {
                            eprintln!("Error -> {:?}", e);
                            return;
                        }

                        if let Err(e) = client.idm_account_set_attr(
                            ano.aopts.account_id.as_str(),
                            "account_valid_from",
                            &[ano.datetime.as_str()],
                        ) {
                            eprintln!("Error -> {:?}", e);
                        } else {
                            println!("Success")
                        }
                    }
                }
            }, // end AccountOpt::Validity
        }
    }
}
