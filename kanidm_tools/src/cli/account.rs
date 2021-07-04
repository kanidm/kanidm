use crate::password_prompt;
use crate::{
    AccountCredential, AccountOpt, AccountPosix, AccountRadius, AccountSsh, AccountValidity,
};
use qrcode::render::unicode;
use qrcode::QrCode;
use std::io;
use time::OffsetDateTime;

use webauthn_authenticator_rs::{u2fhid::U2FHid, WebauthnAuthenticator};

use kanidm_client::ClientError;
use kanidm_client::ClientError::Http as ClientErrorHttp;
use kanidm_proto::v1::OperationError::{PasswordBadListed, PasswordTooShort, PasswordTooWeak};

impl AccountOpt {
    pub fn debug(&self) -> bool {
        match self {
            AccountOpt::Credential(acopt) => match acopt {
                AccountCredential::SetPassword(acs) => acs.copt.debug,
                AccountCredential::GeneratePassword(acs) => acs.copt.debug,
                AccountCredential::RegisterWebauthn(acs) => acs.copt.debug,
                AccountCredential::RemoveWebauthn(acs) => acs.copt.debug,
                AccountCredential::RegisterTotp(acs) => acs.copt.debug,
                AccountCredential::RemoveTotp(acs) => acs.copt.debug,
                AccountCredential::GenerateBackupCode(acs) => acs.copt.debug,
                AccountCredential::BackupCodeRemove(acs) => acs.copt.debug,
                AccountCredential::Status(acs) => acs.copt.debug,
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
                        match e {
                            // TODO: once the password length is configurable at a system level (#498), pull from the configuration.
                            ClientErrorHttp(_, Some(PasswordBadListed), _) => error!("Password is banned by the administrator of this system, please try a different one."),
                            ClientErrorHttp(_, Some(PasswordTooShort(pwminlength)), _) => error!("Password was too short (needs to be at least {} characters), please try again.", pwminlength),
                            ClientErrorHttp(_, Some(PasswordTooWeak), _) => error!("The supplied password did not match configured complexity requirements, please use a password with upper/lower case letters, symbols and digits."),
                            _ => error!("Error setting password -> {:?}", e)
                        }
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
                AccountCredential::RemoveWebauthn(acsopt) => {
                    let client = acsopt.copt.to_client();
                    match client.idm_account_primary_credential_remove_webauthn(
                        acsopt.aopts.account_id.as_str(),
                        acsopt.tag.as_str(),
                    ) {
                        Ok(_) => {
                            println!("Webauthn removal success.");
                        }
                        Err(e) => {
                            eprintln!("Error Removing Webauthn from account -> {:?}", e);
                        }
                    }
                }
                AccountCredential::RegisterTotp(acsopt) => {
                    let client = acsopt.copt.to_client();
                    let (session, tok) = match client.idm_account_primary_credential_generate_totp(
                        acsopt.aopts.account_id.as_str(),
                    ) {
                        Ok(v) => v,
                        Err(e) => {
                            eprintln!("Error Starting Registration -> {:?}", e);
                            return;
                        }
                    };

                    // display the token.
                    eprintln!("Scan the following QR code with your OTP app.");

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

                    eprintln!("Alternatively, you can manually enter the following OTP details:");
                    println!("Account Name: {}", tok.accountname);
                    println!("Issuer: {}", tok.issuer);
                    println!("Algorithm: {}", tok.algo.to_string());
                    println!("Period/Step: {}", tok.step);
                    println!("Secret: {}", tok.get_secret());

                    // prompt for the totp.
                    eprintln!("--------------------------------------------------------------");
                    eprintln!("Enter a TOTP from your authenticator to complete registration:");

                    let mut attempts = 3;
                    while attempts > 0 {
                        eprint!("TOTP: ");
                        let mut totp_input = String::new();
                        let input_result = io::stdin().read_line(&mut totp_input);
                        // Finish the line?
                        eprintln!("");
                        if let Err(e) = input_result {
                            eprintln!("Failed to read from stdin -> {:?}", e);
                            break;
                        };

                        // Convert to a u32.
                        let totp = match u32::from_str_radix(totp_input.trim(), 10) {
                            Ok(v) => v,
                            Err(e) => {
                                eprintln!("Invalid TOTP -> {:?}", e);
                                // Try again.
                                continue;
                            }
                        };

                        match client.idm_account_primary_credential_verify_totp(
                            acsopt.aopts.account_id.as_str(),
                            totp,
                            session,
                        ) {
                            Ok(_) => {
                                println!("TOTP registration success.");
                                break;
                            }
                            Err(ClientError::TotpInvalidSha1(session)) => {
                                eprintln!("⚠️  WARNING - It appears your authenticator app may be broken ⚠️  ");
                                eprintln!(" The TOTP authenticator you are using is forcing the use of SHA1");
                                eprintln!("");
                                eprintln!(" -- If you accept this risk, and wish to proceed, type 'I am sure' ");
                                eprintln!(" -- Otherwise press ENTER to cancel this operation");
                                eprintln!("");
                                eprint!("Are you sure: ");

                                let mut confirm_input = String::new();
                                if let Err(e) = io::stdin().read_line(&mut confirm_input) {
                                    eprintln!("Failed to read from stdin -> {:?}", e);
                                    break;
                                };

                                if confirm_input.to_lowercase().trim() == "i am sure" {
                                    match client.idm_account_primary_credential_accept_sha1_totp(
                                        acsopt.aopts.account_id.as_str(),
                                        session,
                                    ) {
                                        Ok(_) => {
                                            println!("TOTP registration success.");
                                        }
                                        Err(e) => {
                                            eprintln!("Error Completing -> {:?}", e);
                                        }
                                    };
                                    break;
                                } else {
                                    eprintln!("Cancelling TOTP registration");
                                    break;
                                }
                            }
                            Err(ClientError::TotpVerifyFailed(_, _)) => {
                                eprintln!("Incorrect TOTP code - try again");
                                attempts -= 1;
                                continue;
                            }
                            Err(e) => {
                                eprintln!("Error Completing -> {:?}", e);
                                break;
                            }
                        }
                    } // end loop
                }
                AccountCredential::RemoveTotp(acsopt) => {
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
                AccountCredential::GenerateBackupCode(acsopt) => {
                    let client = acsopt.copt.to_client();
                    match client.idm_account_primary_credential_generate_backup_code(
                        acsopt.aopts.account_id.as_str(),
                    ) {
                        Ok(s) => {
                            println!("GenerateBackupCode success.");
                            println!("{:#?}", s);
                        }
                        Err(e) => {
                            eprintln!("Error GenerateBackupCode for account -> {:?}", e);
                        }
                    }
                }
                AccountCredential::BackupCodeRemove(acsopt) => {
                    let client = acsopt.copt.to_client();
                    match client.idm_account_primary_credential_remove_backup_code(
                        acsopt.aopts.account_id.as_str(),
                    ) {
                        Ok(_) => {
                            println!("BackupCodeRemove success.");
                        }
                        Err(e) => {
                            eprintln!("Error BackupCodeRemove for account -> {:?}", e);
                        }
                    }
                }
                AccountCredential::Status(acsopt) => {
                    let client = acsopt.copt.to_client();
                    match client.idm_account_get_credential_status(acsopt.aopts.account_id.as_str())
                    {
                        Ok(status) => {
                            print!("{}", status);
                        }
                        Err(e) => {
                            eprintln!("Error displaying credential status -> {:?}", e);
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
                    if matches!(ano.datetime.as_str(), "never" | "clear") {
                        // Unset the value
                        match client
                            .idm_account_purge_attr(ano.aopts.account_id.as_str(), "account_expire")
                        {
                            Err(e) => eprintln!("Error -> {:?}", e),
                            _ => println!("Success"),
                        }
                    } else {
                        if let Err(e) =
                            OffsetDateTime::parse(ano.datetime.as_str(), time::Format::Rfc3339)
                        {
                            eprintln!("Error -> {:?}", e);
                            return;
                        }

                        match client.idm_account_set_attr(
                            ano.aopts.account_id.as_str(),
                            "account_expire",
                            &[ano.datetime.as_str()],
                        ) {
                            Err(e) => eprintln!("Error -> {:?}", e),
                            _ => println!("Success"),
                        }
                    }
                }
                AccountValidity::BeginFrom(ano) => {
                    let client = ano.copt.to_client();
                    if matches!(ano.datetime.as_str(), "any" | "clear" | "whenever") {
                        // Unset the value
                        match client.idm_account_purge_attr(
                            ano.aopts.account_id.as_str(),
                            "account_valid_from",
                        ) {
                            Err(e) => eprintln!("Error -> {:?}", e),
                            _ => println!("Success"),
                        }
                    } else {
                        // Attempt to parse and set
                        if let Err(e) =
                            OffsetDateTime::parse(ano.datetime.as_str(), time::Format::Rfc3339)
                        {
                            eprintln!("Error -> {:?}", e);
                            return;
                        }

                        match client.idm_account_set_attr(
                            ano.aopts.account_id.as_str(),
                            "account_valid_from",
                            &[ano.datetime.as_str()],
                        ) {
                            Err(e) => eprintln!("Error -> {:?}", e),
                            _ => println!("Success"),
                        }
                    }
                }
            }, // end AccountOpt::Validity
        }
    }
}
