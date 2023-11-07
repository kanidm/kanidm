use crate::ApiOpt;
use std::io::IsTerminal;

impl ApiOpt {
    pub fn debug(&self) -> bool {
        match self {
            ApiOpt::DownloadSchema(asdo) => asdo.copt.debug,
        }
    }

    pub async fn exec(&self) {
        match self {
            ApiOpt::DownloadSchema(aopt) => {
                let client = aopt.copt.to_unauth_client();
                // check if the output file already exists
                if aopt.filename.exists() {
                    debug!("Output file {} already exists", aopt.filename.display());
                    let mut bail = false;
                    if !aopt.force {
                        // check if we're in a terminal
                        if std::io::stdout().is_terminal()
                            && std::io::stderr().is_terminal()
                            && std::io::stdin().is_terminal()
                        {
                            // validate with the user that it's OK to overwrite
                            let response = match dialoguer::Confirm::new()
                                .with_prompt(format!(
                                    "Output file {} already exists, overwrite?",
                                    aopt.filename.display()
                                ))
                                .interact()
                            {
                                Ok(val) => val,
                                // if it throws an error just trigger false
                                Err(err) => {
                                    eprintln!("Failed to get response from user: {:?}", err);
                                    false
                                }
                            };
                            if !response {
                                bail = true;
                            }
                        } else {
                            debug!("stdin is not a terminal, bailing!");
                            bail = true;
                        }
                        if bail {
                            error!("Output file {} already exists and user hasn't forced overwrite, can't continue!", aopt.filename.display());
                            std::process::exit(1);
                        }
                    }
                }
                let url = client.make_url("/docs/v1/openapi.json");
                debug!(
                    "Downloading schema from {} to {}",
                    url,
                    aopt.filename.display()
                );
                let jsondata: serde_json::Value =
                    match client.perform_get_request("/docs/v1/openapi.json").await {
                        Ok(val) => val,
                        Err(err) => {
                            error!("Failed to download: {:?}", err);
                            std::process::exit(1);
                        }
                    };
                let serialized = match serde_json::to_string_pretty(&jsondata) {
                    Ok(val) => val,
                    Err(err) => {
                        error!("Failed to serialize schema: {:?}", err);
                        std::process::exit(1);
                    }
                };

                match std::fs::write(&aopt.filename, serialized.as_bytes()) {
                    Ok(_) => {
                        info!("Wrote schema to {}", aopt.filename.display());
                    }
                    Err(err) => {
                        error!(
                            "Failed to write schema to {}: {:?}",
                            aopt.filename.display(),
                            err
                        );
                        std::process::exit(1);
                    }
                }
            }
        }
    }
}
