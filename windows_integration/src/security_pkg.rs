use kanidm_client::{KanidmClient, KanidmClientBuilder, ClientError};
use tracing::{event, span, Level};
use windows::Win32::{
    Foundation::{NTSTATUS, STATUS_SUCCESS, STATUS_UNSUCCESSFUL, UNICODE_STRING},
    Security::{Authentication::Identity::{
        LSA_SECPKG_FUNCTION_TABLE, SECPKG_PARAMETERS, SECPKG_PRIMARY_CRED,
        SECPKG_SUPPLEMENTAL_CRED, SECURITY_LOGON_TYPE,
    }, Credentials::STATUS_LOGON_FAILURE},
};
use tokio::runtime::Builder as RuntimeBuilder;

pub static mut GLOBAL_SECURITY_PACKAGE: SecurityPackage = SecurityPackage {
    package_id: None,
    params: None,
    lsa_support_fns: None,
    kani_client: None,
};

pub struct SecurityPackage {
    /// The id of the security package assigned by the LSA
    pub package_id: Option<usize>,
    /// The parameters which contain primary domain & machine state info
    pub params: Option<&'static SECPKG_PARAMETERS>,
    /// The LSA support functions
    pub lsa_support_fns: Option<&'static LSA_SECPKG_FUNCTION_TABLE>,
    /// The kanidm client
    pub kani_client: Option<KanidmClient>,
}

impl SecurityPackage {
    pub fn initialise_package(
        &mut self,
        package_id: usize,
        params: *const SECPKG_PARAMETERS,
        lsa_support_fns: *const LSA_SECPKG_FUNCTION_TABLE,
    ) -> NTSTATUS {
        let init_pkg_span = span!(Level::INFO, "Initialising kanidm security package").entered();

        if self.package_id.is_some() || self.params.is_some() || self.lsa_support_fns.is_some() {
            event!(
                Level::ERROR,
                "kanidm security package has already been initialised"
            );

            return STATUS_UNSUCCESSFUL;
        }

        let func_table_ref = unsafe {
            match lsa_support_fns.as_ref() {
                Some(tbl) => tbl,
                None => {
                    event!(
                        Level::ERROR,
                        "Failed to get reference to the LSA's support functions"
                    );

                    return STATUS_UNSUCCESSFUL;
                }
            }
        };
        let params_ref = unsafe {
            match params.as_ref() {
                Some(prms) => prms,
                None => {
                    event!(Level::ERROR, "Failed to get reference to secpkg parameters");

                    return STATUS_UNSUCCESSFUL;
                }
            }
        };
        let kanidm_client = match KanidmClientBuilder::new().connect_timeout(60u64).build() {
            Ok(client) => client,
            Err(e) => {
                event!(
                    Level::ERROR,
                    "Failed to build client for interacting with kanidm server"
                );
                event!(Level::DEBUG, "KanidmClientBuilderError {}", e);

                return STATUS_UNSUCCESSFUL;
            }
        };

        self.package_id = Some(package_id);
        self.params = Some(params_ref);
        self.lsa_support_fns = Some(func_table_ref);
        self.kani_client = Some(kanidm_client);

        init_pkg_span.exit();
        STATUS_SUCCESS
    }

    pub fn shutdown_package(&mut self) -> NTSTATUS {
        // TODO: Implement cleanup logic when there is resources to clean up

        STATUS_SUCCESS
    }

    pub async fn accept_credentials(
        &self,
        logon_type: SECURITY_LOGON_TYPE,
        account_name: *const UNICODE_STRING,
        primary_creds: *const SECPKG_PRIMARY_CRED,
        supplementary_creds: *const SECPKG_SUPPLEMENTAL_CRED,
    ) -> NTSTATUS {
        let accept_creds_span =
            span!(Level::INFO, "Attempting to logon with provided credentials").entered();
        let client = match &self.kani_client {
            Some(client) => client,
            None => {
                event!(
                    Level::ERROR,
                    "Failed to get client to interact with kanidm server"
                );

                return STATUS_UNSUCCESSFUL;
            }
        };

        let ident = unsafe {
            match (*account_name).Buffer.to_string() {
                Ok(str) => str,
                Err(e) => {
                    event!(Level::ERROR, "Failed to convert account name to string");
                    event!(Level::DEBUG, "FromUtf16Error {}", e);

                    return STATUS_UNSUCCESSFUL;
                }
            }
        };
		let password = unsafe {
			match (*primary_creds).Password.Buffer.to_string() {
				Ok(pw) => pw,
				Err(e) => {
					event!(Level::ERROR, "Failed to convert password to string");
					event!(Level::DEBUG, "FromUtf16Error {}", e);

					return STATUS_UNSUCCESSFUL;
				}
			}
		};

		if let Err(res) = client.auth_simple_password(ident.as_str(), password.as_str()).await {
			return match res {
				ClientError::AuthenticationFailed => STATUS_LOGON_FAILURE,
				_ => STATUS_UNSUCCESSFUL,
			};
		}

        accept_creds_span.exit();
        STATUS_SUCCESS
    }
}
