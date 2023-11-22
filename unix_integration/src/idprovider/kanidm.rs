use crate::db::KeyStoreTxn;
use async_trait::async_trait;
use kanidm_client::{ClientError, KanidmClient, StatusCode};
use kanidm_proto::v1::{OperationError, UnixGroupToken, UnixUserToken};
use tokio::sync::RwLock;

use super::interface::{
    // KeyStore,
    tpm,
    AuthCacheAction,
    AuthCredHandler,
    AuthRequest,
    AuthResult,
    GroupToken,
    Id,
    IdProvider,
    IdpError,
    UserToken,
};
use crate::unix_proto::PamAuthRequest;

const TAG_IDKEY: &str = "idkey";

pub struct KanidmProvider {
    client: RwLock<KanidmClient>,
}

impl KanidmProvider {
    pub fn new(client: KanidmClient) -> Self {
        KanidmProvider {
            client: RwLock::new(client),
        }
    }
}

impl From<UnixUserToken> for UserToken {
    fn from(value: UnixUserToken) -> UserToken {
        let UnixUserToken {
            name,
            spn,
            displayname,
            gidnumber,
            uuid,
            shell,
            groups,
            sshkeys,
            valid,
        } = value;

        let groups = groups.into_iter().map(GroupToken::from).collect();

        UserToken {
            name,
            spn,
            uuid,
            gidnumber,
            displayname,
            shell,
            groups,
            sshkeys,
            valid,
        }
    }
}

impl From<UnixGroupToken> for GroupToken {
    fn from(value: UnixGroupToken) -> GroupToken {
        let UnixGroupToken {
            name,
            spn,
            uuid,
            gidnumber,
        } = value;

        GroupToken {
            name,
            spn,
            uuid,
            gidnumber,
        }
    }
}

#[async_trait]
impl IdProvider for KanidmProvider {
    async fn configure_hsm_keys<D: KeyStoreTxn + Send>(
        &self,
        keystore: &mut D,
        tpm: &mut (dyn tpm::Tpm + Send),
        machine_key: &tpm::MachineKey,
    ) -> Result<(), IdpError> {
        let id_key: Option<tpm::LoadableIdentityKey> =
            keystore.get_tagged_hsm_key(TAG_IDKEY).map_err(|ks_err| {
                error!(?ks_err);
                IdpError::KeyStore
            })?;

        if id_key.is_none() {
            let loadable_id_key = tpm
                .identity_key_create(machine_key, tpm::KeyAlgorithm::Ecdsa256)
                .map_err(|tpm_err| {
                    error!(?tpm_err);
                    IdpError::Tpm
                })?;

            keystore
                .insert_tagged_hsm_key(TAG_IDKEY, &loadable_id_key)
                .map_err(|ks_err| {
                    error!(?ks_err);
                    IdpError::KeyStore
                })?;
        }

        Ok(())
    }

    // Needs .read on all types except re-auth.
    async fn provider_authenticate(&self) -> Result<(), IdpError> {
        match self.client.write().await.auth_anonymous().await {
            Ok(_uat) => Ok(()),
            Err(err) => {
                error!(?err, "Provider authentication failed");
                Err(IdpError::ProviderUnauthorised)
            }
        }
    }

    async fn unix_user_get(
        &self,
        id: &Id,
        _token: Option<&UserToken>,
    ) -> Result<UserToken, IdpError> {
        match self
            .client
            .read()
            .await
            .idm_account_unix_token_get(id.to_string().as_str())
            .await
        {
            Ok(tok) => Ok(UserToken::from(tok)),
            Err(ClientError::Transport(err)) => {
                error!(?err);
                Err(IdpError::Transport)
            }
            Err(ClientError::Http(StatusCode::UNAUTHORIZED, reason, opid)) => {
                match reason {
                    Some(OperationError::NotAuthenticated) => warn!(
                        "session not authenticated - attempting reauthentication - eventid {}",
                        opid
                    ),
                    Some(OperationError::SessionExpired) => warn!(
                        "session expired - attempting reauthentication - eventid {}",
                        opid
                    ),
                    e => error!(
                        "authentication error {:?}, moving to offline - eventid {}",
                        e, opid
                    ),
                };
                Err(IdpError::ProviderUnauthorised)
            }
            Err(ClientError::Http(
                StatusCode::BAD_REQUEST,
                Some(OperationError::NoMatchingEntries),
                opid,
            ))
            | Err(ClientError::Http(
                StatusCode::NOT_FOUND,
                Some(OperationError::NoMatchingEntries),
                opid,
            ))
            | Err(ClientError::Http(
                StatusCode::BAD_REQUEST,
                Some(OperationError::InvalidAccountState(_)),
                opid,
            )) => {
                debug!(
                    ?opid,
                    "entry has been removed or is no longer a valid posix account"
                );
                Err(IdpError::NotFound)
            }
            Err(err) => {
                error!(?err, "client error");
                Err(IdpError::BadRequest)
            }
        }
    }

    async fn unix_user_online_auth_init(
        &self,
        _account_id: &str,
        _token: Option<&UserToken>,
    ) -> Result<(AuthRequest, AuthCredHandler), IdpError> {
        // Not sure that I need to do much here?
        Ok((AuthRequest::Password, AuthCredHandler::Password))
    }

    async fn unix_user_online_auth_step(
        &self,
        account_id: &str,
        cred_handler: &mut AuthCredHandler,
        pam_next_req: PamAuthRequest,
    ) -> Result<(AuthResult, AuthCacheAction), IdpError> {
        match (cred_handler, pam_next_req) {
            (AuthCredHandler::Password, PamAuthRequest::Password { cred }) => {
                match self
                    .client
                    .read()
                    .await
                    .idm_account_unix_cred_verify(account_id, &cred)
                    .await
                {
                    Ok(Some(n_tok)) => Ok((
                        AuthResult::Success {
                            token: UserToken::from(n_tok),
                        },
                        AuthCacheAction::PasswordHashUpdate { cred },
                    )),
                    Ok(None) => Ok((AuthResult::Denied, AuthCacheAction::None)),
                    Err(ClientError::Transport(err)) => {
                        error!(?err);
                        Err(IdpError::Transport)
                    }
                    Err(ClientError::Http(StatusCode::UNAUTHORIZED, reason, opid)) => {
                        match reason {
                            Some(OperationError::NotAuthenticated) => warn!(
                                "session not authenticated - attempting reauthentication - eventid {}",
                                opid
                            ),
                            Some(OperationError::SessionExpired) => warn!(
                                "session expired - attempting reauthentication - eventid {}",
                                opid
                            ),
                            e => error!(
                                "authentication error {:?}, moving to offline - eventid {}",
                                e, opid
                            ),
                        };
                        Err(IdpError::ProviderUnauthorised)
                    }
                    Err(ClientError::Http(
                        StatusCode::BAD_REQUEST,
                        Some(OperationError::NoMatchingEntries),
                        opid,
                    ))
                    | Err(ClientError::Http(
                        StatusCode::NOT_FOUND,
                        Some(OperationError::NoMatchingEntries),
                        opid,
                    ))
                    | Err(ClientError::Http(
                        StatusCode::BAD_REQUEST,
                        Some(OperationError::InvalidAccountState(_)),
                        opid,
                    )) => {
                        error!(
                            "unknown account or is not a valid posix account - eventid {}",
                            opid
                        );
                        Err(IdpError::NotFound)
                    }
                    Err(err) => {
                        error!(?err, "client error");
                        // Some other unknown processing error?
                        Err(IdpError::BadRequest)
                    }
                }
            }
            (
                AuthCredHandler::DeviceAuthorizationGrant,
                PamAuthRequest::DeviceAuthorizationGrant { .. },
            ) => {
                error!("DeviceAuthorizationGrant not implemented!");
                Err(IdpError::BadRequest)
            }
            _ => {
                error!("invalid authentication request state");
                Err(IdpError::BadRequest)
            }
        }
    }

    async fn unix_user_offline_auth_init(
        &self,
        _account_id: &str,
        _token: Option<&UserToken>,
    ) -> Result<(AuthRequest, AuthCredHandler), IdpError> {
        // Not sure that I need to do much here?
        Ok((AuthRequest::Password, AuthCredHandler::Password))
    }

    /*
    async fn unix_user_offline_auth_step(
        &self,
        _account_id: &str,
        _cred_handler: &mut AuthCredHandler,
        _pam_next_req: PamAuthRequest,
        _online_at_init: bool,
    ) -> Result<AuthResult, IdpError> {
        // We need any cached credentials here.
        todo!();
    }
    */

    async fn unix_group_get(&self, id: &Id) -> Result<GroupToken, IdpError> {
        match self
            .client
            .read()
            .await
            .idm_group_unix_token_get(id.to_string().as_str())
            .await
        {
            Ok(tok) => Ok(GroupToken::from(tok)),
            Err(ClientError::Transport(err)) => {
                error!(?err);
                Err(IdpError::Transport)
            }
            Err(ClientError::Http(StatusCode::UNAUTHORIZED, reason, opid)) => {
                match reason {
                    Some(OperationError::NotAuthenticated) => warn!(
                        "session not authenticated - attempting reauthentication - eventid {}",
                        opid
                    ),
                    Some(OperationError::SessionExpired) => warn!(
                        "session expired - attempting reauthentication - eventid {}",
                        opid
                    ),
                    e => error!(
                        "authentication error {:?}, moving to offline - eventid {}",
                        e, opid
                    ),
                };
                Err(IdpError::ProviderUnauthorised)
            }
            Err(ClientError::Http(
                StatusCode::BAD_REQUEST,
                Some(OperationError::NoMatchingEntries),
                opid,
            ))
            | Err(ClientError::Http(
                StatusCode::NOT_FOUND,
                Some(OperationError::NoMatchingEntries),
                opid,
            ))
            | Err(ClientError::Http(
                StatusCode::BAD_REQUEST,
                Some(OperationError::InvalidAccountState(_)),
                opid,
            )) => {
                debug!(
                    ?opid,
                    "entry has been removed or is no longer a valid posix group"
                );
                Err(IdpError::NotFound)
            }
            Err(err) => {
                error!(?err, "client error");
                Err(IdpError::BadRequest)
            }
        }
    }
}
