use async_trait::async_trait;
use kanidm_client::{ClientError, KanidmClient, StatusCode};
use kanidm_proto::v1::{OperationError, UnixGroupToken, UnixUserToken};
use tokio::sync::RwLock;

use super::interface::{GroupToken, Id, IdProvider, IdpError, UserToken};

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
        _old_token: Option<UserToken>,
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

    async fn unix_user_authenticate(
        &self,
        id: &Id,
        cred: &str,
    ) -> Result<Option<UserToken>, IdpError> {
        match self
            .client
            .read()
            .await
            .idm_account_unix_cred_verify(id.to_string().as_str(), cred)
            .await
        {
            Ok(Some(n_tok)) => Ok(Some(UserToken::from(n_tok))),
            Ok(None) => Ok(None),
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
