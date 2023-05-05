use kanidm_windows::secpkg::ap_proto::v1::*;
use tracing::{event, Level};

use crate::package::KANIDM_WINDOWS_CLIENT;

pub async fn handle_request(request: &AuthPkgRequest) -> AuthPkgResponse {
    return match request {
        AuthPkgRequest::GetAccounts(req) => get_accounts(req).await,
        AuthPkgRequest::CreateAccount(_) => todo!(),
        AuthPkgRequest::ReadAccount(_) => todo!(),
        AuthPkgRequest::UpdateAccount(_) => todo!(),
        AuthPkgRequest::DeleteAccount(_) => todo!(),
        AuthPkgRequest::CreateAccountAttribute(_) => todo!(),
        AuthPkgRequest::ReadAccountAttribute(_) => todo!(),
        AuthPkgRequest::UpdateAccountAttribute(_) => todo!(),
        AuthPkgRequest::DeleteAccountAttribute(_) => todo!(),
        AuthPkgRequest::CreateServiceAccountApiToken(_) => todo!(),
        AuthPkgRequest::ReadServiceAccountApiToken(_) => todo!(),
        AuthPkgRequest::DeleteServiceAccountApiToken(_) => todo!(),
        AuthPkgRequest::UpdateServiceAccountToPerson(_) => todo!(),
        AuthPkgRequest::CreateServiceAccountPassword(_) => todo!(),
        AuthPkgRequest::CreateSyncAccount(_) => todo!(),
        AuthPkgRequest::ReadSyncAccount(_) => todo!(),
        AuthPkgRequest::CreateSyncAccountToken(_) => todo!(),
        AuthPkgRequest::DeleteSyncAccountToken(_) => todo!(),
        AuthPkgRequest::ReadPasswordBadlist(_) => todo!(),
        AuthPkgRequest::UpdatePasswordBadlist(_) => todo!(),
        AuthPkgRequest::DeletePasswordBadlist(_) => todo!(),
        AuthPkgRequest::ReadCurrentUser(_) => todo!(),
        AuthPkgRequest::ReadCurrentAuthState(_) => todo!(),
        AuthPkgRequest::ReadGroups(_) => todo!(),
        AuthPkgRequest::CreateGroup(_) => todo!(),
        AuthPkgRequest::ReadGroup(_) => todo!(),
        AuthPkgRequest::DeleteGroup(_) => todo!(),
        AuthPkgRequest::ReadGroupMembers(_) => todo!(),
        AuthPkgRequest::UpdateGroupMembers(_) => todo!(),
        AuthPkgRequest::DeleteGroupMember(_) => todo!(),
        AuthPkgRequest::DeleteGroupMembers(_) => todo!(),
        AuthPkgRequest::GetDomain(_) => todo!(),
        AuthPkgRequest::GetDomainSSID(_) => todo!(),
        AuthPkgRequest::UpdateUserSSHPubKey(_) => todo!(),
        AuthPkgRequest::DeleteUserSSHPubKey(_) => todo!(),
        AuthPkgRequest::UpdateUserUnixCreds(_) => todo!(),
        AuthPkgRequest::DeleteUserUnixCreds(_) => todo!(),
        AuthPkgRequest::CreateUserRadiusCreds(_) => todo!(),
        AuthPkgRequest::GetUserRadiusCreds(_) => todo!(),
        AuthPkgRequest::DeleteUserRadiusCreds(_) => todo!(),
        AuthPkgRequest::AuthUserTransactionBegin(_) => todo!(),
        AuthPkgRequest::AuthUserTransactionFinish(_) => todo!(),
        AuthPkgRequest::AuthUserAnonymous(_) => todo!(),
        AuthPkgRequest::AuthUserStepPassword(_) => todo!(),
        AuthPkgRequest::AuthUserStepBackupCode(_) => todo!(),
        AuthPkgRequest::AuthUserStepTotp(_) => todo!(),
        AuthPkgRequest::AuthUserStepSecurityKey(_) => todo!(),
        AuthPkgRequest::AuthUserStepPassKey(_) => todo!(),
    };
}

async fn get_accounts(request: &GetAccountsRequest) -> AuthPkgResponse {
    let client = unsafe { KANIDM_WINDOWS_CLIENT.as_ref().unwrap() };

    let accounts = match client.get_accounts(&request.account_type).await {
        Ok(accounts) => accounts,
        Err(e) => {
            event!(
                Level::ERROR,
                "Failed to get all accounts, ClientError {:?}",
                e
            );
            return AuthPkgResponse::Error(AuthPkgError::ClientRequestUnsuccessful);
        }
    };

    return AuthPkgResponse::GetAccounts(GetAccountsResponse { accounts: accounts });
}
