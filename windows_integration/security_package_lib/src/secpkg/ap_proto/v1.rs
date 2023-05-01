pub enum AuthPkgRequest {
	// All Accounts Operations
	/// Get all accounts associated with the kanidm server
	GetAccounts(GetAccountsRequest),

	// Account Operations
	/// Create a new account on the kanidm server
	CreateAccount(CreateAccountRequest),
	/// Get an account from the kanidm server
	ReadAccount(ReadAccountRequest),
	/// Update details of an account
	UpdateAccount(UpdateAccountRequest),
	/// Delete an account from the kanidm server
	DeleteAccount(DeleteAccountRequest),

	// Account Attributes Operations
	/// Create a new attribute for an account
	CreateAccountAttribute(CreateAccountAttributeRequest),
	/// Get an attribute from an account
	ReadAccountAttribute(ReadAccountAttributeRequest),
	/// Update an existing attribute for an account
	UpdateAccountAttribute(UpdateAccountAttributeRequest),
	/// Delete an attribute associated with an account
	DeleteAccountAttribute(DeleteAccountAttributeRequest),

	// Service Account Operations
	/// Create an api token for a service account
	CreateServiceAccountApiToken(CreateServiceAccountApiTokenRequest),
	/// Get the api token of a service account
	ReadServiceAccountApiToken(ReadServiceAccountApiTokenRequest),
	/// Delete the api token associated with a service account
	DeleteServiceAccountApiToken(DeleteServiceAccountApiTokenRequest),

	/// Migrate a service account to a person account
	UpdateServiceAccountToPerson(UpdateServiceAccountToPersonRequest),
	/// Generate a new password for a service account
	CreateServiceAccountPassword(CreateServiceAccountPasswordRequest),

	// Sync Account Operations
	/// Create a new sync account
	CreateSyncAccount(CreateSyncAccountRequest),
	/// Get a sync account from the kanidm server
	ReadSyncAccount(ReadSyncAccountRequest),

	/// Create a new sync token for a sync account
	CreateSyncAccountToken(CreateSyncAccountTokenRequest),
	/// Delete the sync token associated with a sync account
	DeleteSyncAccountToken(DeleteSyncAccountTokenRequest),

	// Server Password Criteria Operations
	/// Get the current password badlist
	ReadPasswordBadlist(ReadPasswordBadlistRequest),
	/// Add to the current password badlist
	UpdatePasswordBadlist(UpdatePasswordBadlistRequest),
	/// Remove from the current password badlist
	DeletePasswordBadlist(DeletePasswordBadlistRequest),

	// Current User Operations
	/// Get the current signed in user
	ReadCurrentUser(ReadCurrentUserRequest),
	/// Check whether the current user's auth is valid
	ReadCurrentAuthState(ReadCurrentAuthStateRequest),

	// Group Operations
	/// Get all groups on the kanidm server
	ReadGroups(ReadGroupsRequest),

	/// Create a new group
	CreateGroup(CreateGroupRequest),
	/// Get info associated with a group
	ReadGroup(ReadGroupRequest),
	/// Delete a group
	DeleteGroup(DeleteGroupRequest),

	/// Get the accounts in a group
	ReadGroupMembers(ReadGroupMembersRequest),
	/// Add new accounts to a group
	UpdateGroupMembers(UpdateGroupMembersRequest),
	/// Remove a account from the group
	DeleteGroupMember(DeleteGroupMemberRequest),
	/// Remove all accounts from the group
	DeleteGroupMembers(DeleteGroupMembersRequest),

	// Domain Operations
	/// Get the domain name of the kanidm server
	GetDomain(GetDomainRequest),
	/// Get the domain ssid of the kanidm server
	GetDomainSSID(GetDomainSSIDRequest),

	// SSH Key Operations
	/// Add or Update an account's ssh public key
	UpdateUserSSHPubKey(UpdateUserSSHPubKeyRequest),
	/// Remove a ssh public key associated with an account
	DeleteUserSSHPubKey(DeleteUserSSHPubKeyRequest),

	// Unix Cred Operations
	/// Add or Update the unix credentials associated with an accouunt
	UpdateUserUnixCreds(UpdateUserUnixCredsRequest),
	/// Remove unix credentials associated with an account
	DeleteUserUnixCreds(DeleteUserUnixCredsRequest),

	// Radius Operations
	/// Create new radius credentials for an account
	CreateUserRadiusCreds(CreateUserRadiusCredsRequest),
	/// Get the radius credentials associated with an account
	GetUserRadiusCreds(GetUserRadiusCredsRequest),
	/// Delete the radius credentials associated with an account
	DeleteUserRadiusCreds(DeleteUserRadiusCredsRequest),

	// General Auth Operations
	/// Begin a new authentication attempt
	AuthUserTransactionBegin(AuthUserTransactionBeginRequest),
	/// Commit the authentication attempt to the kanidm server
	AuthUserTransactionFinish(AuthUserTransactionFinishRequest),
	/// Log in the user anonymously 
	AuthUserAnonymous(AuthUserAnonymousRequest),
	/// Use password step
	AuthUserStepPassword(AuthUserStepPasswordRequest),
	/// Use backup code step
	AuthUserStepBackupCode(AuthUserStepBackupCodeRequest),
	/// Use totp step
	AuthUserStepTotp(AuthUserStepTotpRequest),
	/// Use security key step
	AuthUserStepSecurityKey(AuthUserStepSecurityKeyRequest),
	/// Use passkey step
	AuthUserStepPassKey(AuthUserStepPassKeyRequest),
}


pub enum AuthPkgResponse {
	Error(AuthPkgError),
	// All Accounts Operations
	/// Get all accounts associated with the kanidm server
	GetAccounts(GetAccountsResponse),

	// Account Operations
	/// Create a new account on the kanidm server
	CreateAccount(CreateAccountResponse),
	/// Get an account from the kanidm server
	ReadAccount(ReadAccountResponse),
	/// Update details of an account
	UpdateAccount(UpdateAccountResponse),
	/// Delete an account from the kanidm server
	DeleteAccount(DeleteAccountResponse),

	// Account Attributes Operations
	/// Create a new attribute for an account
	CreateAccountAttribute(CreateAccountAttributeResponse),
	/// Get an attribute from an account
	ReadAccountAttribute(ReadAccountAttributeResponse),
	/// Update an existing attribute for an account
	UpdateAccountAttribute(UpdateAccountAttributeResponse),
	/// Delete an attribute associated with an account
	DeleteAccountAttribute(DeleteAccountAttributeResponse),

	// Service Account Operations
	/// Create an api token for a service account
	CreateServiceAccountApiToken(CreateServiceAccountApiTokenResponse),
	/// Get the api token of a service account
	ReadServiceAccountApiToken(ReadServiceAccountApiTokenResponse),
	/// Delete the api token associated with a service account
	DeleteServiceAccountApiToken(DeleteServiceAccountApiTokenResponse),

	/// Migrate a service account to a person account
	UpdateServiceAccountToPerson(UpdateServiceAccountToPersonResponse),
	/// Generate a new password for a service account
	CreateServiceAccountPassword(CreateServiceAccountPasswordResponse),

	// Sync Account Operations
	/// Create a new sync account
	CreateSyncAccount(CreateSyncAccountResponse),
	/// Get a sync account from the kanidm server
	ReadSyncAccount(ReadSyncAccountResponse),

	/// Create a new sync token for a sync account
	CreateSyncAccountToken(CreateSyncAccountTokenResponse),
	/// Delete the sync token associated with a sync account
	DeleteSyncAccountToken(DeleteSyncAccountTokenResponse),

	// Server Password Criteria Operations
	/// Get the current password badlist
	ReadPasswordBadlist(ReadPasswordBadlistResponse),
	/// Add to the current password badlist
	UpdatePasswordBadlist(UpdatePasswordBadlistResponse),
	/// Remove from the current password badlist
	DeletePasswordBadlist(DeletePasswordBadlistResponse),

	// Current User Operations
	/// Get the current signed in user
	ReadCurrentUser(ReadCurrentUserResponse),
	/// Check whether the current user's auth is valid
	ReadCurrentAuthState(ReadCurrentAuthStateResponse),

	// Group Operations
	/// Get all groups on the kanidm server
	ReadGroups(ReadGroupsResponse),

	/// Create a new group
	CreateGroup(CreateGroupResponse),
	/// Get info associated with a group
	ReadGroup(ReadGroupResponse),
	/// Delete a group
	DeleteGroup(DeleteGroupResponse),

	/// Get the accounts in a group
	ReadGroupMembers(ReadGroupMembersResponse),
	/// Add new accounts to a group
	UpdateGroupMembers(UpdateGroupMembersResponse),
	/// Remove a account from the group
	DeleteGroupMember(DeleteGroupMemberResponse),
	/// Remove all accounts from the group
	DeleteGroupMembers(DeleteGroupMembersResponse),

	// Domain Operations
	/// Get the domain name of the kanidm server
	GetDomain(GetDomainResponse),
	/// Get the domain ssid of the kanidm server
	GetDomainSSID(GetDomainSSIDResponse),

	// SSH Key Operations
	/// Add or Update an account's ssh public key
	UpdateUserSSHPubKey(UpdateUserSSHPubKeyResponse),
	/// Remove a ssh public key associated with an account
	DeleteUserSSHPubKey(DeleteUserSSHPubKeyResponse),

	// Unix Cred Operations
	/// Add or Update the unix credentials associated with an accouunt
	UpdateUserUnixCreds(UpdateUserUnixCredsResponse),
	/// Remove unix credentials associated with an account
	DeleteUserUnixCreds(DeleteUserUnixCredsResponse),

	// Radius Operations
	/// Create new radius credentials for an account
	CreateUserRadiusCreds(CreateUserRadiusCredsResponse),
	/// Get the radius credentials associated with an account
	GetUserRadiusCreds(GetUserRadiusCredsResponse),
	/// Delete the radius credentials associated with an account
	DeleteUserRadiusCreds(DeleteUserRadiusCredsResponse),

	// General Auth Operations
	/// Begin a new authentication attempt
	AuthUserTransactionBegin(AuthUserTransactionBeginResponse),
	/// Commit the authentication attempt to the kanidm server
	AuthUserTransactionFinish(AuthUserTransactionFinishResponse),
	/// Log in the user anonymously 
	AuthUserAnonymous(AuthUserAnonymousResponse),
	/// Use password step
	AuthUserStepPassword(AuthUserStepPasswordResponse),
	/// Use backup code step
	AuthUserStepBackupCode(AuthUserStepBackupCodeResponse),
	/// Use totp step
	AuthUserStepTotp(AuthUserStepTotpResponse),
	/// Use security key step
	AuthUserStepSecurityKey(AuthUserStepSecurityKeyResponse),
	/// Use passkey step
	AuthUserStepPassKey(AuthUserStepPassKeyResponse),
}

pub enum AuthPkgError {}

pub struct GetAccountsRequest {}
pub struct GetAccountsResponse {} 

pub struct CreateAccountRequest {}
pub struct CreateAccountResponse {} 

pub struct ReadAccountRequest {}
pub struct ReadAccountResponse {} 

pub struct UpdateAccountRequest {}
pub struct UpdateAccountResponse {} 

pub struct DeleteAccountRequest {}
pub struct DeleteAccountResponse {} 

pub struct CreateAccountAttributeRequest {}
pub struct CreateAccountAttributeResponse {} 

pub struct ReadAccountAttributeRequest {}
pub struct ReadAccountAttributeResponse {} 

pub struct UpdateAccountAttributeRequest {}
pub struct UpdateAccountAttributeResponse {} 

pub struct DeleteAccountAttributeRequest {}
pub struct DeleteAccountAttributeResponse {} 

pub struct CreateServiceAccountApiTokenRequest {}
pub struct CreateServiceAccountApiTokenResponse {} 

pub struct ReadServiceAccountApiTokenRequest {}
pub struct ReadServiceAccountApiTokenResponse {} 

pub struct DeleteServiceAccountApiTokenRequest {}
pub struct DeleteServiceAccountApiTokenResponse {} 

pub struct UpdateServiceAccountToPersonRequest {}
pub struct UpdateServiceAccountToPersonResponse {} 

pub struct CreateServiceAccountPasswordRequest {}
pub struct CreateServiceAccountPasswordResponse {} 

pub struct CreateSyncAccountRequest {}
pub struct CreateSyncAccountResponse {} 

pub struct ReadSyncAccountRequest {}
pub struct ReadSyncAccountResponse {} 

pub struct CreateSyncAccountTokenRequest {}
pub struct CreateSyncAccountTokenResponse {} 

pub struct DeleteSyncAccountTokenRequest {}
pub struct DeleteSyncAccountTokenResponse {} 

pub struct ReadPasswordBadlistRequest {}
pub struct ReadPasswordBadlistResponse {} 

pub struct UpdatePasswordBadlistRequest {}
pub struct UpdatePasswordBadlistResponse {} 

pub struct DeletePasswordBadlistRequest {}
pub struct DeletePasswordBadlistResponse {} 

pub struct ReadCurrentUserRequest {}
pub struct ReadCurrentUserResponse {} 

pub struct ReadCurrentAuthStateRequest {}
pub struct ReadCurrentAuthStateResponse {} 

pub struct ReadGroupsRequest {}
pub struct ReadGroupsResponse {} 

pub struct CreateGroupRequest {}
pub struct CreateGroupResponse {} 

pub struct ReadGroupRequest {}
pub struct ReadGroupResponse {} 

pub struct DeleteGroupRequest {}
pub struct DeleteGroupResponse {} 

pub struct ReadGroupMembersRequest {}
pub struct ReadGroupMembersResponse {} 

pub struct UpdateGroupMembersRequest {}
pub struct UpdateGroupMembersResponse {} 

pub struct DeleteGroupMemberRequest {}
pub struct DeleteGroupMemberResponse {} 

pub struct DeleteGroupMembersRequest {}
pub struct DeleteGroupMembersResponse {} 

pub struct GetDomainRequest {}
pub struct GetDomainResponse {} 

pub struct GetDomainSSIDRequest {}
pub struct GetDomainSSIDResponse {} 

pub struct UpdateUserSSHPubKeyRequest {}
pub struct UpdateUserSSHPubKeyResponse {} 

pub struct DeleteUserSSHPubKeyRequest {}
pub struct DeleteUserSSHPubKeyResponse {} 

pub struct UpdateUserUnixCredsRequest {}
pub struct UpdateUserUnixCredsResponse {} 

pub struct DeleteUserUnixCredsRequest {}
pub struct DeleteUserUnixCredsResponse {} 

pub struct CreateUserRadiusCredsRequest {}
pub struct CreateUserRadiusCredsResponse {} 

pub struct GetUserRadiusCredsRequest {}
pub struct GetUserRadiusCredsResponse {} 

pub struct DeleteUserRadiusCredsRequest {}
pub struct DeleteUserRadiusCredsResponse {} 

pub struct AuthUserTransactionBeginRequest {}
pub struct AuthUserTransactionBeginResponse {} 

pub struct AuthUserTransactionFinishRequest {}
pub struct AuthUserTransactionFinishResponse {} 

pub struct AuthUserAnonymousRequest {}
pub struct AuthUserAnonymousResponse {} 

pub struct AuthUserStepPasswordRequest {}
pub struct AuthUserStepPasswordResponse {} 

pub struct AuthUserStepBackupCodeRequest {}
pub struct AuthUserStepBackupCodeResponse {} 

pub struct AuthUserStepTotpRequest {}
pub struct AuthUserStepTotpResponse {} 

pub struct AuthUserStepSecurityKeyRequest {}
pub struct AuthUserStepSecurityKeyResponse {} 

pub struct AuthUserStepPassKeyRequest {}
pub struct AuthUserStepPassKeyResponse {}
