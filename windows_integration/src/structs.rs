use kanidm_proto::v1::UnixUserToken;
use windows::Win32::Foundation::UNICODE_STRING;


// * Logon User
pub struct AuthInfo {
	pub username: UNICODE_STRING,
	pub password: UNICODE_STRING,
}

pub struct ProfileBuffer {
	pub token: UnixUserToken,
}

// * Call Package
pub enum AuthPkgRequest {
	V1(AuthPkgRequestV1),
}

pub enum AuthPkgRequestV1 {
	// All Accounts Operations
	/// Get all accounts associated with the kanidm server
	GetAccounts,

	// Account Operations
	/// Create a new account on the kanidm server
	CreateAccount,
	/// Get an account from the kanidm server
	ReadAccount,
	/// Update details of an account
	UpdateAccount,
	/// Delete an account from the kanidm server
	DeleteAccount,

	// Account Attributes Operations
	/// Create a new attribute for an account
	CreateAccountAttribute,
	/// Get an attribute from an account
	ReadAccountAttribute,
	/// Update an existing attribute for an account
	UpdateAccountAttribute,
	/// Delete an attribute associated with an account
	DeleteAccountAttribute,

	// Service Account Operations
	/// Create an api token for a service account
	CreateServiceAccountApiToken,
	/// Get the api token of a service account
	ReadServiceAccountApiToken,
	/// Delete the api token associated with a service account
	DeleteServiceAccountApiToken,

	/// Migrate a service account to a person account
	UpdateServiceAccountToPerson,
	/// Generate a new password for a service account
	CreateServiceAccountPassword,

	// Sync Account Operations
	/// Create a new sync account
	CreateSyncAccount,
	/// Get a sync account from the kanidm server
	ReadSyncAccount,

	/// Create a new sync token for a sync account
	CreateSyncAccountToken,
	/// Delete the sync token associated with a sync account
	DeleteSyncAccountToken,

	// Server Password Criteria Operations
	/// Get the current password badlist
	ReadPasswordBadlist,
	/// Add to the current password badlist
	UpdatePasswordBadlist,
	/// Remove from the current password badlist
	DeletePasswordBadlist,

	// Current User Operations
	/// Get the current signed in user
	ReadCurrentUser,
	/// Check whether the current user's auth is valid
	ReadCurrentAuthState,

	// Group Operations
	/// Get all groups on the kanidm server
	ReadGroups,

	/// Create a new group
	CreateGroup,
	/// Get info associated with a group
	ReadGroup,
	/// Delete a group
	DeleteGroup,

	/// Get the accounts in a group
	ReadGroupMembers,
	/// Add new accounts to a group
	UpdateGroupMembers,
	/// Remove a account from the group
	DeleteGroupMember,
	/// Remove all accounts from the group
	DeleteGroupMembers,

	// Domain Operations
	/// Get the domain name of the kanidm server
	GetDomain,
	/// Get the domain ssid of the kanidm server
	GetDomainSSID,

	// SSH Key Operations
	/// Add or Update an account's ssh public key
	UpdateUserSSHPubKey,
	/// Remove a ssh public key associated with an account
	DeleteUserSSHPubKey,

	// Unix Cred Operations
	/// Add or Update the unix credentials associated with an accouunt
	UpdateUserUnixCreds,
	/// Remove unix credentials associated with an account
	DeleteUserUnixCreds,

	// Radius Operations
	/// Create new radius credentials for an account
	CreateUserRadiusCreds,
	/// Get the radius credentials associated with an account
	GetUserRadiusCreds,
	/// Delete the radius credentials associated with an account
	DeleteUserRadiusCreds,

	// General Auth Operations
	/// Begin a new authentication attempt
	AuthUserTransactionBegin,
	/// Commit the authentication attempt to the kanidm server
	AuthUserTransactionFinish,
	/// Log in the user anonymously 
	AuthUserAnonymous,
	/// Use password step
	AuthUserStepPassword,
	/// Use backup code step
	AuthUserStepBackupCode,
	/// Use totp step
	AuthUserStepTotp,
	/// Use security key step
	AuthUserStepSecurityKey,
	/// Use passkey step
	AuthUserStepPassKey,
}