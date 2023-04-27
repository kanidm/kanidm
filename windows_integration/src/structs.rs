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
pub enum ProtocolSubmitBuffer {
	V1(ProtocolSubmitBufferV1),
}

pub enum ProtocolSubmitBufferV1 {
	// All Accounts Operations
	GetAccounts,

	// Account Operations
	CreateAccount,
	ReadAccount,
	UpdateAccount,
	DeleteAccount,

	// Account Attributes Operations
	CreateAccountAttribute,
	ReadAccountAttribute,
	UpdateAccountAttribute,
	DeleteAccountAttribute,

	// Service Account Operations
	CreateServiceAccountApiToken,
	ReadServiceAccountApiToken,
	DeleteServiceAccountApiToken,

	UpdateServiceAccountToPerson,
	CreateServiceAccountPassword,

	// Sync Account Operations
	CreateSyncAccount,
	ReadSyncAccount,

	CreateSyncAccountToken,
	DeleteSyncAccountToken,

	// Server Password Criteria Operations
	ReadPasswordBadlist,
	UpdatePasswordBadlist,
	DeletePasswordBadlist,

	// Current User Operations
	ReadCurrentUser,
	ReadCurrentAuthState,

	// Group Operations
	ReadGroups,

	CreateGroup,
	ReadGroup,
	DeleteGroup,

	ReadGroupMembers,
	UpdateGroupMembers,
	DeleteGroupMember,
	DeleteGroupMembers,

	// Domain Operations
	GetDomain,
	GetDomainSSID,

	// SSH Key Operations
	UpdateUserSSHPubKey,
	DeleteUserSSHPubKey,

	// Unix Cred Operations
	UpdateUserUnixCreds,
	DeleteUserUnixCreds,

	// Radius Operations
	CreateUserRadiusCreds,
	GetUserRadiusCreds,
	DeleteUserRadiusCreds,

	// General Auth Operations
	AuthUserTransactionBegin,
	AuthUserTransactionFinish,
	AuthUserAnonymous,
	AuthUserPassword,
	AuthUserBackupCode,
	AuthUserTotp,
	AuthUserSecurityKey,
	AuthUserPassKey,
}