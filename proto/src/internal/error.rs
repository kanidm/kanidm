use super::credupdate::PasswordFeedback;
use crate::attribute::Attribute;
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};
use utoipa::ToSchema;
use uuid::Uuid;

/* ===== errors ===== */
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum SchemaError {
    NotImplemented,
    NoClassFound,
    InvalidClass(Vec<String>),
    MissingMustAttribute(Vec<Attribute>),
    InvalidAttribute(String),
    InvalidAttributeSyntax(String),
    AttributeNotValidForClass(String),
    SupplementsNotSatisfied(Vec<String>),
    ExcludesNotSatisfied(Vec<String>),
    EmptyFilter,
    Corrupted,
    PhantomAttribute(String),
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum PluginError {
    Base(String),
    ReferentialIntegrity(String),
    CredImport(String),
    Oauth2Secrets,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum ConsistencyError {
    Unknown,
    // Class, Attribute
    SchemaClassMissingAttribute(String, String),
    SchemaClassPhantomAttribute(String, String),
    SchemaUuidNotUnique(Uuid),
    QueryServerSearchFailure,
    EntryUuidCorrupt(u64),
    UuidIndexCorrupt(String),
    UuidNotUnique(String),
    RefintNotUpheld(u64),
    MemberOfInvalid(u64),
    InvalidAttributeType(String),
    DuplicateUniqueAttribute,
    InvalidSpn(u64),
    SqliteIntegrityFailure,
    BackendAllIdsSync,
    BackendIndexSync,
    ChangelogDesynchronised(u64),
    ChangeStateDesynchronised(u64),
    RuvInconsistent(String),
    DeniedName(Uuid),
    KeyProviderUuidMissing { key_object: Uuid },
    KeyProviderNoKeys { key_object: Uuid },
    KeyProviderNotFound { key_object: Uuid, provider: Uuid },
}

#[derive(Serialize, Deserialize, Debug, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum OperationError {
    // Logic errors, or "soft" errors. These are to guide the user or user-interface
    // in some way.
    SessionExpired,
    DuplicateKey,
    DuplicateLabel,
    EmptyRequest,
    Backend,
    NoMatchingEntries,
    NoMatchingAttributes,
    UniqueConstraintViolation,
    CorruptedEntry(u64),
    CorruptedIndex(String),
    ConsistencyError(Vec<ConsistencyError>),
    SchemaViolation(SchemaError),
    Plugin(PluginError),
    FilterGeneration,
    FilterParseError,
    FilterUuidResolution,
    InvalidAttributeName(String),
    InvalidAttribute(String),
    InvalidLabel,
    InvalidDbState,
    InvalidCacheState,
    InvalidValueState,
    InvalidEntryId,
    InvalidRequestState,
    InvalidSyncState,
    InvalidState,
    InvalidEntryState,
    InvalidUuid,
    InvalidReplChangeId,
    InvalidAcpState(String),
    InvalidSchemaState(String),
    InvalidAccountState(String),
    // This really oughta be EntryClass but its not in proto...
    // It should at least be &'static str but we
    // Serialize & Deserialize this enum...
    MissingClass(String),
    MissingAttribute(Attribute),
    AttributeUniqueness(Vec<Attribute>),
    MissingEntries,
    ModifyAssertionFailed,
    BackendEngine,
    SqliteError, //(RusqliteError)
    FsError,
    SerdeJsonError,
    SerdeCborError,
    AccessDenied,
    NotAuthenticated,
    NotAuthorised,
    InvalidAuthState(String),
    InvalidSessionState,
    SystemProtectedObject,
    SystemProtectedAttribute,
    PasswordQuality(Vec<PasswordFeedback>),
    CryptographyError,
    ResourceLimit,
    QueueDisconnected,
    Webauthn,
    #[serde(with = "time::serde::timestamp")]
    Wait(time::OffsetDateTime),
    ReplReplayFailure,
    ReplEntryNotChanged,
    ReplInvalidRUVState,
    ReplDomainLevelUnsatisfiable,
    ReplDomainUuidMismatch,
    ReplServerUuidSplitDataState,
    TransactionAlreadyCommitted,
    CannotStartMFADuringOngoingMFASession,
    /// when you ask for a gid that overlaps a system reserved range
    /// When a name is denied by the system config
    ValueDenyName,
    /// When the DB is potentially over-loaded a timeout can occur starting
    /// your operation.
    DatabaseLockAcquisitionTimeout,
    /// Your change would introduce a reference loop
    ReferenceLoop,
    /// This session is not able to re-authenticate and has static privileges
    SessionMayNotReauth,

    // Specific internal errors.
    AU0001InvalidState,
    AU0002JwsSerialisation,
    AU0003JwsSignature,
    AU0004UserAuthTokenInvalid,
    AU0005DelayedProcessFailure,
    AU0006CredentialMayNotReauthenticate,
    AU0007UserAuthTokenInvalid,
    AU0008ClientAuthInfoPrevalidation,

    // Kanidm Generic Errors
    KG001TaskTimeout,
    KG002TaskCommFailure,
    KG003CacheClearFailed,
    KG004UnknownFeatureUuid,
    KG005HowDidYouEvenManageThis,
    KG006DatastructureCorruption,

    // Credential Update Errors
    CU0001WebauthnAttestationNotTrusted,
    CU0002WebauthnRegistrationError,
    CU0003WebauthnUserNotVerified,

    // The session is inconsistent and can't be committed, but the errors
    // can be resolved.
    CU0004SessionInconsistent,
    // Another session used this intent token, and so it can't be committed.
    CU0005IntentTokenConflict,
    // The intent token was invalidated before we could commit.
    CU0006IntentTokenInvalidated,

    // ValueSet errors
    VS0001IncomingReplSshPublicKey,
    VS0002CertificatePublicKeyDigest,
    VS0003CertificateDerDecode,
    VS0004CertificatePublicKeyDigest,
    VS0005CertificatePublicKeyDigest,
    // Value Errors
    VL0001ValueSshPublicKeyString,

    // LDAP Errors
    LD0001AnonymousNotAllowed,

    // DB low level errors.
    DB0001MismatchedRestoreVersion,
    DB0002MismatchedRestoreVersion,
    DB0003FilterResolveCacheBuild,
    DB0004DatabaseTooOld,

    // SCIM
    SC0001IncomingSshPublicKey,
    SC0002ReferenceSyntaxInvalid,
    SC0003MailSyntaxInvalid,
    SC0004UuidSyntaxInvalid,
    SC0005BoolSyntaxInvalid,
    SC0006Uint32SyntaxInvalid,
    SC0007UrlSyntaxInvalid,
    SC0008SyntaxTypeSyntaxInvalid,
    SC0009IndexTypeSyntaxInvalid,
    SC0010DateTimeSyntaxInvalid,
    SC0011AddressSyntaxInvalid,
    SC0012CertificateSyntaxInvalid,
    SC0013CertificateInvalidDer,
    SC0014CertificateInvalidDigest,
    SC0015CredentialTypeSyntaxInvalid,
    SC0016InameSyntaxInvalid,
    SC0017Iutf8SyntaxInvalid,
    SC0018NsUniqueIdSyntaxInvalid,
    SC0019Oauth2ScopeSyntaxInvalid,
    SC0020Oauth2ScopeMapSyntaxInvalid,
    SC0021Oauth2ScopeMapMissingGroupIdentifier,
    SC0022Oauth2ClaimMapSyntaxInvalid,
    SC0023Oauth2ClaimMapMissingGroupIdentifier,
    SC0024SshPublicKeySyntaxInvalid,
    SC0025UiHintSyntaxInvalid,
    SC0026Utf8SyntaxInvalid,
    SC0027ClassSetInvalid,
    SC0028CreatedUuidsInvalid,
    SC0029PaginationOutOfBounds,
    SC0030Sha256SyntaxInvalid,
    SC0031Int64SyntaxInvalid,
    SC0032Uint64SyntaxInvalid,
    SC0033AssertionContainsDuplicateUuids,
    // Migration
    MG0001InvalidReMigrationLevel,
    MG0002RaiseDomainLevelExceedsMaximum,
    MG0003ServerPhaseInvalidForMigration,
    MG0004DomainLevelInDevelopment,
    MG0005GidConstraintsNotMet,
    MG0006SKConstraintsNotMet,
    MG0007Oauth2StrictConstraintsNotMet,
    MG0008SkipUpgradeAttempted,
    MG0009InvalidTargetLevelForBootstrap,
    MG0010DowngradeNotAllowed,
    //
    KP0001KeyProviderNotLoaded,
    KP0002KeyProviderInvalidClass,
    KP0003KeyProviderInvalidType,
    KP0004KeyProviderMissingAttributeName,
    KP0005KeyProviderDuplicate,
    KP0006KeyObjectJwtEs256Generation,
    KP0007KeyProviderDefaultNotAvailable,
    KP0008KeyObjectMissingUuid,
    KP0009KeyObjectPrivateToDer,
    KP0010KeyObjectSignerToVerifier,
    KP0011KeyObjectMissingClass,
    KP0012KeyObjectMissingProvider,
    KP0012KeyProviderNotLoaded,
    KP0013KeyObjectJwsEs256DerInvalid,
    KP0014KeyObjectSignerToVerifier,
    KP0015KeyObjectJwsEs256DerInvalid,
    KP0016KeyObjectJwsEs256DerInvalid,
    KP0017KeyProviderNoSuchKey,
    KP0018KeyProviderNoSuchKey,
    KP0019KeyProviderUnsupportedAlgorithm,
    KP0020KeyObjectNoActiveSigningKeys,
    KP0021KeyObjectJwsEs256Signature,
    KP0022KeyObjectJwsNotAssociated,
    KP0023KeyObjectJwsKeyRevoked,
    KP0024KeyObjectJwsInvalid,
    KP0025KeyProviderNotAvailable,
    KP0026KeyObjectNoSuchKey,
    KP0027KeyObjectPublicToDer,
    KP0028KeyObjectImportJwsEs256DerInvalid,
    KP0029KeyObjectSignerToVerifier,
    KP0030KeyObjectPublicToDer,
    KP0031KeyObjectNotFound,
    KP0032KeyProviderNoSuchKey,
    KP0033KeyProviderNoSuchKey,
    KP0034KeyProviderUnsupportedAlgorithm,
    KP0035KeyObjectJweA128GCMGeneration,
    KP0036KeyObjectPrivateToBytes,
    KP0037KeyObjectImportJweA128GCMInvalid,
    KP0038KeyObjectImportJweA128GCMInvalid,
    KP0039KeyObjectJweNotAssociated,
    KP0040KeyObjectJweInvalid,
    KP0041KeyObjectJweRevoked,
    KP0042KeyObjectNoActiveEncryptionKeys,
    KP0043KeyObjectJweA128GCMEncryption,
    KP0044KeyObjectJwsPublicJwk,

    KP0045KeyObjectImportJwsRs256DerInvalid,
    KP0046KeyObjectSignerToVerifier,
    KP0047KeyObjectPublicToDer,
    KP0048KeyObjectJwtRs256Generation,
    KP0049KeyObjectSignerToVerifier,
    KP0050KeyObjectPrivateToDer,
    KP0051KeyObjectPublicToDer,
    KP0052KeyObjectJwsRs256DerInvalid,
    KP0053KeyObjectSignerToVerifier,
    KP0054KeyObjectJwsRs256DerInvalid,
    KP0055KeyObjectJwsRs256DerInvalid,
    KP0056KeyObjectJwsRs256Signature,
    KP0057KeyObjectJwsNotAssociated,
    KP0058KeyObjectJwsInvalid,
    KP0059KeyObjectJwsKeyRevoked,
    KP0060KeyObjectJwsPublicJwk,
    KP0061KeyObjectNoActiveSigningKeys,
    KP0062KeyProviderNoSuchKey,

    KP0063KeyObjectJwsHs256DerInvalid,
    KP0064KeyObjectSignerToVerifier,
    KP0065KeyObjectJwtHs256Generation,
    KP0066KeyObjectJwsHs256DerInvalid,
    KP0067KeyObjectSignerToVerifier,
    KP0068KeyObjectJwsHs256DerInvalid,
    KP0069KeyObjectNoActiveSigningKeys,
    KP0070KeyObjectJwsHs256Signature,
    KP0071KeyObjectPrivateToDer,

    KP0072KeyObjectHs256Invalid,
    KP0073KeyObjectHs256Invalid,
    KP0074KeyObjectNoActiveSigningKeys,
    KP0075KeyObjectHmacInvalidLength,
    KP0076KeyObjectHkdfOutputLengthInvalid,
    KP0077KeyProviderNoSuchKey,
    KP0078KeyObjectNotFound,
    KP0079KeyObjectNotFound,

    KP0080KeyProviderNoSuchKey,

    // Plugins
    PL0001GidOverlapsSystemRange,

    // Web UI
    UI0001ChallengeSerialisation,
    UI0002InvalidState,
    UI0003InvalidOauth2Resume,
    UI0004MemberAlreadyExists,

    // Unixd Things
    KU001InitWhileSessionActive,
    KU002ContinueWhileSessionInActive,
    KU003PamAuthFailed,
    KU004PamInitFailed,
    KU005ErrorCheckingAccount,
    KU006OnlyRootAllowed,
}

impl PartialEq for OperationError {
    fn eq(&self, other: &Self) -> bool {
        // We do this to avoid InvalidPassword being checked as it's not
        // derive PartialEq. Generally we only use the PartialEq for TESTING
        // anyway.
        std::mem::discriminant(self) == std::mem::discriminant(other)
    }
}

impl Display for OperationError {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        let mut output = format!("{self:?}")
            .split("::")
            .last()
            .unwrap_or("")
            .to_string();

        if let Some(msg) = self.message() {
            output += &format!(" - {msg}");
        };
        f.write_str(&output)
    }
}

impl OperationError {
    /// Return the message associated with the error if there is one.
    pub fn message(&self) -> Option<String> {
        match self {
            Self::SessionExpired => None,
            Self::EmptyRequest => None,
            Self::Backend => None,
            Self::NoMatchingEntries => None,
            Self::NoMatchingAttributes => None,
            Self::UniqueConstraintViolation => Some("A unique constraint was violated resulting in multiple conflicting results.".into()),
            Self::CorruptedEntry(_) => None,
            Self::CorruptedIndex(_) => None,
            Self::ConsistencyError(_) => None,
            Self::SchemaViolation(_) => None,
            Self::Plugin(_) => None,
            Self::FilterGeneration => None,
            Self::FilterParseError => None,
            Self::FilterUuidResolution => None,
            Self::InvalidAttributeName(_) => None,
            Self::InvalidAttribute(_) => None,
            Self::InvalidLabel => Some("The submitted label for this item is invalid.".into()),
            Self::DuplicateLabel => Some("The submitted label for this item is already in use.".into()),
            Self::DuplicateKey => Some("The submitted key already exists.".into()),
            Self::InvalidDbState => None,
            Self::InvalidCacheState => None,
            Self::InvalidValueState => None,
            Self::InvalidEntryId => None,
            Self::InvalidRequestState => None,
            Self::InvalidSyncState => None,
            Self::InvalidState => None,
            Self::InvalidEntryState => None,
            Self::InvalidUuid => None,
            Self::InvalidReplChangeId => None,
            Self::InvalidAcpState(_) => None,
            Self::InvalidSchemaState(_) => None,
            Self::InvalidAccountState(val) => Some(format!("Invalid account state: {val}")),
            Self::MissingClass(val) => Some(format!("Missing class: {val}")),
            Self::MissingAttribute(val) => Some(format!("Missing attribute: {val}")),
            Self::AttributeUniqueness(attrs) => Some(format!("The value of some attributes is not unique. {attrs:?}")),
            Self::MissingEntries => None,
            Self::ModifyAssertionFailed => None,
            Self::BackendEngine => None,
            Self::SqliteError => None,
            Self::FsError => None,
            Self::SerdeJsonError => None,
            Self::SerdeCborError => None,
            Self::AccessDenied => None,
            Self::NotAuthenticated => None,
            Self::NotAuthorised => None,
            Self::InvalidAuthState(_) => None,
            Self::InvalidSessionState => None,
            Self::SystemProtectedObject => None,
            Self::SystemProtectedAttribute => None,
            Self::PasswordQuality(_) => None,
            Self::CryptographyError => None,
            Self::ResourceLimit => None,
            Self::QueueDisconnected => None,
            Self::Webauthn => None,
            Self::Wait(_) => None,
            Self::CannotStartMFADuringOngoingMFASession => Some("Cannot start a new MFA authentication flow when there already is one active.".into()),
            Self::ReplReplayFailure => None,
            Self::ReplEntryNotChanged => None,
            Self::ReplInvalidRUVState => None,
            Self::ReplDomainLevelUnsatisfiable => None,
            Self::ReplDomainUuidMismatch => None,
            Self::ReplServerUuidSplitDataState => None,
            Self::TransactionAlreadyCommitted => None,
            Self::ValueDenyName => None,
            Self::DatabaseLockAcquisitionTimeout => Some("Unable to acquire a database lock - the current server may be too busy. Try again later.".into()),
            Self::ReferenceLoop => Some("The change you have made would introduce an invalid reference loop. Unable to proceed.".into()),
            Self::SessionMayNotReauth => Some("The current session is not able to re-authenticate to elevate privileges to read-write.".into()),

    Self::AU0001InvalidState => Some("Invalid authentication session state for request".into()),
    Self::AU0002JwsSerialisation => Some("JWS serialisation failed".into()),
    Self::AU0003JwsSignature => Some("JWS signature failed".into()),
    Self::AU0004UserAuthTokenInvalid => Some("User auth token was unable to be generated".into()),
    Self::AU0005DelayedProcessFailure => Some("Delaying processing failure, unable to proceed".into()),
    Self::AU0006CredentialMayNotReauthenticate => Some("Credential may not reauthenticate".into()),
    Self::AU0007UserAuthTokenInvalid => Some("User auth token was unable to be generated".into()),
    Self::AU0008ClientAuthInfoPrevalidation => Some("Client Authentication Info prevalidation did not occur when expected".into()),

            Self::CU0001WebauthnAttestationNotTrusted => None,
            Self::CU0002WebauthnRegistrationError => None,
            Self::CU0003WebauthnUserNotVerified => Some("User Verification bit not set while registering credential, you may need to configure a PIN on this device.".into()),

            Self::CU0004SessionInconsistent => Some("The session is unable to be committed due to unresolved warnings.".into()),
            Self::CU0005IntentTokenConflict => Some("The intent token used to create this session has been reused in another browser/tab and may not proceed.".into()),
            Self::CU0006IntentTokenInvalidated => Some("The intent token has been invalidated/revoked before the commit could be accepted. Has it been used in another browser or tab?".into()),

            Self::DB0001MismatchedRestoreVersion => None,
            Self::DB0002MismatchedRestoreVersion => None,
            Self::DB0003FilterResolveCacheBuild => None,
            Self::DB0004DatabaseTooOld => Some("The database is too old to be migrated.".into()),
            Self::KG001TaskTimeout => Some("Task timed out".into()),
            Self::KG002TaskCommFailure => Some("Inter-Task communication failure".into()),
            Self::KG003CacheClearFailed => Some("Failed to clear cache".into()),
            Self::KG004UnknownFeatureUuid => None,
            Self::KG005HowDidYouEvenManageThis => Some("You have damaged the fabric of space time and managed to perform an impossible action.".into()),
            Self::KG006DatastructureCorruption => None,
            Self::KP0001KeyProviderNotLoaded => None,
            Self::KP0002KeyProviderInvalidClass => None,
            Self::KP0003KeyProviderInvalidType => None,
            Self::KP0004KeyProviderMissingAttributeName => None,
            Self::KP0005KeyProviderDuplicate => None,
            Self::KP0006KeyObjectJwtEs256Generation => None,
            Self::KP0007KeyProviderDefaultNotAvailable => None,
            Self::KP0008KeyObjectMissingUuid => None,
            Self::KP0009KeyObjectPrivateToDer => None,
            Self::KP0010KeyObjectSignerToVerifier => None,
            Self::KP0011KeyObjectMissingClass => None,
            Self::KP0012KeyObjectMissingProvider => None,
            Self::KP0012KeyProviderNotLoaded => None,
            Self::KP0013KeyObjectJwsEs256DerInvalid => None,
            Self::KP0014KeyObjectSignerToVerifier => None,
            Self::KP0015KeyObjectJwsEs256DerInvalid => None,
            Self::KP0016KeyObjectJwsEs256DerInvalid => None,
            Self::KP0017KeyProviderNoSuchKey => None,
            Self::KP0018KeyProviderNoSuchKey => None,
            Self::KP0019KeyProviderUnsupportedAlgorithm => None,
            Self::KP0020KeyObjectNoActiveSigningKeys => None,
            Self::KP0021KeyObjectJwsEs256Signature => None,
            Self::KP0022KeyObjectJwsNotAssociated => None,
            Self::KP0023KeyObjectJwsKeyRevoked => None,
            Self::KP0024KeyObjectJwsInvalid => None,
            Self::KP0025KeyProviderNotAvailable => None,
            Self::KP0026KeyObjectNoSuchKey => None,
            Self::KP0027KeyObjectPublicToDer => None,
            Self::KP0028KeyObjectImportJwsEs256DerInvalid => None,
            Self::KP0029KeyObjectSignerToVerifier => None,
            Self::KP0030KeyObjectPublicToDer => None,
            Self::KP0031KeyObjectNotFound => None,
            Self::KP0032KeyProviderNoSuchKey => None,
            Self::KP0033KeyProviderNoSuchKey => None,
            Self::KP0034KeyProviderUnsupportedAlgorithm => None,
            Self::KP0035KeyObjectJweA128GCMGeneration => None,
            Self::KP0036KeyObjectPrivateToBytes => None,
            Self::KP0037KeyObjectImportJweA128GCMInvalid => None,
            Self::KP0038KeyObjectImportJweA128GCMInvalid => None,
            Self::KP0039KeyObjectJweNotAssociated => None,
            Self::KP0040KeyObjectJweInvalid => None,
            Self::KP0041KeyObjectJweRevoked => None,
            Self::KP0042KeyObjectNoActiveEncryptionKeys => None,
            Self::KP0043KeyObjectJweA128GCMEncryption => None,
            Self::KP0044KeyObjectJwsPublicJwk => None,

            Self::KP0045KeyObjectImportJwsRs256DerInvalid => None,
            Self::KP0046KeyObjectSignerToVerifier => None,
            Self::KP0047KeyObjectPublicToDer => None,
            Self::KP0048KeyObjectJwtRs256Generation => None,
            Self::KP0049KeyObjectSignerToVerifier => None,
            Self::KP0050KeyObjectPrivateToDer => None,
            Self::KP0051KeyObjectPublicToDer => None,
            Self::KP0052KeyObjectJwsRs256DerInvalid => None,
            Self::KP0053KeyObjectSignerToVerifier => None,
            Self::KP0054KeyObjectJwsRs256DerInvalid => None,
            Self::KP0055KeyObjectJwsRs256DerInvalid => None,
            Self::KP0056KeyObjectJwsRs256Signature => None,
            Self::KP0057KeyObjectJwsNotAssociated => None,
            Self::KP0058KeyObjectJwsInvalid => None,
            Self::KP0059KeyObjectJwsKeyRevoked => None,
            Self::KP0060KeyObjectJwsPublicJwk => None,
            Self::KP0061KeyObjectNoActiveSigningKeys => None,
            Self::KP0062KeyProviderNoSuchKey => None,
            Self::KP0063KeyObjectJwsHs256DerInvalid => None,
            Self::KP0064KeyObjectSignerToVerifier => None,
            Self::KP0065KeyObjectJwtHs256Generation => None,
            Self::KP0066KeyObjectJwsHs256DerInvalid => None,
            Self::KP0067KeyObjectSignerToVerifier => None,
            Self::KP0068KeyObjectJwsHs256DerInvalid => None,
            Self::KP0069KeyObjectNoActiveSigningKeys => None,
            Self::KP0070KeyObjectJwsHs256Signature => None,
            Self::KP0071KeyObjectPrivateToDer => None,
            Self::KP0072KeyObjectHs256Invalid => None,
            Self::KP0073KeyObjectHs256Invalid => None,
            Self::KP0074KeyObjectNoActiveSigningKeys => None,
            Self::KP0075KeyObjectHmacInvalidLength => None,
            Self::KP0076KeyObjectHkdfOutputLengthInvalid => None,
            Self::KP0077KeyProviderNoSuchKey => None,
            Self::KP0078KeyObjectNotFound => None,
            Self::KP0079KeyObjectNotFound => None,
            Self::KP0080KeyProviderNoSuchKey => None,

            Self::KU001InitWhileSessionActive => Some("The session was active when the init function was called.".into()),
            Self::KU002ContinueWhileSessionInActive => Some("Attempted to continue auth session while current session is inactive".into()),
            Self::KU003PamAuthFailed => Some("Failed PAM account authentication step".into()),
            Self::KU004PamInitFailed => Some("Failed to initialise PAM authentication".into()),
            Self::KU005ErrorCheckingAccount => Some("Error checking account".into()),
            Self::KU006OnlyRootAllowed => Some("Only root is allowed to perform this operation".into()),
            Self::LD0001AnonymousNotAllowed => Some("Anonymous is not allowed to access LDAP with this method.".into()),
            Self::MG0001InvalidReMigrationLevel => None,
            Self::MG0002RaiseDomainLevelExceedsMaximum => None,
            Self::MG0003ServerPhaseInvalidForMigration => None,
            Self::MG0004DomainLevelInDevelopment => None,
            Self::MG0005GidConstraintsNotMet => None,
            Self::MG0006SKConstraintsNotMet => Some("Migration Constraints Not Met - Security Keys should not be present.".into()),
            Self::MG0007Oauth2StrictConstraintsNotMet => Some("Migration Constraints Not Met - All OAuth2 clients must have strict-redirect-uri mode enabled.".into()),
            Self::MG0008SkipUpgradeAttempted => Some("Skip Upgrade Attempted.".into()),
            Self::MG0009InvalidTargetLevelForBootstrap => Some("The request target domain level was not valid for bootstrapping a new server instance".into()),
            Self::MG0010DowngradeNotAllowed => Some("Downgrade Attempted".into()),
            Self::PL0001GidOverlapsSystemRange => None,
            Self::SC0001IncomingSshPublicKey => None,
            Self::SC0002ReferenceSyntaxInvalid => Some("A SCIM Reference Set contained invalid syntax and can not be processed.".into()),
            Self::SC0003MailSyntaxInvalid => Some("A SCIM Mail Address contained invalid syntax".into()),
            Self::SC0004UuidSyntaxInvalid => Some("A SCIM Uuid contained invalid syntax".into()),
            Self::SC0005BoolSyntaxInvalid => Some("A SCIM boolean contained invalid syntax".into()),
            Self::SC0006Uint32SyntaxInvalid => Some("A SCIM Uint32 contained invalid syntax".into()),
            Self::SC0007UrlSyntaxInvalid => Some("A SCIM Url contained invalid syntax".into()),
            Self::SC0008SyntaxTypeSyntaxInvalid => Some("A SCIM SyntaxType contained invalid syntax".into()),
            Self::SC0009IndexTypeSyntaxInvalid => Some("A SCIM IndexType contained invalid syntax".into()),
            Self::SC0010DateTimeSyntaxInvalid => Some("A SCIM DateTime contained invalid syntax".into()),

            Self::SC0011AddressSyntaxInvalid => Some("A SCIM Address contained invalid syntax".into()),
            Self::SC0012CertificateSyntaxInvalid => Some("A SCIM Certificate contained invalid binary data".into()),
            Self::SC0013CertificateInvalidDer => Some("A SCIM Certificate did not contain valid DER".into()),
            Self::SC0014CertificateInvalidDigest => Some("A SCIM Certificate was unable to be digested".into()),
            Self::SC0015CredentialTypeSyntaxInvalid => Some("A SCIM CredentialType contained invalid syntax".into()),
            Self::SC0016InameSyntaxInvalid => Some("A SCIM Iname string contained invalid syntax".into()),
            Self::SC0017Iutf8SyntaxInvalid => Some("A SCIM Iutf8 string contained invalid syntax".into()),
            Self::SC0018NsUniqueIdSyntaxInvalid => Some("A SCIM NsUniqueID contained invalid syntax".into()),
            Self::SC0019Oauth2ScopeSyntaxInvalid => Some("A SCIM Oauth2 Scope contained invalid syntax".into()),
            Self::SC0020Oauth2ScopeMapSyntaxInvalid => Some("A SCIM Oauth2 Scope Map contained invalid syntax".into()),
            Self::SC0021Oauth2ScopeMapMissingGroupIdentifier => Some("A SCIM Oauth2 Scope Map was missing a group name or uuid".into()),
            Self::SC0022Oauth2ClaimMapSyntaxInvalid => Some("A SCIM Oauth2 Claim Map contained invalid syntax".into()),
            Self::SC0023Oauth2ClaimMapMissingGroupIdentifier => Some("A SCIM Claim Map was missing a group name or uuid".into()),
            Self::SC0024SshPublicKeySyntaxInvalid => Some("A SCIM Ssh Public Key contained invalid syntax".into()),
            Self::SC0025UiHintSyntaxInvalid => Some("A SCIM UiHint contained invalid syntax".into()),
            Self::SC0026Utf8SyntaxInvalid => Some("A SCIM Utf8 String Scope Map contained invalid syntax".into()),
            Self::SC0027ClassSetInvalid => Some("The internal set of class templates used in this create operation was invalid. THIS IS A BUG.".into()),
            Self::SC0028CreatedUuidsInvalid => Some("The internal create query did not return the set of created UUIDs. THIS IS A BUG".into()),
            Self::SC0029PaginationOutOfBounds => Some("The requested range for pagination was out of bounds of the result set".into()),
            Self::SC0030Sha256SyntaxInvalid => Some("A SCIM SHA256 hex string was invalid.".into()),
            Self::SC0031Int64SyntaxInvalid => Some("A SCIM Int64 contained invalid syntax".into()),
            Self::SC0032Uint64SyntaxInvalid => Some("A SCIM Uint64 contained invalid syntax".into()),
            Self::SC0033AssertionContainsDuplicateUuids => Some("SCIM assertion contains duplicate entry ids, unable to proceed.".into()),
            Self::UI0001ChallengeSerialisation => Some("The WebAuthn challenge was unable to be serialised.".into()),
            Self::UI0002InvalidState => Some("The credential update process returned an invalid state transition.".into()),
            Self::UI0003InvalidOauth2Resume => Some("The server attempted to resume OAuth2, but no OAuth2 session is in progress.".into()),
            Self::UI0004MemberAlreadyExists => Some("The target is already a member.".into()),
            Self::VL0001ValueSshPublicKeyString => None,
            Self::VS0001IncomingReplSshPublicKey => None,
            Self::VS0002CertificatePublicKeyDigest |
            Self::VS0003CertificateDerDecode => Some("Decoding the stored certificate from DER failed.".into()),
            Self::VS0004CertificatePublicKeyDigest |
            Self::VS0005CertificatePublicKeyDigest => Some("The certificates public key is unable to be digested.".into()),

        }
    }
}

#[test]
fn test_operationerror_as_nice_string() {
    assert_eq!(
        OperationError::CU0001WebauthnAttestationNotTrusted.to_string(),
        "CU0001WebauthnAttestationNotTrusted".to_string()
    );
    assert_eq!(
        OperationError::CU0003WebauthnUserNotVerified.to_string(),
        "CU0003WebauthnUserNotVerified - User Verification bit not set while registering credential, you may need to configure a PIN on this device.".to_string()
    );
    assert_eq!(
        OperationError::SessionExpired.to_string(),
        "SessionExpired".to_string()
    );
    assert_eq!(
        OperationError::CorruptedEntry(12345).to_string(),
        "CorruptedEntry(12345)".to_string()
    );
}
