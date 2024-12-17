use std::fmt::{Display, Formatter};

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use super::credupdate::PasswordFeedback;
use crate::attribute::Attribute;

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
    AttrUnique(String),
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
    // Logic errors, or "soft" errors.
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

    // Specific internal errors.

    // Kanidm Generic Errors
    KG001TaskTimeout,
    KG002TaskCommFailure,
    KG003CacheClearFailed,

    // What about something like this for unique errors?
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
    // Migration
    MG0001InvalidReMigrationLevel,
    MG0002RaiseDomainLevelExceedsMaximum,
    MG0003ServerPhaseInvalidForMigration,
    MG0004DomainLevelInDevelopment,
    MG0005GidConstraintsNotMet,
    MG0006SKConstraintsNotMet,
    MG0007Oauth2StrictConstraintsNotMet,
    MG0008SkipUpgradeAttempted,
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

    // Plugins
    PL0001GidOverlapsSystemRange,

    // Web UI
    UI0001ChallengeSerialisation,
    UI0002InvalidState,
    UI0003InvalidOauth2Resume,

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
        let mut output = format!("{:?}", self)
            .split("::")
            .last()
            .unwrap_or("")
            .to_string();

        if let Some(msg) = self.message() {
            output += &format!(" - {}", msg);
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
            Self::InvalidAccountState(val) => Some(format!("Invalid account state: {}", val)),
            Self::MissingClass(val) => Some(format!("Missing class: {}", val)),
            Self::MissingAttribute(val) => Some(format!("Missing attribute: {}", val)),
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
            Self::PL0001GidOverlapsSystemRange => None,

            Self::SC0001IncomingSshPublicKey => None,

            Self::UI0001ChallengeSerialisation => Some("The WebAuthn challenge was unable to be serialised.".into()),
            Self::UI0002InvalidState => Some("The credential update process returned an invalid state transition.".into()),
            Self::UI0003InvalidOauth2Resume => Some("The server attemped to resume OAuth2, but no OAuth2 session is in progress.".into()),
            Self::VL0001ValueSshPublicKeyString => None,
            Self::VS0001IncomingReplSshPublicKey => None,
            Self::VS0002CertificatePublicKeyDigest |
            Self::VS0003CertificateDerDecode => Some("Decoding the stored certificate from DER failed.".into()),
            Self::VS0004CertificatePublicKeyDigest |
            Self::VS0005CertificatePublicKeyDigest => Some("The certificates public key is unabled to be digested.".into()),
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
