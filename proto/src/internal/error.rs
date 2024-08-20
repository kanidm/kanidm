use std::fmt::{Display, Formatter};

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use super::credupdate::PasswordFeedback;

/* ===== errors ===== */
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum SchemaError {
    NotImplemented,
    NoClassFound,
    InvalidClass(Vec<String>),
    MissingMustAttribute(Vec<String>),
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
    EmptyRequest,
    Backend,
    NoMatchingEntries,
    NoMatchingAttributes,
    CorruptedEntry(u64),
    CorruptedIndex(String),
    // TODO: this should just be a vec of the ConsistencyErrors, surely?
    ConsistencyError(Vec<Result<(), ConsistencyError>>),
    SchemaViolation(SchemaError),
    Plugin(PluginError),
    FilterGeneration,
    FilterUuidResolution,
    InvalidAttributeName(String),
    InvalidAttribute(String),
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

    // What about something like this for unique errors?
    // Credential Update Errors
    CU0001WebauthnAttestationNotTrusted,
    CU0002WebauthnRegistrationError,
    CU0003WebauthnUserNotVerified,
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
    fn message(&self) -> Option<&'static str> {
        match self {
            Self::SessionExpired => None,
            Self::EmptyRequest => None,
            Self::Backend => None,
            Self::NoMatchingEntries => None,
            Self::NoMatchingAttributes => None,
            Self::CorruptedEntry(_) => None,
            Self::CorruptedIndex(_) => None,
            Self::ConsistencyError(_) => None,
            Self::SchemaViolation(_) => None,
            Self::Plugin(_) => None,
            Self::FilterGeneration => None,
            Self::FilterUuidResolution => None,
            Self::InvalidAttributeName(_) => None,
            Self::InvalidAttribute(_) => None,
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
            Self::InvalidAccountState(_) => None,
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
            Self::CannotStartMFADuringOngoingMFASession => Some("Cannot start a new MFA authentication flow when there already is one active."),
            Self::ReplReplayFailure => None,
            Self::ReplEntryNotChanged => None,
            Self::ReplInvalidRUVState => None,
            Self::ReplDomainLevelUnsatisfiable => None,
            Self::ReplDomainUuidMismatch => None,
            Self::ReplServerUuidSplitDataState => None,
            Self::TransactionAlreadyCommitted => None,
            Self::ValueDenyName => None,
            Self::DatabaseLockAcquisitionTimeout => Some("Unable to acquire a database lock - the current server may be too busy. Try again later."),
            Self::CU0002WebauthnRegistrationError => None,
            Self::CU0003WebauthnUserNotVerified => Some("User Verification bit not set while registering credential, you may need to configure a PIN on this device."),
            Self::CU0001WebauthnAttestationNotTrusted => None,
            Self::VS0001IncomingReplSshPublicKey => None,
            Self::VS0003CertificateDerDecode => Some("Decoding the stored certificate from DER failed."),
            Self::VS0002CertificatePublicKeyDigest |
            Self::VS0004CertificatePublicKeyDigest |
            Self::VS0005CertificatePublicKeyDigest => Some("The certificates public key is unabled to be digested."),
            Self::VL0001ValueSshPublicKeyString => None,
            Self::LD0001AnonymousNotAllowed => Some("Anonymous is not allowed to access LDAP with this method."),
            Self::SC0001IncomingSshPublicKey => None,
            Self::MG0001InvalidReMigrationLevel => None,
            Self::MG0002RaiseDomainLevelExceedsMaximum => None,
            Self::MG0003ServerPhaseInvalidForMigration => None,
            Self::DB0001MismatchedRestoreVersion => None,
            Self::DB0002MismatchedRestoreVersion => None,
            Self::DB0003FilterResolveCacheBuild => None,
            Self::MG0004DomainLevelInDevelopment => None,
            Self::MG0005GidConstraintsNotMet => None,
            Self::MG0006SKConstraintsNotMet => Some("Migration Constraints Not Met - Security Keys should not be present."),
            Self::MG0007Oauth2StrictConstraintsNotMet => Some("Migration Constraints Not Met - All OAuth2 clients must have strict-redirect-uri mode enabled."),
            Self::MG0008SkipUpgradeAttempted => Some("Skip Upgrade Attempted."),
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
            Self::PL0001GidOverlapsSystemRange => None,
            Self::UI0001ChallengeSerialisation => Some("The WebAuthn challenge was unable to be serialised."),
            Self::UI0002InvalidState => Some("The credential update process returned an invalid state transition."),
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
