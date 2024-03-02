use std::fmt::{self, Display, Formatter};

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
    /// when you ask for a gid that overlaps a system reserved range
    /// When a name is denied by the system config
    ValueDenyName,
    // What about something like this for unique errors?
    // Credential Update Errors
    CU0001WebauthnAttestationNotTrusted,
    CU0002WebauthnRegistrationError,
    CU0003WebauthnUserNotVerified,
    // ValueSet errors
    VS0001IncomingReplSshPublicKey,
    // Value Errors
    VL0001ValueSshPublicKeyString,

    // DB low level errors.
    DB0001MismatchedRestoreVersion,
    DB0002MismatchedRestoreVersion,

    // SCIM
    SC0001IncomingSshPublicKey,
    // Migration
    MG0001InvalidReMigrationLevel,
    MG0002RaiseDomainLevelExceedsMaximum,
    MG0003ServerPhaseInvalidForMigration,
    MG0004DomainLevelInDevelopment,
    MG0005GidConstraintsNotMet,
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
}

impl PartialEq for OperationError {
    fn eq(&self, other: &Self) -> bool {
        // We do this to avoid InvalidPassword being checked as it's not
        // derive PartialEq. Generally we only use the PartialEq for TESTING
        // anyway.
        std::mem::discriminant(self) == std::mem::discriminant(other)
    }
}

impl OperationError {
    /// This is bad but I don't feel that bad.
    ///
    /// It takes something like `CU0001WebauthnAttestationNotTrusted` and turns it
    /// into `CU0001 - Webauthn Attestation Not Trusted` if it can, otherwise you just get the normal
    /// debug format with spaces
    ///
    /// Probably shouldn't use this with any of the complex types because it'll get weird quick!
    pub fn variant_as_nice_string(&self) -> String {
        let asstr = self.to_string();
        let asstr = asstr.split("::").last().unwrap();
        let parser = regex::Regex::new(r"^(?P<errcode>[A-Z]{2}\d{4})(?P<therest>.*)")
            .expect("Failed to parse regex!");

        let splitter = regex::Regex::new(r"([A-Z])").expect("Failed to parse splitter regex!");
        match parser.captures(asstr) {
            Some(caps) => {
                let mut nice_string = splitter.replace_all(&caps["therest"], " $1").to_string();
                while nice_string.contains("  ") {
                    nice_string = nice_string.replace("  ", " ");
                }
                format!("{} - {}", &caps["errcode"], nice_string.trim())
            }
            None => {
                let nice_string = splitter.replace_all(asstr, " $1").to_string();
                nice_string.trim().to_string()
            }
        }
    }
}

#[test]
fn test_operationerror_as_nice_string() {
    assert_eq!(
        OperationError::CU0001WebauthnAttestationNotTrusted.variant_as_nice_string(),
        "CU0001 - Webauthn Attestation Not Trusted".to_string()
    );
    assert_eq!(
        OperationError::CU0003WebauthnUserNotVerified.variant_as_nice_string(),
        "CU0003 - User Verification bit not set while registering credential.".to_string()
    );
    assert_eq!(
        OperationError::SessionExpired.variant_as_nice_string(),
        "Session Expired".to_string()
    );
    assert_eq!(
        OperationError::CorruptedEntry(12345).variant_as_nice_string(),
        "Corrupted Entry(12345)".to_string()
    );
}

impl Display for OperationError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            OperationError::SessionExpired => write!(f, "{:?}", self),
            OperationError::EmptyRequest => write!(f, "{:?}", self),
            OperationError::Backend => write!(f, "{:?}", self),
            OperationError::NoMatchingEntries => write!(f, "{:?}", self),
            OperationError::NoMatchingAttributes => write!(f, "{:?}", self),
            OperationError::CorruptedEntry(_) => write!(f, "{:?}", self),
            OperationError::CorruptedIndex(_) => write!(f, "{:?}", self),
            OperationError::ConsistencyError(_) => write!(f, "{:?}", self),
            OperationError::SchemaViolation(_) => write!(f, "{:?}", self),
            OperationError::Plugin(_) => write!(f, "{:?}", self),
            OperationError::FilterGeneration => write!(f, "{:?}", self),
            OperationError::FilterUuidResolution => write!(f, "{:?}", self),
            OperationError::InvalidAttributeName(_) => write!(f, "{:?}", self),
            OperationError::InvalidAttribute(_) => write!(f, "{:?}", self),
            OperationError::InvalidDbState => write!(f, "{:?}", self),
            OperationError::InvalidCacheState => write!(f, "{:?}", self),
            OperationError::InvalidValueState => write!(f, "{:?}", self),
            OperationError::InvalidEntryId => write!(f, "{:?}", self),
            OperationError::InvalidRequestState => write!(f, "{:?}", self),
            OperationError::InvalidSyncState => write!(f, "{:?}", self),
            OperationError::InvalidState => write!(f, "{:?}", self),
            OperationError::InvalidEntryState => write!(f, "{:?}", self),
            OperationError::InvalidUuid => write!(f, "{:?}", self),
            OperationError::InvalidReplChangeId => write!(f, "{:?}", self),
            OperationError::InvalidAcpState(_) => write!(f, "{:?}", self),
            OperationError::InvalidSchemaState(_) => write!(f, "{:?}", self),
            OperationError::InvalidAccountState(_) => write!(f, "{:?}", self),
            OperationError::MissingEntries => write!(f, "{:?}", self),
            OperationError::ModifyAssertionFailed => write!(f, "{:?}", self),
            OperationError::BackendEngine => write!(f, "{:?}", self),
            OperationError::SqliteError => write!(f, "{:?}", self),
            OperationError::FsError => write!(f, "{:?}", self),
            OperationError::SerdeJsonError => write!(f, "{:?}", self),
            OperationError::SerdeCborError => write!(f, "{:?}", self),
            OperationError::AccessDenied => write!(f, "{:?}", self),
            OperationError::NotAuthenticated => write!(f, "{:?}", self),
            OperationError::NotAuthorised => write!(f, "{:?}", self),
            OperationError::InvalidAuthState(_) => write!(f, "{:?}", self),
            OperationError::InvalidSessionState => write!(f, "{:?}", self),
            OperationError::SystemProtectedObject => write!(f, "{:?}", self),
            OperationError::SystemProtectedAttribute => write!(f, "{:?}", self),
            OperationError::PasswordQuality(_) => write!(f, "{:?}", self),
            OperationError::CryptographyError => write!(f, "{:?}", self),
            OperationError::ResourceLimit => write!(f, "{:?}", self),
            OperationError::QueueDisconnected => write!(f, "{:?}", self),
            OperationError::Webauthn => write!(f, "{:?}", self),
            OperationError::Wait(_) => write!(f, "{:?}", self),
            OperationError::ReplReplayFailure => write!(f, "{:?}", self),
            OperationError::ReplEntryNotChanged => write!(f, "{:?}", self),
            OperationError::ReplInvalidRUVState => write!(f, "{:?}", self),
            OperationError::ReplDomainLevelUnsatisfiable => write!(f, "{:?}", self),
            OperationError::ReplDomainUuidMismatch => write!(f, "{:?}", self),
            OperationError::ReplServerUuidSplitDataState => write!(f, "{:?}", self),
            OperationError::TransactionAlreadyCommitted => write!(f, "{:?}", self),
            OperationError::GidOverlapsSystemMin(_) => write!(f, "{:?}", self),
            OperationError::ValueDenyName => write!(f, "{:?}", self),
            OperationError::CU0001WebauthnAttestationNotTrusted => write!(f, "{:?}", self),
            OperationError::CU0002WebauthnRegistrationError => write!(f, "{:?}", self),
            OperationError::CU0003WebauthnUserNotVerified => write!(
                f,
                "CU0003 User Verification bit not set while registering credential.", // TODO: provide actionable message
            ),
            OperationError::VS0001IncomingReplSshPublicKey => write!(f, "{:?}", self),
            OperationError::VL0001ValueSshPublicKeyString => write!(f, "{:?}", self),
            OperationError::SC0001IncomingSshPublicKey => write!(f, "{:?}", self),
            OperationError::MG0001InvalidReMigrationLevel => write!(f, "{:?}", self),
            OperationError::MG0002RaiseDomainLevelExceedsMaximum => write!(f, "{:?}", self),
            OperationError::MG0003ServerPhaseInvalidForMigration => write!(f, "{:?}", self),
        }
    }
}
