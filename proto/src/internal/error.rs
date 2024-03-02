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
        let asstr = format!("{:?}", self);
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
                let message = match self.message() {
                    Some(val) => format!(" - {}", val),
                    None => "".to_string(),
                };

                format!("{} - {}{}", &caps["errcode"], nice_string.trim(), message)
            }
            None => {
                let nice_string = splitter.replace_all(asstr, " $1").to_string();
                nice_string.trim().to_string()
            }
        }
    }

    fn message(&self) -> Option<&'static str> {
        match self {
            OperationError::SessionExpired => None,
            OperationError::EmptyRequest => None,
            OperationError::Backend => None,
            OperationError::NoMatchingEntries => None,
            OperationError::NoMatchingAttributes => None,
            OperationError::CorruptedEntry(_) => None,
            OperationError::CorruptedIndex(_) => None,
            OperationError::ConsistencyError(_) => None,
            OperationError::SchemaViolation(_) => None,
            OperationError::Plugin(_) => None,
            OperationError::FilterGeneration => None,
            OperationError::FilterUuidResolution => None,
            OperationError::InvalidAttributeName(_) => None,
            OperationError::InvalidAttribute(_) => None,
            OperationError::InvalidDbState => None,
            OperationError::InvalidCacheState => None,
            OperationError::InvalidValueState => None,
            OperationError::InvalidEntryId => None,
            OperationError::InvalidRequestState => None,
            OperationError::InvalidSyncState => None,
            OperationError::InvalidState => None,
            OperationError::InvalidEntryState => None,
            OperationError::InvalidUuid => None,
            OperationError::InvalidReplChangeId => None,
            OperationError::InvalidAcpState(_) => None,
            OperationError::InvalidSchemaState(_) => None,
            OperationError::InvalidAccountState(_) => None,
            OperationError::MissingEntries => None,
            OperationError::ModifyAssertionFailed => None,
            OperationError::BackendEngine => None,
            OperationError::SqliteError => None,
            OperationError::FsError => None,
            OperationError::SerdeJsonError => None,
            OperationError::SerdeCborError => None,
            OperationError::AccessDenied => None,
            OperationError::NotAuthenticated => None,
            OperationError::NotAuthorised => None,
            OperationError::InvalidAuthState(_) => None,
            OperationError::InvalidSessionState => None,
            OperationError::SystemProtectedObject => None,
            OperationError::SystemProtectedAttribute => None,
            OperationError::PasswordQuality(_) => None,
            OperationError::CryptographyError => None,
            OperationError::ResourceLimit => None,
            OperationError::QueueDisconnected => None,
            OperationError::Webauthn => None,
            OperationError::Wait(_) => None,
            OperationError::ReplReplayFailure => None,
            OperationError::ReplEntryNotChanged => None,
            OperationError::ReplInvalidRUVState => None,
            OperationError::ReplDomainLevelUnsatisfiable => None,
            OperationError::ReplDomainUuidMismatch => None,
            OperationError::ReplServerUuidSplitDataState => None,
            OperationError::TransactionAlreadyCommitted => None,
            OperationError::GidOverlapsSystemMin(_) => None,
            OperationError::ValueDenyName => None,
            OperationError::CU0002WebauthnRegistrationError => None,
            OperationError::CU0003WebauthnUserNotVerified => Some("User Verification bit not set while registering credential, you may need to configure a PIN on this device."),
                OperationError::CU0001WebauthnAttestationNotTrusted => None,
            OperationError::VS0001IncomingReplSshPublicKey => None,
            OperationError::VL0001ValueSshPublicKeyString => None,
            OperationError::SC0001IncomingSshPublicKey => None,
            OperationError::MG0001InvalidReMigrationLevel => None,
            OperationError::MG0002RaiseDomainLevelExceedsMaximum => None,
            OperationError::MG0003ServerPhaseInvalidForMigration => None,
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
        "CU0003 - Webauthn User Not Verified - User Verification bit not set while registering credential, you may need to configure a PIN on this device.".to_string()
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
