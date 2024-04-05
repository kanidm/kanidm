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
    // ValueSet errors
    VS0001IncomingReplSshPublicKey,
    // Value Errors
    VL0001ValueSshPublicKeyString,
    // LDAP
    LD0001InvalidAuthenticationToken,

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
