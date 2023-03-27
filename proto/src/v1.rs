use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::str::FromStr;

use num_enum::TryFromPrimitive;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use webauthn_rs_proto::{
    CreationChallengeResponse, PublicKeyCredential, RegisterPublicKeyCredential,
    RequestChallengeResponse,
};

// These proto implementations are here because they have public definitions

/* ===== errors ===== */

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
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

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum PluginError {
    AttrUnique(String),
    Base(String),
    ReferentialIntegrity(String),
    CredImport(String),
    Oauth2Secrets,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
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
    DuplicateUniqueAttribute(String),
    InvalidSpn(u64),
    SqliteIntegrityFailure,
    BackendAllIdsSync,
    BackendIndexSync,
    ChangelogDesynchronised(u64),
    ChangeStateDesynchronised(u64),
    RuvInconsistent(String),
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "lowercase")]
pub enum PasswordFeedback {
    // https://docs.rs/zxcvbn/latest/zxcvbn/feedback/enum.Suggestion.html
    UseAFewWordsAvoidCommonPhrases,
    NoNeedForSymbolsDigitsOrUppercaseLetters,
    AddAnotherWordOrTwo,
    CapitalizationDoesntHelpVeryMuch,
    AllUppercaseIsAlmostAsEasyToGuessAsAllLowercase,
    ReversedWordsArentMuchHarderToGuess,
    PredictableSubstitutionsDontHelpVeryMuch,
    UseALongerKeyboardPatternWithMoreTurns,
    AvoidRepeatedWordsAndCharacters,
    AvoidSequences,
    AvoidRecentYears,
    AvoidYearsThatAreAssociatedWithYou,
    AvoidDatesAndYearsThatAreAssociatedWithYou,
    // https://docs.rs/zxcvbn/latest/zxcvbn/feedback/enum.Warning.html
    StraightRowsOfKeysAreEasyToGuess,
    ShortKeyboardPatternsAreEasyToGuess,
    RepeatsLikeAaaAreEasyToGuess,
    RepeatsLikeAbcAbcAreOnlySlightlyHarderToGuess,
    ThisIsATop10Password,
    ThisIsATop100Password,
    ThisIsACommonPassword,
    ThisIsSimilarToACommonlyUsedPassword,
    SequencesLikeAbcAreEasyToGuess,
    RecentYearsAreEasyToGuess,
    AWordByItselfIsEasyToGuess,
    DatesAreOftenEasyToGuess,
    NamesAndSurnamesByThemselvesAreEasyToGuess,
    CommonNamesAndSurnamesAreEasyToGuess,
    // Custom
    TooShort(usize),
    BadListed,
}

/// Human-readable PasswordFeedback result.
impl fmt::Display for PasswordFeedback {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PasswordFeedback::AddAnotherWordOrTwo => write!(f, "Add another word or two."),
            PasswordFeedback::AllUppercaseIsAlmostAsEasyToGuessAsAllLowercase => write!(
                f,
                "All uppercase is almost as easy to guess as all lowercase."
            ),
            PasswordFeedback::AvoidDatesAndYearsThatAreAssociatedWithYou => write!(
                f,
                "Avoid dates and years that are associated with you or your account."
            ),
            PasswordFeedback::AvoidRecentYears => write!(f, "Avoid recent years."),
            PasswordFeedback::AvoidRepeatedWordsAndCharacters => {
                write!(f, "Avoid repeated words and characters.")
            }
            PasswordFeedback::AvoidSequences => write!(f, "Avoid sequences of characters."),
            PasswordFeedback::AvoidYearsThatAreAssociatedWithYou => {
                write!(f, "Avoid years that are associated with you.")
            }
            PasswordFeedback::AWordByItselfIsEasyToGuess => {
                write!(f, "A word by itself is easy to guess.")
            }
            PasswordFeedback::BadListed => write!(
                f,
                "This password has been compromised or otherwise blocked and can not be used."
            ),
            PasswordFeedback::CapitalizationDoesntHelpVeryMuch => {
                write!(f, "Capitalization doesn't help very much.")
            }
            PasswordFeedback::CommonNamesAndSurnamesAreEasyToGuess => {
                write!(f, "Common names and surnames are easy to guess.")
            }
            PasswordFeedback::DatesAreOftenEasyToGuess => {
                write!(f, "Dates are often easy to guess.")
            }
            PasswordFeedback::NamesAndSurnamesByThemselvesAreEasyToGuess => {
                write!(f, "Names and surnames by themselves are easy to guess.")
            }
            PasswordFeedback::NoNeedForSymbolsDigitsOrUppercaseLetters => {
                write!(f, "No need for symbols, digits or upper-case letters.")
            }
            PasswordFeedback::PredictableSubstitutionsDontHelpVeryMuch => {
                write!(f, "Predictable substitutions don't help very much.")
            }
            PasswordFeedback::RecentYearsAreEasyToGuess => {
                write!(f, "Recent years are easy to guess.")
            }
            PasswordFeedback::RepeatsLikeAaaAreEasyToGuess => {
                write!(f, "Repeats like 'aaa' are easy to guess.")
            }
            PasswordFeedback::RepeatsLikeAbcAbcAreOnlySlightlyHarderToGuess => write!(
                f,
                "Repeats like abcabcabc are only slightly harder to guess."
            ),
            PasswordFeedback::ReversedWordsArentMuchHarderToGuess => {
                write!(f, "Reversed words aren't much harder to guess.")
            }
            PasswordFeedback::SequencesLikeAbcAreEasyToGuess => {
                write!(f, "Sequences like 'abc' are easy to guess.")
            }
            PasswordFeedback::ShortKeyboardPatternsAreEasyToGuess => {
                write!(f, "Short keyboard patterns are easy to guess.")
            }
            PasswordFeedback::StraightRowsOfKeysAreEasyToGuess => {
                write!(f, "Straight rows of keys are easy to guess.")
            }
            PasswordFeedback::ThisIsACommonPassword => write!(f, "This is a common password."),
            PasswordFeedback::ThisIsATop100Password => write!(f, "This is a top 100 password."),
            PasswordFeedback::ThisIsATop10Password => write!(f, "This is a top 10 password."),
            PasswordFeedback::ThisIsSimilarToACommonlyUsedPassword => {
                write!(f, "This is similar to a commonly used password.")
            }
            PasswordFeedback::TooShort(minlength) => write!(
                f,
                "Password too was short, needs to be at least {} characters long.",
                minlength
            ),
            PasswordFeedback::UseAFewWordsAvoidCommonPhrases => {
                write!(f, "Use a few words and avoid common phrases.")
            }
            PasswordFeedback::UseALongerKeyboardPatternWithMoreTurns => {
                write!(
                    f,
                    "The password included keyboard patterns across too much of a single row."
                )
            }
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "lowercase")]
pub enum OperationError {
    SessionExpired,
    EmptyRequest,
    Backend,
    NoMatchingEntries,
    NoMatchingAttributes,
    CorruptedEntry(u64),
    CorruptedIndex(String),
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
}

impl PartialEq for OperationError {
    fn eq(&self, other: &Self) -> bool {
        // We do this to avoid InvalidPassword being checked as it's not
        // derive PartialEq. Generally we only use the PartialEq for TESTING
        // anyway.
        std::mem::discriminant(self) == std::mem::discriminant(other)
    }
}

/* ===== higher level types ===== */
// These are all types that are conceptually layers on top of entry and
// friends. They allow us to process more complex requests and provide
// domain specific fields for the purposes of IDM, over the normal
// entry/ava/filter types. These related deeply to schema.

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Group {
    pub spn: String,
    pub uuid: String,
}

impl fmt::Display for Group {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[ spn: {}, ", self.spn)?;
        write!(f, "uuid: {} ]", self.uuid)
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claim {
    pub name: String,
    pub uuid: String,
    // These can be ephemeral, or shortlived in a session.
    // some may even need requesting.
    // pub expiry: DateTime
}

/*
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Application {
    pub name: String,
    pub uuid: String,
}
*/

#[derive(Debug, Serialize, Deserialize, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[serde(rename_all = "lowercase")]
#[derive(TryFromPrimitive)]
#[repr(u16)]
pub enum UiHint {
    ExperimentalFeatures = 0,
    PosixAccount = 1,
    CredentialUpdate = 2,
}

impl fmt::Display for UiHint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UiHint::PosixAccount => write!(f, "PosixAccount"),
            UiHint::CredentialUpdate => write!(f, "CredentialUpdate"),
            UiHint::ExperimentalFeatures => write!(f, "ExperimentalFeatures"),
        }
    }
}

impl FromStr for UiHint {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "CredentialUpdate" => Ok(UiHint::CredentialUpdate),
            "PosixAccount" => Ok(UiHint::PosixAccount),
            "ExperimentalFeatures" => Ok(UiHint::ExperimentalFeatures),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "lowercase")]
pub enum UatPurposeStatus {
    ReadOnly,
    ReadWrite,
    PrivilegeCapable,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "lowercase")]
pub struct UatStatus {
    pub account_id: Uuid,
    pub session_id: Uuid,
    #[serde(with = "time::serde::timestamp::option")]
    pub expiry: Option<time::OffsetDateTime>,
    #[serde(with = "time::serde::timestamp")]
    pub issued_at: time::OffsetDateTime,
    pub purpose: UatPurposeStatus,
}

impl fmt::Display for UatStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "account_id: {}", self.account_id)?;
        writeln!(f, "session_id: {}", self.session_id)?;
        if let Some(exp) = self.expiry {
            writeln!(f, "expiry: {}", exp)?;
        } else {
            writeln!(f, "expiry: -")?;
        }
        writeln!(f, "issued_at: {}", self.issued_at)?;
        match &self.purpose {
            UatPurposeStatus::ReadOnly => writeln!(f, "purpose: read only")?,
            UatPurposeStatus::ReadWrite => writeln!(f, "purpose: read write")?,
            UatPurposeStatus::PrivilegeCapable => writeln!(f, "purpose: privilege capable")?,
        }
        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "lowercase")]
pub enum UatPurpose {
    ReadOnly,
    ReadWrite {
        /// If none, there is no expiry, and this is always rw. If there is
        /// an expiry, check that the current time < expiry.
        #[serde(with = "time::serde::timestamp::option")]
        expiry: Option<time::OffsetDateTime>,
    },
}

/// The currently authenticated user, and any required metadata for them
/// to properly authorise them. This is similar in nature to oauth and the krb
/// PAC/PAD structures. This information is transparent to clients and CAN
/// be parsed by them!
///
/// This structure and how it works will *very much* change over time from this
/// point onward! This means on updates, that sessions will invalidate in many
/// cases.
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "lowercase")]
pub struct UserAuthToken {
    pub session_id: Uuid,
    #[serde(with = "time::serde::timestamp")]
    pub issued_at: time::OffsetDateTime,
    /// If none, there is no expiry, and this is always valid. If there is
    /// an expiry, check that the current time < expiry.
    #[serde(with = "time::serde::timestamp::option")]
    pub expiry: Option<time::OffsetDateTime>,
    pub purpose: UatPurpose,
    pub uuid: Uuid,
    pub displayname: String,
    pub spn: String,
    pub mail_primary: Option<String>,
    // pub groups: Vec<Group>,
    pub ui_hints: BTreeSet<UiHint>,
}

impl fmt::Display for UserAuthToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "spn: {}", self.spn)?;
        writeln!(f, "uuid: {}", self.uuid)?;
        writeln!(f, "display: {}", self.displayname)?;
        if let Some(exp) = self.expiry {
            writeln!(f, "expiry: {}", exp)?;
        } else {
            writeln!(f, "expiry: -")?;
        }
        match &self.purpose {
            UatPurpose::ReadOnly => writeln!(f, "purpose: read only")?,
            UatPurpose::ReadWrite {
                expiry: Some(expiry),
            } => writeln!(f, "purpose: read write (expiry: {})", expiry)?,
            UatPurpose::ReadWrite { expiry: None } => {
                writeln!(f, "purpose: read write (expiry: none)")?
            }
        }
        /*
        for group in &self.groups {
            writeln!(f, "group: {:?}", group.spn)?;
        }
        */
        Ok(())
    }
}

impl PartialEq for UserAuthToken {
    fn eq(&self, other: &Self) -> bool {
        self.session_id == other.session_id
    }
}

impl Eq for UserAuthToken {}

impl UserAuthToken {
    pub fn name(&self) -> &str {
        self.spn.split_once('@').map(|x| x.0).unwrap_or(&self.spn)
    }

    /// Show if the uat at a current point in time has active read-write
    /// capabilities.
    pub fn purpose_readwrite_active(&self, ct: time::OffsetDateTime) -> bool {
        match self.purpose {
            UatPurpose::ReadWrite { expiry: Some(exp) } => ct < exp,
            _ => false,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "lowercase")]
pub enum ApiTokenPurpose {
    #[default]
    ReadOnly,
    ReadWrite,
    Synchronise,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "lowercase")]
pub struct ApiToken {
    // The account this is associated with.
    pub account_id: Uuid,
    pub token_id: Uuid,
    pub label: String,
    #[serde(with = "time::serde::timestamp::option")]
    pub expiry: Option<time::OffsetDateTime>,
    #[serde(with = "time::serde::timestamp")]
    pub issued_at: time::OffsetDateTime,
    // Defaults to ReadOnly if not present
    #[serde(default)]
    pub purpose: ApiTokenPurpose,
}

impl fmt::Display for ApiToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "account_id: {}", self.account_id)?;
        writeln!(f, "token_id: {}", self.token_id)?;
        writeln!(f, "label: {}", self.label)?;
        writeln!(f, "issued at: {}", self.issued_at)?;
        if let Some(expiry) = self.expiry {
            writeln!(
                f,
                "token expiry: {}",
                expiry
                    .to_offset(
                        time::UtcOffset::try_current_local_offset().unwrap_or(time::UtcOffset::UTC),
                    )
                    .format(time::Format::Rfc3339)
            )
        } else {
            writeln!(f, "token expiry: never")
        }
    }
}

impl PartialEq for ApiToken {
    fn eq(&self, other: &Self) -> bool {
        self.token_id == other.token_id
    }
}

impl Eq for ApiToken {}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "lowercase")]
pub struct ApiTokenGenerate {
    pub label: String,
    #[serde(with = "time::serde::timestamp::option")]
    pub expiry: Option<time::OffsetDateTime>,
    pub read_write: bool,
}

// UAT will need a downcast to Entry, which adds in the claims to the entry
// for the purpose of filtering.

// This is similar to uat, but omits claims (they have no role in radius), and adds
// the radius secret field.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RadiusAuthToken {
    pub name: String,
    pub displayname: String,
    pub uuid: String,
    pub secret: String,
    pub groups: Vec<Group>,
}

impl fmt::Display for RadiusAuthToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "name: {}", self.name)?;
        writeln!(f, "displayname: {}", self.displayname)?;
        writeln!(f, "uuid: {}", self.uuid)?;
        writeln!(f, "secret: {}", self.secret)?;
        self.groups
            .iter()
            .try_for_each(|g| writeln!(f, "group: {}", g))
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct UnixGroupToken {
    pub name: String,
    pub spn: String,
    pub uuid: String,
    pub gidnumber: u32,
}

impl fmt::Display for UnixGroupToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[ spn: {}, ", self.spn)?;
        write!(f, "gidnumber: {} ", self.gidnumber)?;
        write!(f, "name: {}, ", self.name)?;
        write!(f, "uuid: {} ]", self.uuid)
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct GroupUnixExtend {
    pub gidnumber: Option<u32>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct UnixUserToken {
    pub name: String,
    pub spn: String,
    pub displayname: String,
    pub gidnumber: u32,
    pub uuid: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shell: Option<String>,
    pub groups: Vec<UnixGroupToken>,
    pub sshkeys: Vec<String>,
    // The default value of bool is false.
    #[serde(default)]
    pub valid: bool,
}

impl fmt::Display for UnixUserToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "---")?;
        writeln!(f, "spn: {}", self.spn)?;
        writeln!(f, "name: {}", self.name)?;
        writeln!(f, "displayname: {}", self.displayname)?;
        writeln!(f, "uuid: {}", self.uuid)?;
        match &self.shell {
            Some(s) => writeln!(f, "shell: {}", s)?,
            None => writeln!(f, "shell: <none>")?,
        }
        self.sshkeys
            .iter()
            .try_for_each(|s| writeln!(f, "ssh_publickey: {}", s))?;
        self.groups
            .iter()
            .try_for_each(|g| writeln!(f, "group: {}", g))
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AccountUnixExtend {
    pub gidnumber: Option<u32>,
    pub shell: Option<String>,
}

/*
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AccountOrgPersonExtend {
    pub mail: String,
}
*/

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub enum CredentialDetailType {
    Password,
    GeneratedPassword,
    Passkey(Vec<String>),
    /// totp, webauthn
    PasswordMfa(Vec<String>, Vec<String>, usize),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CredentialDetail {
    pub uuid: Uuid,
    pub type_: CredentialDetailType,
}

impl fmt::Display for CredentialDetail {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "uuid: {}", self.uuid)?;
        /*
        writeln!(f, "claims:")?;
        for claim in &self.claims {
            writeln!(f, " * {}", claim)?;
        }
        */
        match &self.type_ {
            CredentialDetailType::Password => writeln!(f, "password: set"),
            CredentialDetailType::GeneratedPassword => writeln!(f, "generated password: set"),
            CredentialDetailType::Passkey(labels) => {
                if labels.is_empty() {
                    writeln!(f, "passkeys: none registered")
                } else {
                    writeln!(f, "passkeys:")?;
                    for label in labels {
                        writeln!(f, " * {}", label)?;
                    }
                    write!(f, "")
                }
            }
            CredentialDetailType::PasswordMfa(totp_labels, wan_labels, backup_code) => {
                writeln!(f, "password: set")?;

                if !totp_labels.is_empty() {
                    writeln!(f, "totp:")?;
                    for label in totp_labels {
                        writeln!(f, " * {}", label)?;
                    }
                } else {
                    writeln!(f, "totp: disabled")?;
                }

                if *backup_code > 0 {
                    writeln!(f, "backup_code: enabled")?;
                } else {
                    writeln!(f, "backup_code: disabled")?;
                }

                if !wan_labels.is_empty() {
                    // We no longer show the deprecated security key case by default.
                    writeln!(f, " ⚠️  warning - security keys are deprecated.")?;
                    writeln!(f, " ⚠️  you should re-enroll these to passkeys.")?;
                    writeln!(f, "security keys:")?;
                    for label in wan_labels {
                        writeln!(f, " * {}", label)?;
                    }
                    write!(f, "")
                } else {
                    write!(f, "")
                }
            }
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PasskeyDetail {
    pub uuid: Uuid,
    pub tag: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CredentialStatus {
    pub creds: Vec<CredentialDetail>,
}

impl fmt::Display for CredentialStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for cred in &self.creds {
            writeln!(f, "---")?;
            cred.fmt(f)?;
        }
        writeln!(f, "---")
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct BackupCodesView {
    pub backup_codes: Vec<String>,
}

/* ===== low level proto types ===== */

// ProtoEntry vs Entry
// There is a good future reason for this separation. It allows changing
// the in memory server core entry type, without affecting the protoEntry type
//

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Default)]
pub struct Entry {
    pub attrs: BTreeMap<String, Vec<String>>,
}

impl fmt::Display for Entry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "---")?;
        self.attrs
            .iter()
            .try_for_each(|(k, vs)| vs.iter().try_for_each(|v| writeln!(f, "{}: {}", k, v)))
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum Filter {
    // This is attr - value
    #[serde(alias = "Eq")]
    Eq(String, String),
    #[serde(alias = "Sub")]
    Sub(String, String),
    #[serde(alias = "Pres")]
    Pres(String),
    #[serde(alias = "Or")]
    Or(Vec<Filter>),
    #[serde(alias = "And")]
    And(Vec<Filter>),
    #[serde(alias = "AndNot")]
    AndNot(Box<Filter>),
    #[serde(rename = "self", alias = "Self")]
    SelfUuid,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "lowercase")]
pub enum Modify {
    Present(String, String),
    Removed(String, String),
    Purged(String),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ModifyList {
    pub mods: Vec<Modify>,
}

impl ModifyList {
    pub fn new_list(mods: Vec<Modify>) -> Self {
        ModifyList { mods }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SearchRequest {
    pub filter: Filter,
}

impl SearchRequest {
    pub fn new(filter: Filter) -> Self {
        SearchRequest { filter }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SearchResponse {
    pub entries: Vec<Entry>,
}

impl SearchResponse {
    pub fn new(entries: Vec<Entry>) -> Self {
        SearchResponse { entries }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateRequest {
    pub entries: Vec<Entry>,
}

impl CreateRequest {
    pub fn new(entries: Vec<Entry>) -> Self {
        CreateRequest { entries }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DeleteRequest {
    pub filter: Filter,
}

impl DeleteRequest {
    pub fn new(filter: Filter) -> Self {
        DeleteRequest { filter }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ModifyRequest {
    // Probably needs a modlist?
    pub filter: Filter,
    pub modlist: ModifyList,
}

impl ModifyRequest {
    pub fn new(filter: Filter, modlist: ModifyList) -> Self {
        ModifyRequest { filter, modlist }
    }
}

// Login is a multi-step process potentially. First the client says who they
// want to request
//
// we respond with a set of possible authentications that can proceed, and perhaps
// we indicate which options must/may?
//
// The client can then step and negotiate each.
//
// This continues until a LoginSuccess, or LoginFailure is returned.
//
// On loginSuccess, we send a cookie, and that allows the token to be
// generated. The cookie can be shared between servers.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthCredential {
    Anonymous,
    Password(String),
    Totp(u32),
    SecurityKey(Box<PublicKeyCredential>),
    BackupCode(String),
    // Should this just be discoverable?
    Passkey(Box<PublicKeyCredential>),
}

impl fmt::Debug for AuthCredential {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match self {
            AuthCredential::Anonymous => write!(fmt, "Anonymous"),
            AuthCredential::Password(_) => write!(fmt, "Password(_)"),
            AuthCredential::Totp(_) => write!(fmt, "TOTP(_)"),
            AuthCredential::SecurityKey(_) => write!(fmt, "SecurityKey(_)"),
            AuthCredential::BackupCode(_) => write!(fmt, "BackupCode(_)"),
            AuthCredential::Passkey(_) => write!(fmt, "Passkey(_)"),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum AuthMech {
    Anonymous,
    Password,
    PasswordMfa,
    Passkey,
}

impl PartialEq for AuthMech {
    fn eq(&self, other: &Self) -> bool {
        std::mem::discriminant(self) == std::mem::discriminant(other)
    }
}

impl fmt::Display for AuthMech {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthMech::Anonymous => write!(f, "Anonymous (no credentials)"),
            AuthMech::Password => write!(f, "Password"),
            AuthMech::PasswordMfa => write!(f, "TOTP/Backup Code and Password"),
            AuthMech::Passkey => write!(f, "Passkey"),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Copy, Clone)]
#[serde(rename_all = "lowercase")]
pub enum AuthIssueSession {
    Token,
    Cookie,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthStep {
    // name
    Init(String),
    // A new way to issue sessions. Doing this as a new init type
    // to prevent breaking existing clients. Allows requesting of the type
    // of session that will be issued at the end if successful.
    Init2 {
        username: String,
        issue: AuthIssueSession,
    },
    // We want to talk to you like this.
    Begin(AuthMech),
    // Provide a response to a challenge.
    Cred(AuthCredential),
}

// Request auth for identity X with roles Y?
#[derive(Debug, Serialize, Deserialize)]
pub struct AuthRequest {
    pub step: AuthStep,
}

// Respond with the list of auth types and nonce, etc.
// It can also contain a denied, or success.
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "lowercase")]
pub enum AuthAllowed {
    Anonymous,
    BackupCode,
    Password,
    Totp,
    SecurityKey(RequestChallengeResponse),
    Passkey(RequestChallengeResponse),
}

impl PartialEq for AuthAllowed {
    fn eq(&self, other: &Self) -> bool {
        std::mem::discriminant(self) == std::mem::discriminant(other)
    }
}

impl Eq for AuthAllowed {}

impl Ord for AuthAllowed {
    fn cmp(&self, other: &Self) -> Ordering {
        if self.eq(other) {
            Ordering::Equal
        } else {
            // Relies on the fact that match is executed in order!
            match (self, other) {
                (AuthAllowed::Anonymous, _) => Ordering::Less,
                (_, AuthAllowed::Anonymous) => Ordering::Greater,
                (AuthAllowed::Password, _) => Ordering::Less,
                (_, AuthAllowed::Password) => Ordering::Greater,
                (AuthAllowed::BackupCode, _) => Ordering::Less,
                (_, AuthAllowed::BackupCode) => Ordering::Greater,
                (AuthAllowed::Totp, _) => Ordering::Less,
                (_, AuthAllowed::Totp) => Ordering::Greater,
                (AuthAllowed::SecurityKey(_), _) => Ordering::Less,
                (_, AuthAllowed::SecurityKey(_)) => Ordering::Greater,
                (AuthAllowed::Passkey(_), _) => Ordering::Less,
                // Unreachable
                // (_, AuthAllowed::Passkey(_)) => Ordering::Greater,
            }
        }
    }
}

impl PartialOrd for AuthAllowed {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Display for AuthAllowed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthAllowed::Anonymous => write!(f, "Anonymous (no credentials)"),
            AuthAllowed::Password => write!(f, "Password"),
            AuthAllowed::BackupCode => write!(f, "Backup Code"),
            AuthAllowed::Totp => write!(f, "TOTP"),
            AuthAllowed::SecurityKey(_) => write!(f, "Security Token"),
            AuthAllowed::Passkey(_) => write!(f, "Passkey"),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthState {
    // You need to select how you want to talk to me.
    Choose(Vec<AuthMech>),
    // Continue to auth, allowed mechanisms/challenges listed.
    Continue(Vec<AuthAllowed>),
    // Something was bad, your session is terminated and no cookie.
    Denied(String),
    // Everything is good, your bearer token has been issued and is within
    // the result.
    Success(String),
    // Everything is good, your cookie has been issued.
    SuccessCookie,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthResponse {
    pub sessionid: Uuid,
    pub state: AuthState,
}

// Types needed for setting credentials
/*
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SetCredentialRequest {
    Password(String),
    GeneratePassword,
    TotpGenerate,
    TotpVerify(Uuid, u32),
    TotpAcceptSha1(Uuid),
    TotpRemove,
    BackupCodeGenerate,
    BackupCodeRemove,
}
*/

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TotpAlgo {
    Sha1,
    Sha256,
    Sha512,
}

impl fmt::Display for TotpAlgo {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            TotpAlgo::Sha1 => write!(f, "SHA1"),
            TotpAlgo::Sha256 => write!(f, "SHA256"),
            TotpAlgo::Sha512 => write!(f, "SHA512"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TotpSecret {
    pub accountname: String,
    /// User-facing name of the system, issuer of the TOTP
    pub issuer: String,
    pub secret: Vec<u8>,
    pub algo: TotpAlgo,
    pub step: u64,
    pub digits: u8,
}

impl TotpSecret {
    /// <https://github.com/google/google-authenticator/wiki/Key-Uri-Format>
    pub fn to_uri(&self) -> String {
        let accountname = urlencoding::Encoded(&self.accountname);
        let issuer = urlencoding::Encoded(&self.issuer);
        let label = format!("{}:{}", issuer, accountname);
        let algo = self.algo.to_string();
        let secret = self.get_secret();
        let period = self.step;
        let digits = self.digits;

        format!(
            "otpauth://totp/{}?secret={}&issuer={}&algorithm={}&digits={}&period={}",
            label, secret, issuer, algo, digits, period
        )
    }

    pub fn get_secret(&self) -> String {
        base32::encode(base32::Alphabet::RFC4648 { padding: false }, &self.secret)
    }
}

/*
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SetCredentialResponse {
    Success,
    Token(String),
    TotpCheck(Uuid, TotpSecret),
    TotpInvalidSha1(Uuid),
    SecurityKeyCreateChallenge(Uuid, CreationChallengeResponse),
    BackupCodes(Vec<String>),
}
*/

#[derive(Debug, Serialize, Deserialize)]
pub struct CUIntentToken {
    pub token: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CUSessionToken {
    pub token: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CURequest {
    PrimaryRemove,
    Password(String),
    CancelMFAReg,
    TotpGenerate,
    TotpVerify(u32, String),
    TotpAcceptSha1,
    TotpRemove(String),
    BackupCodeGenerate,
    BackupCodeRemove,
    PasskeyInit,
    PasskeyFinish(String, RegisterPublicKeyCredential),
    PasskeyRemove(Uuid),
}

impl fmt::Debug for CURequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let t = match self {
            CURequest::PrimaryRemove => "CURequest::PrimaryRemove",
            CURequest::Password(_) => "CURequest::Password",
            CURequest::CancelMFAReg => "CURequest::CancelMFAReg",
            CURequest::TotpGenerate => "CURequest::TotpGenerate",
            CURequest::TotpVerify(_, _) => "CURequest::TotpVerify",
            CURequest::TotpAcceptSha1 => "CURequest::TotpAcceptSha1",
            CURequest::TotpRemove(_) => "CURequest::TotpRemove",
            CURequest::BackupCodeGenerate => "CURequest::BackupCodeGenerate",
            CURequest::BackupCodeRemove => "CURequest::BackupCodeRemove",
            CURequest::PasskeyInit => "CURequest::PasskeyInit",
            CURequest::PasskeyFinish(_, _) => "CURequest::PasskeyFinish",
            CURequest::PasskeyRemove(_) => "CURequest::PasskeyRemove",
        };
        writeln!(f, "{}", t)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CURegState {
    // Nothing in progress.
    None,
    TotpCheck(TotpSecret),
    TotpTryAgain,
    TotpInvalidSha1,
    BackupCodes(Vec<String>),
    Passkey(CreationChallengeResponse),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CUStatus {
    pub spn: String,
    pub displayname: String,
    pub can_commit: bool,
    pub primary: Option<CredentialDetail>,
    pub passkeys: Vec<PasskeyDetail>,
    pub mfaregstate: CURegState,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct WhoamiResponse {
    // Should we just embed the entry? Or destructure it?
    pub youare: Entry,
}

impl WhoamiResponse {
    pub fn new(youare: Entry) -> Self {
        WhoamiResponse { youare }
    }
}

// Simple string value provision.
#[derive(Debug, Serialize, Deserialize)]
pub struct SingleStringRequest {
    pub value: String,
}

impl SingleStringRequest {
    pub fn new(s: String) -> Self {
        SingleStringRequest { value: s }
    }
}
// Use OperationResponse here ...

#[cfg(test)]
mod tests {
    use crate::v1::{Filter as ProtoFilter, TotpAlgo, TotpSecret};

    #[test]
    fn test_protofilter_simple() {
        let pf: ProtoFilter = ProtoFilter::Pres("class".to_string());

        println!("{:?}", serde_json::to_string(&pf).expect("JSON failure"));
    }

    #[test]
    fn totp_to_string() {
        let totp = TotpSecret {
            accountname: "william".to_string(),
            issuer: "blackhats".to_string(),
            secret: vec![0xaa, 0xbb, 0xcc, 0xdd],
            step: 30,
            algo: TotpAlgo::Sha256,
            digits: 6,
        };
        let s = totp.to_uri();
        assert!(s == "otpauth://totp/blackhats:william?secret=VK54ZXI&issuer=blackhats&algorithm=SHA256&digits=6&period=30");

        // check that invalid issuer/accounts are cleaned up.
        let totp = TotpSecret {
            accountname: "william:%3A".to_string(),
            issuer: "blackhats australia".to_string(),
            secret: vec![0xaa, 0xbb, 0xcc, 0xdd],
            step: 30,
            algo: TotpAlgo::Sha256,
            digits: 6,
        };
        let s = totp.to_uri();
        println!("{}", s);
        assert!(s == "otpauth://totp/blackhats%20australia:william%3A%253A?secret=VK54ZXI&issuer=blackhats%20australia&algorithm=SHA256&digits=6&period=30");
    }
}
