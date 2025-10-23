use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use url::Url;
use utoipa::ToSchema;
use uuid::Uuid;

use webauthn_rs_proto::CreationChallengeResponse;
use webauthn_rs_proto::RegisterPublicKeyCredential;

pub use sshkey_attest::proto::PublicKey as SshPublicKey;

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
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

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
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
        let label = format!("{issuer}:{accountname}");
        let algo = self.algo.to_string();
        let secret = self.get_secret();
        let period = self.step;
        let digits = self.digits;

        format!(
            "otpauth://totp/{label}?secret={secret}&issuer={issuer}&algorithm={algo}&digits={digits}&period={period}"
        )
    }

    pub fn get_secret(&self) -> String {
        base32::encode(base32::Alphabet::Rfc4648 { padding: false }, &self.secret)
    }
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct CUIntentToken {
    pub token: String,
    #[serde(with = "time::serde::timestamp")]
    pub expiry_time: time::OffsetDateTime,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct CUSessionToken {
    pub token: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CURequest {
    PrimaryRemove,
    PasswordQualityCheck(String),
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
    AttestedPasskeyInit,
    AttestedPasskeyFinish(String, RegisterPublicKeyCredential),
    AttestedPasskeyRemove(Uuid),
    UnixPasswordRemove,
    UnixPassword(String),
    SshPublicKey(String, SshPublicKey),
    SshPublicKeyRemove(String),
}

impl fmt::Debug for CURequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let t = match self {
            CURequest::PrimaryRemove => "CURequest::PrimaryRemove",
            CURequest::PasswordQualityCheck(_) => "CURequest::PasswordQualityCheck",
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
            CURequest::AttestedPasskeyInit => "CURequest::AttestedPasskeyInit",
            CURequest::AttestedPasskeyFinish(_, _) => "CURequest::AttestedPasskeyFinish",
            CURequest::AttestedPasskeyRemove(_) => "CURequest::AttestedPasskeyRemove",
            CURequest::UnixPassword(_) => "CURequest::UnixPassword",
            CURequest::UnixPasswordRemove => "CURequest::UnixPasswordRemove",
            CURequest::SshPublicKey(_, _) => "CURequest::SSHKeySubmit",
            CURequest::SshPublicKeyRemove(_) => "CURequest::SSHKeyRemove",
        };
        writeln!(f, "{t}")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub enum CURegState {
    // Nothing in progress.
    None,
    TotpCheck(TotpSecret),
    TotpTryAgain,
    TotpNameTryAgain(String),
    TotpInvalidSha1,
    BackupCodes(Vec<String>),
    #[schema(value_type = HashMap<String, Value>)]
    Passkey(CreationChallengeResponse),
    #[schema(value_type = HashMap<String, Value>)]
    AttestedPasskey(CreationChallengeResponse),
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub enum CUExtPortal {
    None,
    Hidden,
    Some(Url),
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, ToSchema, PartialEq)]
pub enum CUCredState {
    Modifiable,
    DeleteOnly,
    AccessDeny,
    PolicyDeny,
    // Disabled,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub enum CURegWarning {
    MfaRequired,
    PasskeyRequired,
    AttestedPasskeyRequired,
    AttestedResidentKeyRequired,
    Unsatisfiable,
    WebauthnAttestationUnsatisfiable,
    WebauthnUserVerificationRequired,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CUStatus {
    // Display values
    pub spn: String,
    pub displayname: String,
    pub ext_cred_portal: CUExtPortal,
    // Internal State Tracking
    pub mfaregstate: CURegState,
    // Display hints + The credential details.
    pub can_commit: bool,
    pub warnings: Vec<CURegWarning>,
    pub primary: Option<CredentialDetail>,
    pub primary_state: CUCredState,
    pub passkeys: Vec<PasskeyDetail>,
    pub passkeys_state: CUCredState,
    pub attested_passkeys: Vec<PasskeyDetail>,
    pub attested_passkeys_state: CUCredState,
    pub attested_passkeys_allowed_devices: Vec<String>,

    pub unixcred: Option<CredentialDetail>,
    pub unixcred_state: CUCredState,

    #[schema(value_type = BTreeMap<String, Value>)]
    pub sshkeys: BTreeMap<String, SshPublicKey>,
    pub sshkeys_state: CUCredState,
}

#[derive(Debug, Serialize, Deserialize, Clone, ToSchema)]
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

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, ToSchema)]
pub enum CredentialDetailType {
    Password,
    GeneratedPassword,
    Passkey(Vec<String>),
    /// totp, webauthn
    PasswordMfa(Vec<String>, Vec<String>, usize),
}

#[derive(Debug, Serialize, Deserialize, Clone, ToSchema)]
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
                        writeln!(f, " * {label}")?;
                    }
                    write!(f, "")
                }
            }
            CredentialDetailType::PasswordMfa(totp_labels, wan_labels, backup_code) => {
                writeln!(f, "password: set")?;

                if !totp_labels.is_empty() {
                    writeln!(f, "totp:")?;
                    for label in totp_labels {
                        writeln!(f, " * {label}")?;
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
                        writeln!(f, " * {label}")?;
                    }
                    write!(f, "")
                } else {
                    write!(f, "")
                }
            }
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, ToSchema)]
pub struct PasskeyDetail {
    pub uuid: Uuid,
    pub tag: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, ToSchema)]
pub struct BackupCodesView {
    pub backup_codes: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, ToSchema, PartialEq, Eq, PartialOrd, Ord)]
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
    TooShort(u32),
    BadListed,
    DontReusePasswords,
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
            PasswordFeedback::DontReusePasswords => {
                write!(
                    f,
                    "Don't reuse passwords that already exist on your account"
                )
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
                "Password was too short, needs to be at least {minlength} characters long."
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

#[cfg(test)]
mod tests {
    use super::{TotpAlgo, TotpSecret};

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
        assert_eq!(s,"otpauth://totp/blackhats:william?secret=VK54ZXI&issuer=blackhats&algorithm=SHA256&digits=6&period=30");

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
        println!("{s}");
        assert_eq!(s,"otpauth://totp/blackhats%20australia:william%3A%253A?secret=VK54ZXI&issuer=blackhats%20australia&algorithm=SHA256&digits=6&period=30");
    }
}
