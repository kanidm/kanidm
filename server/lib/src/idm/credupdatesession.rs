use core::ops::Deref;
use std::collections::BTreeMap;
use std::fmt::{self, Display};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use sshkey_attest::proto::PublicKey as SshPublicKey;

use hashbrown::HashSet;
use kanidm_proto::internal::{
    CUCredState, CUExtPortal, CURegState, CURegWarning, CUStatus, CredentialDetail, PasskeyDetail,
    PasswordFeedback, TotpSecret,
};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use webauthn_rs::prelude::{
    AttestedPasskey as AttestedPasskeyV4, AttestedPasskeyRegistration, CreationChallengeResponse,
    Passkey as PasskeyV4, PasskeyRegistration, RegisterPublicKeyCredential, WebauthnError,
};

use crate::credential::totp::{Totp, TOTP_DEFAULT_STEP};
use crate::credential::{BackupCodes, Credential};
use crate::idm::account::Account;
use crate::idm::server::{IdmServerCredUpdateTransaction, IdmServerProxyWriteTransaction};
use crate::prelude::*;
use crate::server::access::Access;
use crate::utils::{backup_code_from_random, readable_password_from_random, uuid_from_duration};
use crate::value::{CredUpdateSessionPerms, CredentialType, IntentTokenState};
use compact_jwt::compact::JweCompact;
use compact_jwt::jwe::JweBuilder;

use super::accountpolicy::ResolvedAccountPolicy;

const MAXIMUM_CRED_UPDATE_TTL: Duration = Duration::from_secs(900);
// Default 1 hour.
const DEFAULT_INTENT_TTL: Duration = Duration::from_secs(3600);
// Default 1 day.
const MAXIMUM_INTENT_TTL: Duration = Duration::from_secs(86400);
// Minimum 5 minutes.
const MINIMUM_INTENT_TTL: Duration = Duration::from_secs(300);

#[derive(Debug)]
pub enum PasswordQuality {
    TooShort(u32),
    BadListed,
    DontReusePasswords,
    Feedback(Vec<PasswordFeedback>),
}

#[derive(Clone, Debug)]
pub struct CredentialUpdateIntentToken {
    pub intent_id: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct CredentialUpdateSessionTokenInner {
    pub sessionid: Uuid,
    // How long is it valid for?
    pub max_ttl: Duration,
}

#[derive(Debug)]
pub struct CredentialUpdateSessionToken {
    pub token_enc: JweCompact,
}

/// The current state of MFA registration
#[derive(Clone)]
enum MfaRegState {
    None,
    TotpInit(Totp),
    TotpTryAgain(Totp),
    TotpInvalidSha1(Totp, Totp, String),
    Passkey(Box<CreationChallengeResponse>, PasskeyRegistration),
    #[allow(dead_code)]
    AttestedPasskey(Box<CreationChallengeResponse>, AttestedPasskeyRegistration),
}

impl fmt::Debug for MfaRegState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let t = match self {
            MfaRegState::None => "MfaRegState::None",
            MfaRegState::TotpInit(_) => "MfaRegState::TotpInit",
            MfaRegState::TotpTryAgain(_) => "MfaRegState::TotpTryAgain",
            MfaRegState::TotpInvalidSha1(_, _, _) => "MfaRegState::TotpInvalidSha1",
            MfaRegState::Passkey(_, _) => "MfaRegState::Passkey",
            MfaRegState::AttestedPasskey(_, _) => "MfaRegState::AttestedPasskey",
        };
        write!(f, "{t}")
    }
}

#[derive(Debug, Clone, Copy)]
enum CredentialState {
    Modifiable,
    DeleteOnly,
    AccessDeny,
    PolicyDeny,
    // Disabled,
}

impl From<CredentialState> for CUCredState {
    fn from(val: CredentialState) -> CUCredState {
        match val {
            CredentialState::Modifiable => CUCredState::Modifiable,
            CredentialState::DeleteOnly => CUCredState::DeleteOnly,
            CredentialState::AccessDeny => CUCredState::AccessDeny,
            CredentialState::PolicyDeny => CUCredState::PolicyDeny,
            // CredentialState::Disabled => CUCredState::Disabled ,
        }
    }
}

#[derive(Clone)]
pub(crate) struct CredentialUpdateSession {
    issuer: String,
    // Current credentials - these are on the Account!
    account: Account,
    // The account policy applied to this account
    resolved_account_policy: ResolvedAccountPolicy,
    // What intent was used to initiate this session.
    intent_token_id: Option<String>,

    // Is there an extertal credential portal?
    ext_cred_portal: CUExtPortal,

    // The pw credential as they are being updated
    primary_state: CredentialState,
    primary: Option<Credential>,

    // Unix / Sudo PW
    unixcred: Option<Credential>,
    unixcred_can_edit: bool,

    // Ssh Keys
    sshkeys: BTreeMap<String, SshPublicKey>,
    sshpubkey_can_edit: bool,

    // Passkeys that have been configured.
    passkeys: BTreeMap<Uuid, (String, PasskeyV4)>,
    passkeys_state: CredentialState,

    // Attested Passkeys
    attested_passkeys: BTreeMap<Uuid, (String, AttestedPasskeyV4)>,
    attested_passkeys_state: CredentialState,

    // Internal reg state of any inprogress totp or webauthn credentials.
    mfaregstate: MfaRegState,
}

impl fmt::Debug for CredentialUpdateSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let primary: Option<CredentialDetail> = self.primary.as_ref().map(|c| c.into());
        let passkeys: Vec<PasskeyDetail> = self
            .passkeys
            .iter()
            .map(|(uuid, (tag, _pk))| PasskeyDetail {
                tag: tag.clone(),
                uuid: *uuid,
            })
            .collect();
        let attested_passkeys: Vec<PasskeyDetail> = self
            .attested_passkeys
            .iter()
            .map(|(uuid, (tag, _pk))| PasskeyDetail {
                tag: tag.clone(),
                uuid: *uuid,
            })
            .collect();
        f.debug_struct("CredentialUpdateSession")
            .field("account.spn", &self.account.spn)
            .field("account.unix", &self.account.unix_extn().is_some())
            .field("resolved_account_policy", &self.resolved_account_policy)
            .field("intent_token_id", &self.intent_token_id)
            .field("primary.detail()", &primary)
            .field("primary.state", &self.primary_state)
            .field("passkeys.list()", &passkeys)
            .field("passkeys.state", &self.passkeys_state)
            .field("attested_passkeys.list()", &attested_passkeys)
            .field("attested_passkeys.state", &self.attested_passkeys_state)
            .field("mfaregstate", &self.mfaregstate)
            .finish()
    }
}

impl CredentialUpdateSession {
    // Vec of the issues with the current session so that UI's can highlight properly how to proceed.
    fn can_commit(&self) -> (bool, Vec<CredentialUpdateSessionStatusWarnings>) {
        let mut warnings = Vec::with_capacity(0);

        let cred_type_min = self.resolved_account_policy.credential_policy();

        debug!(?cred_type_min);

        match cred_type_min {
            CredentialType::Any => {}
            CredentialType::Mfa => {
                if self
                    .primary
                    .as_ref()
                    .map(|cred| !cred.is_mfa())
                    // If it's none, then we can proceed because we satisfy mfa on other
                    // parts.
                    .unwrap_or(false)
                {
                    warnings.push(CredentialUpdateSessionStatusWarnings::MfaRequired);
                }
            }
            CredentialType::Passkey => {
                // NOTE: Technically this is unreachable, but we keep it for correctness.
                // Primary can't be set at all.
                if self.primary.is_some() {
                    warnings.push(CredentialUpdateSessionStatusWarnings::PasskeyRequired);
                }
            }
            CredentialType::AttestedPasskey => {
                // Also unreachable - during these sessions, there will be no values present here.
                if !self.passkeys.is_empty() || self.primary.is_some() {
                    warnings.push(CredentialUpdateSessionStatusWarnings::AttestedPasskeyRequired);
                }
            }
            CredentialType::AttestedResidentkey => {
                // Also unreachable - during these sessions, there will be no values present here.
                if !self.attested_passkeys.is_empty()
                    || !self.passkeys.is_empty()
                    || self.primary.is_some()
                {
                    warnings
                        .push(CredentialUpdateSessionStatusWarnings::AttestedResidentKeyRequired);
                }
            }
            CredentialType::Invalid => {
                // special case, must always deny all changes.
                warnings.push(CredentialUpdateSessionStatusWarnings::Unsatisfiable)
            }
        }

        if let Some(att_ca_list) = self.resolved_account_policy.webauthn_attestation_ca_list() {
            if att_ca_list.is_empty() {
                warnings
                    .push(CredentialUpdateSessionStatusWarnings::WebauthnAttestationUnsatisfiable)
            }
        }

        (warnings.is_empty(), warnings)
    }
}

pub enum MfaRegStateStatus {
    // Nothing in progress.
    None,
    TotpCheck(TotpSecret),
    TotpTryAgain,
    TotpInvalidSha1,
    BackupCodes(HashSet<String>),
    Passkey(CreationChallengeResponse),
    AttestedPasskey(CreationChallengeResponse),
}

impl fmt::Debug for MfaRegStateStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let t = match self {
            MfaRegStateStatus::None => "MfaRegStateStatus::None",
            MfaRegStateStatus::TotpCheck(_) => "MfaRegStateStatus::TotpCheck(_)",
            MfaRegStateStatus::TotpTryAgain => "MfaRegStateStatus::TotpTryAgain",
            MfaRegStateStatus::TotpInvalidSha1 => "MfaRegStateStatus::TotpInvalidSha1",
            MfaRegStateStatus::BackupCodes(_) => "MfaRegStateStatus::BackupCodes",
            MfaRegStateStatus::Passkey(_) => "MfaRegStateStatus::Passkey",
            MfaRegStateStatus::AttestedPasskey(_) => "MfaRegStateStatus::AttestedPasskey",
        };
        write!(f, "{t}")
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum CredentialUpdateSessionStatusWarnings {
    MfaRequired,
    PasskeyRequired,
    AttestedPasskeyRequired,
    AttestedResidentKeyRequired,
    Unsatisfiable,
    WebauthnAttestationUnsatisfiable,
}

impl Display for CredentialUpdateSessionStatusWarnings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "{:?}", self)
    }
}

impl From<CredentialUpdateSessionStatusWarnings> for CURegWarning {
    fn from(val: CredentialUpdateSessionStatusWarnings) -> CURegWarning {
        match val {
            CredentialUpdateSessionStatusWarnings::MfaRequired => CURegWarning::MfaRequired,
            CredentialUpdateSessionStatusWarnings::PasskeyRequired => CURegWarning::PasskeyRequired,
            CredentialUpdateSessionStatusWarnings::AttestedPasskeyRequired => {
                CURegWarning::AttestedPasskeyRequired
            }
            CredentialUpdateSessionStatusWarnings::AttestedResidentKeyRequired => {
                CURegWarning::AttestedResidentKeyRequired
            }
            CredentialUpdateSessionStatusWarnings::Unsatisfiable => CURegWarning::Unsatisfiable,
            CredentialUpdateSessionStatusWarnings::WebauthnAttestationUnsatisfiable => {
                CURegWarning::WebauthnAttestationUnsatisfiable
            }
        }
    }
}

#[derive(Debug)]
pub struct CredentialUpdateSessionStatus {
    spn: String,
    // The target user's display name
    displayname: String,
    ext_cred_portal: CUExtPortal,
    // Any info the client needs about mfareg state.
    mfaregstate: MfaRegStateStatus,
    can_commit: bool,
    // If can_commit is false, this will have warnings populated.
    warnings: Vec<CredentialUpdateSessionStatusWarnings>,
    primary: Option<CredentialDetail>,
    primary_state: CredentialState,
    passkeys: Vec<PasskeyDetail>,
    passkeys_state: CredentialState,
    attested_passkeys: Vec<PasskeyDetail>,
    attested_passkeys_state: CredentialState,
    attested_passkeys_allowed_devices: Vec<String>,
}

impl CredentialUpdateSessionStatus {
    pub fn can_commit(&self) -> bool {
        self.can_commit
    }

    pub fn mfaregstate(&self) -> &MfaRegStateStatus {
        &self.mfaregstate
    }
}

// We allow Into here because CUStatus is foreign so it's impossible for us to implement From
// in a valid manner
#[allow(clippy::from_over_into)]
impl Into<CUStatus> for CredentialUpdateSessionStatus {
    fn into(self) -> CUStatus {
        CUStatus {
            spn: self.spn,
            displayname: self.displayname,
            ext_cred_portal: self.ext_cred_portal,
            mfaregstate: match self.mfaregstate {
                MfaRegStateStatus::None => CURegState::None,
                MfaRegStateStatus::TotpCheck(c) => CURegState::TotpCheck(c),
                MfaRegStateStatus::TotpTryAgain => CURegState::TotpTryAgain,
                MfaRegStateStatus::TotpInvalidSha1 => CURegState::TotpInvalidSha1,
                MfaRegStateStatus::BackupCodes(s) => {
                    CURegState::BackupCodes(s.into_iter().collect())
                }
                MfaRegStateStatus::Passkey(r) => CURegState::Passkey(r),
                MfaRegStateStatus::AttestedPasskey(r) => CURegState::AttestedPasskey(r),
            },
            can_commit: self.can_commit,
            warnings: self.warnings.into_iter().map(|w| w.into()).collect(),
            primary: self.primary,
            primary_state: self.primary_state.into(),
            passkeys: self.passkeys,
            passkeys_state: self.passkeys_state.into(),
            attested_passkeys: self.attested_passkeys,
            attested_passkeys_state: self.attested_passkeys_state.into(),
            attested_passkeys_allowed_devices: self.attested_passkeys_allowed_devices,
        }
    }
}

impl From<&CredentialUpdateSession> for CredentialUpdateSessionStatus {
    fn from(session: &CredentialUpdateSession) -> Self {
        let (can_commit, warnings) = session.can_commit();

        let attested_passkeys_allowed_devices: Vec<String> = session
            .resolved_account_policy
            .webauthn_attestation_ca_list()
            .iter()
            .flat_map(|att_ca_list: &&webauthn_rs::prelude::AttestationCaList| {
                att_ca_list.cas().values().flat_map(|ca| {
                    ca.aaguids()
                        .values()
                        .map(|device| device.description_en().to_string())
                })
            })
            .collect();

        CredentialUpdateSessionStatus {
            spn: session.account.spn.clone(),
            displayname: session.account.displayname.clone(),
            ext_cred_portal: session.ext_cred_portal.clone(),
            can_commit,
            warnings,
            primary: session.primary.as_ref().map(|c| c.into()),
            primary_state: session.primary_state,
            passkeys: session
                .passkeys
                .iter()
                .map(|(uuid, (tag, _pk))| PasskeyDetail {
                    tag: tag.clone(),
                    uuid: *uuid,
                })
                .collect(),
            passkeys_state: session.passkeys_state,
            attested_passkeys: session
                .attested_passkeys
                .iter()
                .map(|(uuid, (tag, _pk))| PasskeyDetail {
                    tag: tag.clone(),
                    uuid: *uuid,
                })
                .collect(),
            attested_passkeys_state: session.attested_passkeys_state,
            attested_passkeys_allowed_devices,
            mfaregstate: match &session.mfaregstate {
                MfaRegState::None => MfaRegStateStatus::None,
                MfaRegState::TotpInit(token) => MfaRegStateStatus::TotpCheck(
                    token.to_proto(session.account.name.as_str(), session.issuer.as_str()),
                ),
                MfaRegState::TotpTryAgain(_) => MfaRegStateStatus::TotpTryAgain,
                MfaRegState::TotpInvalidSha1(_, _, _) => MfaRegStateStatus::TotpInvalidSha1,
                MfaRegState::Passkey(r, _) => MfaRegStateStatus::Passkey(r.as_ref().clone()),
                MfaRegState::AttestedPasskey(r, _) => {
                    MfaRegStateStatus::AttestedPasskey(r.as_ref().clone())
                }
            },
        }
    }
}

pub(crate) type CredentialUpdateSessionMutex = Arc<Mutex<CredentialUpdateSession>>;

pub struct InitCredentialUpdateIntentEvent {
    // Who initiated this?
    pub ident: Identity,
    // Who is it targeting?
    pub target: Uuid,
    // How long is it valid for?
    pub max_ttl: Option<Duration>,
}

impl InitCredentialUpdateIntentEvent {
    pub fn new(ident: Identity, target: Uuid, max_ttl: Option<Duration>) -> Self {
        InitCredentialUpdateIntentEvent {
            ident,
            target,
            max_ttl,
        }
    }

    #[cfg(test)]
    pub fn new_impersonate_entry(
        e: std::sync::Arc<Entry<EntrySealed, EntryCommitted>>,
        target: Uuid,
        max_ttl: Duration,
    ) -> Self {
        let ident = Identity::from_impersonate_entry_readwrite(e);
        InitCredentialUpdateIntentEvent {
            ident,
            target,
            max_ttl: Some(max_ttl),
        }
    }
}

pub struct InitCredentialUpdateEvent {
    pub ident: Identity,
    pub target: Uuid,
}

impl InitCredentialUpdateEvent {
    pub fn new(ident: Identity, target: Uuid) -> Self {
        InitCredentialUpdateEvent { ident, target }
    }

    #[cfg(test)]
    pub fn new_impersonate_entry(e: std::sync::Arc<Entry<EntrySealed, EntryCommitted>>) -> Self {
        let ident = Identity::from_impersonate_entry_readwrite(e);

        let target = ident
            .get_uuid()
            .ok_or(OperationError::InvalidState)
            .expect("Identity has no uuid associated");
        InitCredentialUpdateEvent { ident, target }
    }
}

impl<'a> IdmServerProxyWriteTransaction<'a> {
    fn validate_init_credential_update(
        &mut self,
        target: Uuid,
        ident: &Identity,
    ) -> Result<(Account, ResolvedAccountPolicy, CredUpdateSessionPerms), OperationError> {
        let entry = self.qs_write.internal_search_uuid(target)?;

        security_info!(
            %target,
            "Initiating Credential Update Session",
        );

        // The initiating identity must be in readwrite mode! Effective permission assumes you
        // are in rw.
        if ident.access_scope() != AccessScope::ReadWrite {
            security_access!("identity access scope is not permitted to modify");
            security_access!("denied ❌");
            return Err(OperationError::AccessDenied);
        }

        // Is target an account? This checks for us.
        let (account, resolved_account_policy) =
            Account::try_from_entry_with_policy(entry.as_ref(), &mut self.qs_write)?;

        let effective_perms = self
            .qs_write
            .get_accesscontrols()
            .effective_permission_check(
                ident,
                Some(btreeset![
                    Attribute::PrimaryCredential.into(),
                    Attribute::PassKeys.into(),
                    Attribute::AttestedPasskeys.into(),
                    Attribute::UnixPassword.into(),
                    Attribute::SshPublicKey.into()
                ]),
                &[entry],
            )?;

        let eperm = effective_perms.first().ok_or_else(|| {
            error!("Effective Permission check returned no results");
            OperationError::InvalidState
        })?;

        // Does the ident have permission to modify AND search the user-credentials of the target, given
        // the current status of it's authentication?

        if eperm.target != account.uuid {
            error!("Effective Permission check target differs from requested entry uuid");
            return Err(OperationError::InvalidEntryState);
        }

        let eperm_search_primary_cred = match &eperm.search {
            Access::Denied => false,
            Access::Grant => true,
            Access::Allow(attrs) => attrs.contains(Attribute::PrimaryCredential.as_ref()),
        };

        let eperm_mod_primary_cred = match &eperm.modify_pres {
            Access::Denied => false,
            Access::Grant => true,
            Access::Allow(attrs) => attrs.contains(Attribute::PrimaryCredential.as_ref()),
        };

        let eperm_rem_primary_cred = match &eperm.modify_rem {
            Access::Denied => false,
            Access::Grant => true,
            Access::Allow(attrs) => attrs.contains(Attribute::PrimaryCredential.as_ref()),
        };

        let primary_can_edit =
            eperm_search_primary_cred && eperm_mod_primary_cred && eperm_rem_primary_cred;

        let eperm_search_passkeys = match &eperm.search {
            Access::Denied => false,
            Access::Grant => true,
            Access::Allow(attrs) => attrs.contains(Attribute::PassKeys.as_ref()),
        };

        let eperm_mod_passkeys = match &eperm.modify_pres {
            Access::Denied => false,
            Access::Grant => true,
            Access::Allow(attrs) => attrs.contains(Attribute::PassKeys.as_ref()),
        };

        let eperm_rem_passkeys = match &eperm.modify_rem {
            Access::Denied => false,
            Access::Grant => true,
            Access::Allow(attrs) => attrs.contains(Attribute::PassKeys.as_ref()),
        };

        let passkeys_can_edit = eperm_search_passkeys && eperm_mod_passkeys && eperm_rem_passkeys;

        let eperm_search_attested_passkeys = match &eperm.search {
            Access::Denied => false,
            Access::Grant => true,
            Access::Allow(attrs) => attrs.contains(Attribute::AttestedPasskeys.as_ref()),
        };

        let eperm_mod_attested_passkeys = match &eperm.modify_pres {
            Access::Denied => false,
            Access::Grant => true,
            Access::Allow(attrs) => attrs.contains(Attribute::AttestedPasskeys.as_ref()),
        };

        let eperm_rem_attested_passkeys = match &eperm.modify_rem {
            Access::Denied => false,
            Access::Grant => true,
            Access::Allow(attrs) => attrs.contains(Attribute::AttestedPasskeys.as_ref()),
        };

        let attested_passkeys_can_edit = eperm_search_attested_passkeys
            && eperm_mod_attested_passkeys
            && eperm_rem_attested_passkeys;

        let eperm_search_unixcred = match &eperm.search {
            Access::Denied => false,
            Access::Grant => true,
            Access::Allow(attrs) => attrs.contains(Attribute::UnixPassword.as_ref()),
        };

        let eperm_mod_unixcred = match &eperm.modify_pres {
            Access::Denied => false,
            Access::Grant => true,
            Access::Allow(attrs) => attrs.contains(Attribute::UnixPassword.as_ref()),
        };

        let eperm_rem_unixcred = match &eperm.modify_rem {
            Access::Denied => false,
            Access::Grant => true,
            Access::Allow(attrs) => attrs.contains(Attribute::UnixPassword.as_ref()),
        };

        let unixcred_can_edit = account.unix_extn().is_some()
            && eperm_search_unixcred
            && eperm_mod_unixcred
            && eperm_rem_unixcred;

        let eperm_search_sshpubkey = match &eperm.search {
            Access::Denied => false,
            Access::Grant => true,
            Access::Allow(attrs) => attrs.contains(Attribute::SshPublicKey.as_ref()),
        };

        let eperm_mod_sshpubkey = match &eperm.modify_pres {
            Access::Denied => false,
            Access::Grant => true,
            Access::Allow(attrs) => attrs.contains(Attribute::SshPublicKey.as_ref()),
        };

        let eperm_rem_sshpubkey = match &eperm.modify_rem {
            Access::Denied => false,
            Access::Grant => true,
            Access::Allow(attrs) => attrs.contains(Attribute::SshPublicKey.as_ref()),
        };

        let sshpubkey_can_edit = account.unix_extn().is_some()
            && eperm_search_sshpubkey
            && eperm_mod_sshpubkey
            && eperm_rem_sshpubkey;

        let ext_cred_portal_can_view = if let Some(sync_parent_uuid) = account.sync_parent_uuid {
            // In theory this is always granted due to how access controls work, but we check anyway.
            let entry = self.qs_write.internal_search_uuid(sync_parent_uuid)?;

            let effective_perms = self
                .qs_write
                .get_accesscontrols()
                .effective_permission_check(
                    ident,
                    Some(btreeset![Attribute::SyncCredentialPortal.into()]),
                    &[entry],
                )?;

            let eperm = effective_perms.first().ok_or_else(|| {
                admin_error!("Effective Permission check returned no results");
                OperationError::InvalidState
            })?;

            match &eperm.search {
                Access::Denied => false,
                Access::Grant => true,
                Access::Allow(attrs) => attrs.contains(Attribute::SyncCredentialPortal.as_ref()),
            }
        } else {
            false
        };

        // At lease *one* must be modifiable OR visible.
        if !(primary_can_edit
            || passkeys_can_edit
            || attested_passkeys_can_edit
            || ext_cred_portal_can_view
            || sshpubkey_can_edit
            || unixcred_can_edit)
        {
            error!("Unable to proceed with credential update intent - at least one type of credential must be modifiable or visible.");
            Err(OperationError::NotAuthorised)
        } else {
            security_info!(%primary_can_edit, %passkeys_can_edit, %unixcred_can_edit, %sshpubkey_can_edit, %ext_cred_portal_can_view, "Proceeding");
            Ok((
                account,
                resolved_account_policy,
                CredUpdateSessionPerms {
                    ext_cred_portal_can_view,
                    passkeys_can_edit,
                    attested_passkeys_can_edit,
                    primary_can_edit,
                    unixcred_can_edit,
                    sshpubkey_can_edit,
                },
            ))
        }
    }

    fn create_credupdate_session(
        &mut self,
        sessionid: Uuid,
        intent_token_id: Option<String>,
        account: Account,
        resolved_account_policy: ResolvedAccountPolicy,
        perms: CredUpdateSessionPerms,
        ct: Duration,
    ) -> Result<(CredentialUpdateSessionToken, CredentialUpdateSessionStatus), OperationError> {
        let ext_cred_portal_can_view = perms.ext_cred_portal_can_view;
        let unixcred_can_edit = perms.unixcred_can_edit;
        let sshpubkey_can_edit = perms.sshpubkey_can_edit;

        let cred_type_min = resolved_account_policy.credential_policy();

        // We can't decide this based on CredentialType alone since we may have CredentialType::Mfa
        // and still need attestation. As a result, we have to decide this based on presence of
        // the attestation policy.
        let passkey_attestation_required = resolved_account_policy
            .webauthn_attestation_ca_list()
            .is_some();

        let primary_state = if cred_type_min > CredentialType::Mfa {
            CredentialState::PolicyDeny
        } else if perms.primary_can_edit {
            CredentialState::Modifiable
        } else {
            CredentialState::AccessDeny
        };

        let passkeys_state =
            if cred_type_min > CredentialType::Passkey || passkey_attestation_required {
                CredentialState::PolicyDeny
            } else if perms.passkeys_can_edit {
                CredentialState::Modifiable
            } else {
                CredentialState::AccessDeny
            };

        let attested_passkeys_state = if cred_type_min > CredentialType::AttestedPasskey {
            CredentialState::PolicyDeny
        } else if perms.attested_passkeys_can_edit {
            if passkey_attestation_required {
                CredentialState::Modifiable
            } else {
                // User can only delete, no police available to add more keys.
                CredentialState::DeleteOnly
            }
        } else {
            CredentialState::AccessDeny
        };

        // - stash the current state of all associated credentials
        let primary = if matches!(primary_state, CredentialState::Modifiable) {
            account.primary.clone()
        } else {
            None
        };

        let passkeys = if matches!(passkeys_state, CredentialState::Modifiable) {
            account.passkeys.clone()
        } else {
            BTreeMap::default()
        };

        let unixcred: Option<Credential> = if unixcred_can_edit {
            account.unix_extn().and_then(|uext| uext.ucred()).cloned()
        } else {
            None
        };

        let sshkeys = if sshpubkey_can_edit {
            account
                .unix_extn()
                .map(|uext| uext.sshkeys().clone())
                .unwrap_or_default()
        } else {
            BTreeMap::default()
        };

        // Before we start, we pre-filter out anything that no longer conforms to policy.
        // These would already be failing authentication, so they should have the appearance
        // of "being removed".
        let attested_passkeys = if matches!(attested_passkeys_state, CredentialState::Modifiable)
            || matches!(attested_passkeys_state, CredentialState::DeleteOnly)
        {
            if let Some(att_ca_list) = resolved_account_policy.webauthn_attestation_ca_list() {
                let mut attested_passkeys = BTreeMap::default();

                for (uuid, (label, apk)) in account.attested_passkeys.iter() {
                    match apk.verify_attestation(att_ca_list) {
                        Ok(_) => {
                            // Good to go
                            attested_passkeys.insert(*uuid, (label.clone(), apk.clone()));
                        }
                        Err(e) => {
                            warn!(eclass=?e, emsg=%e, "credential no longer meets attestation criteria");
                        }
                    }
                }

                attested_passkeys
            } else {
                // Seems weird here to be skipping filtering of the credentials. The reason is that
                // if an account had registered attested passkeys in the past we can delete them, but
                // not add new ones. Situation only occurs when policy isn't present on the account.
                account.attested_passkeys.clone()
            }
        } else {
            BTreeMap::default()
        };

        // Get the external credential portal, if any.
        let ext_cred_portal = match (account.sync_parent_uuid, ext_cred_portal_can_view) {
            (Some(sync_parent_uuid), true) => {
                let sync_entry = self.qs_write.internal_search_uuid(sync_parent_uuid)?;
                sync_entry
                    .get_ava_single_url(Attribute::SyncCredentialPortal)
                    .cloned()
                    .map(CUExtPortal::Some)
                    .unwrap_or(CUExtPortal::Hidden)
            }
            (Some(_), false) => CUExtPortal::Hidden,
            (None, _) => CUExtPortal::None,
        };

        // Stash the issuer for some UI elements
        let issuer = self.qs_write.get_domain_display_name().to_string();

        // - store account policy (if present)
        let session = CredentialUpdateSession {
            account,
            resolved_account_policy,
            issuer,
            intent_token_id,
            ext_cred_portal,
            primary,
            primary_state,
            unixcred,
            unixcred_can_edit,
            sshkeys,
            sshpubkey_can_edit,
            passkeys,
            passkeys_state,
            attested_passkeys,
            attested_passkeys_state,
            mfaregstate: MfaRegState::None,
        };

        let max_ttl = ct + MAXIMUM_CRED_UPDATE_TTL;

        let token = CredentialUpdateSessionTokenInner { sessionid, max_ttl };

        let token_data = serde_json::to_vec(&token).map_err(|e| {
            admin_error!(err = ?e, "Unable to encode token data");
            OperationError::SerdeJsonError
        })?;

        let token_jwe = JweBuilder::from(token_data).build();

        let token_enc = self
            .qs_write
            .get_domain_key_object_handle()?
            .jwe_encrypt(&token_jwe, ct)?;

        let status: CredentialUpdateSessionStatus = (&session).into();

        let session = Arc::new(Mutex::new(session));

        // Point of no return

        // Sneaky! Now we know it will work, prune old sessions.
        self.expire_credential_update_sessions(ct);

        // Store the update session into the map.
        self.cred_update_sessions.insert(sessionid, session);
        trace!("cred_update_sessions.insert - {}", sessionid);

        // - issue the CredentialUpdateToken (enc)
        Ok((CredentialUpdateSessionToken { token_enc }, status))
    }

    #[instrument(level = "debug", skip_all)]
    pub fn init_credential_update_intent(
        &mut self,
        event: &InitCredentialUpdateIntentEvent,
        ct: Duration,
    ) -> Result<CredentialUpdateIntentToken, OperationError> {
        let (account, _resolved_account_policy, perms) =
            self.validate_init_credential_update(event.target, &event.ident)?;

        // We should check in the acc-pol if we can proceed?
        // Is there a reason account policy might deny us from proceeding?

        // ==== AUTHORISATION CHECKED ===

        // Build the intent token. Previously this was using 0 and then
        // relying on clamp to raise this to 5 minutes, but that led to
        // rapid timeouts that affected some users.
        let mttl = event.max_ttl.unwrap_or(DEFAULT_INTENT_TTL);
        let clamped_mttl = mttl.clamp(MINIMUM_INTENT_TTL, MAXIMUM_INTENT_TTL);
        debug!(?clamped_mttl, "clamped update intent validity");
        let max_ttl = ct + clamped_mttl;

        let intent_id = readable_password_from_random();

        // Mark that we have created an intent token on the user.
        // ⚠️   -- remember, there is a risk, very low, but still a risk of collision of the intent_id.
        //        instead of enforcing unique, which would divulge that the collision occurred, we
        //        write anyway, and instead on the intent access path we invalidate IF the collision
        //        occurs.
        let mut modlist = ModifyList::new_append(
            Attribute::CredentialUpdateIntentToken,
            Value::IntentToken(
                intent_id.clone(),
                IntentTokenState::Valid { max_ttl, perms },
            ),
        );

        // Remove any old credential update intents
        account
            .credential_update_intent_tokens
            .iter()
            .for_each(|(existing_intent_id, state)| {
                let max_ttl = match state {
                    IntentTokenState::Valid { max_ttl, perms: _ }
                    | IntentTokenState::InProgress {
                        max_ttl,
                        perms: _,
                        session_id: _,
                        session_ttl: _,
                    }
                    | IntentTokenState::Consumed { max_ttl } => *max_ttl,
                };

                if ct >= max_ttl {
                    modlist.push_mod(Modify::Removed(
                        Attribute::CredentialUpdateIntentToken.into(),
                        PartialValue::IntentToken(existing_intent_id.clone()),
                    ));
                }
            });

        self.qs_write
            .internal_modify(
                // Filter as executed
                &filter!(f_eq(Attribute::Uuid, PartialValue::Uuid(account.uuid))),
                &modlist,
            )
            .map_err(|e| {
                request_error!(error = ?e);
                e
            })?;

        Ok(CredentialUpdateIntentToken { intent_id })
    }

    pub fn exchange_intent_credential_update(
        &mut self,
        token: CredentialUpdateIntentToken,
        current_time: Duration,
    ) -> Result<(CredentialUpdateSessionToken, CredentialUpdateSessionStatus), OperationError> {
        let CredentialUpdateIntentToken { intent_id } = token;

        /*
            let entry = self.qs_write.internal_search_uuid(&token.target)?;
        */
        // ⚠️  due to a low, but possible risk of intent_id collision, if there are multiple
        // entries, we will reject the intent.
        // DO we need to force both to "Consumed" in this step?
        //
        // ⚠️  If not present, it may be due to replication delay. We can report this.

        let mut vs = self.qs_write.internal_search(filter!(f_eq(
            Attribute::CredentialUpdateIntentToken,
            PartialValue::IntentToken(intent_id.clone())
        )))?;

        let entry = match vs.pop() {
            Some(entry) => {
                if vs.is_empty() {
                    // Happy Path!
                    entry
                } else {
                    // Multiple entries matched! This is bad!
                    let matched_uuids = std::iter::once(entry.get_uuid())
                        .chain(vs.iter().map(|e| e.get_uuid()))
                        .collect::<Vec<_>>();

                    security_error!("Multiple entries had identical intent_id - for safety, rejecting the use of this intent_id! {:?}", matched_uuids);

                    /*
                    let mut modlist = ModifyList::new();

                    modlist.push_mod(Modify::Removed(
                        Attribute::CredentialUpdateIntentToken.into(),
                        PartialValue::IntentToken(intent_id.clone()),
                    ));

                    let filter_or = matched_uuids.into_iter()
                        .map(|u| f_eq(Attribute::Uuid, PartialValue::new_uuid(u)))
                        .collect();

                    self.qs_write
                        .internal_modify(
                            // Filter as executed
                            &filter!(f_or(filter_or)),
                            &modlist,
                        )
                        .map_err(|e| {
                            request_error!(error = ?e);
                            e
                        })?;
                    */

                    return Err(OperationError::InvalidState);
                }
            }
            None => {
                security_info!(
                    "Rejecting Update Session - Intent Token does not exist (replication delay?)",
                );
                return Err(OperationError::Wait(
                    OffsetDateTime::UNIX_EPOCH + (current_time + Duration::from_secs(150)),
                ));
            }
        };

        // Is target an account? This checks for us.
        let (account, resolved_account_policy) =
            Account::try_from_entry_with_policy(entry.as_ref(), &mut self.qs_write)?;

        // Check there is not already a user session in progress with this intent token.
        // Is there a need to revoke intent tokens?

        let (max_ttl, perms) = match account.credential_update_intent_tokens.get(&intent_id) {
            Some(IntentTokenState::Consumed { max_ttl: _ }) => {
                security_info!(
                    %entry,
                    %account.uuid,
                    "Rejecting Update Session - Intent Token has already been exchanged",
                );
                return Err(OperationError::SessionExpired);
            }
            Some(IntentTokenState::InProgress {
                max_ttl,
                perms,
                session_id,
                session_ttl,
            }) => {
                if current_time > *session_ttl {
                    // The former session has expired, continue.
                    security_info!(
                        %entry,
                        %account.uuid,
                        "Initiating Credential Update Session - Previous session {} has expired", session_id
                    );
                } else {
                    // The former session has been orphaned while in use. This can be from someone
                    // ctrl-c during their use of the session or refreshing the page without committing.
                    //
                    // we don't try to exclusive lock the token here with the current time as we previously
                    // did. This is because with async replication, there isn't a guarantee this will actually
                    // be sent to another server "soon enough" to prevent abuse on the separate server. So
                    // all this "lock" actually does is annoy legitimate users and not stop abuse. We
                    // STILL keep the InProgress state though since we check it on commit, so this
                    // forces the previous orphan session to be immediately invalidated!
                    security_info!(
                        %entry,
                        %account.uuid,
                        "Initiating Update Session - Intent Token was in use {} - this will be invalidated.", session_id
                    );
                };
                (*max_ttl, *perms)
            }
            Some(IntentTokenState::Valid { max_ttl, perms }) => {
                // Check the TTL
                if current_time >= *max_ttl {
                    trace!(?current_time, ?max_ttl);
                    security_info!(%account.uuid, "intent has expired");
                    return Err(OperationError::SessionExpired);
                } else {
                    security_info!(
                        %entry,
                        %account.uuid,
                        "Initiating Credential Update Session",
                    );
                    (*max_ttl, *perms)
                }
            }
            None => {
                admin_error!("Corruption may have occurred - index yielded an entry for intent_id, but the entry does not contain that intent_id");
                return Err(OperationError::InvalidState);
            }
        };

        // To prevent issues with repl, we need to associate this cred update session id, with
        // this intent token id.

        // Store the intent id in the session (if needed) so that we can check the state at the
        // end of the update.

        // We need to pin the id from the intent token into the credential to ensure it's not reused

        // Need to change this to the expiry time, so we can purge up to.
        let session_id = uuid_from_duration(current_time + MAXIMUM_CRED_UPDATE_TTL, self.sid);

        let mut modlist = ModifyList::new();

        modlist.push_mod(Modify::Removed(
            Attribute::CredentialUpdateIntentToken.into(),
            PartialValue::IntentToken(intent_id.clone()),
        ));
        modlist.push_mod(Modify::Present(
            Attribute::CredentialUpdateIntentToken.into(),
            Value::IntentToken(
                intent_id.clone(),
                IntentTokenState::InProgress {
                    max_ttl,
                    perms,
                    session_id,
                    session_ttl: current_time + MAXIMUM_CRED_UPDATE_TTL,
                },
            ),
        ));

        self.qs_write
            .internal_modify(
                // Filter as executed
                &filter!(f_eq(Attribute::Uuid, PartialValue::Uuid(account.uuid))),
                &modlist,
            )
            .map_err(|e| {
                request_error!(error = ?e);
                e
            })?;

        // ==========
        // Okay, good to exchange.

        self.create_credupdate_session(
            session_id,
            Some(intent_id),
            account,
            resolved_account_policy,
            perms,
            current_time,
        )
    }

    #[instrument(level = "debug", skip_all)]
    pub fn init_credential_update(
        &mut self,
        event: &InitCredentialUpdateEvent,
        current_time: Duration,
    ) -> Result<(CredentialUpdateSessionToken, CredentialUpdateSessionStatus), OperationError> {
        let (account, resolved_account_policy, perms) =
            self.validate_init_credential_update(event.target, &event.ident)?;

        // ==== AUTHORISATION CHECKED ===
        // This is the expiry time, so that our cleanup task can "purge up to now" rather
        // than needing to do calculations.
        let sessionid = uuid_from_duration(current_time + MAXIMUM_CRED_UPDATE_TTL, self.sid);

        // Build the cred update session.
        self.create_credupdate_session(
            sessionid,
            None,
            account,
            resolved_account_policy,
            perms,
            current_time,
        )
    }

    #[instrument(level = "trace", skip(self))]
    pub fn expire_credential_update_sessions(&mut self, ct: Duration) {
        let before = self.cred_update_sessions.len();
        let split_at = uuid_from_duration(ct, self.sid);
        trace!(?split_at, "expiring less than");
        self.cred_update_sessions.split_off_lt(&split_at);
        let removed = before - self.cred_update_sessions.len();
        trace!(?removed);
    }

    // This shares some common paths between commit and cancel.
    fn credential_update_commit_common(
        &mut self,
        cust: &CredentialUpdateSessionToken,
        ct: Duration,
    ) -> Result<
        (
            ModifyList<ModifyInvalid>,
            CredentialUpdateSession,
            CredentialUpdateSessionTokenInner,
        ),
        OperationError,
    > {
        let session_token: CredentialUpdateSessionTokenInner = self
            .qs_write
            .get_domain_key_object_handle()?
            .jwe_decrypt(&cust.token_enc)
            .map_err(|e| {
                admin_error!(?e, "Failed to decrypt credential update session request");
                OperationError::SessionExpired
            })
            .and_then(|data| {
                data.from_json().map_err(|e| {
                    admin_error!(err = ?e, "Failed to deserialise credential update session request");
                    OperationError::SerdeJsonError
                })
            })?;

        if ct >= session_token.max_ttl {
            trace!(?ct, ?session_token.max_ttl);
            security_info!(%session_token.sessionid, "session expired");
            return Err(OperationError::SessionExpired);
        }

        let session_handle = self.cred_update_sessions.remove(&session_token.sessionid)
            .ok_or_else(|| {
                admin_error!("No such sessionid exists on this server - may be due to a load balancer failover or replay? {:?}", session_token.sessionid);
                OperationError::InvalidState
            })?;

        let session = session_handle
            .try_lock()
            .map(|guard| (*guard).clone())
            .map_err(|_| {
                admin_error!("Session already locked, unable to proceed.");
                OperationError::InvalidState
            })?;

        trace!(?session);

        let modlist = ModifyList::new();

        Ok((modlist, session, session_token))
    }

    pub fn commit_credential_update(
        &mut self,
        cust: &CredentialUpdateSessionToken,
        ct: Duration,
    ) -> Result<(), OperationError> {
        let (mut modlist, session, session_token) =
            self.credential_update_commit_common(cust, ct)?;

        // Can we actually proceed?
        let can_commit = session.can_commit();
        if !can_commit.0 {
            let commit_failure_reasons = can_commit
                .1
                .iter()
                .map(|e| e.to_string())
                .collect::<Vec<String>>()
                .join(", ");
            admin_error!(
                "Session is unable to commit due to: {}",
                commit_failure_reasons
            );
            // TODO: perhaps it would be more helpful to add a new operation error that describes what the issue is
            return Err(OperationError::InvalidState);
        }

        // Setup mods for the various bits. We always assert an *exact* state.

        // IF an intent was used on this session, AND that intent is not in our
        // session state as an exact match, FAIL the commit. Move the intent to "Consumed".
        //
        // Should we mark the credential as suspect (lock the account?)
        //
        // If the credential has changed, reject? Do we need "asserts" in the modlist?
        // that would allow better expression of this, and will allow resolving via replication

        // If an intent token was used, remove it's former value, and add it as consumed.
        if let Some(intent_token_id) = &session.intent_token_id {
            let entry = self.qs_write.internal_search_uuid(session.account.uuid)?;
            let account = Account::try_from_entry_rw(entry.as_ref(), &mut self.qs_write)?;

            let max_ttl = match account.credential_update_intent_tokens.get(intent_token_id) {
                Some(IntentTokenState::InProgress {
                    max_ttl,
                    perms: _,
                    session_id,
                    session_ttl: _,
                }) => {
                    if *session_id != session_token.sessionid {
                        security_info!("Session originated from an intent token, but the intent token has initiated a conflicting second update session. Refusing to commit changes.");
                        return Err(OperationError::InvalidState);
                    } else {
                        *max_ttl
                    }
                }
                Some(IntentTokenState::Consumed { max_ttl: _ })
                | Some(IntentTokenState::Valid {
                    max_ttl: _,
                    perms: _,
                })
                | None => {
                    security_info!("Session originated from an intent token, but the intent token has transitioned to an invalid state. Refusing to commit changes.");
                    return Err(OperationError::InvalidState);
                }
            };

            modlist.push_mod(Modify::Removed(
                Attribute::CredentialUpdateIntentToken.into(),
                PartialValue::IntentToken(intent_token_id.clone()),
            ));
            modlist.push_mod(Modify::Present(
                Attribute::CredentialUpdateIntentToken.into(),
                Value::IntentToken(
                    intent_token_id.clone(),
                    IntentTokenState::Consumed { max_ttl },
                ),
            ));
        };

        match session.primary_state {
            CredentialState::Modifiable => {
                modlist.push_mod(Modify::Purged(Attribute::PrimaryCredential.into()));
                if let Some(ncred) = &session.primary {
                    let vcred = Value::new_credential("primary", ncred.clone());
                    modlist.push_mod(Modify::Present(Attribute::PrimaryCredential.into(), vcred));
                };
            }
            CredentialState::DeleteOnly | CredentialState::PolicyDeny => {
                modlist.push_mod(Modify::Purged(Attribute::PrimaryCredential.into()));
            }
            CredentialState::AccessDeny => {}
        };

        match session.passkeys_state {
            CredentialState::DeleteOnly | CredentialState::Modifiable => {
                modlist.push_mod(Modify::Purged(Attribute::PassKeys.into()));
                // Add all the passkeys. If none, nothing will be added! This handles
                // the delete case quite cleanly :)
                session.passkeys.iter().for_each(|(uuid, (tag, pk))| {
                    let v_pk = Value::Passkey(*uuid, tag.clone(), pk.clone());
                    modlist.push_mod(Modify::Present(Attribute::PassKeys.into(), v_pk));
                });
            }
            CredentialState::PolicyDeny => {
                modlist.push_mod(Modify::Purged(Attribute::PassKeys.into()));
            }
            CredentialState::AccessDeny => {}
        };

        match session.attested_passkeys_state {
            CredentialState::DeleteOnly | CredentialState::Modifiable => {
                modlist.push_mod(Modify::Purged(Attribute::AttestedPasskeys.into()));
                // Add all the passkeys. If none, nothing will be added! This handles
                // the delete case quite cleanly :)
                session
                    .attested_passkeys
                    .iter()
                    .for_each(|(uuid, (tag, pk))| {
                        let v_pk = Value::AttestedPasskey(*uuid, tag.clone(), pk.clone());
                        modlist.push_mod(Modify::Present(Attribute::AttestedPasskeys.into(), v_pk));
                    });
            }
            CredentialState::PolicyDeny => {
                modlist.push_mod(Modify::Purged(Attribute::AttestedPasskeys.into()));
            }
            // CredentialState::Disabled |
            CredentialState::AccessDeny => {}
        };

        if session.unixcred_can_edit {
            modlist.push_mod(Modify::Purged(Attribute::UnixPassword.into()));
            if let Some(ncred) = &session.unixcred {
                let vcred = Value::new_credential("unix", ncred.clone());
                modlist.push_mod(Modify::Present(Attribute::UnixPassword.into(), vcred));
            }
        }

        if session.sshpubkey_can_edit {
            modlist.push_mod(Modify::Purged(Attribute::SshPublicKey.into()));
            for (tag, pk) in &session.sshkeys {
                let v_sk = Value::SshKey(tag.clone(), pk.clone());
                modlist.push_mod(Modify::Present(Attribute::SshPublicKey.into(), v_sk));
            }
        }

        // Apply to the account!
        trace!(?modlist, "processing change");

        if modlist.is_empty() {
            trace!("no changes to apply");
            Ok(())
        } else {
            self.qs_write
                .internal_modify(
                    // Filter as executed
                    &filter!(f_eq(
                        Attribute::Uuid,
                        PartialValue::Uuid(session.account.uuid)
                    )),
                    &modlist,
                )
                .map_err(|e| {
                    request_error!(error = ?e);
                    e
                })
        }
    }

    pub fn cancel_credential_update(
        &mut self,
        cust: &CredentialUpdateSessionToken,
        ct: Duration,
    ) -> Result<(), OperationError> {
        let (mut modlist, session, session_token) =
            self.credential_update_commit_common(cust, ct)?;

        // If an intent token was used, remove it's former value, and add it as VALID since we didn't commit.
        if let Some(intent_token_id) = &session.intent_token_id {
            let entry = self.qs_write.internal_search_uuid(session.account.uuid)?;
            let account = Account::try_from_entry_rw(entry.as_ref(), &mut self.qs_write)?;

            let (max_ttl, perms) = match account
                .credential_update_intent_tokens
                .get(intent_token_id)
            {
                Some(IntentTokenState::InProgress {
                    max_ttl,
                    perms,
                    session_id,
                    session_ttl: _,
                }) => {
                    if *session_id != session_token.sessionid {
                        security_info!("Session originated from an intent token, but the intent token has initiated a conflicting second update session. Refusing to commit changes.");
                        return Err(OperationError::InvalidState);
                    } else {
                        (*max_ttl, *perms)
                    }
                }
                Some(IntentTokenState::Consumed { max_ttl: _ })
                | Some(IntentTokenState::Valid {
                    max_ttl: _,
                    perms: _,
                })
                | None => {
                    security_info!("Session originated from an intent token, but the intent token has transitioned to an invalid state. Refusing to commit changes.");
                    return Err(OperationError::InvalidState);
                }
            };

            modlist.push_mod(Modify::Removed(
                Attribute::CredentialUpdateIntentToken.into(),
                PartialValue::IntentToken(intent_token_id.clone()),
            ));
            modlist.push_mod(Modify::Present(
                Attribute::CredentialUpdateIntentToken.into(),
                Value::IntentToken(
                    intent_token_id.clone(),
                    IntentTokenState::Valid { max_ttl, perms },
                ),
            ));
        };

        // Apply to the account!
        if !modlist.is_empty() {
            trace!(?modlist, "processing change");

            self.qs_write
                .internal_modify(
                    // Filter as executed
                    &filter!(f_eq(
                        Attribute::Uuid,
                        PartialValue::Uuid(session.account.uuid)
                    )),
                    &modlist,
                )
                .map_err(|e| {
                    request_error!(error = ?e);
                    e
                })
        } else {
            Ok(())
        }
    }
}

impl<'a> IdmServerCredUpdateTransaction<'a> {
    #[cfg(test)]
    pub fn get_origin(&self) -> &Url {
        &self.webauthn.get_allowed_origins()[0]
    }

    fn get_current_session(
        &self,
        cust: &CredentialUpdateSessionToken,
        ct: Duration,
    ) -> Result<CredentialUpdateSessionMutex, OperationError> {
        let session_token: CredentialUpdateSessionTokenInner = self
            .qs_read
            .get_domain_key_object_handle()?
            .jwe_decrypt(&cust.token_enc)
            .map_err(|e| {
                admin_error!(?e, "Failed to decrypt credential update session request");
                OperationError::SessionExpired
            })
            .and_then(|data| {
                data.from_json().map_err(|e| {
                    admin_error!(err = ?e, "Failed to deserialise credential update session request");
                    OperationError::SerdeJsonError
                })
            })?;

        // Check the TTL
        if ct >= session_token.max_ttl {
            trace!(?ct, ?session_token.max_ttl);
            security_info!(%session_token.sessionid, "session expired");
            return Err(OperationError::SessionExpired);
        }

        self.cred_update_sessions.get(&session_token.sessionid)
            .ok_or_else(|| {
                admin_error!("No such sessionid exists on this server - may be due to a load balancer failover or token replay? {}", session_token.sessionid);
                OperationError::InvalidState
            })
            .cloned()
    }

    // I think I need this to be a try lock instead, and fail on error, because
    // of the nature of the async bits.
    pub fn credential_update_status(
        &self,
        cust: &CredentialUpdateSessionToken,
        ct: Duration,
    ) -> Result<CredentialUpdateSessionStatus, OperationError> {
        let session_handle = self.get_current_session(cust, ct)?;
        let session = session_handle.try_lock().map_err(|_| {
            admin_error!("Session already locked, unable to proceed.");
            OperationError::InvalidState
        })?;
        trace!(?session);

        let status: CredentialUpdateSessionStatus = session.deref().into();
        Ok(status)
    }

    #[instrument(level = "trace", skip(self))]
    fn check_password_quality(
        &self,
        cleartext: &str,
        resolved_account_policy: &ResolvedAccountPolicy,
        related_inputs: &[&str],
        radius_secret: Option<&str>,
    ) -> Result<(), PasswordQuality> {
        // password strength and badlisting is always global, rather than per-pw-policy.
        // pw-policy as check on the account is about requirements for mfa for example.

        // is the password at least 10 char?
        let pw_min_length = resolved_account_policy.pw_min_length();
        if cleartext.len() < pw_min_length as usize {
            return Err(PasswordQuality::TooShort(pw_min_length));
        }

        if let Some(some_radius_secret) = radius_secret {
            if cleartext.contains(some_radius_secret) {
                return Err(PasswordQuality::DontReusePasswords);
            }
        }

        // zxcvbn doesn't appear to be picking these up?
        for related in related_inputs {
            if cleartext.contains(related) {
                return Err(PasswordQuality::Feedback(vec![
                    PasswordFeedback::NamesAndSurnamesByThemselvesAreEasyToGuess,
                    PasswordFeedback::AvoidDatesAndYearsThatAreAssociatedWithYou,
                ]));
            }
        }

        // does the password pass zxcvbn?
        let entropy = zxcvbn::zxcvbn(cleartext, related_inputs).map_err(|e| {
            admin_error!("zxcvbn check failure (password empty?) {:?}", e);
            // Return some generic feedback when the password is this bad.
            PasswordQuality::Feedback(vec![
                PasswordFeedback::UseAFewWordsAvoidCommonPhrases,
                PasswordFeedback::AddAnotherWordOrTwo,
                PasswordFeedback::NoNeedForSymbolsDigitsOrUppercaseLetters,
            ])
        })?;

        // PW's should always be enforced as strong as possible.
        if entropy.score() < 4 {
            // The password is too week as per:
            // https://docs.rs/zxcvbn/2.0.0/zxcvbn/struct.Entropy.html
            let feedback: zxcvbn::feedback::Feedback = entropy
                .feedback()
                .as_ref()
                .ok_or(OperationError::InvalidState)
                .map(|v| v.clone())
                .map_err(|e| {
                    security_info!("zxcvbn returned no feedback when score < 3 -> {:?}", e);
                    // Return some generic feedback when the password is this bad.
                    PasswordQuality::Feedback(vec![
                        PasswordFeedback::UseAFewWordsAvoidCommonPhrases,
                        PasswordFeedback::AddAnotherWordOrTwo,
                        PasswordFeedback::NoNeedForSymbolsDigitsOrUppercaseLetters,
                    ])
                })?;

            security_info!(?feedback, "pw quality feedback");

            let feedback: Vec<_> = feedback
                .suggestions()
                .iter()
                .map(|s| {
                    match s {
                            zxcvbn::feedback::Suggestion::UseAFewWordsAvoidCommonPhrases => {
                                PasswordFeedback::UseAFewWordsAvoidCommonPhrases
                            }
                            zxcvbn::feedback::Suggestion::NoNeedForSymbolsDigitsOrUppercaseLetters => {
                                PasswordFeedback::NoNeedForSymbolsDigitsOrUppercaseLetters
                            }
                            zxcvbn::feedback::Suggestion::AddAnotherWordOrTwo => {
                                PasswordFeedback::AddAnotherWordOrTwo
                            }
                            zxcvbn::feedback::Suggestion::CapitalizationDoesntHelpVeryMuch => {
                                PasswordFeedback::CapitalizationDoesntHelpVeryMuch
                            }
                            zxcvbn::feedback::Suggestion::AllUppercaseIsAlmostAsEasyToGuessAsAllLowercase => {
                                PasswordFeedback::AllUppercaseIsAlmostAsEasyToGuessAsAllLowercase
                            }
                            zxcvbn::feedback::Suggestion::ReversedWordsArentMuchHarderToGuess => {
                                PasswordFeedback::ReversedWordsArentMuchHarderToGuess
                            }
                            zxcvbn::feedback::Suggestion::PredictableSubstitutionsDontHelpVeryMuch => {
                                PasswordFeedback::PredictableSubstitutionsDontHelpVeryMuch
                            }
                            zxcvbn::feedback::Suggestion::UseALongerKeyboardPatternWithMoreTurns => {
                                PasswordFeedback::UseALongerKeyboardPatternWithMoreTurns
                            }
                            zxcvbn::feedback::Suggestion::AvoidRepeatedWordsAndCharacters => {
                                PasswordFeedback::AvoidRepeatedWordsAndCharacters
                            }
                            zxcvbn::feedback::Suggestion::AvoidSequences => {
                                PasswordFeedback::AvoidSequences
                            }
                            zxcvbn::feedback::Suggestion::AvoidRecentYears => {
                                PasswordFeedback::AvoidRecentYears
                            }
                            zxcvbn::feedback::Suggestion::AvoidYearsThatAreAssociatedWithYou => {
                                PasswordFeedback::AvoidYearsThatAreAssociatedWithYou
                            }
                            zxcvbn::feedback::Suggestion::AvoidDatesAndYearsThatAreAssociatedWithYou => {
                                PasswordFeedback::AvoidDatesAndYearsThatAreAssociatedWithYou
                            }
                        }
                })
                .chain(feedback.warning().map(|w| match w {
                    zxcvbn::feedback::Warning::StraightRowsOfKeysAreEasyToGuess => {
                        PasswordFeedback::StraightRowsOfKeysAreEasyToGuess
                    }
                    zxcvbn::feedback::Warning::ShortKeyboardPatternsAreEasyToGuess => {
                        PasswordFeedback::ShortKeyboardPatternsAreEasyToGuess
                    }
                    zxcvbn::feedback::Warning::RepeatsLikeAaaAreEasyToGuess => {
                        PasswordFeedback::RepeatsLikeAaaAreEasyToGuess
                    }
                    zxcvbn::feedback::Warning::RepeatsLikeAbcAbcAreOnlySlightlyHarderToGuess => {
                        PasswordFeedback::RepeatsLikeAbcAbcAreOnlySlightlyHarderToGuess
                    }
                    zxcvbn::feedback::Warning::ThisIsATop10Password => {
                        PasswordFeedback::ThisIsATop10Password
                    }
                    zxcvbn::feedback::Warning::ThisIsATop100Password => {
                        PasswordFeedback::ThisIsATop100Password
                    }
                    zxcvbn::feedback::Warning::ThisIsACommonPassword => {
                        PasswordFeedback::ThisIsACommonPassword
                    }
                    zxcvbn::feedback::Warning::ThisIsSimilarToACommonlyUsedPassword => {
                        PasswordFeedback::ThisIsSimilarToACommonlyUsedPassword
                    }
                    zxcvbn::feedback::Warning::SequencesLikeAbcAreEasyToGuess => {
                        PasswordFeedback::SequencesLikeAbcAreEasyToGuess
                    }
                    zxcvbn::feedback::Warning::RecentYearsAreEasyToGuess => {
                        PasswordFeedback::RecentYearsAreEasyToGuess
                    }
                    zxcvbn::feedback::Warning::AWordByItselfIsEasyToGuess => {
                        PasswordFeedback::AWordByItselfIsEasyToGuess
                    }
                    zxcvbn::feedback::Warning::DatesAreOftenEasyToGuess => {
                        PasswordFeedback::DatesAreOftenEasyToGuess
                    }
                    zxcvbn::feedback::Warning::NamesAndSurnamesByThemselvesAreEasyToGuess => {
                        PasswordFeedback::NamesAndSurnamesByThemselvesAreEasyToGuess
                    }
                    zxcvbn::feedback::Warning::CommonNamesAndSurnamesAreEasyToGuess => {
                        PasswordFeedback::CommonNamesAndSurnamesAreEasyToGuess
                    }
                }))
                .collect();

            return Err(PasswordQuality::Feedback(feedback));
        }

        // check a password badlist to eliminate more content
        // we check the password as "lower case" to help eliminate possibilities
        // also, when pw_badlist_cache is read from DB, it is read as Value (iutf8 lowercase)
        if self
            .qs_read
            .pw_badlist()
            .contains(&cleartext.to_lowercase())
        {
            security_info!("Password found in badlist, rejecting");
            Err(PasswordQuality::BadListed)
        } else {
            Ok(())
        }
    }

    #[instrument(level = "trace", skip(cust, self))]
    pub fn credential_primary_set_password(
        &self,
        cust: &CredentialUpdateSessionToken,
        ct: Duration,
        pw: &str,
    ) -> Result<CredentialUpdateSessionStatus, OperationError> {
        let session_handle = self.get_current_session(cust, ct)?;
        let mut session = session_handle.try_lock().map_err(|_| {
            admin_error!("Session already locked, unable to proceed.");
            OperationError::InvalidState
        })?;
        trace!(?session);

        if !matches!(session.primary_state, CredentialState::Modifiable) {
            error!("Session does not have permission to modify primary credential");
            return Err(OperationError::AccessDenied);
        };

        self.check_password_quality(
            pw,
            &session.resolved_account_policy,
            session.account.related_inputs().as_slice(),
            session.account.radius_secret.as_deref(),
        )
        .map_err(|e| match e {
            PasswordQuality::TooShort(sz) => {
                OperationError::PasswordQuality(vec![PasswordFeedback::TooShort(sz)])
            }
            PasswordQuality::BadListed => {
                OperationError::PasswordQuality(vec![PasswordFeedback::BadListed])
            }
            PasswordQuality::DontReusePasswords => {
                OperationError::PasswordQuality(vec![PasswordFeedback::DontReusePasswords])
            }
            PasswordQuality::Feedback(feedback) => OperationError::PasswordQuality(feedback),
        })?;

        let ncred = match &session.primary {
            Some(primary) => {
                // Is there a need to update the uuid of the cred re softlocks?
                primary.set_password(self.crypto_policy, pw)?
            }
            None => Credential::new_password_only(self.crypto_policy, pw)?,
        };

        session.primary = Some(ncred);
        Ok(session.deref().into())
    }

    pub fn credential_primary_init_totp(
        &self,
        cust: &CredentialUpdateSessionToken,
        ct: Duration,
    ) -> Result<CredentialUpdateSessionStatus, OperationError> {
        let session_handle = self.get_current_session(cust, ct)?;
        let mut session = session_handle.try_lock().map_err(|_| {
            admin_error!("Session already locked, unable to proceed.");
            OperationError::InvalidState
        })?;
        trace!(?session);

        if !matches!(session.primary_state, CredentialState::Modifiable) {
            error!("Session does not have permission to modify primary credential");
            return Err(OperationError::AccessDenied);
        };

        // Is there something else in progress?
        // Or should this just cancel it ....
        if !matches!(session.mfaregstate, MfaRegState::None) {
            admin_info!("Invalid TOTP state, another update is in progress");
            return Err(OperationError::InvalidState);
        }

        // Generate the TOTP.
        let totp_token = Totp::generate_secure(TOTP_DEFAULT_STEP);

        session.mfaregstate = MfaRegState::TotpInit(totp_token);
        // Now that it's in the state, it'll be in the status when returned.
        Ok(session.deref().into())
    }

    pub fn credential_primary_check_totp(
        &self,
        cust: &CredentialUpdateSessionToken,
        ct: Duration,
        totp_chal: u32,
        label: &str,
    ) -> Result<CredentialUpdateSessionStatus, OperationError> {
        let session_handle = self.get_current_session(cust, ct)?;
        let mut session = session_handle.try_lock().map_err(|_| {
            admin_error!("Session already locked, unable to proceed.");
            OperationError::InvalidState
        })?;
        trace!(?session);

        if !matches!(session.primary_state, CredentialState::Modifiable) {
            error!("Session does not have permission to modify primary credential");
            return Err(OperationError::AccessDenied);
        };

        // Are we in a totp reg state?
        match &session.mfaregstate {
            MfaRegState::TotpInit(totp_token)
            | MfaRegState::TotpTryAgain(totp_token)
            | MfaRegState::TotpInvalidSha1(totp_token, _, _) => {
                if totp_token.verify(totp_chal, ct) {
                    // It was valid. Update the credential.
                    let ncred = session
                        .primary
                        .as_ref()
                        .map(|cred| cred.append_totp(label.to_string(), totp_token.clone()))
                        .ok_or_else(|| {
                            admin_error!("A TOTP was added, but no primary credential stub exists");
                            OperationError::InvalidState
                        })?;

                    session.primary = Some(ncred);

                    // Set the state to None.
                    session.mfaregstate = MfaRegState::None;
                    Ok(session.deref().into())
                } else {
                    // What if it's a broken authenticator app? Google authenticator
                    // and Authy both force SHA1 and ignore the algo we send. So let's
                    // check that just in case.
                    let token_sha1 = totp_token.clone().downgrade_to_legacy();

                    if token_sha1.verify(totp_chal, ct) {
                        // Greeeaaaaaatttt. It's a broken app. Let's check the user
                        // knows this is broken, before we proceed.
                        session.mfaregstate = MfaRegState::TotpInvalidSha1(
                            totp_token.clone(),
                            token_sha1,
                            label.to_string(),
                        );
                        Ok(session.deref().into())
                    } else {
                        // Let them check again, it's a typo.
                        session.mfaregstate = MfaRegState::TotpTryAgain(totp_token.clone());
                        Ok(session.deref().into())
                    }
                }
            }
            _ => Err(OperationError::InvalidRequestState),
        }
    }

    pub fn credential_primary_accept_sha1_totp(
        &self,
        cust: &CredentialUpdateSessionToken,
        ct: Duration,
    ) -> Result<CredentialUpdateSessionStatus, OperationError> {
        let session_handle = self.get_current_session(cust, ct)?;
        let mut session = session_handle.try_lock().map_err(|_| {
            admin_error!("Session already locked, unable to proceed.");
            OperationError::InvalidState
        })?;
        trace!(?session);

        if !matches!(session.primary_state, CredentialState::Modifiable) {
            error!("Session does not have permission to modify primary credential");
            return Err(OperationError::AccessDenied);
        };

        // Are we in a totp reg state?
        match &session.mfaregstate {
            MfaRegState::TotpInvalidSha1(_, token_sha1, label) => {
                // They have accepted it as sha1
                let ncred = session
                    .primary
                    .as_ref()
                    .map(|cred| cred.append_totp(label.to_string(), token_sha1.clone()))
                    .ok_or_else(|| {
                        admin_error!("A TOTP was added, but no primary credential stub exists");
                        OperationError::InvalidState
                    })?;

                security_info!("A SHA1 TOTP credential was accepted");

                session.primary = Some(ncred);

                // Set the state to None.
                session.mfaregstate = MfaRegState::None;
                Ok(session.deref().into())
            }
            _ => Err(OperationError::InvalidRequestState),
        }
    }

    pub fn credential_primary_remove_totp(
        &self,
        cust: &CredentialUpdateSessionToken,
        ct: Duration,
        label: &str,
    ) -> Result<CredentialUpdateSessionStatus, OperationError> {
        let session_handle = self.get_current_session(cust, ct)?;
        let mut session = session_handle.try_lock().map_err(|_| {
            admin_error!("Session already locked, unable to proceed.");
            OperationError::InvalidState
        })?;
        trace!(?session);

        if !matches!(session.primary_state, CredentialState::Modifiable) {
            error!("Session does not have permission to modify primary credential");
            return Err(OperationError::AccessDenied);
        };

        if !matches!(session.mfaregstate, MfaRegState::None) {
            admin_info!("Invalid TOTP state, another update is in progress");
            return Err(OperationError::InvalidState);
        }

        let ncred = session
            .primary
            .as_ref()
            .map(|cred| cred.remove_totp(label))
            .ok_or_else(|| {
                admin_error!("Try to remove TOTP, but no primary credential stub exists");
                OperationError::InvalidState
            })?;

        session.primary = Some(ncred);

        // Set the state to None.
        session.mfaregstate = MfaRegState::None;
        Ok(session.deref().into())
    }

    pub fn credential_primary_init_backup_codes(
        &self,
        cust: &CredentialUpdateSessionToken,
        ct: Duration,
    ) -> Result<CredentialUpdateSessionStatus, OperationError> {
        let session_handle = self.get_current_session(cust, ct)?;
        let mut session = session_handle.try_lock().map_err(|_| {
            admin_error!("Session already locked, unable to proceed.");
            OperationError::InvalidState
        })?;
        trace!(?session);

        if !matches!(session.primary_state, CredentialState::Modifiable) {
            error!("Session does not have permission to modify primary credential");
            return Err(OperationError::AccessDenied);
        };

        // I think we override/map the status to inject the codes as a once-off state message.

        let codes = backup_code_from_random();

        let ncred = session
            .primary
            .as_ref()
            .ok_or_else(|| {
                admin_error!("Tried to add backup codes, but no primary credential stub exists");
                OperationError::InvalidState
            })
            .and_then(|cred|
                cred.update_backup_code(BackupCodes::new(codes.clone()))
                    .map_err(|_| {
                        admin_error!("Tried to add backup codes, but MFA is not enabled on this credential yet");
                        OperationError::InvalidState
                    })
            )
            ?;

        session.primary = Some(ncred);

        Ok(session.deref().into()).map(|mut status: CredentialUpdateSessionStatus| {
            status.mfaregstate = MfaRegStateStatus::BackupCodes(codes);
            status
        })
    }

    pub fn credential_primary_remove_backup_codes(
        &self,
        cust: &CredentialUpdateSessionToken,
        ct: Duration,
    ) -> Result<CredentialUpdateSessionStatus, OperationError> {
        let session_handle = self.get_current_session(cust, ct)?;
        let mut session = session_handle.try_lock().map_err(|_| {
            admin_error!("Session already locked, unable to proceed.");
            OperationError::InvalidState
        })?;
        trace!(?session);

        if !matches!(session.primary_state, CredentialState::Modifiable) {
            error!("Session does not have permission to modify primary credential");
            return Err(OperationError::AccessDenied);
        };

        let ncred = session
            .primary
            .as_ref()
            .ok_or_else(|| {
                admin_error!("Tried to add backup codes, but no primary credential stub exists");
                OperationError::InvalidState
            })
            .and_then(|cred|
                cred.remove_backup_code()
                    .map_err(|_| {
                        admin_error!("Tried to remove backup codes, but MFA is not enabled on this credential yet");
                        OperationError::InvalidState
                    })
            )
            ?;

        session.primary = Some(ncred);

        Ok(session.deref().into())
    }

    pub fn credential_passkey_init(
        &self,
        cust: &CredentialUpdateSessionToken,
        ct: Duration,
    ) -> Result<CredentialUpdateSessionStatus, OperationError> {
        let session_handle = self.get_current_session(cust, ct)?;
        let mut session = session_handle.try_lock().map_err(|_| {
            admin_error!("Session already locked, unable to proceed.");
            OperationError::InvalidState
        })?;
        trace!(?session);

        if !matches!(session.passkeys_state, CredentialState::Modifiable) {
            error!("Session does not have permission to modify passkeys");
            return Err(OperationError::AccessDenied);
        };

        if !matches!(session.mfaregstate, MfaRegState::None) {
            admin_info!("Invalid Passkey Init state, another update is in progress");
            return Err(OperationError::InvalidState);
        }

        let (ccr, pk_reg) = self
            .webauthn
            .start_passkey_registration(
                session.account.uuid,
                &session.account.spn,
                &session.account.displayname,
                session.account.existing_credential_id_list(),
            )
            .map_err(|e| {
                error!(eclass=?e, emsg=%e, "Unable to start passkey registration");
                OperationError::Webauthn
            })?;

        session.mfaregstate = MfaRegState::Passkey(Box::new(ccr), pk_reg);
        // Now that it's in the state, it'll be in the status when returned.
        Ok(session.deref().into())
    }

    pub fn credential_passkey_finish(
        &self,
        cust: &CredentialUpdateSessionToken,
        ct: Duration,
        label: String,
        reg: &RegisterPublicKeyCredential,
    ) -> Result<CredentialUpdateSessionStatus, OperationError> {
        let session_handle = self.get_current_session(cust, ct)?;
        let mut session = session_handle.try_lock().map_err(|_| {
            admin_error!("Session already locked, unable to proceed.");
            OperationError::InvalidState
        })?;
        trace!(?session);

        if !matches!(session.passkeys_state, CredentialState::Modifiable) {
            error!("Session does not have permission to modify passkeys");
            return Err(OperationError::AccessDenied);
        };

        match &session.mfaregstate {
            MfaRegState::Passkey(_ccr, pk_reg) => {
                let result = self
                    .webauthn
                    .finish_passkey_registration(reg, pk_reg)
                    .map_err(|e| {
                        error!(eclass=?e, emsg=%e, "Unable to complete passkey registration");
                        OperationError::Webauthn
                    });

                // The reg is done. Clean up state before returning errors.
                session.mfaregstate = MfaRegState::None;

                let passkey = result?;

                let pk_id = Uuid::new_v4();
                session.passkeys.insert(pk_id, (label, passkey));

                Ok(session.deref().into())
            }
            _ => Err(OperationError::InvalidRequestState),
        }
    }

    pub fn credential_passkey_remove(
        &self,
        cust: &CredentialUpdateSessionToken,
        ct: Duration,
        uuid: Uuid,
    ) -> Result<CredentialUpdateSessionStatus, OperationError> {
        let session_handle = self.get_current_session(cust, ct)?;
        let mut session = session_handle.try_lock().map_err(|_| {
            admin_error!("Session already locked, unable to proceed.");
            OperationError::InvalidState
        })?;
        trace!(?session);

        if !(matches!(session.passkeys_state, CredentialState::Modifiable)
            || matches!(session.passkeys_state, CredentialState::DeleteOnly))
        {
            error!("Session does not have permission to modify passkeys");
            return Err(OperationError::AccessDenied);
        };

        // No-op if not present
        session.passkeys.remove(&uuid);

        Ok(session.deref().into())
    }

    pub fn credential_attested_passkey_init(
        &self,
        cust: &CredentialUpdateSessionToken,
        ct: Duration,
    ) -> Result<CredentialUpdateSessionStatus, OperationError> {
        let session_handle = self.get_current_session(cust, ct)?;
        let mut session = session_handle.try_lock().map_err(|_| {
            error!("Session already locked, unable to proceed.");
            OperationError::InvalidState
        })?;
        trace!(?session);

        if !matches!(session.attested_passkeys_state, CredentialState::Modifiable) {
            error!("Session does not have permission to modify attested passkeys");
            return Err(OperationError::AccessDenied);
        };

        if !matches!(session.mfaregstate, MfaRegState::None) {
            info!("Invalid Attested Passkey Init state, another update is in progress");
            return Err(OperationError::InvalidState);
        }

        let att_ca_list = session
            .resolved_account_policy
            .webauthn_attestation_ca_list()
            .cloned()
            .ok_or_else(|| {
                error!(
                    "No attestation CA list is available, can not proceed with attested passkeys."
                );
                OperationError::AccessDenied
            })?;

        let (ccr, pk_reg) = self
            .webauthn
            .start_attested_passkey_registration(
                session.account.uuid,
                &session.account.spn,
                &session.account.displayname,
                session.account.existing_credential_id_list(),
                att_ca_list,
                None,
            )
            .map_err(|e| {
                error!(eclass=?e, emsg=%e, "Unable to start passkey registration");
                OperationError::Webauthn
            })?;

        session.mfaregstate = MfaRegState::AttestedPasskey(Box::new(ccr), pk_reg);
        // Now that it's in the state, it'll be in the status when returned.
        Ok(session.deref().into())
    }

    pub fn credential_attested_passkey_finish(
        &self,
        cust: &CredentialUpdateSessionToken,
        ct: Duration,
        label: String,
        reg: &RegisterPublicKeyCredential,
    ) -> Result<CredentialUpdateSessionStatus, OperationError> {
        let session_handle = self.get_current_session(cust, ct)?;
        let mut session = session_handle.try_lock().map_err(|_| {
            admin_error!("Session already locked, unable to proceed.");
            OperationError::InvalidState
        })?;
        trace!(?session);

        if !matches!(session.attested_passkeys_state, CredentialState::Modifiable) {
            error!("Session does not have permission to modify attested passkeys");
            return Err(OperationError::AccessDenied);
        };

        match &session.mfaregstate {
            MfaRegState::AttestedPasskey(_ccr, pk_reg) => {
                let result = self
                    .webauthn
                    .finish_attested_passkey_registration(reg, pk_reg)
                    .map_err(|e| {
                        error!(eclass=?e, emsg=%e, "Unable to complete passkey registration");

                        match e {
                            WebauthnError::AttestationChainNotTrusted(_)
                            | WebauthnError::AttestationNotVerifiable => {
                                OperationError::CU0001WebauthnAttestationNotTrusted
                            }
                            _ => OperationError::CU0002WebauthnRegistrationError,
                        }
                    });

                // The reg is done. Clean up state before returning errors.
                session.mfaregstate = MfaRegState::None;

                let passkey = result?;
                trace!(?passkey);

                let pk_id = Uuid::new_v4();
                session.attested_passkeys.insert(pk_id, (label, passkey));

                trace!(?session.attested_passkeys);

                Ok(session.deref().into())
            }
            _ => Err(OperationError::InvalidRequestState),
        }
    }

    pub fn credential_attested_passkey_remove(
        &self,
        cust: &CredentialUpdateSessionToken,
        ct: Duration,
        uuid: Uuid,
    ) -> Result<CredentialUpdateSessionStatus, OperationError> {
        let session_handle = self.get_current_session(cust, ct)?;
        let mut session = session_handle.try_lock().map_err(|_| {
            admin_error!("Session already locked, unable to proceed.");
            OperationError::InvalidState
        })?;
        trace!(?session);

        if !(matches!(session.attested_passkeys_state, CredentialState::Modifiable)
            || matches!(session.attested_passkeys_state, CredentialState::DeleteOnly))
        {
            error!("Session does not have permission to modify attested passkeys");
            return Err(OperationError::AccessDenied);
        };

        // No-op if not present
        session.attested_passkeys.remove(&uuid);

        Ok(session.deref().into())
    }

    pub fn credential_update_cancel_mfareg(
        &self,
        cust: &CredentialUpdateSessionToken,
        ct: Duration,
    ) -> Result<CredentialUpdateSessionStatus, OperationError> {
        let session_handle = self.get_current_session(cust, ct)?;
        let mut session = session_handle.try_lock().map_err(|_| {
            admin_error!("Session already locked, unable to proceed.");
            OperationError::InvalidState
        })?;
        trace!(?session);
        session.mfaregstate = MfaRegState::None;
        Ok(session.deref().into())
    }

    pub fn credential_primary_delete(
        &self,
        cust: &CredentialUpdateSessionToken,
        ct: Duration,
    ) -> Result<CredentialUpdateSessionStatus, OperationError> {
        let session_handle = self.get_current_session(cust, ct)?;
        let mut session = session_handle.try_lock().map_err(|_| {
            admin_error!("Session already locked, unable to proceed.");
            OperationError::InvalidState
        })?;
        trace!(?session);

        if !(matches!(session.primary_state, CredentialState::Modifiable)
            || matches!(session.primary_state, CredentialState::DeleteOnly))
        {
            error!("Session does not have permission to modify primary credential");
            return Err(OperationError::AccessDenied);
        };

        session.primary = None;
        Ok(session.deref().into())
    }

    // Generate password?
}

#[cfg(test)]
mod tests {
    use compact_jwt::JwsCompact;
    use std::time::Duration;

    use kanidm_proto::internal::{CUExtPortal, CredentialDetailType, PasswordFeedback};
    use kanidm_proto::v1::{AuthAllowed, AuthIssueSession, AuthMech};
    use uuid::uuid;
    use webauthn_authenticator_rs::softpasskey::SoftPasskey;
    use webauthn_authenticator_rs::softtoken::{self, SoftToken};
    use webauthn_authenticator_rs::{AuthenticatorBackend, WebauthnAuthenticator};
    use webauthn_rs::prelude::AttestationCaListBuilder;

    use super::{
        CredentialState, CredentialUpdateSessionStatus, CredentialUpdateSessionStatusWarnings,
        CredentialUpdateSessionToken, InitCredentialUpdateEvent, InitCredentialUpdateIntentEvent,
        MfaRegStateStatus, MAXIMUM_CRED_UPDATE_TTL, MAXIMUM_INTENT_TTL, MINIMUM_INTENT_TTL,
    };
    use crate::credential::totp::Totp;
    use crate::event::CreateEvent;
    use crate::idm::audit::AuditEvent;
    use crate::idm::delayed::DelayedAction;
    use crate::idm::event::{AuthEvent, AuthResult, RegenerateRadiusSecretEvent};
    use crate::idm::server::{IdmServer, IdmServerCredUpdateTransaction, IdmServerDelayed};
    use crate::idm::AuthState;
    use crate::prelude::*;
    use crate::utils::password_from_random_len;
    use crate::value::CredentialType;

    const TEST_CURRENT_TIME: u64 = 6000;
    const TESTPERSON_UUID: Uuid = uuid!("cf231fea-1a8f-4410-a520-fd9b1a379c86");

    #[idm_test]
    async fn test_idm_credential_update_session_init(
        idms: &IdmServer,
        _idms_delayed: &mut IdmServerDelayed,
    ) {
        let ct = Duration::from_secs(TEST_CURRENT_TIME);
        let mut idms_prox_write = idms.proxy_write(ct).await;

        let testaccount_uuid = Uuid::new_v4();

        let e1 = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::Class, EntryClass::ServiceAccount.to_value()),
            (Attribute::Name, Value::new_iname("user_account_only")),
            (Attribute::Uuid, Value::Uuid(testaccount_uuid)),
            (Attribute::Description, Value::new_utf8s("testaccount")),
            (Attribute::DisplayName, Value::new_utf8s("testaccount"))
        );

        let e2 = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::Class, EntryClass::Person.to_value()),
            (Attribute::Name, Value::new_iname("testperson")),
            (Attribute::Uuid, Value::Uuid(TESTPERSON_UUID)),
            (Attribute::Description, Value::new_utf8s("testperson")),
            (Attribute::DisplayName, Value::new_utf8s("testperson"))
        );

        let ce = CreateEvent::new_internal(vec![e1, e2]);
        let cr = idms_prox_write.qs_write.create(&ce);
        assert!(cr.is_ok());

        let testaccount = idms_prox_write
            .qs_write
            .internal_search_uuid(testaccount_uuid)
            .expect("failed");

        let testperson = idms_prox_write
            .qs_write
            .internal_search_uuid(TESTPERSON_UUID)
            .expect("failed");

        let idm_admin = idms_prox_write
            .qs_write
            .internal_search_uuid(UUID_IDM_ADMIN)
            .expect("failed");

        // user without permission - fail
        // - accounts don't have self-write permission.

        let cur = idms_prox_write.init_credential_update(
            &InitCredentialUpdateEvent::new_impersonate_entry(testaccount),
            ct,
        );

        assert!(matches!(cur, Err(OperationError::NotAuthorised)));

        // user with permission - success

        let cur = idms_prox_write.init_credential_update(
            &InitCredentialUpdateEvent::new_impersonate_entry(testperson),
            ct,
        );

        assert!(cur.is_ok());

        // create intent token without permission - fail

        // create intent token with permission - success

        let cur = idms_prox_write.init_credential_update_intent(
            &InitCredentialUpdateIntentEvent::new_impersonate_entry(
                idm_admin,
                TESTPERSON_UUID,
                MINIMUM_INTENT_TTL,
            ),
            ct,
        );

        assert!(cur.is_ok());
        let intent_tok = cur.expect("Failed to create intent token!");

        // exchange intent token - invalid - fail
        // Expired
        let cur = idms_prox_write
            .exchange_intent_credential_update(intent_tok.clone(), ct + MINIMUM_INTENT_TTL);

        assert!(matches!(cur, Err(OperationError::SessionExpired)));

        let cur = idms_prox_write
            .exchange_intent_credential_update(intent_tok.clone(), ct + MAXIMUM_INTENT_TTL);

        assert!(matches!(cur, Err(OperationError::SessionExpired)));

        // exchange intent token - success
        let (cust_a, _c_status) = idms_prox_write
            .exchange_intent_credential_update(intent_tok.clone(), ct)
            .unwrap();

        // Session in progress - This will succeed and then block the former success from
        // committing.
        let (cust_b, _c_status) = idms_prox_write
            .exchange_intent_credential_update(intent_tok, ct + Duration::from_secs(1))
            .unwrap();

        let cur = idms_prox_write.commit_credential_update(&cust_a, ct);

        // Fails as the txn was orphaned.
        trace!(?cur);
        assert!(cur.is_err());

        // Success - this was the second use of the token and is valid.
        let _ = idms_prox_write.commit_credential_update(&cust_b, ct);

        idms_prox_write.commit().expect("Failed to commit txn");
    }

    async fn setup_test_session(
        idms: &IdmServer,
        ct: Duration,
    ) -> (CredentialUpdateSessionToken, CredentialUpdateSessionStatus) {
        let mut idms_prox_write = idms.proxy_write(ct).await;

        // Remove the default all persons policy, it interfers with our test.
        let modlist = ModifyList::new_purge(Attribute::CredentialTypeMinimum);
        idms_prox_write
            .qs_write
            .internal_modify_uuid(UUID_IDM_ALL_PERSONS, &modlist)
            .expect("Unable to change default session exp");

        let e2 = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::Class, EntryClass::Person.to_value()),
            (Attribute::Name, Value::new_iname("testperson")),
            (Attribute::Uuid, Value::Uuid(TESTPERSON_UUID)),
            (Attribute::Description, Value::new_utf8s("testperson")),
            (Attribute::DisplayName, Value::new_utf8s("testperson"))
        );

        let ce = CreateEvent::new_internal(vec![e2]);
        let cr = idms_prox_write.qs_write.create(&ce);
        assert!(cr.is_ok());

        let testperson = idms_prox_write
            .qs_write
            .internal_search_uuid(TESTPERSON_UUID)
            .expect("failed");

        // Setup the radius creds to ensure we don't use them anywhere else.
        let rrse = RegenerateRadiusSecretEvent::new_internal(TESTPERSON_UUID);

        let _ = idms_prox_write
            .regenerate_radius_secret(&rrse)
            .expect("Failed to reset radius credential 1");

        let cur = idms_prox_write.init_credential_update(
            &InitCredentialUpdateEvent::new_impersonate_entry(testperson),
            ct,
        );

        idms_prox_write.commit().expect("Failed to commit txn");

        cur.expect("Failed to start update")
    }

    async fn renew_test_session(
        idms: &IdmServer,
        ct: Duration,
    ) -> (CredentialUpdateSessionToken, CredentialUpdateSessionStatus) {
        let mut idms_prox_write = idms.proxy_write(ct).await;

        let testperson = idms_prox_write
            .qs_write
            .internal_search_uuid(TESTPERSON_UUID)
            .expect("failed");

        let cur = idms_prox_write.init_credential_update(
            &InitCredentialUpdateEvent::new_impersonate_entry(testperson),
            ct,
        );

        trace!(renew_test_session_result = ?cur);

        idms_prox_write.commit().expect("Failed to commit txn");

        cur.expect("Failed to start update")
    }

    async fn commit_session(idms: &IdmServer, ct: Duration, cust: CredentialUpdateSessionToken) {
        let mut idms_prox_write = idms.proxy_write(ct).await;

        idms_prox_write
            .commit_credential_update(&cust, ct)
            .expect("Failed to commit credential update.");

        idms_prox_write.commit().expect("Failed to commit txn");
    }

    async fn check_testperson_password(
        idms: &IdmServer,
        idms_delayed: &mut IdmServerDelayed,
        pw: &str,
        ct: Duration,
    ) -> Option<JwsCompact> {
        let mut idms_auth = idms.auth().await;

        let auth_init = AuthEvent::named_init("testperson");

        let r1 = idms_auth
            .auth(&auth_init, ct, Source::Internal.into())
            .await;
        let ar = r1.unwrap();
        let AuthResult { sessionid, state } = ar;

        if !matches!(state, AuthState::Choose(_)) {
            debug!("Can't proceed - {:?}", state);
            return None;
        };

        let auth_begin = AuthEvent::begin_mech(sessionid, AuthMech::Password);

        let r2 = idms_auth
            .auth(&auth_begin, ct, Source::Internal.into())
            .await;
        let ar = r2.unwrap();
        let AuthResult { sessionid, state } = ar;

        assert!(matches!(state, AuthState::Continue(_)));

        let pw_step = AuthEvent::cred_step_password(sessionid, pw);

        // Expect success
        let r2 = idms_auth.auth(&pw_step, ct, Source::Internal.into()).await;
        debug!("r2 ==> {:?}", r2);
        idms_auth.commit().expect("Must not fail");

        match r2 {
            Ok(AuthResult {
                sessionid: _,
                state: AuthState::Success(token, AuthIssueSession::Token),
            }) => {
                // Process the auth session
                let da = idms_delayed.try_recv().expect("invalid");
                assert!(matches!(da, DelayedAction::AuthSessionRecord(_)));

                Some(token)
            }
            _ => None,
        }
    }

    async fn check_testperson_password_totp(
        idms: &IdmServer,
        idms_delayed: &mut IdmServerDelayed,
        pw: &str,
        token: &Totp,
        ct: Duration,
    ) -> Option<JwsCompact> {
        let mut idms_auth = idms.auth().await;

        let auth_init = AuthEvent::named_init("testperson");

        let r1 = idms_auth
            .auth(&auth_init, ct, Source::Internal.into())
            .await;
        let ar = r1.unwrap();
        let AuthResult { sessionid, state } = ar;

        if !matches!(state, AuthState::Choose(_)) {
            debug!("Can't proceed - {:?}", state);
            return None;
        };

        let auth_begin = AuthEvent::begin_mech(sessionid, AuthMech::PasswordMfa);

        let r2 = idms_auth
            .auth(&auth_begin, ct, Source::Internal.into())
            .await;
        let ar = r2.unwrap();
        let AuthResult { sessionid, state } = ar;

        assert!(matches!(state, AuthState::Continue(_)));

        let totp = token
            .do_totp_duration_from_epoch(&ct)
            .expect("Failed to perform totp step");

        let totp_step = AuthEvent::cred_step_totp(sessionid, totp);
        let r2 = idms_auth
            .auth(&totp_step, ct, Source::Internal.into())
            .await;
        let ar = r2.unwrap();
        let AuthResult { sessionid, state } = ar;

        assert!(matches!(state, AuthState::Continue(_)));

        let pw_step = AuthEvent::cred_step_password(sessionid, pw);

        // Expect success
        let r3 = idms_auth.auth(&pw_step, ct, Source::Internal.into()).await;
        debug!("r3 ==> {:?}", r3);
        idms_auth.commit().expect("Must not fail");

        match r3 {
            Ok(AuthResult {
                sessionid: _,
                state: AuthState::Success(token, AuthIssueSession::Token),
            }) => {
                // Process the auth session
                let da = idms_delayed.try_recv().expect("invalid");
                assert!(matches!(da, DelayedAction::AuthSessionRecord(_)));
                Some(token)
            }
            _ => None,
        }
    }

    async fn check_testperson_password_backup_code(
        idms: &IdmServer,
        idms_delayed: &mut IdmServerDelayed,
        pw: &str,
        code: &str,
        ct: Duration,
    ) -> Option<JwsCompact> {
        let mut idms_auth = idms.auth().await;

        let auth_init = AuthEvent::named_init("testperson");

        let r1 = idms_auth
            .auth(&auth_init, ct, Source::Internal.into())
            .await;
        let ar = r1.unwrap();
        let AuthResult { sessionid, state } = ar;

        if !matches!(state, AuthState::Choose(_)) {
            debug!("Can't proceed - {:?}", state);
            return None;
        };

        let auth_begin = AuthEvent::begin_mech(sessionid, AuthMech::PasswordMfa);

        let r2 = idms_auth
            .auth(&auth_begin, ct, Source::Internal.into())
            .await;
        let ar = r2.unwrap();
        let AuthResult { sessionid, state } = ar;

        assert!(matches!(state, AuthState::Continue(_)));

        let code_step = AuthEvent::cred_step_backup_code(sessionid, code);
        let r2 = idms_auth
            .auth(&code_step, ct, Source::Internal.into())
            .await;
        let ar = r2.unwrap();
        let AuthResult { sessionid, state } = ar;

        assert!(matches!(state, AuthState::Continue(_)));

        let pw_step = AuthEvent::cred_step_password(sessionid, pw);

        // Expect success
        let r3 = idms_auth.auth(&pw_step, ct, Source::Internal.into()).await;
        debug!("r3 ==> {:?}", r3);
        idms_auth.commit().expect("Must not fail");

        match r3 {
            Ok(AuthResult {
                sessionid: _,
                state: AuthState::Success(token, AuthIssueSession::Token),
            }) => {
                // There now should be a backup code invalidation present
                let da = idms_delayed.try_recv().expect("invalid");
                assert!(matches!(da, DelayedAction::BackupCodeRemoval(_)));
                let r = idms.delayed_action(ct, da).await;
                assert!(r.is_ok());

                // Process the auth session
                let da = idms_delayed.try_recv().expect("invalid");
                assert!(matches!(da, DelayedAction::AuthSessionRecord(_)));
                Some(token)
            }
            _ => None,
        }
    }

    async fn check_testperson_passkey<T: AuthenticatorBackend>(
        idms: &IdmServer,
        idms_delayed: &mut IdmServerDelayed,
        wa: &mut WebauthnAuthenticator<T>,
        origin: Url,
        ct: Duration,
    ) -> Option<JwsCompact> {
        let mut idms_auth = idms.auth().await;

        let auth_init = AuthEvent::named_init("testperson");

        let r1 = idms_auth
            .auth(&auth_init, ct, Source::Internal.into())
            .await;
        let ar = r1.unwrap();
        let AuthResult { sessionid, state } = ar;

        if !matches!(state, AuthState::Choose(_)) {
            debug!("Can't proceed - {:?}", state);
            return None;
        };

        let auth_begin = AuthEvent::begin_mech(sessionid, AuthMech::Passkey);

        let r2 = idms_auth
            .auth(&auth_begin, ct, Source::Internal.into())
            .await;
        let ar = r2.unwrap();
        let AuthResult { sessionid, state } = ar;

        trace!(?state);

        let rcr = match state {
            AuthState::Continue(mut allowed) => match allowed.pop() {
                Some(AuthAllowed::Passkey(rcr)) => rcr,
                _ => unreachable!(),
            },
            _ => unreachable!(),
        };

        trace!(?rcr);

        let resp = wa
            .do_authentication(origin, rcr)
            .expect("failed to use softtoken to authenticate");

        let passkey_step = AuthEvent::cred_step_passkey(sessionid, resp);

        let r3 = idms_auth
            .auth(&passkey_step, ct, Source::Internal.into())
            .await;
        debug!("r3 ==> {:?}", r3);
        idms_auth.commit().expect("Must not fail");

        match r3 {
            Ok(AuthResult {
                sessionid: _,
                state: AuthState::Success(token, AuthIssueSession::Token),
            }) => {
                // Process the webauthn update
                let da = idms_delayed.try_recv().expect("invalid");
                assert!(matches!(da, DelayedAction::WebauthnCounterIncrement(_)));
                let r = idms.delayed_action(ct, da).await;
                assert!(r.is_ok());

                // Process the auth session
                let da = idms_delayed.try_recv().expect("invalid");
                assert!(matches!(da, DelayedAction::AuthSessionRecord(_)));

                Some(token)
            }
            _ => None,
        }
    }

    #[idm_test]
    async fn test_idm_credential_update_session_cleanup(
        idms: &IdmServer,
        _idms_delayed: &mut IdmServerDelayed,
    ) {
        let ct = Duration::from_secs(TEST_CURRENT_TIME);
        let (cust, _) = setup_test_session(idms, ct).await;

        let cutxn = idms.cred_update_transaction().await;
        // The session exists
        let c_status = cutxn.credential_update_status(&cust, ct);
        assert!(c_status.is_ok());
        drop(cutxn);

        // Making a new session is what triggers the clean of old sessions.
        let (_cust, _) =
            renew_test_session(idms, ct + MAXIMUM_CRED_UPDATE_TTL + Duration::from_secs(1)).await;

        let cutxn = idms.cred_update_transaction().await;

        // Now fake going back in time .... allows the tokne to decrypt, but the session
        // is gone anyway!
        let c_status = cutxn
            .credential_update_status(&cust, ct)
            .expect_err("Session is still valid!");
        assert!(matches!(c_status, OperationError::InvalidState));
    }

    #[idm_test]
    async fn test_idm_credential_update_onboarding_create_new_pw(
        idms: &IdmServer,
        idms_delayed: &mut IdmServerDelayed,
    ) {
        let test_pw = "fo3EitierohF9AelaNgiem0Ei6vup4equo1Oogeevaetehah8Tobeengae3Ci0ooh0uki";
        let ct = Duration::from_secs(TEST_CURRENT_TIME);

        let (cust, _) = setup_test_session(idms, ct).await;

        let cutxn = idms.cred_update_transaction().await;

        // Get the credential status - this should tell
        // us the details of the credentials, as well as
        // if they are ready and valid to commit?
        let c_status = cutxn
            .credential_update_status(&cust, ct)
            .expect("Failed to get the current session status.");

        trace!(?c_status);

        assert!(c_status.primary.is_none());

        // Test initially creating a credential.
        //   - pw first
        let c_status = cutxn
            .credential_primary_set_password(&cust, ct, test_pw)
            .expect("Failed to update the primary cred password");

        assert!(c_status.can_commit);

        drop(cutxn);
        commit_session(idms, ct, cust).await;

        // Check it works!
        assert!(check_testperson_password(idms, idms_delayed, test_pw, ct)
            .await
            .is_some());

        // Test deleting the pw
        let (cust, _) = renew_test_session(idms, ct).await;
        let cutxn = idms.cred_update_transaction().await;

        let c_status = cutxn
            .credential_update_status(&cust, ct)
            .expect("Failed to get the current session status.");
        trace!(?c_status);
        assert!(c_status.primary.is_some());

        let c_status = cutxn
            .credential_primary_delete(&cust, ct)
            .expect("Failed to delete the primary cred");
        trace!(?c_status);
        assert!(c_status.primary.is_none());

        drop(cutxn);
        commit_session(idms, ct, cust).await;

        // Must fail now!
        assert!(check_testperson_password(idms, idms_delayed, test_pw, ct)
            .await
            .is_none());
    }

    #[idm_test]
    async fn test_idm_credential_update_password_quality_checks(
        idms: &IdmServer,
        _idms_delayed: &mut IdmServerDelayed,
    ) {
        let ct = Duration::from_secs(TEST_CURRENT_TIME);
        let (cust, _) = setup_test_session(idms, ct).await;

        // Get the radius pw

        let mut r_txn = idms.proxy_read().await;

        let radius_secret = r_txn
            .qs_read
            .internal_search_uuid(TESTPERSON_UUID)
            .expect("No such entry")
            .get_ava_single_secret(Attribute::RadiusSecret)
            .expect("No radius secret found")
            .to_string();

        drop(r_txn);

        let cutxn = idms.cred_update_transaction().await;

        // Get the credential status - this should tell
        // us the details of the credentials, as well as
        // if they are ready and valid to commit?
        let c_status = cutxn
            .credential_update_status(&cust, ct)
            .expect("Failed to get the current session status.");

        trace!(?c_status);

        assert!(c_status.primary.is_none());

        // Test initially creating a credential.
        //   - pw first

        let err = cutxn
            .credential_primary_set_password(&cust, ct, "password")
            .unwrap_err();
        trace!(?err);
        assert!(match err {
            OperationError::PasswordQuality(details)
                if details == vec!(PasswordFeedback::TooShort(PW_MIN_LENGTH),) =>
                true,
            _ => false,
        });

        let err = cutxn
            .credential_primary_set_password(&cust, ct, "password1234")
            .unwrap_err();
        trace!(?err);
        assert!(match err {
            OperationError::PasswordQuality(details)
                if details
                    == vec!(
                        PasswordFeedback::AddAnotherWordOrTwo,
                        PasswordFeedback::ThisIsACommonPassword,
                    ) =>
                true,
            _ => false,
        });

        let err = cutxn
            .credential_primary_set_password(&cust, ct, &radius_secret)
            .unwrap_err();
        trace!(?err);
        assert!(match err {
            OperationError::PasswordQuality(details)
                if details == vec!(PasswordFeedback::DontReusePasswords,) =>
                true,
            _ => false,
        });

        let err = cutxn
            .credential_primary_set_password(&cust, ct, "testperson2023")
            .unwrap_err();
        trace!(?err);
        assert!(match err {
            OperationError::PasswordQuality(details)
                if details
                    == vec!(
                        PasswordFeedback::NamesAndSurnamesByThemselvesAreEasyToGuess,
                        PasswordFeedback::AvoidDatesAndYearsThatAreAssociatedWithYou,
                    ) =>
                true,
            _ => false,
        });

        let err = cutxn
            .credential_primary_set_password(
                &cust,
                ct,
                "demo_badlist_shohfie3aeci2oobur0aru9uushah6EiPi2woh4hohngoighaiRuepieN3ongoo1",
            )
            .unwrap_err();
        trace!(?err);
        assert!(match err {
            OperationError::PasswordQuality(details)
                if details == vec!(PasswordFeedback::BadListed) =>
                true,
            _ => false,
        });

        assert!(c_status.can_commit);

        drop(cutxn);
    }

    #[idm_test]
    async fn test_idm_credential_update_password_min_length_account_policy(
        idms: &IdmServer,
        _idms_delayed: &mut IdmServerDelayed,
    ) {
        let ct = Duration::from_secs(TEST_CURRENT_TIME);

        // Set the account policy min pw length
        let test_pw_min_length = PW_MIN_LENGTH * 2;

        let mut idms_prox_write = idms.proxy_write(ct).await;

        let modlist = ModifyList::new_purge_and_set(
            Attribute::AuthPasswordMinimumLength,
            Value::Uint32(test_pw_min_length),
        );
        idms_prox_write
            .qs_write
            .internal_modify_uuid(UUID_IDM_ALL_ACCOUNTS, &modlist)
            .expect("Unable to change default session exp");

        assert!(idms_prox_write.commit().is_ok());
        // This now will affect all accounts for the next cred update.

        let (cust, _) = setup_test_session(idms, ct).await;

        let cutxn = idms.cred_update_transaction().await;

        // Get the credential status - this should tell
        // us the details of the credentials, as well as
        // if they are ready and valid to commit?
        let c_status = cutxn
            .credential_update_status(&cust, ct)
            .expect("Failed to get the current session status.");

        trace!(?c_status);

        assert!(c_status.primary.is_none());

        // Test initially creating a credential.
        //   - pw first
        let pw = password_from_random_len(8);
        let err = cutxn
            .credential_primary_set_password(&cust, ct, &pw)
            .unwrap_err();
        trace!(?err);
        assert!(match err {
            OperationError::PasswordQuality(details)
                if details == vec!(PasswordFeedback::TooShort(test_pw_min_length),) =>
                true,
            _ => false,
        });

        // Test pw len of len minus 1
        let pw = password_from_random_len(test_pw_min_length - 1);
        let err = cutxn
            .credential_primary_set_password(&cust, ct, &pw)
            .unwrap_err();
        trace!(?err);
        assert!(match err {
            OperationError::PasswordQuality(details)
                if details == vec!(PasswordFeedback::TooShort(test_pw_min_length),) =>
                true,
            _ => false,
        });

        // Test pw len of exact len
        let pw = password_from_random_len(test_pw_min_length);
        let c_status = cutxn
            .credential_primary_set_password(&cust, ct, &pw)
            .expect("Failed to update the primary cred password");

        assert!(c_status.can_commit);

        drop(cutxn);
        commit_session(idms, ct, cust).await;
    }

    // Test set of primary account password
    //    - fail pw quality checks etc
    //    - set correctly.

    // - setup TOTP
    #[idm_test]
    async fn test_idm_credential_update_onboarding_create_new_mfa_totp_basic(
        idms: &IdmServer,
        idms_delayed: &mut IdmServerDelayed,
    ) {
        let test_pw = "fo3EitierohF9AelaNgiem0Ei6vup4equo1Oogeevaetehah8Tobeengae3Ci0ooh0uki";
        let ct = Duration::from_secs(TEST_CURRENT_TIME);

        let (cust, _) = setup_test_session(idms, ct).await;
        let cutxn = idms.cred_update_transaction().await;

        // Setup the PW
        let c_status = cutxn
            .credential_primary_set_password(&cust, ct, test_pw)
            .expect("Failed to update the primary cred password");

        // Since it's pw only.
        assert!(c_status.can_commit);

        //
        let c_status = cutxn
            .credential_primary_init_totp(&cust, ct)
            .expect("Failed to update the primary cred password");

        // Check the status has the token.
        let totp_token: Totp = match c_status.mfaregstate {
            MfaRegStateStatus::TotpCheck(secret) => Some(secret.try_into().unwrap()),

            _ => None,
        }
        .expect("Unable to retrieve totp token, invalid state.");

        trace!(?totp_token);
        let chal = totp_token
            .do_totp_duration_from_epoch(&ct)
            .expect("Failed to perform totp step");

        // Intentionally get it wrong.
        let c_status = cutxn
            .credential_primary_check_totp(&cust, ct, chal + 1, "totp")
            .expect("Failed to update the primary cred totp");

        assert!(matches!(
            c_status.mfaregstate,
            MfaRegStateStatus::TotpTryAgain
        ));

        let c_status = cutxn
            .credential_primary_check_totp(&cust, ct, chal, "totp")
            .expect("Failed to update the primary cred totp");

        assert!(matches!(c_status.mfaregstate, MfaRegStateStatus::None));
        assert!(match c_status.primary.as_ref().map(|c| &c.type_) {
            Some(CredentialDetailType::PasswordMfa(totp, _, 0)) => !totp.is_empty(),
            _ => false,
        });

        // Should be okay now!

        drop(cutxn);
        commit_session(idms, ct, cust).await;

        // Check it works!
        assert!(
            check_testperson_password_totp(idms, idms_delayed, test_pw, &totp_token, ct)
                .await
                .is_some()
        );
        // No need to test delete of the whole cred, we already did with pw above.

        // If we remove TOTP, show it reverts back.
        let (cust, _) = renew_test_session(idms, ct).await;
        let cutxn = idms.cred_update_transaction().await;

        let c_status = cutxn
            .credential_primary_remove_totp(&cust, ct, "totp")
            .expect("Failed to update the primary cred password");

        assert!(matches!(c_status.mfaregstate, MfaRegStateStatus::None));
        assert!(matches!(
            c_status.primary.as_ref().map(|c| &c.type_),
            Some(CredentialDetailType::Password)
        ));

        drop(cutxn);
        commit_session(idms, ct, cust).await;

        // Check it works with totp removed.
        assert!(check_testperson_password(idms, idms_delayed, test_pw, ct)
            .await
            .is_some());
    }

    // Check sha1 totp.
    #[idm_test]
    async fn test_idm_credential_update_onboarding_create_new_mfa_totp_sha1(
        idms: &IdmServer,
        idms_delayed: &mut IdmServerDelayed,
    ) {
        let test_pw = "fo3EitierohF9AelaNgiem0Ei6vup4equo1Oogeevaetehah8Tobeengae3Ci0ooh0uki";
        let ct = Duration::from_secs(TEST_CURRENT_TIME);

        let (cust, _) = setup_test_session(idms, ct).await;
        let cutxn = idms.cred_update_transaction().await;

        // Setup the PW
        let c_status = cutxn
            .credential_primary_set_password(&cust, ct, test_pw)
            .expect("Failed to update the primary cred password");

        // Since it's pw only.
        assert!(c_status.can_commit);

        //
        let c_status = cutxn
            .credential_primary_init_totp(&cust, ct)
            .expect("Failed to update the primary cred password");

        // Check the status has the token.
        let totp_token: Totp = match c_status.mfaregstate {
            MfaRegStateStatus::TotpCheck(secret) => Some(secret.try_into().unwrap()),

            _ => None,
        }
        .expect("Unable to retrieve totp token, invalid state.");

        let totp_token = totp_token.downgrade_to_legacy();

        trace!(?totp_token);
        let chal = totp_token
            .do_totp_duration_from_epoch(&ct)
            .expect("Failed to perform totp step");

        // Should getn the warn that it's sha1
        let c_status = cutxn
            .credential_primary_check_totp(&cust, ct, chal, "totp")
            .expect("Failed to update the primary cred password");

        assert!(matches!(
            c_status.mfaregstate,
            MfaRegStateStatus::TotpInvalidSha1
        ));

        // Accept it
        let c_status = cutxn
            .credential_primary_accept_sha1_totp(&cust, ct)
            .expect("Failed to update the primary cred password");

        assert!(matches!(c_status.mfaregstate, MfaRegStateStatus::None));
        assert!(match c_status.primary.as_ref().map(|c| &c.type_) {
            Some(CredentialDetailType::PasswordMfa(totp, _, 0)) => !totp.is_empty(),
            _ => false,
        });

        // Should be okay now!

        drop(cutxn);
        commit_session(idms, ct, cust).await;

        // Check it works!
        assert!(
            check_testperson_password_totp(idms, idms_delayed, test_pw, &totp_token, ct)
                .await
                .is_some()
        );
        // No need to test delete, we already did with pw above.
    }

    #[idm_test]
    async fn test_idm_credential_update_onboarding_create_new_mfa_totp_backup_codes(
        idms: &IdmServer,
        idms_delayed: &mut IdmServerDelayed,
    ) {
        let test_pw = "fo3EitierohF9AelaNgiem0Ei6vup4equo1Oogeevaetehah8Tobeengae3Ci0ooh0uki";
        let ct = Duration::from_secs(TEST_CURRENT_TIME);

        let (cust, _) = setup_test_session(idms, ct).await;
        let cutxn = idms.cred_update_transaction().await;

        // Setup the PW
        let _c_status = cutxn
            .credential_primary_set_password(&cust, ct, test_pw)
            .expect("Failed to update the primary cred password");

        // Backup codes are refused to be added because we don't have mfa yet.
        assert!(matches!(
            cutxn.credential_primary_init_backup_codes(&cust, ct),
            Err(OperationError::InvalidState)
        ));

        let c_status = cutxn
            .credential_primary_init_totp(&cust, ct)
            .expect("Failed to update the primary cred password");

        let totp_token: Totp = match c_status.mfaregstate {
            MfaRegStateStatus::TotpCheck(secret) => Some(secret.try_into().unwrap()),
            _ => None,
        }
        .expect("Unable to retrieve totp token, invalid state.");

        trace!(?totp_token);
        let chal = totp_token
            .do_totp_duration_from_epoch(&ct)
            .expect("Failed to perform totp step");

        let c_status = cutxn
            .credential_primary_check_totp(&cust, ct, chal, "totp")
            .expect("Failed to update the primary cred totp");

        assert!(matches!(c_status.mfaregstate, MfaRegStateStatus::None));
        assert!(match c_status.primary.as_ref().map(|c| &c.type_) {
            Some(CredentialDetailType::PasswordMfa(totp, _, 0)) => !totp.is_empty(),
            _ => false,
        });

        // Now good to go, we need to now add our backup codes.
        // What's the right way to get these back?
        let c_status = cutxn
            .credential_primary_init_backup_codes(&cust, ct)
            .expect("Failed to update the primary cred password");

        let codes = match c_status.mfaregstate {
            MfaRegStateStatus::BackupCodes(codes) => Some(codes),
            _ => None,
        }
        .expect("Unable to retrieve backupcodes, invalid state.");

        // Should error because the number is not 0
        debug!("{:?}", c_status.primary.as_ref().map(|c| &c.type_));
        assert!(match c_status.primary.as_ref().map(|c| &c.type_) {
            Some(CredentialDetailType::PasswordMfa(totp, _, 8)) => !totp.is_empty(),
            _ => false,
        });

        // Should be okay now!
        drop(cutxn);
        commit_session(idms, ct, cust).await;

        let backup_code = codes.iter().next().expect("No codes available");

        // Check it works!
        assert!(check_testperson_password_backup_code(
            idms,
            idms_delayed,
            test_pw,
            backup_code,
            ct
        )
        .await
        .is_some());

        // Renew to start the next steps
        let (cust, _) = renew_test_session(idms, ct).await;
        let cutxn = idms.cred_update_transaction().await;

        // Only 7 codes left.
        let c_status = cutxn
            .credential_update_status(&cust, ct)
            .expect("Failed to get the current session status.");

        assert!(match c_status.primary.as_ref().map(|c| &c.type_) {
            Some(CredentialDetailType::PasswordMfa(totp, _, 7)) => !totp.is_empty(),
            _ => false,
        });

        // If we remove codes, it leaves totp.
        let c_status = cutxn
            .credential_primary_remove_backup_codes(&cust, ct)
            .expect("Failed to update the primary cred password");

        assert!(matches!(c_status.mfaregstate, MfaRegStateStatus::None));
        assert!(match c_status.primary.as_ref().map(|c| &c.type_) {
            Some(CredentialDetailType::PasswordMfa(totp, _, 0)) => !totp.is_empty(),
            _ => false,
        });

        // Re-add the codes.
        let c_status = cutxn
            .credential_primary_init_backup_codes(&cust, ct)
            .expect("Failed to update the primary cred password");

        assert!(matches!(
            c_status.mfaregstate,
            MfaRegStateStatus::BackupCodes(_)
        ));
        assert!(match c_status.primary.as_ref().map(|c| &c.type_) {
            Some(CredentialDetailType::PasswordMfa(totp, _, 8)) => !totp.is_empty(),
            _ => false,
        });

        // If we remove totp, it removes codes.
        let c_status = cutxn
            .credential_primary_remove_totp(&cust, ct, "totp")
            .expect("Failed to update the primary cred password");

        assert!(matches!(c_status.mfaregstate, MfaRegStateStatus::None));
        assert!(matches!(
            c_status.primary.as_ref().map(|c| &c.type_),
            Some(CredentialDetailType::Password)
        ));

        drop(cutxn);
        commit_session(idms, ct, cust).await;
    }

    #[idm_test]
    async fn test_idm_credential_update_onboarding_cancel_inprogress_totp(
        idms: &IdmServer,
        idms_delayed: &mut IdmServerDelayed,
    ) {
        let test_pw = "fo3EitierohF9AelaNgiem0Ei6vup4equo1Oogeevaetehah8Tobeengae3Ci0ooh0uki";
        let ct = Duration::from_secs(TEST_CURRENT_TIME);

        let (cust, _) = setup_test_session(idms, ct).await;
        let cutxn = idms.cred_update_transaction().await;

        // Setup the PW
        let c_status = cutxn
            .credential_primary_set_password(&cust, ct, test_pw)
            .expect("Failed to update the primary cred password");

        // Since it's pw only.
        assert!(c_status.can_commit);

        //
        let c_status = cutxn
            .credential_primary_init_totp(&cust, ct)
            .expect("Failed to update the primary cred totp");

        // Check the status has the token.
        assert!(c_status.can_commit);
        assert!(matches!(
            c_status.mfaregstate,
            MfaRegStateStatus::TotpCheck(_)
        ));

        let c_status = cutxn
            .credential_update_cancel_mfareg(&cust, ct)
            .expect("Failed to cancel in-flight totp change");

        assert!(matches!(c_status.mfaregstate, MfaRegStateStatus::None));
        assert!(c_status.can_commit);

        drop(cutxn);
        commit_session(idms, ct, cust).await;

        // It's pw only, since we canceled TOTP
        assert!(check_testperson_password(idms, idms_delayed, test_pw, ct)
            .await
            .is_some());
    }

    // Primary cred must be pw or pwmfa

    // - setup webauthn
    // - remove webauthn
    // - test multiple webauthn token.

    async fn create_new_passkey(
        ct: Duration,
        origin: &Url,
        cutxn: &IdmServerCredUpdateTransaction<'_>,
        cust: &CredentialUpdateSessionToken,
        wa: &mut WebauthnAuthenticator<SoftPasskey>,
    ) -> CredentialUpdateSessionStatus {
        // Start the registration
        let c_status = cutxn
            .credential_passkey_init(cust, ct)
            .expect("Failed to initiate passkey registration");

        assert!(c_status.passkeys.is_empty());

        let passkey_chal = match c_status.mfaregstate {
            MfaRegStateStatus::Passkey(c) => Some(c),
            _ => None,
        }
        .expect("Unable to access passkey challenge, invalid state");

        let passkey_resp = wa
            .do_registration(origin.clone(), passkey_chal)
            .expect("Failed to create soft passkey");

        // Finish the registration
        let label = "softtoken".to_string();
        let c_status = cutxn
            .credential_passkey_finish(cust, ct, label, &passkey_resp)
            .expect("Failed to initiate passkey registration");

        assert!(matches!(c_status.mfaregstate, MfaRegStateStatus::None));
        assert!(matches!(
            // Should be none.
            c_status.primary.as_ref(),
            None
        ));

        // Check we have the passkey
        trace!(?c_status);
        assert!(c_status.passkeys.len() == 1);

        c_status
    }

    #[idm_test]
    async fn test_idm_credential_update_onboarding_create_new_passkey(
        idms: &IdmServer,
        idms_delayed: &mut IdmServerDelayed,
    ) {
        let ct = Duration::from_secs(TEST_CURRENT_TIME);

        let (cust, _) = setup_test_session(idms, ct).await;
        let cutxn = idms.cred_update_transaction().await;
        let origin = cutxn.get_origin().clone();

        // Create a soft passkey
        let mut wa = WebauthnAuthenticator::new(SoftPasskey::new(true));

        let c_status = create_new_passkey(ct, &origin, &cutxn, &cust, &mut wa).await;

        // Get the UUID of the passkey here.
        let pk_uuid = c_status.passkeys.first().map(|pkd| pkd.uuid).unwrap();

        // Commit
        drop(cutxn);
        commit_session(idms, ct, cust).await;

        // Do an auth test
        assert!(
            check_testperson_passkey(idms, idms_delayed, &mut wa, origin.clone(), ct)
                .await
                .is_some()
        );

        // Now test removing the token
        let (cust, _) = renew_test_session(idms, ct).await;
        let cutxn = idms.cred_update_transaction().await;

        trace!(?c_status);
        assert!(c_status.primary.is_none());
        assert!(c_status.passkeys.len() == 1);

        let c_status = cutxn
            .credential_passkey_remove(&cust, ct, pk_uuid)
            .expect("Failed to delete the passkey");

        trace!(?c_status);
        assert!(c_status.primary.is_none());
        assert!(c_status.passkeys.is_empty());

        drop(cutxn);
        commit_session(idms, ct, cust).await;

        // Must fail now!
        assert!(
            check_testperson_passkey(idms, idms_delayed, &mut wa, origin, ct)
                .await
                .is_none()
        );
    }

    #[idm_test]
    async fn test_idm_credential_update_access_denied(
        idms: &IdmServer,
        _idms_delayed: &mut IdmServerDelayed,
    ) {
        // Test that if access is denied for a synced account, that the actual action to update
        // the credentials is always denied.

        let ct = Duration::from_secs(TEST_CURRENT_TIME);

        let mut idms_prox_write = idms.proxy_write(ct).await;

        let sync_uuid = Uuid::new_v4();

        let e1 = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::SyncAccount.to_value()),
            (Attribute::Name, Value::new_iname("test_scim_sync")),
            (Attribute::Uuid, Value::Uuid(sync_uuid)),
            (
                Attribute::Description,
                Value::new_utf8s("A test sync agreement")
            )
        );

        let e2 = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::SyncObject.to_value()),
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::Class, EntryClass::Person.to_value()),
            (Attribute::SyncParentUuid, Value::Refer(sync_uuid)),
            (Attribute::Name, Value::new_iname("testperson")),
            (Attribute::Uuid, Value::Uuid(TESTPERSON_UUID)),
            (Attribute::Description, Value::new_utf8s("testperson")),
            (Attribute::DisplayName, Value::new_utf8s("testperson"))
        );

        let ce = CreateEvent::new_internal(vec![e1, e2]);
        let cr = idms_prox_write.qs_write.create(&ce);
        assert!(cr.is_ok());

        let testperson = idms_prox_write
            .qs_write
            .internal_search_uuid(TESTPERSON_UUID)
            .expect("failed");

        let cur = idms_prox_write.init_credential_update(
            &InitCredentialUpdateEvent::new_impersonate_entry(testperson),
            ct,
        );

        idms_prox_write.commit().expect("Failed to commit txn");

        let (cust, custatus) = cur.expect("Failed to start update");

        trace!(?custatus);

        // Destructure to force us to update this test if we change this
        // structure at all.
        let CredentialUpdateSessionStatus {
            spn: _,
            displayname: _,
            ext_cred_portal,
            mfaregstate: _,
            can_commit: _,
            warnings: _,
            primary: _,
            primary_state,
            passkeys: _,
            passkeys_state,
            attested_passkeys: _,
            attested_passkeys_state,
            attested_passkeys_allowed_devices: _,
        } = custatus;

        assert!(matches!(ext_cred_portal, CUExtPortal::Hidden));
        assert!(matches!(primary_state, CredentialState::AccessDeny));
        assert!(matches!(passkeys_state, CredentialState::AccessDeny));
        assert!(matches!(
            attested_passkeys_state,
            CredentialState::AccessDeny
        ));

        let cutxn = idms.cred_update_transaction().await;

        // let origin = cutxn.get_origin().clone();

        // Test that any of the primary or passkey update methods fail with access denied.

        // credential_primary_set_password
        let err = cutxn
            .credential_primary_set_password(&cust, ct, "password")
            .unwrap_err();
        assert!(matches!(err, OperationError::AccessDenied));

        // credential_primary_init_totp
        let err = cutxn.credential_primary_init_totp(&cust, ct).unwrap_err();
        assert!(matches!(err, OperationError::AccessDenied));

        // credential_primary_check_totp
        let err = cutxn
            .credential_primary_check_totp(&cust, ct, 0, "totp")
            .unwrap_err();
        assert!(matches!(err, OperationError::AccessDenied));

        // credential_primary_accept_sha1_totp
        let err = cutxn
            .credential_primary_accept_sha1_totp(&cust, ct)
            .unwrap_err();
        assert!(matches!(err, OperationError::AccessDenied));

        // credential_primary_remove_totp
        let err = cutxn
            .credential_primary_remove_totp(&cust, ct, "totp")
            .unwrap_err();
        assert!(matches!(err, OperationError::AccessDenied));

        // credential_primary_init_backup_codes
        let err = cutxn
            .credential_primary_init_backup_codes(&cust, ct)
            .unwrap_err();
        assert!(matches!(err, OperationError::AccessDenied));

        // credential_primary_remove_backup_codes
        let err = cutxn
            .credential_primary_remove_backup_codes(&cust, ct)
            .unwrap_err();
        assert!(matches!(err, OperationError::AccessDenied));

        // credential_primary_delete
        let err = cutxn.credential_primary_delete(&cust, ct).unwrap_err();
        assert!(matches!(err, OperationError::AccessDenied));

        // credential_passkey_init
        let err = cutxn.credential_passkey_init(&cust, ct).unwrap_err();
        assert!(matches!(err, OperationError::AccessDenied));

        // credential_passkey_finish
        //   Can't test because we need a public key response.

        // credential_passkey_remove
        let err = cutxn
            .credential_passkey_remove(&cust, ct, Uuid::new_v4())
            .unwrap_err();
        assert!(matches!(err, OperationError::AccessDenied));

        let c_status = cutxn
            .credential_update_status(&cust, ct)
            .expect("Failed to get the current session status.");
        trace!(?c_status);
        assert!(c_status.primary.is_none());
        assert!(c_status.passkeys.is_empty());

        drop(cutxn);
        commit_session(idms, ct, cust).await;
    }

    // Assert we can't create "just" a password when mfa is required.
    #[idm_test]
    async fn test_idm_credential_update_account_policy_mfa_required(
        idms: &IdmServer,
        _idms_delayed: &mut IdmServerDelayed,
    ) {
        let test_pw = "fo3EitierohF9AelaNgiem0Ei6vup4equo1Oogeevaetehah8Tobeengae3Ci0ooh0uki";
        let ct = Duration::from_secs(TEST_CURRENT_TIME);

        let mut idms_prox_write = idms.proxy_write(ct).await;

        let modlist = ModifyList::new_purge_and_set(
            Attribute::CredentialTypeMinimum,
            CredentialType::Mfa.into(),
        );
        idms_prox_write
            .qs_write
            .internal_modify_uuid(UUID_IDM_ALL_ACCOUNTS, &modlist)
            .expect("Unable to change default session exp");

        assert!(idms_prox_write.commit().is_ok());
        // This now will affect all accounts for the next cred update.

        let (cust, _) = setup_test_session(idms, ct).await;

        let cutxn = idms.cred_update_transaction().await;

        // Get the credential status - this should tell
        // us the details of the credentials, as well as
        // if they are ready and valid to commit?
        let c_status = cutxn
            .credential_update_status(&cust, ct)
            .expect("Failed to get the current session status.");

        trace!(?c_status);

        assert!(c_status.primary.is_none());

        // Test initially creating a credential.
        //   - pw first
        let c_status = cutxn
            .credential_primary_set_password(&cust, ct, test_pw)
            .expect("Failed to update the primary cred password");

        assert!(!c_status.can_commit);
        assert!(c_status
            .warnings
            .contains(&CredentialUpdateSessionStatusWarnings::MfaRequired));
        // Check reason! Must show "no mfa". We need totp to be added now.

        let c_status = cutxn
            .credential_primary_init_totp(&cust, ct)
            .expect("Failed to update the primary cred password");

        // Check the status has the token.
        let totp_token: Totp = match c_status.mfaregstate {
            MfaRegStateStatus::TotpCheck(secret) => Some(secret.try_into().unwrap()),

            _ => None,
        }
        .expect("Unable to retrieve totp token, invalid state.");

        trace!(?totp_token);
        let chal = totp_token
            .do_totp_duration_from_epoch(&ct)
            .expect("Failed to perform totp step");

        let c_status = cutxn
            .credential_primary_check_totp(&cust, ct, chal, "totp")
            .expect("Failed to update the primary cred totp");

        assert!(matches!(c_status.mfaregstate, MfaRegStateStatus::None));
        assert!(match c_status.primary.as_ref().map(|c| &c.type_) {
            Some(CredentialDetailType::PasswordMfa(totp, _, 0)) => !totp.is_empty(),
            _ => false,
        });

        // Done, can now commit.
        assert!(c_status.can_commit);
        assert!(c_status.warnings.is_empty());

        drop(cutxn);
        commit_session(idms, ct, cust).await;

        // If we remove TOTP, it blocks commit.
        let (cust, _) = renew_test_session(idms, ct).await;
        let cutxn = idms.cred_update_transaction().await;

        let c_status = cutxn
            .credential_primary_remove_totp(&cust, ct, "totp")
            .expect("Failed to update the primary cred totp");

        assert!(matches!(c_status.mfaregstate, MfaRegStateStatus::None));
        assert!(matches!(
            c_status.primary.as_ref().map(|c| &c.type_),
            Some(CredentialDetailType::Password)
        ));

        // Delete of the totp forces us back here.
        assert!(!c_status.can_commit);
        assert!(c_status
            .warnings
            .contains(&CredentialUpdateSessionStatusWarnings::MfaRequired));

        // Passkeys satisfy the policy though
        let c_status = cutxn
            .credential_primary_delete(&cust, ct)
            .expect("Failed to delete the primary credential");
        assert!(c_status.primary.is_none());

        let origin = cutxn.get_origin().clone();
        let mut wa = WebauthnAuthenticator::new(SoftPasskey::new(true));

        let c_status = create_new_passkey(ct, &origin, &cutxn, &cust, &mut wa).await;

        assert!(c_status.can_commit);
        assert!(c_status.warnings.is_empty());
        assert!(c_status.passkeys.len() == 1);

        drop(cutxn);
        commit_session(idms, ct, cust).await;
    }

    #[idm_test]
    async fn test_idm_credential_update_account_policy_passkey_required(
        idms: &IdmServer,
        _idms_delayed: &mut IdmServerDelayed,
    ) {
        let test_pw = "fo3EitierohF9AelaNgiem0Ei6vup4equo1Oogeevaetehah8Tobeengae3Ci0ooh0uki";
        let ct = Duration::from_secs(TEST_CURRENT_TIME);

        let mut idms_prox_write = idms.proxy_write(ct).await;

        let modlist = ModifyList::new_purge_and_set(
            Attribute::CredentialTypeMinimum,
            CredentialType::Passkey.into(),
        );
        idms_prox_write
            .qs_write
            .internal_modify_uuid(UUID_IDM_ALL_ACCOUNTS, &modlist)
            .expect("Unable to change default session exp");

        assert!(idms_prox_write.commit().is_ok());
        // This now will affect all accounts for the next cred update.

        let (cust, _) = setup_test_session(idms, ct).await;

        let cutxn = idms.cred_update_transaction().await;

        // Get the credential status - this should tell
        // us the details of the credentials, as well as
        // if they are ready and valid to commit?
        let c_status = cutxn
            .credential_update_status(&cust, ct)
            .expect("Failed to get the current session status.");

        trace!(?c_status);
        assert!(c_status.primary.is_none());
        assert!(matches!(
            c_status.primary_state,
            CredentialState::PolicyDeny
        ));

        let err = cutxn
            .credential_primary_set_password(&cust, ct, test_pw)
            .unwrap_err();
        assert!(matches!(err, OperationError::AccessDenied));

        let origin = cutxn.get_origin().clone();
        let mut wa = WebauthnAuthenticator::new(SoftPasskey::new(true));

        let c_status = create_new_passkey(ct, &origin, &cutxn, &cust, &mut wa).await;

        assert!(c_status.can_commit);
        assert!(c_status.warnings.is_empty());
        assert!(c_status.passkeys.len() == 1);

        drop(cutxn);
        commit_session(idms, ct, cust).await;
    }

    // Attested passkey types

    #[idm_test]
    async fn test_idm_credential_update_account_policy_attested_passkey_required(
        idms: &IdmServer,
        idms_delayed: &mut IdmServerDelayed,
    ) {
        let ct = Duration::from_secs(TEST_CURRENT_TIME);

        // Create the attested soft token we will use in this test.
        let (soft_token_valid, ca_root) = SoftToken::new(true).unwrap();
        let mut wa_token_valid = WebauthnAuthenticator::new(soft_token_valid);

        // Create it's associated policy.
        let mut att_ca_builder = AttestationCaListBuilder::new();
        att_ca_builder
            .insert_device_x509(
                ca_root,
                softtoken::AAGUID,
                "softtoken".to_string(),
                Default::default(),
            )
            .unwrap();
        let att_ca_list = att_ca_builder.build();

        let mut idms_prox_write = idms.proxy_write(ct).await;

        let modlist = ModifyList::new_purge_and_set(
            Attribute::WebauthnAttestationCaList,
            Value::WebauthnAttestationCaList(att_ca_list),
        );
        idms_prox_write
            .qs_write
            .internal_modify_uuid(UUID_IDM_ALL_ACCOUNTS, &modlist)
            .expect("Unable to change webauthn attestation policy");

        assert!(idms_prox_write.commit().is_ok());

        // Create the invalid tokens
        let (soft_token_invalid, _) = SoftToken::new(true).unwrap();
        let mut wa_token_invalid = WebauthnAuthenticator::new(soft_token_invalid);

        let mut wa_passkey_invalid = WebauthnAuthenticator::new(SoftPasskey::new(true));

        // Setup the cred update session.

        let (cust, _) = setup_test_session(idms, ct).await;
        let cutxn = idms.cred_update_transaction().await;
        let origin = cutxn.get_origin().clone();

        // Our status needs the correct device names for UI hinting.
        let c_status = cutxn
            .credential_update_status(&cust, ct)
            .expect("Failed to get the current session status.");

        trace!(?c_status);
        assert!(c_status.attested_passkeys.is_empty());
        assert_eq!(
            c_status.attested_passkeys_allowed_devices,
            vec!["softtoken".to_string()]
        );

        // -------------------------------------------------------
        // Unable to add an passkey when attestation is requested.
        let err = cutxn.credential_passkey_init(&cust, ct).unwrap_err();
        assert!(matches!(err, OperationError::AccessDenied));

        // -------------------------------------------------------
        // Reject a credential that lacks attestation
        let c_status = cutxn
            .credential_attested_passkey_init(&cust, ct)
            .expect("Failed to initiate attested passkey registration");

        let passkey_chal = match c_status.mfaregstate {
            MfaRegStateStatus::AttestedPasskey(c) => Some(c),
            _ => None,
        }
        .expect("Unable to access passkey challenge, invalid state");

        let passkey_resp = wa_passkey_invalid
            .do_registration(origin.clone(), passkey_chal)
            .expect("Failed to create soft passkey");

        // Finish the registration
        let label = "softtoken".to_string();
        let err = cutxn
            .credential_attested_passkey_finish(&cust, ct, label, &passkey_resp)
            .unwrap_err();

        assert!(matches!(
            err,
            OperationError::CU0001WebauthnAttestationNotTrusted
        ));

        // -------------------------------------------------------
        // Reject a credential with wrong CA / correct aaguid
        let c_status = cutxn
            .credential_attested_passkey_init(&cust, ct)
            .expect("Failed to initiate attested passkey registration");

        let passkey_chal = match c_status.mfaregstate {
            MfaRegStateStatus::AttestedPasskey(c) => Some(c),
            _ => None,
        }
        .expect("Unable to access passkey challenge, invalid state");

        let passkey_resp = wa_token_invalid
            .do_registration(origin.clone(), passkey_chal)
            .expect("Failed to create soft passkey");

        // Finish the registration
        let label = "softtoken".to_string();
        let err = cutxn
            .credential_attested_passkey_finish(&cust, ct, label, &passkey_resp)
            .unwrap_err();

        assert!(matches!(
            err,
            OperationError::CU0001WebauthnAttestationNotTrusted
        ));

        // -------------------------------------------------------
        // Accept credential with correct CA/aaguid
        let c_status = cutxn
            .credential_attested_passkey_init(&cust, ct)
            .expect("Failed to initiate attested passkey registration");

        let passkey_chal = match c_status.mfaregstate {
            MfaRegStateStatus::AttestedPasskey(c) => Some(c),
            _ => None,
        }
        .expect("Unable to access passkey challenge, invalid state");

        let passkey_resp = wa_token_valid
            .do_registration(origin.clone(), passkey_chal)
            .expect("Failed to create soft passkey");

        // Finish the registration
        let label = "softtoken".to_string();
        let c_status = cutxn
            .credential_attested_passkey_finish(&cust, ct, label, &passkey_resp)
            .expect("Failed to initiate passkey registration");

        assert!(matches!(c_status.mfaregstate, MfaRegStateStatus::None));
        trace!(?c_status);
        assert_eq!(c_status.attested_passkeys.len(), 1);

        let pk_uuid = c_status
            .attested_passkeys
            .first()
            .map(|pkd| pkd.uuid)
            .unwrap();

        drop(cutxn);
        commit_session(idms, ct, cust).await;

        // Assert that auth works.
        assert!(check_testperson_passkey(
            idms,
            idms_delayed,
            &mut wa_token_valid,
            origin.clone(),
            ct
        )
        .await
        .is_some());

        // Remove attested passkey works.
        let (cust, _) = renew_test_session(idms, ct).await;
        let cutxn = idms.cred_update_transaction().await;

        trace!(?c_status);
        assert!(c_status.primary.is_none());
        assert!(c_status.passkeys.is_empty());
        assert!(c_status.attested_passkeys.len() == 1);

        let c_status = cutxn
            .credential_attested_passkey_remove(&cust, ct, pk_uuid)
            .expect("Failed to delete the attested passkey");

        trace!(?c_status);
        assert!(c_status.primary.is_none());
        assert!(c_status.passkeys.is_empty());
        assert!(c_status.attested_passkeys.is_empty());

        drop(cutxn);
        commit_session(idms, ct, cust).await;

        // Must fail now!
        assert!(
            check_testperson_passkey(idms, idms_delayed, &mut wa_token_valid, origin, ct)
                .await
                .is_none()
        );
    }

    #[idm_test(audit = 1)]
    async fn test_idm_credential_update_account_policy_attested_passkey_changed(
        idms: &IdmServer,
        idms_delayed: &mut IdmServerDelayed,
        idms_audit: &mut IdmServerAudit,
    ) {
        let ct = Duration::from_secs(TEST_CURRENT_TIME);

        // Setup the policy.
        let (soft_token_1, ca_root_1) = SoftToken::new(true).unwrap();
        let mut wa_token_1 = WebauthnAuthenticator::new(soft_token_1);

        let (_soft_token_2, ca_root_2) = SoftToken::new(true).unwrap();

        let mut att_ca_builder = AttestationCaListBuilder::new();
        att_ca_builder
            .insert_device_x509(
                ca_root_1.clone(),
                softtoken::AAGUID,
                "softtoken_1".to_string(),
                Default::default(),
            )
            .unwrap();
        let att_ca_list = att_ca_builder.build();

        trace!(?att_ca_list);

        let mut idms_prox_write = idms.proxy_write(ct).await;

        let modlist = ModifyList::new_purge_and_set(
            Attribute::WebauthnAttestationCaList,
            Value::WebauthnAttestationCaList(att_ca_list),
        );
        idms_prox_write
            .qs_write
            .internal_modify_uuid(UUID_IDM_ALL_ACCOUNTS, &modlist)
            .expect("Unable to change webauthn attestation policy");

        assert!(idms_prox_write.commit().is_ok());

        // Setup the policy for later that lacks token 2.
        let mut att_ca_builder = AttestationCaListBuilder::new();
        att_ca_builder
            .insert_device_x509(
                ca_root_2,
                softtoken::AAGUID,
                "softtoken_2".to_string(),
                Default::default(),
            )
            .unwrap();
        let att_ca_list_post = att_ca_builder.build();

        // Enroll the attested keys
        let (cust, _) = setup_test_session(idms, ct).await;
        let cutxn = idms.cred_update_transaction().await;
        let origin = cutxn.get_origin().clone();

        // -------------------------------------------------------
        let c_status = cutxn
            .credential_attested_passkey_init(&cust, ct)
            .expect("Failed to initiate attested passkey registration");

        let passkey_chal = match c_status.mfaregstate {
            MfaRegStateStatus::AttestedPasskey(c) => Some(c),
            _ => None,
        }
        .expect("Unable to access passkey challenge, invalid state");

        let passkey_resp = wa_token_1
            .do_registration(origin.clone(), passkey_chal)
            .expect("Failed to create soft passkey");

        // Finish the registration
        let label = "softtoken".to_string();
        let c_status = cutxn
            .credential_attested_passkey_finish(&cust, ct, label, &passkey_resp)
            .expect("Failed to initiate passkey registration");

        assert!(matches!(c_status.mfaregstate, MfaRegStateStatus::None));
        trace!(?c_status);
        assert_eq!(c_status.attested_passkeys.len(), 1);

        // -------------------------------------------------------
        // Commit
        drop(cutxn);
        commit_session(idms, ct, cust).await;

        // Check auth works
        assert!(
            check_testperson_passkey(idms, idms_delayed, &mut wa_token_1, origin.clone(), ct)
                .await
                .is_some()
        );

        // Change policy
        let mut idms_prox_write = idms.proxy_write(ct).await;

        let modlist = ModifyList::new_purge_and_set(
            Attribute::WebauthnAttestationCaList,
            Value::WebauthnAttestationCaList(att_ca_list_post),
        );
        idms_prox_write
            .qs_write
            .internal_modify_uuid(UUID_IDM_ALL_ACCOUNTS, &modlist)
            .expect("Unable to change webauthn attestation policy");

        assert!(idms_prox_write.commit().is_ok());

        // Auth fail
        assert!(
            check_testperson_passkey(idms, idms_delayed, &mut wa_token_1, origin.clone(), ct)
                .await
                .is_none()
        );

        // This gives an auth denied because the attested passkey still exists but it no longer
        // meets criteria.
        match idms_audit.audit_rx().try_recv() {
            Ok(AuditEvent::AuthenticationDenied { .. }) => {}
            _ => assert!(false),
        }

        //  Update creds
        let (cust, _) = renew_test_session(idms, ct).await;
        let cutxn = idms.cred_update_transaction().await;

        // Invalid key removed
        let c_status = cutxn
            .credential_update_status(&cust, ct)
            .expect("Failed to get the current session status.");

        trace!(?c_status);
        assert!(c_status.attested_passkeys.is_empty());

        drop(cutxn);
        commit_session(idms, ct, cust).await;

        // Auth fail
        assert!(
            check_testperson_passkey(idms, idms_delayed, &mut wa_token_1, origin.clone(), ct)
                .await
                .is_none()
        );
    }

    // Test that when attestation policy is removed, the apk downgrades to passkey and still works.
    #[idm_test]
    async fn test_idm_credential_update_account_policy_attested_passkey_downgrade(
        idms: &IdmServer,
        idms_delayed: &mut IdmServerDelayed,
    ) {
        let ct = Duration::from_secs(TEST_CURRENT_TIME);

        // Setup the policy.
        let (soft_token_1, ca_root_1) = SoftToken::new(true).unwrap();
        let mut wa_token_1 = WebauthnAuthenticator::new(soft_token_1);

        let mut att_ca_builder = AttestationCaListBuilder::new();
        att_ca_builder
            .insert_device_x509(
                ca_root_1.clone(),
                softtoken::AAGUID,
                "softtoken_1".to_string(),
                Default::default(),
            )
            .unwrap();
        let att_ca_list = att_ca_builder.build();

        trace!(?att_ca_list);

        let mut idms_prox_write = idms.proxy_write(ct).await;

        let modlist = ModifyList::new_purge_and_set(
            Attribute::WebauthnAttestationCaList,
            Value::WebauthnAttestationCaList(att_ca_list),
        );
        idms_prox_write
            .qs_write
            .internal_modify_uuid(UUID_IDM_ALL_ACCOUNTS, &modlist)
            .expect("Unable to change webauthn attestation policy");

        assert!(idms_prox_write.commit().is_ok());

        // Enroll the attested keys
        let (cust, _) = setup_test_session(idms, ct).await;
        let cutxn = idms.cred_update_transaction().await;
        let origin = cutxn.get_origin().clone();

        // -------------------------------------------------------
        let c_status = cutxn
            .credential_attested_passkey_init(&cust, ct)
            .expect("Failed to initiate attested passkey registration");

        let passkey_chal = match c_status.mfaregstate {
            MfaRegStateStatus::AttestedPasskey(c) => Some(c),
            _ => None,
        }
        .expect("Unable to access passkey challenge, invalid state");

        let passkey_resp = wa_token_1
            .do_registration(origin.clone(), passkey_chal)
            .expect("Failed to create soft passkey");

        // Finish the registration
        let label = "softtoken".to_string();
        let c_status = cutxn
            .credential_attested_passkey_finish(&cust, ct, label, &passkey_resp)
            .expect("Failed to initiate passkey registration");

        assert!(matches!(c_status.mfaregstate, MfaRegStateStatus::None));
        trace!(?c_status);
        assert_eq!(c_status.attested_passkeys.len(), 1);

        // -------------------------------------------------------
        // Commit
        drop(cutxn);
        commit_session(idms, ct, cust).await;

        // Check auth works
        assert!(
            check_testperson_passkey(idms, idms_delayed, &mut wa_token_1, origin.clone(), ct)
                .await
                .is_some()
        );

        // Change policy
        let mut idms_prox_write = idms.proxy_write(ct).await;

        let modlist = ModifyList::new_purge(Attribute::WebauthnAttestationCaList);
        idms_prox_write
            .qs_write
            .internal_modify_uuid(UUID_IDM_ALL_ACCOUNTS, &modlist)
            .expect("Unable to change webauthn attestation policy");

        assert!(idms_prox_write.commit().is_ok());

        // Auth still passes, key was downgraded.
        assert!(
            check_testperson_passkey(idms, idms_delayed, &mut wa_token_1, origin.clone(), ct)
                .await
                .is_some()
        );

        // Show it still exists, but can only be deleted now.
        let (cust, _) = renew_test_session(idms, ct).await;
        let cutxn = idms.cred_update_transaction().await;

        let c_status = cutxn
            .credential_update_status(&cust, ct)
            .expect("Failed to get the current session status.");

        trace!(?c_status);
        assert_eq!(c_status.attested_passkeys.len(), 1);
        assert!(matches!(
            c_status.attested_passkeys_state,
            CredentialState::DeleteOnly
        ));

        drop(cutxn);
        commit_session(idms, ct, cust).await;
    }
}
