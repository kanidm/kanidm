use time::OffsetDateTime;
use uuid::Uuid;

use kanidm_lib_crypto::CryptoPolicy;

use crate::idm::group::UnixGroup;
use crate::credential::Credential;
use crate::modify::{ModifyInvalid, ModifyList};
use crate::prelude::*;

#[derive(Debug, Clone)]
pub(crate) struct UnixUserAccount {
    pub name: String,
    pub spn: String,
    pub displayname: String,
    pub uuid: Uuid,
    pub _valid_from: Option<OffsetDateTime>,
    pub _expire: Option<OffsetDateTime>,
    pub radius_secret: Option<String>,
    pub mail: Vec<String>,

    cred: Option<Credential>,
    pub _shell: Option<String>,
    pub _sshkeys: Vec<String>,
    pub _gidnumber: u32,
    pub _groups: Vec<UnixGroup>,
}

macro_rules! try_from_entry {
    ($value:expr, $groups:expr) => {{
        if !$value.attribute_equality(Attribute::Class, &EntryClass::Account.to_partialvalue()) {
            return Err(OperationError::InvalidAccountState(
                "Missing class: account".to_string(),
            ));
        }

        if !$value.attribute_equality(
            Attribute::Class,
            &EntryClass::PosixAccount.to_partialvalue(),
        ) {
            return Err(OperationError::InvalidAccountState(
                "Missing class: posixaccount".to_string(),
            ));
        }

        let name = $value
            .get_ava_single_iname(Attribute::Name)
            .map(|s| s.to_string())
            .ok_or_else(|| {
                OperationError::InvalidAccountState(format!(
                    "Missing attribute: {}",
                    Attribute::Name
                ))
            })?;

        let spn = $value
            .get_ava_single_proto_string(Attribute::Spn)
            .ok_or_else(|| {
                OperationError::InvalidAccountState(format!(
                    "Missing attribute: {}",
                    Attribute::Spn
                ))
            })?;

        let uuid = $value.get_uuid();

        let displayname = $value
            .get_ava_single_utf8(Attribute::DisplayName)
            .map(|s| s.to_string())
            .ok_or_else(|| {
                OperationError::InvalidAccountState(format!(
                    "Missing attribute: {}",
                    Attribute::DisplayName
                ))
            })?;

        let _gidnumber = $value
            .get_ava_single_uint32(Attribute::GidNumber)
            .ok_or_else(|| {
                OperationError::InvalidAccountState(format!(
                    "Missing attribute: {}",
                    Attribute::GidNumber
                ))
            })?;

        let _shell = $value
            .get_ava_single_iutf8(Attribute::LoginShell)
            .map(|s| s.to_string());

        let _sshkeys = $value
            .get_ava_iter_sshpubkeys(Attribute::SshPublicKey)
            .map(|i| i.map(|s| s.to_string()).collect())
            .unwrap_or_default();

        let cred = $value
            .get_ava_single_credential(Attribute::UnixPassword)
            .cloned();

        let radius_secret = $value
            .get_ava_single_secret(Attribute::RadiusSecret)
            .map(str::to_string);

        let mail = $value
            .get_ava_iter_mail(Attribute::Mail)
            .map(|i| i.map(str::to_string).collect())
            .unwrap_or_default();

        let _valid_from = $value.get_ava_single_datetime(Attribute::AccountValidFrom);

        let _expire = $value.get_ava_single_datetime(Attribute::AccountExpire);

        Ok(UnixUserAccount {
            name,
            spn,
            uuid,
            displayname,
            _gidnumber,
            _shell,
            _sshkeys,
            _groups: $groups,
            cred,
            _valid_from,
            _expire,
            radius_secret,
            mail,
        })
    }};
}

impl UnixUserAccount {
    pub(crate) fn try_from_entry_rw(
        value: &Entry<EntrySealed, EntryCommitted>,
        qs: &mut QueryServerWriteTransaction,
    ) -> Result<Self, OperationError> {
        let groups = UnixGroup::try_from_account_entry_rw(value, qs)?;
        try_from_entry!(value, groups)
    }

    pub fn is_anonymous(&self) -> bool {
        self.uuid == UUID_ANONYMOUS
    }

    pub(crate) fn gen_password_mod(
        &self,
        cleartext: &str,
        crypto_policy: &CryptoPolicy,
    ) -> Result<ModifyList<ModifyInvalid>, OperationError> {
        let ncred = Credential::new_password_only(crypto_policy, cleartext)?;
        let vcred = Value::new_credential("unix", ncred);
        Ok(ModifyList::new_purge_and_set(
            Attribute::UnixPassword,
            vcred,
        ))
    }

    pub(crate) fn gen_password_upgrade_mod(
        &self,
        cleartext: &str,
        crypto_policy: &CryptoPolicy,
    ) -> Result<Option<ModifyList<ModifyInvalid>>, OperationError> {
        match &self.cred {
            // Change the cred
            Some(ucred) => {
                if let Some(ncred) = ucred.upgrade_password(crypto_policy, cleartext)? {
                    let vcred = Value::new_credential("primary", ncred);
                    Ok(Some(ModifyList::new_purge_and_set(
                        Attribute::UnixPassword,
                        vcred,
                    )))
                } else {
                    // No action, not the same pw
                    Ok(None)
                }
            }
            // Nothing to do.
            None => Ok(None),
        }
    }

    // Get related inputs, such as account name, email, etc.
    pub fn related_inputs(&self) -> Vec<&str> {
        let mut inputs = Vec::with_capacity(4 + self.mail.len());
        self.mail.iter().for_each(|m| {
            inputs.push(m.as_str());
        });
        inputs.push(self.name.as_str());
        inputs.push(self.spn.as_str());
        inputs.push(self.displayname.as_str());
        if let Some(s) = self.radius_secret.as_deref() {
            inputs.push(s);
        }
        inputs
    }
}
