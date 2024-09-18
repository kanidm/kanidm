use hashbrown::HashMap;
use std::sync::Arc;
use time::OffsetDateTime;
use tokio::sync::Mutex;

use super::interface::{AuthCredHandler, AuthRequest, Id, IdpError};
use kanidm_unix_common::unix_passwd::{EtcGroup, EtcShadow, EtcUser};
use kanidm_unix_common::unix_proto::PamAuthRequest;
use kanidm_unix_common::unix_proto::{NssGroup, NssUser};

pub struct SystemProviderInternal {
    users: HashMap<Id, Arc<EtcUser>>,
    user_list: Vec<Arc<EtcUser>>,
    groups: HashMap<Id, Arc<EtcGroup>>,
    group_list: Vec<Arc<EtcGroup>>,

    shadow_enabled: bool,
    shadow: HashMap<String, Arc<Shadow>>,
}

pub enum SystemProviderAuthInit {
    Begin {
        next_request: AuthRequest,
        cred_handler: AuthCredHandler,
        shadow: Arc<Shadow>,
    },
    ShadowMissing,
    CredentialsUnavailable,
    Expired,
    Ignore,
}

pub enum SystemProviderSession {
    Start,
    // Not sure that we need this
    // StartCreateHome(HomeDirectoryInfo),
    Ignore,
}

pub enum SystemAuthResult {
    Denied,
    Success,
    Next(AuthRequest),
}

pub enum CryptPw {
    Sha256(String),
    Sha512(String),
}

impl TryFrom<String> for CryptPw {
    type Error = ();

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if value.starts_with("$6$") {
            Ok(CryptPw::Sha512(value))
        } else if value.starts_with("$5$") {
            Ok(CryptPw::Sha256(value))
        } else {
            Err(())
        }
    }
}

#[allow(dead_code)]
struct AgingPolicy {
    last_change: time::OffsetDateTime,
    min_password_change: time::OffsetDateTime,
    max_password_change: Option<time::OffsetDateTime>,
    warning_period_start: Option<time::OffsetDateTime>,
    inactivity_period_deadline: Option<time::OffsetDateTime>,
}

impl AgingPolicy {
    fn new(
        change_days: i64,
        days_min_password_age: i64,
        days_max_password_age: Option<i64>,

        days_warning_period: i64,
        days_inactivity_period: Option<i64>,
    ) -> Self {
        // Get the changes days to an absolute.
        let last_change = OffsetDateTime::UNIX_EPOCH + time::Duration::days(change_days);

        let min_password_change = last_change + time::Duration::days(days_min_password_age);

        let max_password_change =
            days_max_password_age.map(|max| last_change + time::Duration::days(max));

        let (warning_period_start, inactivity_period_deadline) =
            if let Some(expiry) = max_password_change.as_ref() {
                // Both of these values are relative to the max age, so without a max age
                // they are meaningless.

                // If the warning isnt 0
                let warning = if days_warning_period != 0 {
                    // This is a subtract
                    Some(*expiry - time::Duration::days(days_warning_period))
                } else {
                    None
                };

                let inactive =
                    days_inactivity_period.map(|inactive| *expiry + time::Duration::days(inactive));

                (warning, inactive)
            } else {
                (None, None)
            };

        AgingPolicy {
            last_change,
            min_password_change,
            max_password_change,
            warning_period_start,
            inactivity_period_deadline,
        }
    }
}

pub struct Shadow {
    crypt_pw: CryptPw,
    #[allow(dead_code)]
    aging_policy: Option<AgingPolicy>,
    expiration_date: Option<time::OffsetDateTime>,
}

impl Shadow {
    pub fn auth_step(
        &self,
        cred_handler: &mut AuthCredHandler,
        pam_next_req: PamAuthRequest,
    ) -> SystemAuthResult {
        match (cred_handler, pam_next_req) {
            (AuthCredHandler::Password, PamAuthRequest::Password { cred }) => {
                let is_valid = match &self.crypt_pw {
                    CryptPw::Sha256(crypt) => sha_crypt::sha256_check(&cred, crypt).is_ok(),
                    CryptPw::Sha512(crypt) => sha_crypt::sha512_check(&cred, crypt).is_ok(),
                };

                if is_valid {
                    SystemAuthResult::Success
                } else {
                    SystemAuthResult::Denied
                }
            }
            _ => SystemAuthResult::Denied,
        }
    }
}

pub struct SystemProvider {
    inner: Mutex<SystemProviderInternal>,
}

impl SystemProvider {
    pub fn new() -> Result<Self, IdpError> {
        Ok(SystemProvider {
            inner: Mutex::new(SystemProviderInternal {
                users: Default::default(),
                user_list: Default::default(),
                groups: Default::default(),
                group_list: Default::default(),
                shadow_enabled: Default::default(),
                shadow: Default::default(),
            }),
        })
    }

    pub async fn reload(
        &self,
        users: Vec<EtcUser>,
        shadow: Option<Vec<EtcShadow>>,
        groups: Vec<EtcGroup>,
    ) {
        let mut system_ids_txn = self.inner.lock().await;
        system_ids_txn.users.clear();
        system_ids_txn.user_list.clear();
        system_ids_txn.groups.clear();
        system_ids_txn.group_list.clear();
        system_ids_txn.shadow.clear();

        system_ids_txn.shadow_enabled = shadow.is_some();

        if let Some(shadow) = shadow {
            let s_iter = shadow.into_iter().filter_map(|shadow_entry| {
                let EtcShadow {
                    name,
                    password,
                    epoch_change_days,
                    days_min_password_age,
                    days_max_password_age,
                    days_warning_period,
                    days_inactivity_period,
                    epoch_expire_date,
                    flag_reserved: _,
                } = shadow_entry;

                match CryptPw::try_from(password) {
                    Ok(crypt_pw) => {
                        let aging_policy = epoch_change_days.map(|change_days| {
                            AgingPolicy::new(
                                change_days,
                                days_min_password_age,
                                days_max_password_age,
                                days_warning_period,
                                days_inactivity_period,
                            )
                        });

                        let expiration_date = epoch_expire_date.map(|expire| {
                            OffsetDateTime::UNIX_EPOCH + time::Duration::days(expire)
                        });

                        Some((
                            name,
                            Arc::new(Shadow {
                                crypt_pw,
                                aging_policy,
                                expiration_date,
                            }),
                        ))
                    }
                    // No valid pw, don't care.
                    Err(()) => None,
                }
            });

            system_ids_txn.shadow.extend(s_iter)
        };

        for group in groups {
            let name = Id::Name(group.name.clone());
            let gid = Id::Gid(group.gid);
            let group = Arc::new(group);

            if system_ids_txn.groups.insert(name, group.clone()).is_some() {
                error!(name = %group.name, gid = %group.gid, "group name conflict");
            };
            if system_ids_txn.groups.insert(gid, group.clone()).is_some() {
                error!(name = %group.name, gid = %group.gid, "group id conflict");
            }
            system_ids_txn.group_list.push(group);
        }

        for user in users {
            let name = Id::Name(user.name.clone());
            let uid = Id::Gid(user.uid);
            let gid = Id::Gid(user.gid);

            if user.uid != user.gid {
                error!(name = %user.name, uid = %user.uid, gid = %user.gid, "user uid and gid are not the same, this may be a security risk!");
            }

            // Security checks.
            if let Some(group) = system_ids_txn.groups.get(&gid) {
                if group.name != user.name {
                    error!(name = %user.name, uid = %user.uid, gid = %user.gid, "user private group does not appear to have the same name as the user, this may be a security risk!");
                }
                if !(group.members.is_empty()
                    || (group.members.len() == 1 && group.members.first() == Some(&user.name)))
                {
                    error!(name = %user.name, uid = %user.uid, gid = %user.gid, members = ?group.members, "user private group must not have members, THIS IS A SECURITY RISK!");
                }
            } else {
                info!(name = %user.name, uid = %user.uid, gid = %user.gid, "user private group is not present on system, synthesising it");
                let group = Arc::new(EtcGroup {
                    name: user.name.clone(),
                    password: String::new(),
                    gid: user.gid,
                    members: vec![user.name.clone()],
                });

                system_ids_txn.groups.insert(name.clone(), group.clone());
                system_ids_txn.groups.insert(gid.clone(), group.clone());
                system_ids_txn.group_list.push(group);
            }

            let user = Arc::new(user);
            if system_ids_txn.users.insert(name, user.clone()).is_some() {
                error!(name = %user.name, uid = %user.uid, "user name conflict");
            }
            if system_ids_txn.users.insert(uid, user.clone()).is_some() {
                error!(name = %user.name, uid = %user.uid, "user id conflict");
            }
            system_ids_txn.user_list.push(user);
        }
    }

    /*
    pub async fn contains_account(&self, account_id: &Id) -> bool {
        let inner = self.inner.lock().await;
        inner.users.contains_key(account_id)
    }
    */

    pub async fn auth_init(
        &self,
        account_id: &Id,
        current_time: OffsetDateTime,
    ) -> SystemProviderAuthInit {
        let inner = self.inner.lock().await;

        let Some(user) = inner.users.get(account_id) else {
            // Not for us, not a system user.
            return SystemProviderAuthInit::Ignore;
        };

        if !inner.shadow_enabled {
            // We were unable to read shadow, so we can't proceed. Return that we don't know
            // the user.
            return SystemProviderAuthInit::ShadowMissing;
        }

        // Does the user have a related shadow entry?
        let Some(shadow) = inner.shadow.get(user.name.as_str()) else {
            return SystemProviderAuthInit::CredentialsUnavailable;
        };

        // If they do, is there a unix style auth policy attached?
        if let Some(expire) = shadow.expiration_date.as_ref() {
            if current_time >= *expire {
                return SystemProviderAuthInit::Expired;
            }
        }

        // Good to go, lets try to auth them.
        // Today, we only support password, but we can support more in future.
        let cred_handler = AuthCredHandler::Password;

        let next_request = AuthRequest::Password;

        SystemProviderAuthInit::Begin {
            next_request,
            cred_handler,
            shadow: shadow.clone(),
        }
    }

    pub async fn authorise(&self, account_id: &Id) -> Option<bool> {
        let inner = self.inner.lock().await;
        if inner.users.contains_key(account_id) {
            Some(true)
        } else {
            None
        }
    }

    pub async fn begin_session(&self, account_id: &Id) -> SystemProviderSession {
        let inner = self.inner.lock().await;
        if inner.users.contains_key(account_id) {
            SystemProviderSession::Start
        } else {
            SystemProviderSession::Ignore
        }
    }

    pub async fn contains_group(&self, account_id: &Id) -> bool {
        let inner = self.inner.lock().await;
        inner.groups.contains_key(account_id)
    }

    pub async fn get_nssaccount(&self, account_id: &Id) -> Option<NssUser> {
        let inner = self.inner.lock().await;
        inner.users.get(account_id).map(NssUser::from)
    }

    pub async fn get_nssaccounts(&self) -> Vec<NssUser> {
        let inner = self.inner.lock().await;
        inner.user_list.iter().map(NssUser::from).collect()
    }

    pub async fn get_nssgroup(&self, grp_id: &Id) -> Option<NssGroup> {
        let inner = self.inner.lock().await;
        inner.groups.get(grp_id).map(NssGroup::from)
    }

    pub async fn get_nssgroups(&self) -> Vec<NssGroup> {
        let inner = self.inner.lock().await;
        inner.group_list.iter().map(NssGroup::from).collect()
    }
}
