use crate::db::KeyStoreTxn;
use async_trait::async_trait;
use kanidm_client::{ClientError, KanidmClient, StatusCode};
use kanidm_proto::internal::OperationError;
use kanidm_proto::v1::{UnixGroupToken, UnixUserToken};
use std::time::{Duration, SystemTime};
use tokio::sync::{broadcast, Mutex};
use std::sync::Arc;
use hashbrown::HashMap;

use kanidm_lib_crypto::CryptoPolicy;
use kanidm_lib_crypto::DbPasswordV1;
use kanidm_lib_crypto::Password;

use super::interface::{
    tpm::{self, HmacKey, Tpm},
    AuthCredHandler, AuthRequest, AuthResult, GroupToken, GroupTokenState, Id, IdProvider,
    IdpError, ProviderOrigin, UserToken, UserTokenState,
};
use kanidm_unix_common::unix_proto::{PamAuthRequest, NssUser, NssGroup};
use kanidm_unix_common::unix_passwd::{EtcGroup, EtcUser};

pub struct SystemProviderInternal {
    allow_group_overrides: Vec<String>,
    users: HashMap<Id, Arc<EtcUser>>,
    user_list: Vec<Arc<EtcUser>>,
    groups: HashMap<Id, Arc<EtcGroup>>,
    group_list: Vec<Arc<EtcGroup>>,
}

pub struct SystemProvider {
    inner: Mutex<SystemProviderInternal>,
}

impl SystemProvider {
    pub fn new(
        // To be removed in a future version, it's too primitive.
        allow_group_overrides: Vec<String>,
    ) -> Result<Self, IdpError> {
        Ok(SystemProvider {
            inner:
            Mutex::new(
                SystemProviderInternal {
                    allow_group_overrides,
                    users: Default::default(),
                    user_list: Default::default(),
                    groups: Default::default(),
                    group_list: Default::default(),
                }
            ),
        })
    }

    pub async fn reload(
        &self, users: Vec<EtcUser>, groups: Vec<EtcGroup>
    ) {
        let mut system_ids_txn = self.inner.lock().await;
        system_ids_txn.users.clear();
        system_ids_txn.user_list.clear();
        system_ids_txn.groups.clear();
        system_ids_txn.group_list.clear();

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
                if !(group.members.is_empty() || (group.members.len() == 1 && group.members.get(0) == Some(&user.name))) {
                    error!(name = %user.name, uid = %user.uid, gid = %user.gid, "user private group must not have members, THIS IS A SECURITY RISK!");
                }
            } else {
                warn!(name = %user.name, uid = %user.uid, gid = %user.gid, "user private group is not present on system, synthesising it");
                let group = EtcGroup {
                    name: user.name.clone(),
                    password: String::new(),
                    gid: user.gid,
                    members: vec![user.name.clone()]
                };
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

    pub async fn contains_account(&self, account_id: &Id) -> bool {
        let inner = self.inner.lock().await;
        inner.users.contains_key(account_id)
    }

    pub async fn contains_group(&self, account_id: &Id) -> bool {
        let inner = self.inner.lock().await;
        inner.groups.contains_key(account_id)
    }

    pub async fn get_nssaccount(&self, account_id: &Id) -> Option<NssUser> {
        let inner = self.inner.lock().await;
        inner.users.get(account_id)
            .map(NssUser::from)
    }

    pub async fn get_nssaccounts(&self) -> Vec<NssUser> {
        let inner = self.inner.lock().await;
        inner.user_list.iter()
            .map(NssUser::from)
            .collect()
    }

    pub async fn get_nssgroup(&self, grp_id: &Id) -> Option<NssGroup> {
        let inner = self.inner.lock().await;
        inner.groups.get(grp_id)
            .map(NssGroup::from)
    }

    pub async fn get_nssgroups(&self) -> Vec<NssGroup> {
        let inner = self.inner.lock().await;
        inner.group_list.iter()
            .map(NssGroup::from)
            .collect()
    }

}

