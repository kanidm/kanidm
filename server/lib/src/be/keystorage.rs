use crate::rusqlite::OptionalExtension;
use kanidm_lib_crypto::prelude::{PKey, Private, X509};
use kanidm_lib_crypto::serialise::{pkeyb64, x509b64};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::hash::Hash;

use super::idl_arc_sqlite::IdlArcSqliteWriteTransaction;
use super::idl_sqlite::IdlSqliteTransaction;
use super::idl_sqlite::IdlSqliteWriteTransaction;
use super::idl_sqlite::{serde_json_error, sqlite_error};
use super::BackendWriteTransaction;
use crate::prelude::OperationError;

/// These are key handles for storing keys related to various cryptographic components
/// within Kanidm. Generally these are for keys that are "static", as in have known
/// long term uses. This could be the servers private replication key, a TPM Storage
/// Root Key, or the Duplicable Storage Key. In future these may end up being in
/// a HSM or similar, but we'll always need a way to persist serialised forms of these.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub enum KeyHandleId {
    ReplicationKey,
}

/// This is a key handle that contains the actual data that is persisted in the DB.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KeyHandle {
    X509Key {
        #[serde(with = "pkeyb64")]
        private: PKey<Private>,
        #[serde(with = "x509b64")]
        x509: X509,
    },
}

impl<'a> BackendWriteTransaction<'a> {
    /// Retrieve a key stored in the database by it's key handle. This
    /// handle may require further processing for the key to be usable
    /// in higher level contexts as this is simply the storage layer
    /// for these keys.
    pub(crate) fn get_key_handle(
        &mut self,
        handle: KeyHandleId,
    ) -> Result<Option<KeyHandle>, OperationError> {
        self.idlayer.get_key_handle(handle)
    }

    /// Update the content of a keyhandle with this new data.
    pub(crate) fn set_key_handle(
        &mut self,
        handle: KeyHandleId,
        data: KeyHandle,
    ) -> Result<(), OperationError> {
        self.idlayer.set_key_handle(handle, data)
    }
}

impl<'a> IdlArcSqliteWriteTransaction<'a> {
    pub(crate) fn get_key_handle(
        &mut self,
        handle: KeyHandleId,
    ) -> Result<Option<KeyHandle>, OperationError> {
        if let Some(kh) = self.keyhandles.get(&handle) {
            Ok(Some(kh.clone()))
        } else {
            let r = self.db.get_key_handle(handle);

            if let Ok(Some(kh)) = &r {
                self.keyhandles.insert(handle, kh.clone());
            }

            r
        }
    }

    /// Update the content of a keyhandle with this new data.
    #[instrument(level = "debug", skip(self, data))]
    pub(crate) fn set_key_handle(
        &mut self,
        handle: KeyHandleId,
        data: KeyHandle,
    ) -> Result<(), OperationError> {
        self.db.set_key_handle(handle, &data)?;
        self.keyhandles.insert(handle, data);
        Ok(())
    }

    pub(super) fn set_key_handles(
        &mut self,
        keyhandles: BTreeMap<KeyHandleId, KeyHandle>,
    ) -> Result<(), OperationError> {
        self.db.set_key_handles(&keyhandles)?;
        self.keyhandles.clear();
        self.keyhandles.extend(keyhandles);
        Ok(())
    }
}

impl IdlSqliteWriteTransaction {
    pub(crate) fn get_key_handle(
        &mut self,
        handle: KeyHandleId,
    ) -> Result<Option<KeyHandle>, OperationError> {
        let s_handle = serde_json::to_vec(&handle).map_err(serde_json_error)?;

        let mut stmt = self
            .get_conn()?
            .prepare(&format!(
                "SELECT data FROM {}.keyhandles WHERE id = :id",
                self.get_db_name()
            ))
            .map_err(sqlite_error)?;
        let data_raw: Option<Vec<u8>> = stmt
            .query_row(&[(":id", &s_handle)], |row| row.get(0))
            // We don't mind if it doesn't exist
            .optional()
            .map_err(sqlite_error)?;

        let data: Option<KeyHandle> = match data_raw {
            Some(d) => serde_json::from_slice(d.as_slice())
                .map(Some)
                .map_err(serde_json_error)?,
            None => None,
        };

        Ok(data)
    }

    pub(super) fn get_key_handles(
        &mut self,
    ) -> Result<BTreeMap<KeyHandleId, KeyHandle>, OperationError> {
        let mut stmt = self
            .get_conn()?
            .prepare(&format!(
                "SELECT id, data FROM {}.keyhandles",
                self.get_db_name()
            ))
            .map_err(sqlite_error)?;

        let kh_iter = stmt
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .map_err(sqlite_error)?;

        kh_iter
            .map(|v| {
                let (id, data): (Vec<u8>, Vec<u8>) = v.map_err(sqlite_error)?;
                let id = serde_json::from_slice(id.as_slice()).map_err(serde_json_error)?;
                let data = serde_json::from_slice(data.as_slice()).map_err(serde_json_error)?;
                Ok((id, data))
            })
            .collect()
    }

    /// Update the content of a keyhandle with this new data.
    #[instrument(level = "debug", skip(self, data))]
    pub(crate) fn set_key_handle(
        &mut self,
        handle: KeyHandleId,
        data: &KeyHandle,
    ) -> Result<(), OperationError> {
        let s_handle = serde_json::to_vec(&handle).map_err(serde_json_error)?;
        let s_data = serde_json::to_vec(&data).map_err(serde_json_error)?;

        self.get_conn()?
            .prepare(&format!(
                "INSERT OR REPLACE INTO {}.keyhandles (id, data) VALUES(:id, :data)",
                self.get_db_name()
            ))
            .and_then(|mut stmt| stmt.execute(&[(":id", &s_handle), (":data", &s_data)]))
            .map(|_| ())
            .map_err(sqlite_error)
    }

    pub(super) fn set_key_handles(
        &mut self,
        keyhandles: &BTreeMap<KeyHandleId, KeyHandle>,
    ) -> Result<(), OperationError> {
        self.get_conn()?
            .execute(
                &format!("DELETE FROM {}.keyhandles", self.get_db_name()),
                [],
            )
            .map(|_| ())
            .map_err(sqlite_error)?;

        for (handle, data) in keyhandles {
            self.set_key_handle(*handle, data)?;
        }
        Ok(())
    }
}
