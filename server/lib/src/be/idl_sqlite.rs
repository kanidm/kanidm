use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::convert::{TryFrom, TryInto};
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use super::keystorage::{KeyHandle, KeyHandleId};

// use crate::valueset;
use hashbrown::HashMap;
use idlset::v2::IDLBitRange;
use kanidm_proto::v1::{ConsistencyError, OperationError};
use rusqlite::vtab::array::Array;
use rusqlite::{Connection, OpenFlags, OptionalExtension};
use uuid::Uuid;

use crate::be::dbentry::{DbEntry, DbIdentSpn};
use crate::be::dbvalue::DbCidV1;
use crate::be::{BackendConfig, IdList, IdRawEntry, IdxKey, IdxSlope};
use crate::entry::{Entry, EntryCommitted, EntrySealed};
use crate::prelude::*;
use crate::value::{IndexType, Value};

// use uuid::Uuid;

const DBV_ID2ENTRY: &str = "id2entry";
const DBV_INDEXV: &str = "indexv";

#[allow(clippy::needless_pass_by_value)] // needs to accept value from `map_err`
pub(super) fn sqlite_error(e: rusqlite::Error) -> OperationError {
    admin_error!(?e, "SQLite Error");
    OperationError::SqliteError
}

#[allow(clippy::needless_pass_by_value)] // needs to accept value from `map_err`
pub(super) fn serde_json_error(e: serde_json::Error) -> OperationError {
    admin_error!(?e, "Serde JSON Error");
    OperationError::SerdeJsonError
}

type ConnPool = Arc<Mutex<VecDeque<Connection>>>;

#[derive(Debug)]
pub struct IdSqliteEntry {
    id: i64,
    data: Vec<u8>,
}

#[derive(Debug)]
struct KeyIdl {
    key: String,
    data: Vec<u8>,
}

impl TryFrom<IdSqliteEntry> for IdRawEntry {
    type Error = OperationError;

    fn try_from(value: IdSqliteEntry) -> Result<Self, Self::Error> {
        if value.id <= 0 {
            return Err(OperationError::InvalidEntryId);
        }
        Ok(IdRawEntry {
            id: value
                .id
                .try_into()
                .map_err(|_| OperationError::InvalidEntryId)?,
            data: value.data,
        })
    }
}

impl TryFrom<IdRawEntry> for IdSqliteEntry {
    type Error = OperationError;

    fn try_from(value: IdRawEntry) -> Result<Self, Self::Error> {
        if value.id == 0 {
            return Err(OperationError::InvalidEntryId);
        }
        Ok(IdSqliteEntry {
            id: value
                .id
                .try_into()
                .map_err(|_| OperationError::InvalidEntryId)?,
            data: value.data,
        })
    }
}

#[derive(Clone)]
pub struct IdlSqlite {
    pool: ConnPool,
    db_name: &'static str,
}

pub struct IdlSqliteReadTransaction {
    pool: ConnPool,
    conn: Option<Connection>,
    db_name: &'static str,
}

pub struct IdlSqliteWriteTransaction {
    pool: ConnPool,
    conn: Option<Connection>,
    db_name: &'static str,
}

pub(crate) trait IdlSqliteTransaction {
    fn get_db_name(&self) -> &str;

    fn get_conn(&self) -> Result<&Connection, OperationError>;

    fn get_identry(&self, idl: &IdList) -> Result<Vec<Arc<EntrySealedCommitted>>, OperationError> {
        self.get_identry_raw(idl)?
            .into_iter()
            .map(|ide| ide.into_entry().map(Arc::new))
            .collect()
    }

    fn get_identry_raw(&self, idl: &IdList) -> Result<Vec<IdRawEntry>, OperationError> {
        // is the idl allids?
        match idl {
            IdList::AllIds => {
                let mut stmt = self
                    .get_conn()?
                    .prepare(&format!(
                        "SELECT id, data FROM {}.id2entry",
                        self.get_db_name()
                    ))
                    .map_err(sqlite_error)?;
                let id2entry_iter = stmt
                    .query_map([], |row| {
                        Ok(IdSqliteEntry {
                            id: row.get(0)?,
                            data: row.get(1)?,
                        })
                    })
                    .map_err(sqlite_error)?;
                id2entry_iter
                    .map(|v| {
                        v.map_err(sqlite_error).and_then(|ise| {
                            // Convert the idsqlite to id raw
                            ise.try_into()
                        })
                    })
                    .collect()
            }
            IdList::Partial(idli) | IdList::PartialThreshold(idli) | IdList::Indexed(idli) => {
                let mut stmt = self
                    .get_conn()?
                    .prepare(&format!(
                        "SELECT id, data FROM {}.id2entry
                         WHERE id IN rarray(:idli)",
                        self.get_db_name()
                    ))
                    .map_err(sqlite_error)?;

                // turn them into i64's
                let mut id_list: Vec<i64> = vec![];
                for id in idli {
                    id_list.push(i64::try_from(id).map_err(|_| OperationError::InvalidEntryId)?);
                }
                // turn them into rusqlite values
                let id_list: Array = std::rc::Rc::new(
                    id_list
                        .into_iter()
                        .map(rusqlite::types::Value::from)
                        .collect::<Vec<rusqlite::types::Value>>(),
                );

                let mut results: Vec<IdRawEntry> = vec![];

                let rows = stmt.query_map(named_params! {":idli": &id_list}, |row| {
                    Ok(IdSqliteEntry {
                        id: row.get(0)?,
                        data: row.get(1)?,
                    })
                });
                let rows = match rows {
                    Ok(rows) => rows,
                    Err(e) => {
                        error!("query failed in get_identry_raw: {:?}", e);
                        return Err(OperationError::SqliteError);
                    }
                };

                for row in rows {
                    match row {
                        Ok(ise) => {
                            // Convert the idsqlite to id raw
                            results.push(ise.try_into()?);
                        }
                        // TODO: make this a better error
                        Err(e) => {
                            admin_error!(?e, "SQLite Error in get_identry_raw");
                            return Err(OperationError::SqliteError);
                        }
                    }
                }
                Ok(results)
            }
        }
    }

    fn exists_table(&self, tname: &str) -> Result<bool, OperationError> {
        let mut stmt = self
            .get_conn()?
            .prepare(&format!(
                "SELECT COUNT(name) from {}.sqlite_master where name = :tname",
                self.get_db_name()
            ))
            .map_err(sqlite_error)?;
        let i: Option<i64> = stmt
            .query_row(&[(":tname", tname)], |row| row.get(0))
            .map_err(sqlite_error)?;

        match i {
            None | Some(0) => Ok(false),
            _ => Ok(true),
        }
    }

    fn exists_idx(&self, attr: &str, itype: IndexType) -> Result<bool, OperationError> {
        let tname = format!("idx_{}_{}", itype.as_idx_str(), attr);
        self.exists_table(&tname)
    }

    #[instrument(level = "trace", skip_all)]
    fn get_idl(
        &self,
        attr: &str,
        itype: IndexType,
        idx_key: &str,
    ) -> Result<Option<IDLBitRange>, OperationError> {
        if !(self.exists_idx(attr, itype)?) {
            debug!(
                "IdlSqliteTransaction: Index {:?} {:?} not found",
                itype, attr
            );
            return Ok(None);
        }
        // The table exists - lets now get the actual index itself.

        let query = format!(
            "SELECT idl FROM {}.idx_{}_{} WHERE key = :idx_key",
            self.get_db_name(),
            itype.as_idx_str(),
            attr
        );
        let mut stmt = self.get_conn()?.prepare(&query).map_err(sqlite_error)?;
        let idl_raw: Option<Vec<u8>> = stmt
            .query_row(&[(":idx_key", &idx_key)], |row| row.get(0))
            // We don't mind if it doesn't exist
            .optional()
            .map_err(sqlite_error)?;

        let idl = match idl_raw {
            Some(d) => serde_json::from_slice(d.as_slice()).map_err(serde_json_error)?,
            // We don't have this value, it must be empty (or we
            // have a corrupted index .....
            None => IDLBitRange::new(),
        };
        trace!(
            miss_index = ?itype,
            attr = ?attr,
            idl = %idl,
        );

        Ok(Some(idl))
    }

    fn name2uuid(&mut self, name: &str) -> Result<Option<Uuid>, OperationError> {
        // The table exists - lets now get the actual index itself.
        let mut stmt = self
            .get_conn()?
            .prepare(&format!(
                "SELECT uuid FROM {}.idx_name2uuid WHERE name = :name",
                self.get_db_name()
            ))
            .map_err(sqlite_error)?;
        let uuid_raw: Option<String> = stmt
            .query_row(&[(":name", &name)], |row| row.get(0))
            // We don't mind if it doesn't exist
            .optional()
            .map_err(sqlite_error)?;

        let uuid = uuid_raw.as_ref().and_then(|u| Uuid::parse_str(u).ok());

        Ok(uuid)
    }

    fn externalid2uuid(&mut self, name: &str) -> Result<Option<Uuid>, OperationError> {
        // The table exists - lets now get the actual index itself.
        let mut stmt = self
            .get_conn()?
            .prepare(&format!(
                "SELECT uuid FROM {}.idx_externalid2uuid WHERE eid = :eid",
                self.get_db_name()
            ))
            .map_err(sqlite_error)?;
        let uuid_raw: Option<String> = stmt
            .query_row(&[(":eid", &name)], |row| row.get(0))
            // We don't mind if it doesn't exist
            .optional()
            .map_err(sqlite_error)?;

        let uuid = uuid_raw.as_ref().and_then(|u| Uuid::parse_str(u).ok());

        Ok(uuid)
    }

    fn uuid2spn(&mut self, uuid: Uuid) -> Result<Option<Value>, OperationError> {
        let uuids = uuid.as_hyphenated().to_string();
        // The table exists - lets now get the actual index itself.
        let mut stmt = self
            .get_conn()?
            .prepare(&format!(
                "SELECT spn FROM {}.idx_uuid2spn WHERE uuid = :uuid",
                self.get_db_name()
            ))
            .map_err(sqlite_error)?;
        let spn_raw: Option<Vec<u8>> = stmt
            .query_row(&[(":uuid", &uuids)], |row| row.get(0))
            // We don't mind if it doesn't exist
            .optional()
            .map_err(sqlite_error)?;

        let spn: Option<Value> = match spn_raw {
            Some(d) => {
                let dbv: DbIdentSpn =
                    serde_json::from_slice(d.as_slice()).map_err(serde_json_error)?;

                Some(Value::from(dbv))
            }
            None => None,
        };

        Ok(spn)
    }

    fn uuid2rdn(&mut self, uuid: Uuid) -> Result<Option<String>, OperationError> {
        let uuids = uuid.as_hyphenated().to_string();
        // The table exists - lets now get the actual index itself.
        let mut stmt = self
            .get_conn()?
            .prepare(&format!(
                "SELECT rdn FROM {}.idx_uuid2rdn WHERE uuid = :uuid",
                self.get_db_name()
            ))
            .map_err(sqlite_error)?;
        let rdn: Option<String> = stmt
            .query_row(&[(":uuid", &uuids)], |row| row.get(0))
            // We don't mind if it doesn't exist
            .optional()
            .map_err(sqlite_error)?;

        Ok(rdn)
    }

    fn get_db_s_uuid(&self) -> Result<Option<Uuid>, OperationError> {
        // Try to get a value.
        let data: Option<Vec<u8>> = self
            .get_conn()?
            .query_row(
                &format!(
                    "SELECT data FROM {}.db_sid WHERE id = 2",
                    self.get_db_name()
                ),
                [],
                |row| row.get(0),
            )
            .optional()
            // this whole map call is useless
            .map(|e_opt| {
                // If we have a row, we try to make it a sid
                e_opt.map(|e| {
                    let y: Vec<u8> = e;
                    y
                })
                // If no sid, we return none.
            })
            .map_err(|_| OperationError::SqliteError)?;

        Ok(match data {
            Some(d) => Some(
                serde_json::from_slice(d.as_slice())
                    .or_else(|e| serde_cbor::from_slice(d.as_slice()).map_err(|_| e))
                    .map_err(|e| {
                        admin_error!(immediate = true, ?e, "CRITICAL: Serde CBOR Error");
                        eprintln!("CRITICAL: Serde CBOR Error -> {e:?}");
                        OperationError::SerdeCborError
                    })?,
            ),
            None => None,
        })
    }

    fn get_db_d_uuid(&self) -> Result<Option<Uuid>, OperationError> {
        // Try to get a value.
        let data: Option<Vec<u8>> = self
            .get_conn()?
            .query_row(
                &format!(
                    "SELECT data FROM {}.db_did WHERE id = 2",
                    self.get_db_name()
                ),
                [],
                |row| row.get(0),
            )
            .optional()
            // this whole map call is useless
            .map(|e_opt| {
                // If we have a row, we try to make it a sid
                e_opt.map(|e| {
                    let y: Vec<u8> = e;
                    y
                })
                // If no sid, we return none.
            })
            .map_err(|_| OperationError::SqliteError)?;

        Ok(match data {
            Some(d) => Some(
                serde_json::from_slice(d.as_slice())
                    .or_else(|e| serde_cbor::from_slice(d.as_slice()).map_err(|_| e))
                    .map_err(|e| {
                        admin_error!(immediate = true, ?e, "CRITICAL: Serde CBOR Error");
                        eprintln!("CRITICAL: Serde CBOR Error -> {e:?}");
                        OperationError::SerdeCborError
                    })?,
            ),
            None => None,
        })
    }

    fn get_db_ts_max(&self) -> Result<Option<Duration>, OperationError> {
        // Try to get a value.
        let data: Option<Vec<u8>> = self
            .get_conn()?
            .query_row(
                &format!(
                    "SELECT data FROM {}.db_op_ts WHERE id = 1",
                    self.get_db_name()
                ),
                [],
                |row| row.get(0),
            )
            .optional()
            .map(|e_opt| {
                // If we have a row, we try to make it a sid
                e_opt.map(|e| {
                    let y: Vec<u8> = e;
                    y
                })
                // If no sid, we return none.
            })
            .map_err(sqlite_error)?;

        Ok(match data {
            Some(d) => Some(
                serde_json::from_slice(d.as_slice())
                    .or_else(|_| serde_cbor::from_slice(d.as_slice()))
                    .map_err(|e| {
                        admin_error!(immediate = true, ?e, "CRITICAL: Serde JSON Error");
                        eprintln!("CRITICAL: Serde JSON Error -> {e:?}");
                        OperationError::SerdeJsonError
                    })?,
            ),
            None => None,
        })
    }

    fn get_key_handles(&mut self) -> Result<BTreeMap<KeyHandleId, KeyHandle>, OperationError> {
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

    #[instrument(level = "debug", name = "idl_sqlite::get_allids", skip_all)]
    fn get_allids(&self) -> Result<IDLBitRange, OperationError> {
        let mut stmt = self
            .get_conn()?
            .prepare(&format!("SELECT id FROM {}.id2entry", self.get_db_name()))
            .map_err(sqlite_error)?;
        let res = stmt.query_map([], |row| row.get(0)).map_err(sqlite_error)?;
        let mut ids: Result<IDLBitRange, _> = res
            .map(|v| {
                v.map_err(sqlite_error).and_then(|id: i64| {
                    // Convert the idsqlite to id raw
                    id.try_into().map_err(|e| {
                        admin_error!(?e, "I64 Parse Error");
                        OperationError::SqliteError
                    })
                })
            })
            .collect();
        if let Ok(i) = &mut ids {
            i.compress()
        }
        ids
    }

    fn list_idxs(&self) -> Result<Vec<String>, OperationError> {
        let mut stmt = self
            .get_conn()?
            .prepare(&format!(
                "SELECT name from {}.sqlite_master where type='table' and name GLOB 'idx_*'",
                self.get_db_name()
            ))
            .map_err(sqlite_error)?;
        let idx_table_iter = stmt.query_map([], |row| row.get(0)).map_err(sqlite_error)?;

        idx_table_iter.map(|v| v.map_err(sqlite_error)).collect()
    }

    fn list_id2entry(&self) -> Result<Vec<(u64, String)>, OperationError> {
        let allids = self.get_identry_raw(&IdList::AllIds)?;
        allids
            .into_iter()
            .map(|data| data.into_dbentry().map(|(id, db_e)| (id, db_e.to_string())))
            .collect()
    }

    fn list_quarantined(&self) -> Result<Vec<(u64, String)>, OperationError> {
        // This is a more direct version of get_identry_raw adapted for the simpler
        // quarantine setup.
        let mut stmt = self
            .get_conn()?
            .prepare(&format!(
                "SELECT id, data FROM {}.id2entry_quarantine",
                self.get_db_name()
            ))
            .map_err(sqlite_error)?;
        let id2entry_iter = stmt
            .query_map([], |row| {
                Ok(IdSqliteEntry {
                    id: row.get(0)?,
                    data: row.get(1)?,
                })
            })
            .map_err(sqlite_error)?;
        let allids = id2entry_iter
            .map(|v| {
                v.map_err(sqlite_error).and_then(|ise| {
                    // Convert the idsqlite to id raw
                    ise.try_into()
                })
            })
            .collect::<Result<Vec<IdRawEntry>, _>>()?;

        allids
            .into_iter()
            .map(|data| data.into_dbentry().map(|(id, db_e)| (id, db_e.to_string())))
            .collect()
    }

    fn get_id2entry(&self, id: u64) -> Result<(u64, String), OperationError> {
        let idl = IdList::Indexed(IDLBitRange::from_u64(id));
        let mut allids = self.get_identry_raw(&idl)?;
        allids
            .pop()
            .ok_or(OperationError::InvalidEntryId)
            .and_then(|data| {
                data.into_dbentry()
                    .map(|(id, db_e)| (id, format!("{db_e:?}")))
            })
    }

    fn list_index_content(
        &self,
        index_name: &str,
    ) -> Result<Vec<(String, IDLBitRange)>, OperationError> {
        // TODO: Once we have slopes we can add .exists_table, and assert
        // it's an idx table.

        let query = format!("SELECT key, idl FROM {}.{}", self.get_db_name(), index_name);
        let mut stmt = self
            .get_conn()?
            .prepare(query.as_str())
            .map_err(sqlite_error)?;

        let idx_iter = stmt
            .query_map([], |row| {
                Ok(KeyIdl {
                    key: row.get(0)?,
                    data: row.get(1)?,
                })
            })
            .map_err(sqlite_error)?;
        idx_iter
            .map(|v| {
                v.map_err(sqlite_error).and_then(|KeyIdl { key, data }| {
                    serde_json::from_slice(data.as_slice())
                        .map_err(serde_json_error)
                        .map(|idl| (key, idl))
                })
            })
            .collect()
    }

    // This allow is critical as it resolves a life time issue in stmt.
    #[allow(clippy::let_and_return)]
    fn verify(&self) -> Vec<Result<(), ConsistencyError>> {
        let Ok(conn) = self.get_conn() else {
            return vec![Err(ConsistencyError::SqliteIntegrityFailure)];
        };

        let Ok(mut stmt) = conn.prepare("PRAGMA integrity_check;") else {
            return vec![Err(ConsistencyError::SqliteIntegrityFailure)];
        };

        // Allow this as it actually extends the life of stmt
        let r = match stmt.query([]) {
            Ok(mut rows) => match rows.next() {
                Ok(Some(v)) => {
                    let r: Result<String, _> = v.get(0);
                    match r {
                        Ok(t) if t == "ok" => vec![],
                        _ => vec![Err(ConsistencyError::SqliteIntegrityFailure)],
                    }
                }
                _ => vec![Err(ConsistencyError::SqliteIntegrityFailure)],
            },
            Err(_) => vec![Err(ConsistencyError::SqliteIntegrityFailure)],
        };
        r
    }
}

impl IdlSqliteTransaction for IdlSqliteReadTransaction {
    fn get_db_name(&self) -> &str {
        self.db_name
    }

    fn get_conn(&self) -> Result<&Connection, OperationError> {
        self.conn
            .as_ref()
            .ok_or(OperationError::TransactionAlreadyCommitted)
    }
}

impl Drop for IdlSqliteReadTransaction {
    // Abort - so far this has proven reliable to use drop here.
    fn drop(&mut self) {
        let mut dropping = None;
        std::mem::swap(&mut dropping, &mut self.conn);

        if let Some(conn) = dropping {
            #[allow(clippy::expect_used)]
            conn.execute("ROLLBACK TRANSACTION", [])
                .expect("Unable to rollback transaction! Can not proceed!!!");

            #[allow(clippy::expect_used)]
            self.pool
                .lock()
                .expect("Unable to access db pool")
                .push_back(conn);
        }
    }
}

impl IdlSqliteReadTransaction {
    pub fn new(
        pool: ConnPool,
        conn: Connection,
        db_name: &'static str,
    ) -> Result<Self, OperationError> {
        // Start the transaction
        //
        // I'm happy for this to be an expect, because this is a huge failure
        // of the server ... but if it happens a lot we should consider making
        // this a Result<>
        //
        // There is no way to flag this is an RO operation.
        conn.execute("BEGIN DEFERRED TRANSACTION", [])
            .map_err(sqlite_error)?;

        Ok(IdlSqliteReadTransaction {
            pool,
            conn: Some(conn),
            db_name,
        })
    }
}

impl IdlSqliteTransaction for IdlSqliteWriteTransaction {
    fn get_db_name(&self) -> &str {
        self.db_name
    }

    fn get_conn(&self) -> Result<&Connection, OperationError> {
        self.conn
            .as_ref()
            .ok_or(OperationError::TransactionAlreadyCommitted)
    }
}

impl Drop for IdlSqliteWriteTransaction {
    // Abort
    fn drop(&mut self) {
        let mut dropping = None;
        std::mem::swap(&mut dropping, &mut self.conn);

        if let Some(conn) = dropping {
            #[allow(clippy::expect_used)]
            conn.execute("ROLLBACK TRANSACTION", [])
                .expect("Unable to rollback transaction! Can not proceed!!!");

            #[allow(clippy::expect_used)]
            self.pool
                .lock()
                .expect("Unable to access db pool")
                .push_back(conn);
        }
    }
}

impl IdlSqliteWriteTransaction {
    pub fn new(
        pool: ConnPool,
        conn: Connection,
        db_name: &'static str,
    ) -> Result<Self, OperationError> {
        // Start the transaction
        conn.execute("BEGIN EXCLUSIVE TRANSACTION", [])
            .map_err(sqlite_error)?;
        Ok(IdlSqliteWriteTransaction {
            pool,
            conn: Some(conn),
            db_name,
        })
    }

    #[instrument(level = "debug", name = "idl_sqlite::commit", skip_all)]
    pub fn commit(mut self) -> Result<(), OperationError> {
        debug_assert!(self.conn.is_some());

        let mut dropping = None;
        std::mem::swap(&mut dropping, &mut self.conn);

        if let Some(conn) = dropping {
            conn.execute("COMMIT TRANSACTION", [])
                .map(|_| ())
                .map_err(|e| {
                    admin_error!(?e, "CRITICAL: failed to commit sqlite txn");
                    OperationError::BackendEngine
                })?;

            self.pool
                .lock()
                .map_err(|err| {
                    error!(?err, "Unable to return connection to pool");
                    OperationError::BackendEngine
                })?
                .push_back(conn);

            Ok(())
        } else {
            Err(OperationError::TransactionAlreadyCommitted)
        }
    }

    pub fn get_id2entry_max_id(&self) -> Result<u64, OperationError> {
        let mut stmt = self
            .get_conn()?
            .prepare(&format!(
                "SELECT MAX(id) as id_max FROM {}.id2entry",
                self.get_db_name(),
            ))
            .map_err(sqlite_error)?;
        // This exists checks for if any rows WERE returned
        // that way we know to shortcut or not.
        let v = stmt.exists([]).map_err(sqlite_error)?;

        if v {
            // We have some rows, let get max!
            let i: Option<i64> = stmt.query_row([], |row| row.get(0)).map_err(sqlite_error)?;
            i.unwrap_or(0)
                .try_into()
                .map_err(|_| OperationError::InvalidEntryId)
        } else {
            // No rows are present, return a 0.
            Ok(0)
        }
    }

    pub fn write_identry(
        &self,
        entry: &Entry<EntrySealed, EntryCommitted>,
    ) -> Result<(), OperationError> {
        let dbe = entry.to_dbentry();
        let data = serde_json::to_vec(&dbe).map_err(serde_json_error)?;

        let raw_entries = std::iter::once(IdRawEntry {
            id: entry.get_id(),
            data,
        });

        self.write_identries_raw(raw_entries)
    }

    pub fn write_identries_raw<I>(&self, mut entries: I) -> Result<(), OperationError>
    where
        I: Iterator<Item = IdRawEntry>,
    {
        let mut stmt = self
            .get_conn()?
            .prepare(&format!(
                "INSERT OR REPLACE INTO {}.id2entry (id, data) VALUES(:id, :data)",
                self.get_db_name()
            ))
            .map_err(sqlite_error)?;

        entries.try_for_each(|e| {
            IdSqliteEntry::try_from(e).and_then(|ser_ent| {
                stmt.execute(named_params! {
                    ":id": &ser_ent.id,
                    ":data": &ser_ent.data.as_slice()
                })
                // remove the updated usize
                .map(|_| ())
                .map_err(sqlite_error)
            })
        })
    }

    pub fn delete_identry(&self, id: u64) -> Result<(), OperationError> {
        let mut stmt = self
            .get_conn()?
            .prepare(&format!(
                "DELETE FROM {}.id2entry WHERE id = :id",
                self.get_db_name()
            ))
            .map_err(sqlite_error)?;

        let iid: i64 = id
            .try_into()
            .map_err(|_| OperationError::InvalidEntryId)
            .and_then(|i| {
                if i > 0 {
                    Ok(i)
                } else {
                    Err(OperationError::InvalidEntryId)
                }
            })?;

        debug_assert!(iid > 0);

        stmt.execute([&iid]).map(|_| ()).map_err(sqlite_error)
    }

    pub fn write_idl(
        &self,
        attr: &str,
        itype: IndexType,
        idx_key: &str,
        idl: &IDLBitRange,
    ) -> Result<(), OperationError> {
        if idl.is_empty() {
            // delete it
            // Delete this idx_key from the table.
            let query = format!(
                "DELETE FROM {}.idx_{}_{} WHERE key = :key",
                self.get_db_name(),
                itype.as_idx_str(),
                attr
            );

            self.get_conn()?
                .prepare(query.as_str())
                .and_then(|mut stmt| stmt.execute(&[(":key", &idx_key)]))
                .map_err(sqlite_error)
        } else {
            // Serialise the IdList to Vec<u8>
            let idl_raw = serde_json::to_vec(idl).map_err(serde_json_error)?;

            // update or create it.
            let query = format!(
                "INSERT OR REPLACE INTO {}.idx_{}_{} (key, idl) VALUES(:key, :idl)",
                self.get_db_name(),
                itype.as_idx_str(),
                attr
            );

            self.get_conn()?
                .prepare(query.as_str())
                .and_then(|mut stmt| {
                    stmt.execute(named_params! {
                        ":key": &idx_key,
                        ":idl": &idl_raw
                    })
                })
                .map_err(sqlite_error)
        }
        // Get rid of the sqlite rows usize
        .map(|_| ())
    }

    pub fn create_name2uuid(&self) -> Result<(), OperationError> {
        self.get_conn()?
            .execute(
                &format!("CREATE TABLE IF NOT EXISTS {}.idx_name2uuid (name TEXT PRIMARY KEY, uuid TEXT)", self.get_db_name()),
                [],
            )
            .map(|_| ())
            .map_err(sqlite_error)
    }

    pub fn write_name2uuid_add(&self, name: &str, uuid: Uuid) -> Result<(), OperationError> {
        let uuids = uuid.as_hyphenated().to_string();

        self.get_conn()?
            .prepare(&format!(
                "INSERT OR REPLACE INTO {}.idx_name2uuid (name, uuid) VALUES(:name, :uuid)",
                self.get_db_name()
            ))
            .and_then(|mut stmt| {
                stmt.execute(named_params! {
                    ":name": &name,
                    ":uuid": uuids.as_str()
                })
            })
            .map(|_| ())
            .map_err(sqlite_error)
    }

    pub fn write_name2uuid_rem(&self, name: &str) -> Result<(), OperationError> {
        self.get_conn()?
            .prepare(&format!(
                "DELETE FROM {}.idx_name2uuid WHERE name = :name",
                self.get_db_name()
            ))
            .and_then(|mut stmt| stmt.execute(&[(":name", &name)]))
            .map(|_| ())
            .map_err(sqlite_error)
    }

    pub fn create_externalid2uuid(&self) -> Result<(), OperationError> {
        self.get_conn()?
            .execute(
                &format!("CREATE TABLE IF NOT EXISTS {}.idx_externalid2uuid (eid TEXT PRIMARY KEY, uuid TEXT)", self.get_db_name()),
                [],
            )
            .map(|_| ())
            .map_err(sqlite_error)
    }

    pub fn write_externalid2uuid_add(&self, name: &str, uuid: Uuid) -> Result<(), OperationError> {
        let uuids = uuid.as_hyphenated().to_string();

        self.get_conn()?
            .prepare(&format!(
                "INSERT OR REPLACE INTO {}.idx_externalid2uuid (eid, uuid) VALUES(:eid, :uuid)",
                self.get_db_name()
            ))
            .and_then(|mut stmt| {
                stmt.execute(named_params! {
                    ":eid": &name,
                    ":uuid": uuids.as_str()
                })
            })
            .map(|_| ())
            .map_err(sqlite_error)
    }

    pub fn write_externalid2uuid_rem(&self, name: &str) -> Result<(), OperationError> {
        self.get_conn()?
            .prepare(&format!(
                "DELETE FROM {}.idx_externalid2uuid WHERE eid = :eid",
                self.get_db_name()
            ))
            .and_then(|mut stmt| stmt.execute(&[(":eid", &name)]))
            .map(|_| ())
            .map_err(sqlite_error)
    }

    pub fn create_uuid2spn(&self) -> Result<(), OperationError> {
        self.get_conn()?
            .execute(
                &format!(
                    "CREATE TABLE IF NOT EXISTS {}.idx_uuid2spn (uuid TEXT PRIMARY KEY, spn BLOB)",
                    self.get_db_name()
                ),
                [],
            )
            .map(|_| ())
            .map_err(sqlite_error)
    }

    fn migrate_dbentryv1_to_dbentryv2(&self) -> Result<(), OperationError> {
        let allids = self.get_identry_raw(&IdList::AllIds)?;
        let raw_entries: Result<Vec<IdRawEntry>, _> = allids
            .into_iter()
            .map(|raw| {
                serde_cbor::from_slice(raw.data.as_slice())
                    .map_err(|e| {
                        admin_error!(?e, "Serde CBOR Error");
                        OperationError::SerdeCborError
                    })
                    .and_then(|dbe: DbEntry| dbe.convert_to_v2())
                    .and_then(|dbe| {
                        serde_json::to_vec(&dbe)
                            .map(|data| IdRawEntry { id: raw.id, data })
                            .map_err(|e| {
                                admin_error!(?e, "Serde Json Error");
                                OperationError::SerdeJsonError
                            })
                    })
            })
            .collect();

        self.write_identries_raw(raw_entries?.into_iter())
    }

    fn migrate_dbentryv2_to_dbentryv3(&self) -> Result<(), OperationError> {
        // To perform this migration we have to load everything to a valid entry, then
        // write them all back down once their change states are created.
        let all_entries = self.get_identry(&IdList::AllIds)?;

        for entry in all_entries {
            self.write_identry(&entry)?;
        }

        Ok(())
    }

    pub fn write_uuid2spn(&self, uuid: Uuid, k: Option<&Value>) -> Result<(), OperationError> {
        let uuids = uuid.as_hyphenated().to_string();
        match k {
            Some(k) => {
                let dbv1: DbIdentSpn = k.to_db_ident_spn();
                let data = serde_json::to_vec(&dbv1).map_err(serde_json_error)?;
                self.get_conn()?
                    .prepare(&format!(
                        "INSERT OR REPLACE INTO {}.idx_uuid2spn (uuid, spn) VALUES(:uuid, :spn)",
                        self.get_db_name()
                    ))
                    .and_then(|mut stmt| {
                        stmt.execute(named_params! {
                            ":uuid": &uuids,
                            ":spn": &data,
                        })
                    })
                    .map(|_| ())
                    .map_err(sqlite_error)
            }
            None => self
                .get_conn()?
                .prepare(&format!(
                    "DELETE FROM {}.idx_uuid2spn WHERE uuid = :uuid",
                    self.get_db_name()
                ))
                .and_then(|mut stmt| stmt.execute(&[(":uuid", &uuids)]))
                .map(|_| ())
                .map_err(sqlite_error),
        }
    }

    pub fn create_uuid2rdn(&self) -> Result<(), OperationError> {
        self.get_conn()?
            .execute(
                &format!(
                    "CREATE TABLE IF NOT EXISTS {}.idx_uuid2rdn (uuid TEXT PRIMARY KEY, rdn TEXT)",
                    self.get_db_name()
                ),
                [],
            )
            .map(|_| ())
            .map_err(sqlite_error)
    }

    pub fn write_uuid2rdn(&self, uuid: Uuid, k: Option<&String>) -> Result<(), OperationError> {
        let uuids = uuid.as_hyphenated().to_string();
        match k {
            Some(k) => self
                .get_conn()?
                .prepare(&format!(
                    "INSERT OR REPLACE INTO {}.idx_uuid2rdn (uuid, rdn) VALUES(:uuid, :rdn)",
                    self.get_db_name()
                ))
                .and_then(|mut stmt| stmt.execute(&[(":uuid", &uuids), (":rdn", k)]))
                .map(|_| ())
                .map_err(sqlite_error),
            None => self
                .get_conn()?
                .prepare(&format!(
                    "DELETE FROM {}.idx_uuid2rdn WHERE uuid = :uuid",
                    self.get_db_name()
                ))
                .and_then(|mut stmt| stmt.execute(&[(":uuid", &uuids)]))
                .map(|_| ())
                .map_err(sqlite_error),
        }
    }

    pub(crate) fn create_keyhandles(&self) -> Result<(), OperationError> {
        self.get_conn()?
            .execute(
                &format!(
                    "CREATE TABLE IF NOT EXISTS {}.keyhandles (id TEXT PRIMARY KEY, data TEXT)",
                    self.get_db_name()
                ),
                [],
            )
            .map(|_| ())
            .map_err(sqlite_error)
    }

    pub(crate) fn create_db_ruv(&self) -> Result<(), OperationError> {
        self.get_conn()?
            .execute(
                &format!(
                    "CREATE TABLE IF NOT EXISTS {}.ruv (cid TEXT PRIMARY KEY)",
                    self.get_db_name()
                ),
                [],
            )
            .map(|_| ())
            .map_err(sqlite_error)
    }

    pub fn get_db_ruv(&self) -> Result<BTreeSet<Cid>, OperationError> {
        let mut stmt = self
            .get_conn()?
            .prepare(&format!("SELECT cid FROM {}.ruv", self.get_db_name()))
            .map_err(sqlite_error)?;

        let kh_iter = stmt.query_map([], |row| row.get(0)).map_err(sqlite_error)?;

        kh_iter
            .map(|v| {
                let ser_cid: String = v.map_err(sqlite_error)?;
                let db_cid: DbCidV1 = serde_json::from_str(&ser_cid).map_err(serde_json_error)?;
                Ok(db_cid.into())
            })
            .collect()
    }

    pub fn write_db_ruv<I, J>(&mut self, mut added: I, mut removed: J) -> Result<(), OperationError>
    where
        I: Iterator<Item = Cid>,
        J: Iterator<Item = Cid>,
    {
        let mut stmt = self
            .get_conn()?
            .prepare(&format!(
                "DELETE FROM {}.ruv WHERE cid = :cid",
                self.get_db_name()
            ))
            .map_err(sqlite_error)?;

        removed.try_for_each(|cid| {
            let db_cid: DbCidV1 = cid.into();

            serde_json::to_string(&db_cid)
                .map_err(serde_json_error)
                .and_then(|ser_cid| {
                    stmt.execute(named_params! {
                        ":cid": &ser_cid
                    })
                    // remove the updated usize
                    .map(|_| ())
                    .map_err(sqlite_error)
                })
        })?;

        let mut stmt = self
            .get_conn()?
            .prepare(&format!(
                "INSERT OR REPLACE INTO {}.ruv (cid) VALUES(:cid)",
                self.get_db_name()
            ))
            .map_err(sqlite_error)?;

        added.try_for_each(|cid| {
            let db_cid: DbCidV1 = cid.into();

            serde_json::to_string(&db_cid)
                .map_err(serde_json_error)
                .and_then(|ser_cid| {
                    stmt.execute(named_params! {
                        ":cid": &ser_cid
                    })
                    // remove the updated usize
                    .map(|_| ())
                    .map_err(sqlite_error)
                })
        })
    }

    pub fn create_idx(&self, attr: Attribute, itype: IndexType) -> Result<(), OperationError> {
        // Is there a better way than formatting this? I can't seem
        // to template into the str.
        //
        // We could also re-design our idl storage.
        let idx_stmt = format!(
            "CREATE TABLE IF NOT EXISTS {}.idx_{}_{} (key TEXT PRIMARY KEY, idl BLOB)",
            self.get_db_name(),
            itype.as_idx_str(),
            attr
        );
        trace!(idx = %idx_stmt, "creating index");

        self.get_conn()?
            .execute(idx_stmt.as_str(), [])
            .map(|_| ())
            .map_err(sqlite_error)
    }

    /// ⚠️  - This function will destroy all indexes in the database.
    ///
    /// It should only be called internally by the backend in limited and
    /// specific situations.
    #[instrument(level = "trace", skip_all)]
    pub fn danger_purge_idxs(&self) -> Result<(), OperationError> {
        let idx_table_list = self.list_idxs()?;
        trace!(tables = ?idx_table_list);

        idx_table_list.iter().try_for_each(|idx_table| {
            debug!(table = ?idx_table, "removing idx_table");
            self.get_conn()?
                .prepare(format!("DROP TABLE {}.{}", self.get_db_name(), idx_table).as_str())
                .and_then(|mut stmt| stmt.execute([]).map(|_| ()))
                .map_err(sqlite_error)
        })
    }

    pub fn store_idx_slope_analysis(
        &self,
        slopes: &HashMap<IdxKey, IdxSlope>,
    ) -> Result<(), OperationError> {
        self.get_conn()?
            .execute(
                &format!(
                    "CREATE TABLE IF NOT EXISTS {}.idxslope_analysis (
                    id TEXT PRIMARY KEY,
                    slope INTEGER
                )",
                    self.get_db_name()
                ),
                [],
            )
            .map(|_| ())
            .map_err(sqlite_error)?;

        // Remove any data if it exists.
        self.get_conn()?
            .execute(
                &format!("DELETE FROM {}.idxslope_analysis", self.get_db_name()),
                [],
            )
            .map(|_| ())
            .map_err(sqlite_error)?;

        slopes.iter().try_for_each(|(k, v)| {
            let key = format!("idx_{}_{}", k.itype.as_idx_str(), k.attr);
            self.get_conn()?
                .execute(
                    &format!("INSERT OR REPLACE INTO {}.idxslope_analysis (id, slope) VALUES(:id, :slope)", self.get_db_name()),
                    named_params! {
                        ":id": &key,
                        ":slope": &v,
                    },
                )
                .map(|_| ())
                .map_err(|e| {
                    admin_error!(immediate = true, ?e, "CRITICAL: rusqlite error in store_idx_slope_analysis");
                    eprintln!("CRITICAL: rusqlite error in store_idx_slope_analysis: {e:?}");
                    OperationError::SqliteError
                })
        })
    }

    pub fn is_idx_slopeyness_generated(&self) -> Result<bool, OperationError> {
        self.exists_table("idxslope_analysis")
    }

    pub fn get_idx_slope(&self, ikey: &IdxKey) -> Result<Option<IdxSlope>, OperationError> {
        let analysis_exists = self.exists_table("idxslope_analysis")?;
        if !analysis_exists {
            return Ok(None);
        }

        // Then we have the table and it should have things in it, lets put
        // it all together.
        let key = format!("idx_{}_{}", ikey.itype.as_idx_str(), ikey.attr);

        let mut stmt = self
            .get_conn()?
            .prepare(&format!(
                "SELECT slope FROM {}.idxslope_analysis WHERE id = :id",
                self.get_db_name()
            ))
            .map_err(sqlite_error)?;

        let slope: Option<IdxSlope> = stmt
            .query_row(&[(":id", &key)], |row| row.get(0))
            // We don't mind if it doesn't exist
            .optional()
            .map_err(sqlite_error)?;
        trace!(name = %key, ?slope, "Got slope for index");

        Ok(slope)
    }

    pub fn quarantine_entry(&self, id: u64) -> Result<(), OperationError> {
        let iid = i64::try_from(id).map_err(|_| OperationError::InvalidEntryId)?;

        let id_sqlite_entry = self
            .get_conn()?
            .query_row(
                &format!(
                    "DELETE FROM {}.id2entry WHERE id = :idl RETURNING id, data",
                    self.get_db_name()
                ),
                [&iid],
                |row| {
                    Ok(IdSqliteEntry {
                        id: row.get(0)?,
                        data: row.get(1)?,
                    })
                },
            )
            .map_err(sqlite_error)?;

        trace!(?id_sqlite_entry);

        self.get_conn()?
            .execute(
                &format!(
                    "INSERT OR REPLACE INTO {}.id2entry_quarantine VALUES(:id, :data)",
                    self.get_db_name()
                ),
                named_params! {
                    ":id": &id_sqlite_entry.id,
                    ":data": &id_sqlite_entry.data.as_slice()
                },
            )
            .map_err(sqlite_error)
            .map(|_| ())
    }

    pub fn restore_quarantined(&self, id: u64) -> Result<(), OperationError> {
        let iid = i64::try_from(id).map_err(|_| OperationError::InvalidEntryId)?;

        let id_sqlite_entry = self
            .get_conn()?
            .query_row(
                &format!(
                    "DELETE FROM {}.id2entry_quarantine WHERE id = :idl RETURNING id, data",
                    self.get_db_name()
                ),
                [&iid],
                |row| {
                    Ok(IdSqliteEntry {
                        id: row.get(0)?,
                        data: row.get(1)?,
                    })
                },
            )
            .map_err(sqlite_error)?;

        trace!(?id_sqlite_entry);

        self.get_conn()?
            .execute(
                &format!(
                    "INSERT INTO {}.id2entry VALUES(:id, :data)",
                    self.get_db_name()
                ),
                named_params! {
                    ":id": &id_sqlite_entry.id,
                    ":data": &id_sqlite_entry.data.as_slice()
                },
            )
            .map_err(sqlite_error)
            .map(|_| ())
    }

    /// ⚠️  - This function will destroy all entries in the database.
    ///
    /// It should only be called internally by the backend in limited and
    /// specific situations.
    #[instrument(level = "trace", skip_all)]
    pub fn danger_purge_id2entry(&self) -> Result<(), OperationError> {
        self.get_conn()?
            .execute(&format!("DELETE FROM {}.id2entry", self.get_db_name()), [])
            .map(|_| ())
            .map_err(sqlite_error)
    }

    pub fn write_db_s_uuid(&self, nsid: Uuid) -> Result<(), OperationError> {
        let data = serde_json::to_vec(&nsid).map_err(|e| {
            admin_error!(immediate = true, ?e, "CRITICAL: Serde JSON Error");
            eprintln!("CRITICAL: Serde JSON Error -> {e:?}");
            OperationError::SerdeJsonError
        })?;

        self.get_conn()?
            .execute(
                &format!(
                    "INSERT OR REPLACE INTO {}.db_sid (id, data) VALUES(:id, :sid)",
                    self.get_db_name()
                ),
                named_params! {
                    ":id": &2,
                    ":sid": &data,
                },
            )
            .map(|_| ())
            .map_err(|e| {
                admin_error!(
                    immediate = true,
                    ?e,
                    "CRITICAL: rusqlite error in write_db_s_uuid"
                );
                eprintln!("CRITICAL: rusqlite error in write_db_s_uuid {e:?}");
                OperationError::SqliteError
            })
    }

    pub fn write_db_d_uuid(&self, nsid: Uuid) -> Result<(), OperationError> {
        let data = serde_json::to_vec(&nsid).map_err(|e| {
            admin_error!(
                immediate = true,
                ?e,
                "CRITICAL: Serde JSON Error in write_db_d_uuid"
            );
            eprintln!("CRITICAL: Serde JSON Error  in write_db_d_uuid-> {e:?}");
            OperationError::SerdeJsonError
        })?;

        self.get_conn()?
            .execute(
                &format!(
                    "INSERT OR REPLACE INTO {}.db_did (id, data) VALUES(:id, :did)",
                    self.get_db_name()
                ),
                named_params! {
                    ":id": &2,
                    ":did": &data,
                },
            )
            .map(|_| ())
            .map_err(|e| {
                admin_error!(
                    immediate = true,
                    ?e,
                    "CRITICAL: rusqlite error in write_db_d_uuid"
                );
                eprintln!("CRITICAL: rusqlite error in write_db_d_uuid {e:?}");
                OperationError::SqliteError
            })
    }

    pub fn set_db_ts_max(&self, ts: Duration) -> Result<(), OperationError> {
        let data = serde_json::to_vec(&ts).map_err(|e| {
            admin_error!(
                immediate = true,
                ?e,
                "CRITICAL: Serde JSON Error in set_db_ts_max"
            );
            eprintln!("CRITICAL: Serde JSON Error in set_db_ts_max -> {e:?}");
            OperationError::SerdeJsonError
        })?;

        self.get_conn()?
            .execute(
                &format!(
                    "INSERT OR REPLACE INTO {}.db_op_ts (id, data) VALUES(:id, :did)",
                    self.get_db_name()
                ),
                named_params! {
                    ":id": &1,
                    ":did": &data,
                },
            )
            .map(|_| ())
            .map_err(|e| {
                admin_error!(
                    immediate = true,
                    ?e,
                    "CRITICAL: rusqlite error in set_db_ts_max"
                );
                eprintln!("CRITICAL: rusqlite error in set_db_ts_max {e:?}");
                OperationError::SqliteError
            })
    }

    // ===== inner helpers =====
    // Some of these are not self due to use in new()
    fn get_db_version_key(&self, key: &str) -> Result<i64, OperationError> {
        self.get_conn().map(|conn| {
            conn.query_row(
                &format!(
                    "SELECT version FROM {}.db_version WHERE id = :id",
                    self.get_db_name()
                ),
                &[(":id", &key)],
                |row| row.get(0),
            )
            .unwrap_or({
                // The value is missing, default to 0.
                0
            })
        })
    }

    fn set_db_version_key(&self, key: &str, v: i64) -> Result<(), OperationError> {
        self.get_conn()?
            .execute(
                &format!(
                    "INSERT OR REPLACE INTO {}.db_version (id, version) VALUES(:id, :dbv_id2entry)",
                    self.get_db_name()
                ),
                named_params! {
                    ":id": &key,
                    ":dbv_id2entry": v,
                },
            )
            .map(|_| ())
            .map_err(|e| {
                admin_error!(
                    immediate = true,
                    ?e,
                    "CRITICAL: rusqlite error in set_db_version_key"
                );
                eprintln!("CRITICAL: rusqlite error in set_db_version_key {e:?}");
                OperationError::SqliteError
            })
    }

    pub(crate) fn get_db_index_version(&self) -> Result<i64, OperationError> {
        self.get_db_version_key(DBV_INDEXV)
    }

    pub(crate) fn set_db_index_version(&self, v: i64) -> Result<(), OperationError> {
        self.set_db_version_key(DBV_INDEXV, v)
    }

    pub fn setup(&self) -> Result<(), OperationError> {
        // If the db_name is NOT main, we MAY need to create it as we are in
        // a test!
        trace!(db_name = %self.get_db_name(), "setup");
        if self.get_db_name() != "main" {
            warn!("Using non-default db-name - this database content WILL be lost!");
            // we need to attach the DB!
            self.get_conn()?
                .execute(&format!("ATTACH DATABASE '' AS {}", self.get_db_name()), [])
                .map_err(sqlite_error)?;
        };

        // This stores versions of components. For example:
        // ----------------------
        // | id       | version |
        // | id2entry | 1       |
        // | index    | 1       |
        // | schema   | 1       |
        // ----------------------
        //
        // This allows each component to initialise on it's own, be
        // rolled back individually, by upgraded in isolation, and more
        //
        // NEVER CHANGE THIS DEFINITION.
        self.get_conn()?
            .execute(
                &format!(
                    "CREATE TABLE IF NOT EXISTS {}.db_version (
                    id TEXT PRIMARY KEY,
                    version INTEGER
                )
                ",
                    self.get_db_name()
                ),
                [],
            )
            .map_err(sqlite_error)?;

        // If the table is empty, populate the versions as 0.
        let mut dbv_id2entry = self.get_db_version_key(DBV_ID2ENTRY)?;

        trace!(%dbv_id2entry);

        // Check db_version here.
        //   * if 0 -> create v1.
        if dbv_id2entry == 0 {
            self.get_conn()?
                .execute(
                    &format!(
                        "CREATE TABLE IF NOT EXISTS {}.id2entry (
                        id INTEGER PRIMARY KEY ASC,
                        data BLOB NOT NULL
                    )
                    ",
                        self.get_db_name()
                    ),
                    [],
                )
                .map_err(sqlite_error)?;

            self.get_conn()?
                .execute(
                    &format!(
                        "CREATE TABLE IF NOT EXISTS {}.db_sid (
                    id INTEGER PRIMARY KEY ASC,
                    data BLOB NOT NULL
                    )
                    ",
                        self.get_db_name()
                    ),
                    [],
                )
                .map_err(sqlite_error)?;

            dbv_id2entry = 1;

            info!(entry = %dbv_id2entry, "dbv_id2entry migrated (id2entry, db_sid)");
        }
        //   * if v1 -> add the domain uuid table
        if dbv_id2entry == 1 {
            self.get_conn()?
                .execute(
                    &format!(
                        "CREATE TABLE IF NOT EXISTS {}.db_did (
                        id INTEGER PRIMARY KEY ASC,
                        data BLOB NOT NULL
                    )
                    ",
                        self.get_db_name()
                    ),
                    [],
                )
                .map_err(sqlite_error)?;

            dbv_id2entry = 2;
            info!(entry = %dbv_id2entry, "dbv_id2entry migrated (db_did)");
        }
        //   * if v2 -> add the op max ts table.
        if dbv_id2entry == 2 {
            self.get_conn()?
                .execute(
                    &format!(
                        "CREATE TABLE IF NOT EXISTS {}.db_op_ts (
                        id INTEGER PRIMARY KEY ASC,
                        data BLOB NOT NULL
                    )
                    ",
                        self.get_db_name()
                    ),
                    [],
                )
                .map_err(sqlite_error)?;
            dbv_id2entry = 3;
            info!(entry = %dbv_id2entry, "dbv_id2entry migrated (db_op_ts)");
        }
        //   * if v3 -> create name2uuid, uuid2spn, uuid2rdn.
        if dbv_id2entry == 3 {
            self.create_name2uuid()
                .and_then(|_| self.create_uuid2spn())
                .and_then(|_| self.create_uuid2rdn())?;
            dbv_id2entry = 4;
            info!(entry = %dbv_id2entry, "dbv_id2entry migrated (name2uuid, uuid2spn, uuid2rdn)");
        }
        //   * if v4 -> migrate v1 to v2 entries.
        if dbv_id2entry == 4 {
            self.migrate_dbentryv1_to_dbentryv2()?;
            dbv_id2entry = 5;
            info!(entry = %dbv_id2entry, "dbv_id2entry migrated (dbentryv1 -> dbentryv2)");
        }
        //   * if v5 -> create externalid2uuid
        if dbv_id2entry == 5 {
            self.create_externalid2uuid()?;
            dbv_id2entry = 6;
            info!(entry = %dbv_id2entry, "dbv_id2entry migrated (externalid2uuid)");
        }
        //   * if v6 -> create id2entry_quarantine.
        if dbv_id2entry == 6 {
            self.get_conn()?
                .execute(
                    &format!(
                        "CREATE TABLE IF NOT EXISTS {}.id2entry_quarantine (
                        id INTEGER PRIMARY KEY ASC,
                        data BLOB NOT NULL
                    )
                    ",
                        self.get_db_name()
                    ),
                    [],
                )
                .map_err(sqlite_error)?;

            dbv_id2entry = 7;
            info!(entry = %dbv_id2entry, "dbv_id2entry migrated (quarantine)");
        }
        //   * if v7 -> create keyhandles storage.
        if dbv_id2entry == 7 {
            self.create_keyhandles()?;
            dbv_id2entry = 8;
            info!(entry = %dbv_id2entry, "dbv_id2entry migrated (keyhandles)");
        }
        //   * if v8 -> migrate all entries to have a change state
        if dbv_id2entry == 8 {
            self.migrate_dbentryv2_to_dbentryv3()?;
            dbv_id2entry = 9;
            info!(entry = %dbv_id2entry, "dbv_id2entry migrated (dbentryv2 -> dbentryv3)");
        }
        //   * if v9 -> complete
        if dbv_id2entry == 9 {
            self.create_db_ruv()?;
            dbv_id2entry = 10;
            info!(entry = %dbv_id2entry, "dbv_id2entry migrated (db_ruv)");
        }
        //   * if v10 -> complete

        self.set_db_version_key(DBV_ID2ENTRY, dbv_id2entry)?;

        // NOTE: Indexing is configured in a different step!
        // Indexing uses a db version flag to represent the version
        // of the indexes representation on disk in case we change
        // it.
        Ok(())
    }
}

impl IdlSqlite {
    pub fn new(cfg: &BackendConfig, vacuum: bool) -> Result<Self, OperationError> {
        if cfg.path.is_empty() {
            debug_assert!(cfg.pool_size == 1);
        }
        // If provided, set the page size to match the tuning we want. By default we use 4096. The VACUUM
        // immediately after is so that on db create the page size takes effect.
        //
        // Enable WAL mode, which is just faster and better for our needs.
        let mut flags = OpenFlags::default();
        // Open with multi thread flags and locking options.

        if cfg!(test) {
            flags.insert(OpenFlags::SQLITE_OPEN_NO_MUTEX);
        };

        let fs_page_size = cfg.fstype as u32;
        let checkpoint_pages = cfg.fstype.checkpoint_pages();

        // Initial setup routines.
        {
            let vconn =
                Connection::open_with_flags(cfg.path.as_str(), flags).map_err(sqlite_error)?;

            vconn
                .execute_batch(
                    format!(
                        "PRAGMA page_size={fs_page_size};
                         PRAGMA journal_mode=WAL;
                         PRAGMA wal_autocheckpoint={checkpoint_pages};
                         PRAGMA wal_checkpoint(RESTART);"
                    )
                    .as_str(),
                )
                .map_err(sqlite_error)?;
        }

        // We need to run vacuum in the setup else we hit sqlite lock conditions.
        if vacuum {
            admin_warn!(
                immediate = true,
                "NOTICE: A db vacuum has been requested. This may take a long time ..."
            );
            /*
            limmediate_warning!(
                audit,
                "NOTICE: A db vacuum has been requested. This may take a long time ...\n"
            );
            */

            let vconn =
                Connection::open_with_flags(cfg.path.as_str(), flags).map_err(sqlite_error)?;

            vconn
                .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
                .map_err(|e| {
                    admin_error!(?e, "rusqlite wal_checkpoint error");
                    OperationError::SqliteError
                })?;

            vconn
                .pragma_update(None, "journal_mode", "DELETE")
                .map_err(|e| {
                    admin_error!(?e, "rusqlite journal_mode update error");
                    OperationError::SqliteError
                })?;

            vconn.close().map_err(|e| {
                admin_error!(?e, "rusqlite db close error");
                OperationError::SqliteError
            })?;

            let vconn =
                Connection::open_with_flags(cfg.path.as_str(), flags).map_err(sqlite_error)?;

            vconn
                .pragma_update(None, "page_size", cfg.fstype as u32)
                .map_err(|e| {
                    admin_error!(?e, "rusqlite page_size update error");
                    OperationError::SqliteError
                })?;

            vconn.execute_batch("VACUUM").map_err(|e| {
                admin_error!(?e, "rusqlite vacuum error");
                OperationError::SqliteError
            })?;

            vconn
                .pragma_update(None, "journal_mode", "WAL")
                .map_err(|e| {
                    admin_error!(?e, "rusqlite journal_mode update error");
                    OperationError::SqliteError
                })?;

            vconn.close().map_err(|e| {
                admin_error!(?e, "rusqlite db close error");
                OperationError::SqliteError
            })?;

            admin_warn!(immediate = true, "NOTICE: db vacuum complete");
            // limmediate_warning!(audit, "NOTICE: db vacuum complete\n");
        };

        let pool = (0..cfg.pool_size)
            .map(|i| {
                trace!("Opening Connection {}", i);
                let conn =
                    Connection::open_with_flags(cfg.path.as_str(), flags).map_err(sqlite_error);
                match conn {
                    Ok(conn) => {
                        // load the rusqlite vtab module to allow for virtual tables
                        rusqlite::vtab::array::load_module(&conn).map_err(|e| {
                            admin_error!(
                                "Failed to load rarray virtual module for sqlite, cannot start! {:?}", e
                            );
                            sqlite_error(e)
                        })?;
                        Ok(conn)
                    }
                    Err(err) => {
                        admin_error!(
                            "Failed to start database connection, cannot start! {:?}",
                            err
                        );
                        Err(err)
                    }
                }
            })
            .collect::<Result<VecDeque<Connection>, OperationError>>()
            .map_err(|e| {
                error!(err = ?e, "Failed to build connection pool");
                e
            })?;

        let pool = Arc::new(Mutex::new(pool));

        Ok(IdlSqlite {
            pool,
            db_name: cfg.db_name,
        })
    }

    pub(crate) fn get_allids_count(&self) -> Result<u64, OperationError> {
        let guard = self.pool.lock().map_err(|err| {
            error!(?err, "Unable to access connection to pool");
            OperationError::BackendEngine
        })?;
        // Get not pop here
        let conn = guard.front().ok_or_else(|| {
            error!("Unable to retrieve connection from pool");
            OperationError::BackendEngine
        })?;

        conn.query_row("select count(id) from id2entry", [], |row| row.get(0))
            .map_err(sqlite_error)
    }

    pub fn read(&self) -> Result<IdlSqliteReadTransaction, OperationError> {
        // This can't fail because we should only get here if a pool conn is available.
        let mut guard = self.pool.lock().map_err(|e| {
            error!(err = ?e, "Unable to lock connection pool.");
            OperationError::BackendEngine
        })?;

        let conn = guard.pop_front().ok_or_else(|| {
            error!("Unable to retrieve connection from pool.");
            OperationError::BackendEngine
        })?;

        IdlSqliteReadTransaction::new(self.pool.clone(), conn, self.db_name)
    }

    pub fn write(&self) -> Result<IdlSqliteWriteTransaction, OperationError> {
        // This can't fail because we should only get here if a pool conn is available.
        let mut guard = self.pool.lock().map_err(|e| {
            error!(err = ?e, "Unable to lock connection pool.");
            OperationError::BackendEngine
        })?;

        let conn = guard.pop_front().ok_or_else(|| {
            error!("Unable to retrieve connection from pool.");
            OperationError::BackendEngine
        })?;

        IdlSqliteWriteTransaction::new(self.pool.clone(), conn, self.db_name)
    }
}

#[cfg(test)]
mod tests {
    use crate::be::idl_sqlite::{IdlSqlite, IdlSqliteTransaction};
    use crate::be::BackendConfig;

    #[test]
    fn test_idl_sqlite_verify() {
        sketching::test_init();
        let cfg = BackendConfig::new_test("main");
        let be = IdlSqlite::new(&cfg, false).unwrap();
        let be_w = be.write().unwrap();
        let r = be_w.verify();
        assert!(r.is_empty());
    }
}
