use crate::audit::AuditScope;
use crate::be::{IdRawEntry, IDL};
use crate::entry::{Entry, EntryCommitted, EntrySealed};
use crate::value::IndexType;
use idlset::IDLBitRange;
use kanidm_proto::v1::{ConsistencyError, OperationError};
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::OptionalExtension;
use rusqlite::NO_PARAMS;
use std::convert::{TryFrom, TryInto};
use std::time::Duration;
use uuid::Uuid;

// use uuid::Uuid;

const DBV_ID2ENTRY: &str = "id2entry";
const DBV_INDEXV: &str = "indexv";

#[derive(Debug)]
pub struct IdSqliteEntry {
    id: i64,
    data: Vec<u8>,
}

impl TryFrom<IdSqliteEntry> for IdRawEntry {
    type Error = OperationError;

    fn try_from(value: IdSqliteEntry) -> Result<Self, Self::Error> {
        if value.id <= 0 {
            return Err(OperationError::InvalidEntryID);
        }
        Ok(IdRawEntry {
            id: value
                .id
                .try_into()
                .map_err(|_| OperationError::InvalidEntryID)?,
            data: value.data,
        })
    }
}

impl TryFrom<IdRawEntry> for IdSqliteEntry {
    type Error = OperationError;

    fn try_from(value: IdRawEntry) -> Result<Self, Self::Error> {
        if value.id <= 0 {
            return Err(OperationError::InvalidEntryID);
        }
        Ok(IdSqliteEntry {
            id: value
                .id
                .try_into()
                .map_err(|_| OperationError::InvalidEntryID)?,
            data: value.data,
        })
    }
}

#[derive(Clone)]
pub struct IdlSqlite {
    pool: Pool<SqliteConnectionManager>,
}

pub struct IdlSqliteReadTransaction {
    committed: bool,
    conn: r2d2::PooledConnection<SqliteConnectionManager>,
}

pub struct IdlSqliteWriteTransaction {
    committed: bool,
    conn: r2d2::PooledConnection<SqliteConnectionManager>,
}

pub trait IdlSqliteTransaction {
    fn get_conn(&self) -> &r2d2::PooledConnection<r2d2_sqlite::SqliteConnectionManager>;

    fn get_identry(
        &self,
        au: &mut AuditScope,
        idl: &IDL,
    ) -> Result<Vec<Entry<EntrySealed, EntryCommitted>>, OperationError> {
        lperf_segment!(au, "be::idl_sqlite::get_identry", || {
            self.get_identry_raw(au, idl)?
                .into_iter()
                .map(|ide| ide.into_entry(au))
                .collect()
        })
    }

    fn get_identry_raw(
        &self,
        au: &mut AuditScope,
        idl: &IDL,
    ) -> Result<Vec<IdRawEntry>, OperationError> {
        // is the idl allids?
        match idl {
            IDL::ALLIDS => {
                let mut stmt = try_audit!(
                    au,
                    self.get_conn().prepare("SELECT id, data FROM id2entry"),
                    "SQLite Error {:?}",
                    OperationError::SQLiteError
                );
                let id2entry_iter = try_audit!(
                    au,
                    stmt.query_map(NO_PARAMS, |row| Ok(IdSqliteEntry {
                        id: row.get(0)?,
                        data: row.get(1)?,
                    })),
                    "SQLite Error {:?}",
                    OperationError::SQLiteError
                );
                id2entry_iter
                    .map(|v| {
                        v.map_err(|e| {
                            ladmin_error!(au, "SQLite Error {:?}", e);
                            OperationError::SQLiteError
                        })
                        .and_then(|ise| {
                            // Convert the idsqlite to id raw
                            ise.try_into()
                        })
                    })
                    .collect()
            }
            IDL::Partial(idli) | IDL::PartialThreshold(idli) | IDL::Indexed(idli) => {
                let mut stmt = try_audit!(
                    au,
                    self.get_conn()
                        .prepare("SELECT id, data FROM id2entry WHERE id = :idl"),
                    "SQLite Error {:?}",
                    OperationError::SQLiteError
                );

                // TODO: I have no idea how to make this an iterator chain ... so what
                // I have now is probably really bad :(
                let mut results = Vec::new();

                for id in idli {
                    let iid = i64::try_from(id).map_err(|_| OperationError::InvalidEntryID)?;
                    let id2entry_iter = stmt
                        .query_map(&[&iid], |row| {
                            Ok(IdSqliteEntry {
                                id: row.get(0)?,
                                data: row.get(1)?,
                            })
                        })
                        .map_err(|e| {
                            ladmin_error!(au, "SQLite Error {:?}", e);
                            OperationError::SQLiteError
                        })?;

                    let r: Result<Vec<_>, _> = id2entry_iter
                        .map(|v| {
                            v.map_err(|e| {
                                ladmin_error!(au, "SQLite Error {:?}", e);
                                OperationError::SQLiteError
                            })
                            .and_then(|ise| {
                                // Convert the idsqlite to id raw
                                ise.try_into()
                            })
                        })
                        .collect();
                    let mut r = r?;
                    results.append(&mut r);
                }
                Ok(results)
            }
        }
    }

    fn exists_idx(
        &self,
        audit: &mut AuditScope,
        attr: &str,
        itype: &IndexType,
    ) -> Result<bool, OperationError> {
        let tname = format!("idx_{}_{}", itype.as_idx_str(), attr);
        let mut stmt = try_audit!(
            audit,
            self.get_conn()
                .prepare("SELECT COUNT(name) from sqlite_master where name = :tname"),
            "SQLite Error {:?}",
            OperationError::SQLiteError
        );
        let i: Option<i64> = try_audit!(
            audit,
            stmt.query_row_named(&[(":tname", &tname)], |row| row.get(0)),
            "SQLite Error {:?}",
            OperationError::SQLiteError
        );

        if i.unwrap_or(0) == 0 {
            Ok(false)
        } else {
            Ok(true)
        }
    }

    fn get_idl(
        &self,
        audit: &mut AuditScope,
        attr: &str,
        itype: &IndexType,
        idx_key: &str,
    ) -> Result<Option<IDLBitRange>, OperationError> {
        lperf_segment!(audit, "be::idl_sqlite::get_idl", || {
            if !(self.exists_idx(audit, attr, itype)?) {
                lfilter_error!(audit, "Index {:?} {:?} not found", itype, attr);
                return Ok(None);
            }
            // The table exists - lets now get the actual index itself.

            let query = format!(
                "SELECT idl FROM idx_{}_{} WHERE key = :idx_key",
                itype.as_idx_str(),
                attr
            );
            let mut stmt = try_audit!(
                audit,
                self.get_conn().prepare(query.as_str()),
                "SQLite Error {:?}",
                OperationError::SQLiteError
            );
            let idl_raw: Option<Vec<u8>> = try_audit!(
                audit,
                stmt.query_row_named(&[(":idx_key", &idx_key)], |row| row.get(0))
                    // We don't mind if it doesn't exist
                    .optional(),
                "SQLite Error {:?}",
                OperationError::SQLiteError
            );

            let idl = match idl_raw {
                Some(d) => serde_cbor::from_slice(d.as_slice())
                    .map_err(|_| OperationError::SerdeCborError)?,
                // We don't have this value, it must be empty (or we
                // have a corrupted index .....
                None => IDLBitRange::new(),
            };
            ltrace!(audit, "Got idl for index {:?} {:?} -> {}", itype, attr, idl);

            Ok(Some(idl))
        })
    }

    /*
    fn get_name2uuid(&self, name: &str) -> Result<Uuid, OperationError> {
        unimplemented!();
    }

    fn get_uuid2name(&self, uuid: &Uuid) -> Result<String, OperationError> {
        unimplemented!();
    }
    */

    fn get_db_s_uuid(&self) -> Result<Option<Uuid>, OperationError> {
        // Try to get a value.
        let data: Option<Vec<u8>> = self
            .get_conn()
            .query_row_named("SELECT data FROM db_sid WHERE id = 2", &[], |row| {
                row.get(0)
            })
            .optional()
            .map(|e_opt| {
                // If we have a row, we try to make it a sid
                e_opt.map(|e| {
                    let y: Vec<u8> = e;
                    y
                })
                // If no sid, we return none.
            })
            .map_err(|_| OperationError::SQLiteError)?;

        Ok(match data {
            Some(d) => Some(
                serde_cbor::from_slice(d.as_slice()).map_err(|_| OperationError::SerdeCborError)?,
            ),
            None => None,
        })
    }

    fn get_db_d_uuid(&self) -> Result<Option<Uuid>, OperationError> {
        // Try to get a value.
        let data: Option<Vec<u8>> = self
            .get_conn()
            .query_row_named("SELECT data FROM db_did WHERE id = 2", &[], |row| {
                row.get(0)
            })
            .optional()
            .map(|e_opt| {
                // If we have a row, we try to make it a sid
                e_opt.map(|e| {
                    let y: Vec<u8> = e;
                    y
                })
                // If no sid, we return none.
            })
            .map_err(|_| OperationError::SQLiteError)?;

        Ok(match data {
            Some(d) => Some(
                serde_cbor::from_slice(d.as_slice()).map_err(|_| OperationError::SerdeCborError)?,
            ),
            None => None,
        })
    }

    #[allow(clippy::let_and_return)]
    fn verify(&self) -> Vec<Result<(), ConsistencyError>> {
        let mut stmt = match self.get_conn().prepare("PRAGMA integrity_check;") {
            Ok(r) => r,
            Err(_) => return vec![Err(ConsistencyError::SqliteIntegrityFailure)],
        };

        // Allow this as it actually extends the life of stmt
        let r = match stmt.query(NO_PARAMS) {
            Ok(mut rows) => match rows.next() {
                Ok(Some(v)) => {
                    let r: Result<String, _> = v.get(0);
                    match r {
                        Ok(t) => {
                            if t == "ok" {
                                Vec::new()
                            } else {
                                vec![Err(ConsistencyError::SqliteIntegrityFailure)]
                            }
                        }
                        Err(_) => vec![Err(ConsistencyError::SqliteIntegrityFailure)],
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
    fn get_conn(&self) -> &r2d2::PooledConnection<r2d2_sqlite::SqliteConnectionManager> {
        &self.conn
    }
}

impl Drop for IdlSqliteReadTransaction {
    // Abort - so far this has proven reliable to use drop here.
    fn drop(self: &mut Self) {
        if !self.committed {
            self.conn
                .execute("ROLLBACK TRANSACTION", NO_PARAMS)
                // We can't do this without expect.
                // We may need to change how we do transactions to not rely on drop if
                // it becomes and issue :(
                .expect("Unable to rollback transaction! Can not proceed!!!");
        }
    }
}

impl IdlSqliteReadTransaction {
    pub fn new(conn: r2d2::PooledConnection<SqliteConnectionManager>) -> Self {
        // Start the transaction
        //
        // I'm happy for this to be an expect, because this is a huge failure
        // of the server ... but if it happens a lot we should consider making
        // this a Result<>
        //
        // There is no way to flag this is an RO operation.
        conn.execute("BEGIN TRANSACTION", NO_PARAMS)
            .expect("Unable to begin transaction!");
        IdlSqliteReadTransaction {
            committed: false,
            conn,
        }
    }
}

impl IdlSqliteTransaction for IdlSqliteWriteTransaction {
    fn get_conn(&self) -> &r2d2::PooledConnection<r2d2_sqlite::SqliteConnectionManager> {
        &self.conn
    }
}

impl Drop for IdlSqliteWriteTransaction {
    // Abort
    fn drop(self: &mut Self) {
        if !self.committed {
            self.conn
                .execute("ROLLBACK TRANSACTION", NO_PARAMS)
                .expect("Unable to rollback transaction! Can not proceed!!!");
        }
    }
}

impl IdlSqliteWriteTransaction {
    pub fn new(conn: r2d2::PooledConnection<SqliteConnectionManager>) -> Self {
        // Start the transaction
        conn.execute("BEGIN TRANSACTION", NO_PARAMS)
            .expect("Unable to begin transaction!");
        IdlSqliteWriteTransaction {
            committed: false,
            conn,
        }
    }

    pub fn commit(mut self, audit: &mut AuditScope) -> Result<(), OperationError> {
        lperf_segment!(audit, "be::idl_sqlite::commit", || {
            // ltrace!(audit, "Commiting BE WR txn");
            assert!(!self.committed);
            self.committed = true;

            self.conn
                .execute("COMMIT TRANSACTION", NO_PARAMS)
                .map(|_| ())
                .map_err(|e| {
                    ladmin_error!(audit, "CRITICAL: failed to commit sqlite txn -> {:?}", e);
                    OperationError::BackendEngine
                })
        })
    }

    pub fn get_id2entry_max_id(&self) -> Result<u64, OperationError> {
        let mut stmt = self
            .conn
            .prepare("SELECT MAX(id) as id_max FROM id2entry")
            .map_err(|_| OperationError::SQLiteError)?;
        // This exists checks for if any rows WERE returned
        // that way we know to shortcut or not.
        let v = stmt
            .exists(NO_PARAMS)
            .map_err(|_| OperationError::SQLiteError)?;

        if v {
            // We have some rows, let get max!
            let i: Option<i64> = stmt
                .query_row(NO_PARAMS, |row| row.get(0))
                .map_err(|_| OperationError::SQLiteError)?;
            i.unwrap_or(0)
                .try_into()
                .map_err(|_| OperationError::InvalidEntryID)
        } else {
            // No rows are present, return a 0.
            Ok(0)
        }
    }

    pub fn write_identries<'b, I>(
        &'b self,
        au: &mut AuditScope,
        entries: I,
    ) -> Result<(), OperationError>
    where
        I: Iterator<Item = &'b Entry<EntrySealed, EntryCommitted>>,
    {
        lperf_segment!(au, "be::idl_sqlite::write_identries", || {
            let raw_entries: Result<Vec<_>, _> = entries
                .map(|e| {
                    let dbe = e.to_dbentry();
                    let data =
                        serde_cbor::to_vec(&dbe).map_err(|_| OperationError::SerdeCborError)?;

                    Ok(IdRawEntry {
                        id: e.get_id(),
                        data,
                    })
                })
                .collect();
            self.write_identries_raw(au, raw_entries?.into_iter())
        })
    }

    pub fn write_identries_raw<I>(
        &self,
        au: &mut AuditScope,
        mut entries: I,
    ) -> Result<(), OperationError>
    where
        I: Iterator<Item = IdRawEntry>,
    {
        let mut stmt = try_audit!(
            au,
            self.conn
                .prepare("INSERT OR REPLACE INTO id2entry (id, data) VALUES(:id, :data)"),
            "RusqliteError: {:?}",
            OperationError::SQLiteError
        );

        try_audit!(
            au,
            entries.try_for_each(|e| {
                let ser_ent = IdSqliteEntry::try_from(e)?;
                stmt.execute_named(&[(":id", &ser_ent.id), (":data", &ser_ent.data)])
                    // remove the updated usize
                    .map(|_| ())
                    .map_err(|_| OperationError::SQLiteError)
            })
        );
        Ok(())
    }

    pub fn delete_identry<I>(&self, au: &mut AuditScope, mut idl: I) -> Result<(), OperationError>
    where
        I: Iterator<Item = u64>,
    {
        lperf_segment!(au, "be::idl_sqlite::delete_identry", || {
            let mut stmt = self
                .conn
                .prepare("DELETE FROM id2entry WHERE id = :id")
                .map_err(|e| {
                    ladmin_error!(au, "SQLite Error {:?}", e);
                    OperationError::SQLiteError
                })?;

            idl.try_for_each(|id| {
                let iid: i64 = id
                    .try_into()
                    .map_err(|_| OperationError::InvalidEntryID)
                    .and_then(|i| {
                        if i > 0 {
                            Ok(i)
                        } else {
                            Err(OperationError::InvalidEntryID)
                        }
                    })?;

                debug_assert!(iid > 0);

                stmt.execute(&[&iid]).map(|_| ()).map_err(|e| {
                    ladmin_error!(au, "SQLite Error {:?}", e);
                    OperationError::SQLiteError
                })
            })
        })
    }

    pub fn write_idl(
        &self,
        audit: &mut AuditScope,
        attr: &str,
        itype: &IndexType,
        idx_key: &str,
        idl: &IDLBitRange,
    ) -> Result<(), OperationError> {
        lperf_segment!(audit, "be::idl_sqlite::write_idl", || {
            if idl.len() == 0 {
                ltrace!(audit, "purging idl -> {:?}", idl);
                // delete it
                // Delete this idx_key from the table.
                let query = format!(
                    "DELETE FROM idx_{}_{} WHERE key = :key",
                    itype.as_idx_str(),
                    attr
                );

                self.conn
                    .prepare(query.as_str())
                    .and_then(|mut stmt| stmt.execute_named(&[(":key", &idx_key)]))
                    .map_err(|e| {
                        ladmin_error!(audit, "SQLite Error {:?}", e);
                        OperationError::SQLiteError
                    })
            } else {
                ltrace!(audit, "writing idl -> {}", idl);
                // Serialise the IDL to Vec<u8>
                let idl_raw = serde_cbor::to_vec(idl).map_err(|e| {
                    ladmin_error!(audit, "Serde CBOR Error -> {:?}", e);
                    OperationError::SerdeCborError
                })?;

                // update or create it.
                let query = format!(
                    "INSERT OR REPLACE INTO idx_{}_{} (key, idl) VALUES(:key, :idl)",
                    itype.as_idx_str(),
                    attr
                );

                self.conn
                    .prepare(query.as_str())
                    .and_then(|mut stmt| {
                        stmt.execute_named(&[(":key", &idx_key), (":idl", &idl_raw)])
                    })
                    .map_err(|e| {
                        ladmin_error!(audit, "SQLite Error {:?}", e);
                        OperationError::SQLiteError
                    })
            }
            // Get rid of the sqlite rows usize
            .map(|_| ())
        })
    }

    pub fn create_name2uuid(&self, audit: &mut AuditScope) -> Result<(), OperationError> {
        try_audit!(
            audit,
            self.conn.execute(
                "CREATE TABLE IF NOT EXISTS idx_name2uuid (name TEXT PRIMARY KEY, uuid TEXT)",
                NO_PARAMS
            ),
            "sqlite error {:?}",
            OperationError::SQLiteError
        );
        Ok(())
    }

    pub fn create_uuid2name(&self, audit: &mut AuditScope) -> Result<(), OperationError> {
        try_audit!(
            audit,
            self.conn.execute(
                "CREATE TABLE IF NOT EXISTS idx_uuid2name (uuid TEXT PRIMARY KEY, name TEXT)",
                NO_PARAMS
            ),
            "sqlite error {:?}",
            OperationError::SQLiteError
        );
        Ok(())
    }

    pub fn create_idx(
        &self,
        audit: &mut AuditScope,
        attr: &str,
        itype: &IndexType,
    ) -> Result<(), OperationError> {
        // Is there a better way than formatting this? I can't seem
        // to template into the str.
        //
        // We could also re-design our idl storage.
        let idx_stmt = format!(
            "CREATE TABLE IF NOT EXISTS idx_{}_{} (key TEXT PRIMARY KEY, idl BLOB)",
            itype.as_idx_str(),
            attr
        );
        ltrace!(audit, "Creating index -> {}", idx_stmt);

        try_audit!(
            audit,
            self.conn.execute(idx_stmt.as_str(), NO_PARAMS),
            "sqlite error {:?}",
            OperationError::SQLiteError
        );
        Ok(())
    }

    pub fn list_idxs(&self, audit: &mut AuditScope) -> Result<Vec<String>, OperationError> {
        let mut stmt = try_audit!(
            audit,
            self.get_conn()
                .prepare("SELECT name from sqlite_master where type='table' and name LIKE 'idx_%'"),
            "SQLite Error {:?}",
            OperationError::SQLiteError
        );
        let idx_table_iter = try_audit!(
            audit,
            stmt.query_map(NO_PARAMS, |row| row.get(0)),
            "SQLite Error {:?}",
            OperationError::SQLiteError
        );

        let r: Result<_, _> = idx_table_iter
            .map(|v| {
                v.map_err(|e| {
                    ladmin_error!(audit, "SQLite Error {:?}", e);
                    OperationError::SQLiteError
                })
            })
            .collect();

        r
    }

    pub unsafe fn purge_idxs(&self, audit: &mut AuditScope) -> Result<(), OperationError> {
        let idx_table_list = self.list_idxs(audit)?;

        idx_table_list.iter().try_for_each(|idx_table| {
            ltrace!(audit, "removing idx_table -> {:?}", idx_table);
            self.conn
                .prepare(format!("DROP TABLE {}", idx_table).as_str())
                .and_then(|mut stmt| stmt.execute(NO_PARAMS).map(|_| ()))
                .map_err(|e| {
                    ladmin_error!(audit, "sqlite error {:?}", e);
                    OperationError::SQLiteError
                })
        })
    }

    pub unsafe fn purge_id2entry(&self, audit: &mut AuditScope) -> Result<(), OperationError> {
        try_audit!(
            audit,
            self.conn.execute("DELETE FROM id2entry", NO_PARAMS),
            "rustqlite error {:?}",
            OperationError::SQLiteError
        );
        ltrace!(audit, "purge id2entry ...");
        Ok(())
    }

    pub fn write_db_s_uuid(&self, nsid: Uuid) -> Result<(), OperationError> {
        let data = serde_cbor::to_vec(&nsid).map_err(|_e| OperationError::SerdeCborError)?;

        self.conn
            .execute_named(
                "INSERT OR REPLACE INTO db_sid (id, data) VALUES(:id, :sid)",
                &[(":id", &2), (":sid", &data)],
            )
            .map(|_| ())
            .map_err(|e| {
                error!("rusqlite error {:?}", e);

                OperationError::SQLiteError
            })
    }

    pub fn write_db_d_uuid(&self, nsid: Uuid) -> Result<(), OperationError> {
        let data = serde_cbor::to_vec(&nsid).map_err(|_e| OperationError::SerdeCborError)?;

        self.conn
            .execute_named(
                "INSERT OR REPLACE INTO db_did (id, data) VALUES(:id, :did)",
                &[(":id", &2), (":did", &data)],
            )
            .map(|_| ())
            .map_err(|e| {
                error!("rusqlite error {:?}", e);

                OperationError::SQLiteError
            })
    }

    pub fn set_db_ts_max(&self, ts: &Duration) -> Result<(), OperationError> {
        let data = serde_cbor::to_vec(ts).map_err(|_e| OperationError::SerdeCborError)?;

        self.conn
            .execute_named(
                "INSERT OR REPLACE INTO db_op_ts (id, data) VALUES(:id, :did)",
                &[(":id", &1), (":did", &data)],
            )
            .map(|_| ())
            .map_err(|e| {
                error!("rusqlite error {:?}", e);

                OperationError::SQLiteError
            })
    }

    pub fn get_db_ts_max(&self) -> Result<Option<Duration>, OperationError> {
        // Try to get a value.
        let data: Option<Vec<u8>> = self
            .get_conn()
            .query_row_named("SELECT data FROM db_op_ts WHERE id = 1", &[], |row| {
                row.get(0)
            })
            .optional()
            .map(|e_opt| {
                // If we have a row, we try to make it a sid
                e_opt.map(|e| {
                    let y: Vec<u8> = e;
                    y
                })
                // If no sid, we return none.
            })
            .map_err(|_| OperationError::SQLiteError)?;

        Ok(match data {
            Some(d) => Some(
                serde_cbor::from_slice(d.as_slice()).map_err(|_| OperationError::SerdeCborError)?,
            ),
            None => None,
        })
    }

    // ===== inner helpers =====
    // Some of these are not self due to use in new()
    fn get_db_version_key(&self, key: &str) -> i64 {
        match self.conn.query_row_named(
            "SELECT version FROM db_version WHERE id = :id",
            &[(":id", &key)],
            |row| row.get(0),
        ) {
            Ok(e) => e,
            Err(_) => {
                // The value is missing, default to 0.
                0
            }
        }
    }

    fn set_db_version_key(&self, key: &str, v: i64) -> Result<(), rusqlite::Error> {
        self.conn
            .execute_named(
                "INSERT OR REPLACE INTO db_version (id, version) VALUES(:id, :dbv_id2entry)",
                &[(":id", &key), (":dbv_id2entry", &v)],
            )
            .map(|_| ())
    }

    pub(crate) fn get_db_index_version(&self) -> i64 {
        self.get_db_version_key(DBV_INDEXV)
    }

    pub(crate) fn set_db_index_version(&self, v: i64) -> Result<(), OperationError> {
        self.set_db_version_key(DBV_INDEXV, v).map_err(|e| {
            error!("sqlite error {:?}", e);
            OperationError::SQLiteError
        })
    }

    pub fn setup(&self, audit: &mut AuditScope) -> Result<(), OperationError> {
        // Enable WAL mode, which is just faster and better.
        //
        // We have to use stmt + prepare because execute can't handle
        // the "wal" row on result when this works!
        let mut wal_stmt = try_audit!(
            audit,
            self.conn.prepare("PRAGMA journal_mode=WAL;"),
            "sqlite error {:?}",
            OperationError::SQLiteError
        );
        try_audit!(
            audit,
            wal_stmt.query(NO_PARAMS),
            "sqlite error {:?}",
            OperationError::SQLiteError
        );

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
        try_audit!(
            audit,
            self.conn.execute(
                "CREATE TABLE IF NOT EXISTS db_version (
                    id TEXT PRIMARY KEY,
                    version INTEGER
                )
                ",
                NO_PARAMS,
            ),
            "sqlite error {:?}",
            OperationError::SQLiteError
        );

        // If the table is empty, populate the versions as 0.
        let mut dbv_id2entry = self.get_db_version_key(DBV_ID2ENTRY);
        ltrace!(audit, "dbv_id2entry initial == {}", dbv_id2entry);

        // Check db_version here.
        //   * if 0 -> create v1.
        if dbv_id2entry == 0 {
            try_audit!(
                audit,
                self.conn.execute(
                    "CREATE TABLE IF NOT EXISTS id2entry (
                        id INTEGER PRIMARY KEY ASC,
                        data BLOB NOT NULL
                    )
                    ",
                    NO_PARAMS,
                ),
                "sqlite error {:?}",
                OperationError::SQLiteError
            );
            try_audit!(
                audit,
                self.conn.execute(
                    "CREATE TABLE IF NOT EXISTS db_sid (
                        id INTEGER PRIMARY KEY ASC,
                        data BLOB NOT NULL
                    )
                    ",
                    NO_PARAMS,
                ),
                "sqlite error {:?}",
                OperationError::SQLiteError
            );
            dbv_id2entry = 1;
            ltrace!(
                audit,
                "dbv_id2entry migrated (id2entry, db_sid) -> {}",
                dbv_id2entry
            );
        }
        //   * if v1 -> add the domain uuid table
        if dbv_id2entry == 1 {
            try_audit!(
                audit,
                self.conn.execute(
                    "CREATE TABLE IF NOT EXISTS db_did (
                        id INTEGER PRIMARY KEY ASC,
                        data BLOB NOT NULL
                    )
                    ",
                    NO_PARAMS,
                ),
                "sqlite error {:?}",
                OperationError::SQLiteError
            );
            dbv_id2entry = 2;
            ltrace!(audit, "dbv_id2entry migrated (db_did) -> {}", dbv_id2entry);
        }
        //   * if v2 -> add the op max ts table.
        if dbv_id2entry == 2 {
            try_audit!(
                audit,
                self.conn.execute(
                    "CREATE TABLE IF NOT EXISTS db_op_ts (
                        id INTEGER PRIMARY KEY ASC,
                        data BLOB NOT NULL
                    )
                    ",
                    NO_PARAMS,
                ),
                "sqlite error {:?}",
                OperationError::SQLiteError
            );
            dbv_id2entry = 3;
            ltrace!(
                audit,
                "dbv_id2entry migrated (db_op_ts) -> {}",
                dbv_id2entry
            );
        }
        //   * if v3 -> complete.

        try_audit!(
            audit,
            self.set_db_version_key(DBV_ID2ENTRY, dbv_id2entry),
            "sqlite error {:?}",
            OperationError::SQLiteError
        );

        // NOTE: Indexing is configured in a different step!
        // Indexing uses a db version flag to represent the version
        // of the indexes representation on disk in case we change
        // it.
        Ok(())
    }
}

impl IdlSqlite {
    pub fn new(audit: &mut AuditScope, path: &str, pool_size: u32) -> Result<Self, OperationError> {
        let manager = SqliteConnectionManager::file(path);
        let builder1 = Pool::builder();
        let builder2 = if path == "" {
            // We are in a debug mode, with in memory. We MUST have only
            // a single DB thread, else we cause consistency issues.
            builder1.max_size(1)
        } else {
            builder1.max_size(pool_size)
        };
        // Look at max_size and thread_pool here for perf later
        let pool = builder2.build(manager).map_err(|e| {
            ladmin_error!(audit, "r2d2 error {:?}", e);
            OperationError::SQLiteError
        })?;

        Ok(IdlSqlite { pool })
    }

    pub fn read(&self) -> IdlSqliteReadTransaction {
        let conn = self
            .pool
            .get()
            .expect("Unable to get connection from pool!!!");
        IdlSqliteReadTransaction::new(conn)
    }

    pub fn write(&self) -> IdlSqliteWriteTransaction {
        let conn = self
            .pool
            .get()
            .expect("Unable to get connection from pool!!!");
        IdlSqliteWriteTransaction::new(conn)
    }
}

#[cfg(test)]
mod tests {
    use crate::audit::AuditScope;
    use crate::be::idl_sqlite::{IdlSqlite, IdlSqliteTransaction};

    #[test]
    fn test_idl_sqlite_verify() {
        let mut audit = AuditScope::new("run_test", uuid::Uuid::new_v4());
        let be = IdlSqlite::new(&mut audit, "", 1).unwrap();
        let be_w = be.write();
        let r = be_w.verify();
        assert!(r.len() == 0);
    }
}
