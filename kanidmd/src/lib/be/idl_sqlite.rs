use crate::audit::AuditScope;
use crate::be::{BackendConfig, IdRawEntry, IDL};
use crate::entry::{Entry, EntryCommitted, EntrySealed};
use crate::value::{IndexType, Value};
use idlset::v2::IDLBitRange;
use kanidm_proto::v1::{ConsistencyError, OperationError};
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::Connection;
use rusqlite::OpenFlags;
use rusqlite::OptionalExtension;
use std::convert::{TryFrom, TryInto};
use std::time::Duration;
use uuid::Uuid;

// use uuid::Uuid;

const DBV_ID2ENTRY: &str = "id2entry";
const DBV_INDEXV: &str = "indexv";

#[repr(u32)]
#[derive(Debug, Copy, Clone)]
pub enum FsType {
    Generic = 4096,
    ZFS = 65536,
}

#[derive(Debug)]
pub struct IdSqliteEntry {
    id: i64,
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
        lperf_trace_segment!(au, "be::idl_sqlite::get_identry", || {
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
                let mut stmt = self
                    .get_conn()
                    .prepare("SELECT id, data FROM id2entry")
                    .map_err(|e| {
                        ladmin_error!(au, "SQLite Error {:?}", e);
                        OperationError::SqliteError
                    })?;
                let id2entry_iter = stmt
                    .query_map([], |row| {
                        Ok(IdSqliteEntry {
                            id: row.get(0)?,
                            data: row.get(1)?,
                        })
                    })
                    .map_err(|e| {
                        ladmin_error!(au, "SQLite Error {:?}", e);
                        OperationError::SqliteError
                    })?;
                id2entry_iter
                    .map(|v| {
                        v.map_err(|e| {
                            ladmin_error!(au, "SQLite Error {:?}", e);
                            OperationError::SqliteError
                        })
                        .and_then(|ise| {
                            // Convert the idsqlite to id raw
                            ise.try_into()
                        })
                    })
                    .collect()
            }
            IDL::Partial(idli) | IDL::PartialThreshold(idli) | IDL::Indexed(idli) => {
                let mut stmt = self
                    .get_conn()
                    .prepare("SELECT id, data FROM id2entry WHERE id = :idl")
                    .map_err(|e| {
                        ladmin_error!(au, "SQLite Error {:?}", e);
                        OperationError::SqliteError
                    })?;

                // TODO #258: Can this actually just load in a single select?
                // TODO #258: I have no idea how to make this an iterator chain ... so what
                // I have now is probably really bad :(
                let mut results = Vec::new();

                /*
                let decompressed: Result<Vec<i64>, _> = idli.into_iter()
                    .map(|u| i64::try_from(u).map_err(|_| OperationError::InvalidEntryId))
                    .collect();
                */

                for id in idli {
                    let iid = i64::try_from(id).map_err(|_| OperationError::InvalidEntryId)?;
                    let id2entry_iter = stmt
                        .query_map(&[&iid], |row| {
                            Ok(IdSqliteEntry {
                                id: row.get(0)?,
                                data: row.get(1)?,
                            })
                        })
                        .map_err(|e| {
                            ladmin_error!(au, "SQLite Error {:?}", e);
                            OperationError::SqliteError
                        })?;

                    let r: Result<Vec<_>, _> = id2entry_iter
                        .map(|v| {
                            v.map_err(|e| {
                                ladmin_error!(au, "SQLite Error {:?}", e);
                                OperationError::SqliteError
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
        let mut stmt = self
            .get_conn()
            .prepare("SELECT COUNT(name) from sqlite_master where name = :tname")
            .map_err(|e| {
                ladmin_error!(audit, "SQLite Error {:?}", e);
                OperationError::SqliteError
            })?;
        let i: Option<i64> = stmt
            .query_row(&[(":tname", &tname)], |row| row.get(0))
            .map_err(|e| {
                ladmin_error!(audit, "SQLite Error {:?}", e);
                OperationError::SqliteError
            })?;

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
        lperf_trace_segment!(audit, "be::idl_sqlite::get_idl", || {
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
            let mut stmt = self.get_conn().prepare(query.as_str()).map_err(|e| {
                ladmin_error!(audit, "SQLite Error {:?}", e);
                OperationError::SqliteError
            })?;
            let idl_raw: Option<Vec<u8>> = stmt
                .query_row(&[(":idx_key", &idx_key)], |row| row.get(0))
                // We don't mind if it doesn't exist
                .optional()
                .map_err(|e| {
                    ladmin_error!(audit, "SQLite Error {:?}", e);
                    OperationError::SqliteError
                })?;

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

    fn name2uuid(
        &mut self,
        audit: &mut AuditScope,
        name: &str,
    ) -> Result<Option<Uuid>, OperationError> {
        lperf_trace_segment!(audit, "be::idl_sqlite::name2uuid", || {
            // The table exists - lets now get the actual index itself.
            let mut stmt = self
                .get_conn()
                .prepare("SELECT uuid FROM idx_name2uuid WHERE name = :name")
                .map_err(|e| {
                    ladmin_error!(audit, "SQLite Error {:?}", e);
                    OperationError::SqliteError
                })?;
            let uuid_raw: Option<String> = stmt
                .query_row(&[(":name", &name)], |row| row.get(0))
                // We don't mind if it doesn't exist
                .optional()
                .map_err(|e| {
                    ladmin_error!(audit, "SQLite Error {:?}", e);
                    OperationError::SqliteError
                })?;

            let uuid = uuid_raw.as_ref().and_then(|u| Uuid::parse_str(u).ok());
            ltrace!(audit, "Got uuid for index name {} -> {:?}", name, uuid);

            Ok(uuid)
        })
    }

    fn uuid2spn(
        &mut self,
        audit: &mut AuditScope,
        uuid: &Uuid,
    ) -> Result<Option<Value>, OperationError> {
        lperf_trace_segment!(audit, "be::idl_sqlite::uuid2spn", || {
            let uuids = uuid.to_hyphenated_ref().to_string();
            // The table exists - lets now get the actual index itself.
            let mut stmt = self
                .get_conn()
                .prepare("SELECT spn FROM idx_uuid2spn WHERE uuid = :uuid")
                .map_err(|e| {
                    ladmin_error!(audit, "SQLite Error {:?}", e);
                    OperationError::SqliteError
                })?;
            let spn_raw: Option<Vec<u8>> = stmt
                .query_row(&[(":uuid", &uuids)], |row| row.get(0))
                // We don't mind if it doesn't exist
                .optional()
                .map_err(|e| {
                    ladmin_error!(audit, "SQLite Error {:?}", e);
                    OperationError::SqliteError
                })?;

            let spn: Option<Value> = match spn_raw {
                Some(d) => {
                    let dbv = serde_cbor::from_slice(d.as_slice())
                        .map_err(|_| OperationError::SerdeCborError)?;
                    let spn = Value::from_db_valuev1(dbv)
                        .map_err(|_| OperationError::CorruptedIndex("uuid2spn".to_string()))?;
                    Some(spn)
                }
                None => None,
            };

            ltrace!(audit, "Got spn for uuid {:?} -> {:?}", uuid, spn);

            Ok(spn)
        })
    }

    fn uuid2rdn(
        &mut self,
        audit: &mut AuditScope,
        uuid: &Uuid,
    ) -> Result<Option<String>, OperationError> {
        lperf_trace_segment!(audit, "be::idl_sqlite::uuid2rdn", || {
            let uuids = uuid.to_hyphenated_ref().to_string();
            // The table exists - lets now get the actual index itself.
            let mut stmt = self
                .get_conn()
                .prepare("SELECT rdn FROM idx_uuid2rdn WHERE uuid = :uuid")
                .map_err(|e| {
                    ladmin_error!(audit, "SQLite Error {:?}", e);
                    OperationError::SqliteError
                })?;
            let rdn: Option<String> = stmt
                .query_row(&[(":uuid", &uuids)], |row| row.get(0))
                // We don't mind if it doesn't exist
                .optional()
                .map_err(|e| {
                    ladmin_error!(audit, "SQLite Error {:?}", e);
                    OperationError::SqliteError
                })?;

            ltrace!(audit, "Got rdn for uuid {:?} -> {:?}", uuid, rdn);

            Ok(rdn)
        })
    }

    fn get_db_s_uuid(&self) -> Result<Option<Uuid>, OperationError> {
        // Try to get a value.
        let data: Option<Vec<u8>> = self
            .get_conn()
            .query_row("SELECT data FROM db_sid WHERE id = 2", [], |row| row.get(0))
            .optional()
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
                serde_cbor::from_slice(d.as_slice()).map_err(|_| OperationError::SerdeCborError)?,
            ),
            None => None,
        })
    }

    fn get_db_d_uuid(&self) -> Result<Option<Uuid>, OperationError> {
        // Try to get a value.
        let data: Option<Vec<u8>> = self
            .get_conn()
            .query_row("SELECT data FROM db_did WHERE id = 2", [], |row| row.get(0))
            .optional()
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
                serde_cbor::from_slice(d.as_slice()).map_err(|_| OperationError::SerdeCborError)?,
            ),
            None => None,
        })
    }

    // This allow is critical as it resolves a life time issue in stmt.
    #[allow(clippy::let_and_return)]
    fn verify(&self) -> Vec<Result<(), ConsistencyError>> {
        let mut stmt = match self.get_conn().prepare("PRAGMA integrity_check;") {
            Ok(r) => r,
            Err(_) => return vec![Err(ConsistencyError::SqliteIntegrityFailure)],
        };

        // Allow this as it actually extends the life of stmt
        let r = match stmt.query([]) {
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
    fn drop(&mut self) {
        if !self.committed {
            #[allow(clippy::expect_used)]
            self.conn
                .execute("ROLLBACK TRANSACTION", [])
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
        #[allow(clippy::expect_used)]
        conn.execute("BEGIN TRANSACTION", [])
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
    fn drop(&mut self) {
        if !self.committed {
            #[allow(clippy::expect_used)]
            self.conn
                .execute("ROLLBACK TRANSACTION", [])
                .expect("Unable to rollback transaction! Can not proceed!!!");
        }
    }
}

impl IdlSqliteWriteTransaction {
    pub fn new(conn: r2d2::PooledConnection<SqliteConnectionManager>) -> Self {
        // Start the transaction
        #[allow(clippy::expect_used)]
        conn.execute("BEGIN TRANSACTION", [])
            .expect("Unable to begin transaction!");
        IdlSqliteWriteTransaction {
            committed: false,
            conn,
        }
    }

    pub fn commit(mut self, audit: &mut AuditScope) -> Result<(), OperationError> {
        lperf_trace_segment!(audit, "be::idl_sqlite::commit", || {
            // ltrace!(audit, "Commiting BE WR txn");
            assert!(!self.committed);
            self.committed = true;

            self.conn
                .execute("COMMIT TRANSACTION", [])
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
            .map_err(|_| OperationError::SqliteError)?;
        // This exists checks for if any rows WERE returned
        // that way we know to shortcut or not.
        let v = stmt.exists([]).map_err(|_| OperationError::SqliteError)?;

        if v {
            // We have some rows, let get max!
            let i: Option<i64> = stmt
                .query_row([], |row| row.get(0))
                .map_err(|_| OperationError::SqliteError)?;
            i.unwrap_or(0)
                .try_into()
                .map_err(|_| OperationError::InvalidEntryId)
        } else {
            // No rows are present, return a 0.
            Ok(0)
        }
    }

    /*
    pub fn write_identries<'b, I>(
        &'b self,
        au: &mut AuditScope,
        entries: I,
    ) -> Result<(), OperationError>
    where
        I: Iterator<Item = &'b Entry<EntrySealed, EntryCommitted>>,
    {
        lperf_trace_segment!(au, "be::idl_sqlite::write_identries", || {
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
    */

    pub fn write_identry(
        &self,
        au: &mut AuditScope,
        entry: &Entry<EntrySealed, EntryCommitted>,
    ) -> Result<(), OperationError> {
        let dbe = entry.to_dbentry();
        let data = serde_cbor::to_vec(&dbe).map_err(|_| OperationError::SerdeCborError)?;

        let raw_entries = std::iter::once(IdRawEntry {
            id: entry.get_id(),
            data,
        });

        self.write_identries_raw(au, raw_entries)
    }

    pub fn write_identries_raw<I>(
        &self,
        au: &mut AuditScope,
        mut entries: I,
    ) -> Result<(), OperationError>
    where
        I: Iterator<Item = IdRawEntry>,
    {
        let mut stmt = self
            .conn
            .prepare("INSERT OR REPLACE INTO id2entry (id, data) VALUES(:id, :data)")
            .map_err(|e| {
                ladmin_error!(au, "SQLite Error {:?}", e);
                OperationError::SqliteError
            })?;

        entries.try_for_each(|e| {
            IdSqliteEntry::try_from(e).and_then(|ser_ent| {
                stmt.execute(named_params! {
                    ":id": &ser_ent.id,
                    ":data": &ser_ent.data.as_slice()
                })
                // remove the updated usize
                .map(|_| ())
                .map_err(|e| {
                    ladmin_error!(au, "SQLite Error {:?}", e);
                    OperationError::SqliteError
                })
            })
        })
    }

    /*
    pub fn delete_identries<I>(&self, au: &mut AuditScope, mut idl: I) -> Result<(), OperationError>
    where
        I: Iterator<Item = u64>,
    {
        lperf_trace_segment!(au, "be::idl_sqlite::delete_identries", || {
            let mut stmt = self
                .conn
                .prepare("DELETE FROM id2entry WHERE id = :id")
                .map_err(|e| {
                    ladmin_error!(au, "SQLite Error {:?}", e);
                    OperationError::SqliteError
                })?;

            idl.try_for_each(|id| {
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

                stmt.execute(&[&iid]).map(|_| ()).map_err(|e| {
                    ladmin_error!(au, "SQLite Error {:?}", e);
                    OperationError::SqliteError
                })
            })
        })
    }
    */

    pub fn delete_identry(&self, au: &mut AuditScope, id: u64) -> Result<(), OperationError> {
        // lperf_trace_segment!(au, "be::idl_sqlite::delete_identry", || {
        let mut stmt = self
            .conn
            .prepare("DELETE FROM id2entry WHERE id = :id")
            .map_err(|e| {
                ladmin_error!(au, "SQLite Error {:?}", e);
                OperationError::SqliteError
            })?;

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

        stmt.execute(&[&iid]).map(|_| ()).map_err(|e| {
            ladmin_error!(au, "SQLite Error {:?}", e);
            OperationError::SqliteError
        })
        // })
    }

    pub fn write_idl(
        &self,
        audit: &mut AuditScope,
        attr: &str,
        itype: &IndexType,
        idx_key: &str,
        idl: &IDLBitRange,
    ) -> Result<(), OperationError> {
        lperf_trace_segment!(audit, "be::idl_sqlite::write_idl", || {
            if idl.is_empty() {
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
                    .and_then(|mut stmt| stmt.execute(&[(":key", &idx_key)]))
                    .map_err(|e| {
                        ladmin_error!(audit, "SQLite Error {:?}", e);
                        OperationError::SqliteError
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
                        stmt.execute(named_params! {
                            ":key": &idx_key,
                            ":idl": &idl_raw
                        })
                    })
                    .map_err(|e| {
                        ladmin_error!(audit, "SQLite Error {:?}", e);
                        OperationError::SqliteError
                    })
            }
            // Get rid of the sqlite rows usize
            .map(|_| ())
        })
    }

    pub fn create_name2uuid(&self, audit: &mut AuditScope) -> Result<(), OperationError> {
        self.conn
            .execute(
                "CREATE TABLE IF NOT EXISTS idx_name2uuid (name TEXT PRIMARY KEY, uuid TEXT)",
                [],
            )
            .map(|_| ())
            .map_err(|e| {
                ladmin_error!(audit, "SQLite Error {:?}", e);
                OperationError::SqliteError
            })
    }

    pub fn write_name2uuid_add(
        &self,
        audit: &mut AuditScope,
        name: &str,
        uuid: &Uuid,
    ) -> Result<(), OperationError> {
        let uuids = uuid.to_hyphenated_ref().to_string();

        self.conn
            .prepare("INSERT OR REPLACE INTO idx_name2uuid (name, uuid) VALUES(:name, :uuid)")
            .and_then(|mut stmt| {
                stmt.execute(named_params! {
                    ":name": &name,
                    ":uuid": uuids.as_str()
                })
            })
            .map(|_| ())
            .map_err(|e| {
                ladmin_error!(audit, "SQLite Error {:?}", e);
                OperationError::SqliteError
            })
    }

    pub fn write_name2uuid_rem(
        &self,
        audit: &mut AuditScope,
        name: &str,
    ) -> Result<(), OperationError> {
        self.conn
            .prepare("DELETE FROM idx_name2uuid WHERE name = :name")
            .and_then(|mut stmt| stmt.execute(&[(":name", &name)]))
            .map(|_| ())
            .map_err(|e| {
                ladmin_error!(audit, "SQLite Error {:?}", e);
                OperationError::SqliteError
            })
    }

    pub fn create_uuid2spn(&self, audit: &mut AuditScope) -> Result<(), OperationError> {
        self.conn
            .execute(
                "CREATE TABLE IF NOT EXISTS idx_uuid2spn (uuid TEXT PRIMARY KEY, spn BLOB)",
                [],
            )
            .map(|_| ())
            .map_err(|e| {
                ladmin_error!(audit, "SQLite Error {:?}", e);
                OperationError::SqliteError
            })
    }

    pub fn write_uuid2spn(
        &self,
        audit: &mut AuditScope,
        uuid: &Uuid,
        k: Option<&Value>,
    ) -> Result<(), OperationError> {
        let uuids = uuid.to_hyphenated_ref().to_string();
        match k {
            Some(k) => {
                let dbv1 = k.to_db_valuev1();
                let data =
                    serde_cbor::to_vec(&dbv1).map_err(|_e| OperationError::SerdeCborError)?;
                self.conn
                    .prepare("INSERT OR REPLACE INTO idx_uuid2spn (uuid, spn) VALUES(:uuid, :spn)")
                    .and_then(|mut stmt| {
                        stmt.execute(named_params! {
                            ":uuid": &uuids,
                            ":spn": &data,
                        })
                    })
                    .map(|_| ())
                    .map_err(|e| {
                        ladmin_error!(audit, "SQLite Error {:?}", e);
                        OperationError::SqliteError
                    })
            }
            None => self
                .conn
                .prepare("DELETE FROM idx_uuid2spn WHERE uuid = :uuid")
                .and_then(|mut stmt| stmt.execute(&[(":uuid", &uuids)]))
                .map(|_| ())
                .map_err(|e| {
                    ladmin_error!(audit, "SQLite Error {:?}", e);
                    OperationError::SqliteError
                }),
        }
    }

    pub fn create_uuid2rdn(&self, audit: &mut AuditScope) -> Result<(), OperationError> {
        self.conn
            .execute(
                "CREATE TABLE IF NOT EXISTS idx_uuid2rdn (uuid TEXT PRIMARY KEY, rdn TEXT)",
                [],
            )
            .map(|_| ())
            .map_err(|e| {
                ladmin_error!(audit, "SQLite Error {:?}", e);
                OperationError::SqliteError
            })
    }

    pub fn write_uuid2rdn(
        &self,
        audit: &mut AuditScope,
        uuid: &Uuid,
        k: Option<&String>,
    ) -> Result<(), OperationError> {
        let uuids = uuid.to_hyphenated_ref().to_string();
        match k {
            Some(k) => self
                .conn
                .prepare("INSERT OR REPLACE INTO idx_uuid2rdn (uuid, rdn) VALUES(:uuid, :rdn)")
                .and_then(|mut stmt| stmt.execute(&[(":uuid", &uuids), (":rdn", &k)]))
                .map(|_| ())
                .map_err(|e| {
                    ladmin_error!(audit, "SQLite Error {:?}", e);
                    OperationError::SqliteError
                }),
            None => self
                .conn
                .prepare("DELETE FROM idx_uuid2rdn WHERE uuid = :uuid")
                .and_then(|mut stmt| stmt.execute(&[(":uuid", &uuids)]))
                .map(|_| ())
                .map_err(|e| {
                    ladmin_error!(audit, "SQLite Error {:?}", e);
                    OperationError::SqliteError
                }),
        }
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

        self.conn
            .execute(idx_stmt.as_str(), [])
            .map(|_| ())
            .map_err(|e| {
                ladmin_error!(audit, "SQLite Error {:?}", e);
                OperationError::SqliteError
            })
    }

    pub fn list_idxs(&self, audit: &mut AuditScope) -> Result<Vec<String>, OperationError> {
        let mut stmt = self
            .get_conn()
            .prepare("SELECT name from sqlite_master where type='table' and name LIKE 'idx_%'")
            .map_err(|e| {
                ladmin_error!(audit, "SQLite Error {:?}", e);
                OperationError::SqliteError
            })?;
        let idx_table_iter = stmt.query_map([], |row| row.get(0)).map_err(|e| {
            ladmin_error!(audit, "SQLite Error {:?}", e);
            OperationError::SqliteError
        })?;

        let r: Result<_, _> = idx_table_iter
            .map(|v| {
                v.map_err(|e| {
                    ladmin_error!(audit, "SQLite Error {:?}", e);
                    OperationError::SqliteError
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
                .and_then(|mut stmt| stmt.execute([]).map(|_| ()))
                .map_err(|e| {
                    ladmin_error!(audit, "sqlite error {:?}", e);
                    OperationError::SqliteError
                })
        })
    }

    pub unsafe fn purge_id2entry(&self, audit: &mut AuditScope) -> Result<(), OperationError> {
        ltrace!(audit, "purge id2entry ...");
        self.conn
            .execute("DELETE FROM id2entry", [])
            .map(|_| ())
            .map_err(|e| {
                ladmin_error!(audit, "sqlite error {:?}", e);
                OperationError::SqliteError
            })
    }

    pub fn write_db_s_uuid(&self, nsid: Uuid) -> Result<(), OperationError> {
        let data = serde_cbor::to_vec(&nsid).map_err(|_e| OperationError::SerdeCborError)?;

        self.conn
            .execute(
                "INSERT OR REPLACE INTO db_sid (id, data) VALUES(:id, :sid)",
                named_params! {
                    ":id": &2,
                    ":sid": &data,
                },
            )
            .map(|_| ())
            .map_err(|e| {
                eprintln!("CRITICAL: rusqlite error {:?}", e);
                OperationError::SqliteError
            })
    }

    pub fn write_db_d_uuid(&self, nsid: Uuid) -> Result<(), OperationError> {
        let data = serde_cbor::to_vec(&nsid).map_err(|_e| OperationError::SerdeCborError)?;

        self.conn
            .execute(
                "INSERT OR REPLACE INTO db_did (id, data) VALUES(:id, :did)",
                named_params! {
                    ":id": &2,
                    ":did": &data,
                },
            )
            .map(|_| ())
            .map_err(|e| {
                eprintln!("CRITICAL: rusqlite error {:?}", e);
                OperationError::SqliteError
            })
    }

    pub fn set_db_ts_max(&self, ts: &Duration) -> Result<(), OperationError> {
        let data = serde_cbor::to_vec(ts).map_err(|_e| OperationError::SerdeCborError)?;

        self.conn
            .execute(
                "INSERT OR REPLACE INTO db_op_ts (id, data) VALUES(:id, :did)",
                named_params! {
                    ":id": &1,
                    ":did": &data,
                },
            )
            .map(|_| ())
            .map_err(|e| {
                eprintln!("CRITICAL: rusqlite error {:?}", e);
                OperationError::SqliteError
            })
    }

    pub fn get_db_ts_max(&self) -> Result<Option<Duration>, OperationError> {
        // Try to get a value.
        let data: Option<Vec<u8>> = self
            .get_conn()
            .query_row("SELECT data FROM db_op_ts WHERE id = 1", [], |row| {
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
            .map_err(|_| OperationError::SqliteError)?;

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
        match self.conn.query_row(
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
            .execute(
                "INSERT OR REPLACE INTO db_version (id, version) VALUES(:id, :dbv_id2entry)",
                named_params! {
                    ":id": &key,
                    ":dbv_id2entry": v,
                },
            )
            .map(|_| ())
    }

    pub(crate) fn get_db_index_version(&self) -> i64 {
        self.get_db_version_key(DBV_INDEXV)
    }

    pub(crate) fn set_db_index_version(&self, v: i64) -> Result<(), OperationError> {
        self.set_db_version_key(DBV_INDEXV, v).map_err(|e| {
            eprintln!("CRITICAL: rusqlite error {:?}", e);
            OperationError::SqliteError
        })
    }

    pub(crate) fn get_allids(&self, au: &mut AuditScope) -> Result<IDLBitRange, OperationError> {
        ltrace!(au, "Building allids...");
        let mut stmt = self.conn.prepare("SELECT id FROM id2entry").map_err(|e| {
            ladmin_error!(au, "SQLite Error {:?}", e);
            OperationError::SqliteError
        })?;
        let res = stmt.query_map([], |row| row.get(0)).map_err(|e| {
            ladmin_error!(au, "SQLite Error {:?}", e);
            OperationError::SqliteError
        })?;
        res.map(|v| {
            v.map_err(|e| {
                ladmin_error!(au, "SQLite Error {:?}", e);
                OperationError::SqliteError
            })
            .and_then(|id: i64| {
                // Convert the idsqlite to id raw
                id.try_into().map_err(|e| {
                    ladmin_error!(au, "I64 Parse Error {:?}", e);
                    OperationError::SqliteError
                })
            })
        })
        .collect()
    }

    pub fn setup(&self, audit: &mut AuditScope) -> Result<(), OperationError> {
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
        self.conn
            .execute(
                "CREATE TABLE IF NOT EXISTS db_version (
                    id TEXT PRIMARY KEY,
                    version INTEGER
                )
                ",
                [],
            )
            .map_err(|e| {
                ladmin_error!(audit, "sqlite error {:?}", e);
                OperationError::SqliteError
            })?;

        // If the table is empty, populate the versions as 0.
        let mut dbv_id2entry = self.get_db_version_key(DBV_ID2ENTRY);
        ltrace!(audit, "dbv_id2entry initial == {}", dbv_id2entry);

        // Check db_version here.
        //   * if 0 -> create v1.
        if dbv_id2entry == 0 {
            self.conn
                .execute(
                    "CREATE TABLE IF NOT EXISTS id2entry (
                        id INTEGER PRIMARY KEY ASC,
                        data BLOB NOT NULL
                    )
                    ",
                    [],
                )
                .and_then(|_| {
                    self.conn.execute(
                        "CREATE TABLE IF NOT EXISTS db_sid (
                        id INTEGER PRIMARY KEY ASC,
                        data BLOB NOT NULL
                    )
                    ",
                        [],
                    )
                })
                .map_err(|e| {
                    ladmin_error!(audit, "sqlite error {:?}", e);
                    OperationError::SqliteError
                })?;

            dbv_id2entry = 1;
            ladmin_info!(
                audit,
                "dbv_id2entry migrated (id2entry, db_sid) -> {}",
                dbv_id2entry
            );
        }
        //   * if v1 -> add the domain uuid table
        if dbv_id2entry == 1 {
            self.conn
                .execute(
                    "CREATE TABLE IF NOT EXISTS db_did (
                        id INTEGER PRIMARY KEY ASC,
                        data BLOB NOT NULL
                    )
                    ",
                    [],
                )
                .map_err(|e| {
                    ladmin_error!(audit, "sqlite error {:?}", e);
                    OperationError::SqliteError
                })?;

            dbv_id2entry = 2;
            ladmin_info!(audit, "dbv_id2entry migrated (db_did) -> {}", dbv_id2entry);
        }
        //   * if v2 -> add the op max ts table.
        if dbv_id2entry == 2 {
            self.conn
                .execute(
                    "CREATE TABLE IF NOT EXISTS db_op_ts (
                        id INTEGER PRIMARY KEY ASC,
                        data BLOB NOT NULL
                    )
                    ",
                    [],
                )
                .map_err(|e| {
                    ladmin_error!(audit, "sqlite error {:?}", e);
                    OperationError::SqliteError
                })?;
            dbv_id2entry = 3;
            ladmin_info!(
                audit,
                "dbv_id2entry migrated (db_op_ts) -> {}",
                dbv_id2entry
            );
        }
        //   * if v3 -> complete.
        if dbv_id2entry == 3 {
            self.create_name2uuid(audit)
                .and_then(|_| self.create_uuid2spn(audit))
                .and_then(|_| self.create_uuid2rdn(audit))?;
            dbv_id2entry = 4;
            ladmin_info!(
                audit,
                "dbv_id2entry migrated (name2uuid, uuid2spn, uuid2rdn) -> {}",
                dbv_id2entry
            );
        }
        //   * if v4 -> complete.

        self.set_db_version_key(DBV_ID2ENTRY, dbv_id2entry)
            .map_err(|e| {
                ladmin_error!(audit, "sqlite error {:?}", e);
                OperationError::SqliteError
            })?;

        // NOTE: Indexing is configured in a different step!
        // Indexing uses a db version flag to represent the version
        // of the indexes representation on disk in case we change
        // it.
        Ok(())
    }
}

impl IdlSqlite {
    pub fn new(
        audit: &mut AuditScope,
        cfg: &BackendConfig,
        vacuum: bool,
    ) -> Result<Self, OperationError> {
        if cfg.path.is_empty() {
            debug_assert!(cfg.pool_size == 1);
        }
        // If provided, set the page size to match the tuning we want. By default we use 4096. The VACUUM
        // immediately after is so that on db create the page size takes effect.
        //
        // Enable WAL mode, which is just faster and better for our needs.
        let mut flags = OpenFlags::default();
        // Open with multi thread flags and locking options.
        flags.insert(OpenFlags::SQLITE_OPEN_NO_MUTEX);

        // We need to run vacuum in the setup else we hit sqlite lock conditions.
        if vacuum {
            limmediate_warning!(
                audit,
                "NOTICE: A db vacuum has been requested. This may take a long time ...\n"
            );

            let vconn = Connection::open_with_flags(cfg.path.as_str(), flags).map_err(|e| {
                ladmin_error!(audit, "rusqlite error {:?}", e);
                OperationError::SqliteError
            })?;

            vconn
                .pragma_update(None, "journal_mode", &"DELETE")
                .map_err(|e| {
                    ladmin_error!(audit, "rusqlite journal_mode update error {:?}", e);
                    OperationError::SqliteError
                })?;

            vconn.close().map_err(|e| {
                ladmin_error!(audit, "rusqlite db close error {:?}", e);
                OperationError::SqliteError
            })?;

            let vconn = Connection::open_with_flags(cfg.path.as_str(), flags).map_err(|e| {
                ladmin_error!(audit, "rusqlite error {:?}", e);
                OperationError::SqliteError
            })?;

            vconn
                .pragma_update(None, "page_size", &(cfg.fstype as u32))
                .map_err(|e| {
                    ladmin_error!(audit, "rusqlite page_size update error {:?}", e);
                    OperationError::SqliteError
                })?;

            vconn.execute_batch("VACUUM").map_err(|e| {
                ladmin_error!(audit, "rusqlite vacuum error {:?}", e);
                OperationError::SqliteError
            })?;

            vconn
                .pragma_update(None, "journal_mode", &"WAL")
                .map_err(|e| {
                    ladmin_error!(audit, "rusqlite journal_mode update error {:?}", e);
                    OperationError::SqliteError
                })?;

            vconn.close().map_err(|e| {
                ladmin_error!(audit, "rusqlite db close error {:?}", e);
                OperationError::SqliteError
            })?;

            limmediate_warning!(audit, "NOTICE: db vacuum complete\n");
        };

        let fstype = cfg.fstype as u32;

        let manager = SqliteConnectionManager::file(cfg.path.as_str())
            .with_init(move |c| {
                c.execute_batch(
                    format!("PRAGMA page_size={}; PRAGMA journal_mode=WAL;", fstype).as_str(),
                )
            })
            .with_flags(flags);

        let builder1 = Pool::builder();
        let builder2 = builder1.max_size(cfg.pool_size);
        // Look at max_size and thread_pool here for perf later
        let pool = builder2.build(manager).map_err(|e| {
            ladmin_error!(audit, "r2d2 error {:?}", e);
            OperationError::SqliteError
        })?;

        Ok(IdlSqlite { pool })
    }

    pub(crate) fn get_allids_count(&self, au: &mut AuditScope) -> Result<u64, OperationError> {
        ltrace!(au, "Counting allids...");
        self.pool
            .try_get()
            .expect("Unable to get connection from pool!!!")
            .query_row("select count(id) from id2entry", [], |row| row.get(0))
            .map_err(|e| {
                ltrace!(au, "SQLite Error {:?}", e);
                OperationError::SqliteError
            })
    }

    pub fn read(&self) -> IdlSqliteReadTransaction {
        // When we make this async, this will allow us to backoff
        // when we miss-grabbing from the conn-pool.
        // async_std::task::yield_now().await
        #[allow(clippy::expect_used)]
        let conn = self
            .pool
            .try_get()
            .expect("Unable to get connection from pool!!!");
        IdlSqliteReadTransaction::new(conn)
    }

    pub fn write(&self) -> IdlSqliteWriteTransaction {
        #[allow(clippy::expect_used)]
        let conn = self
            .pool
            .try_get()
            .expect("Unable to get connection from pool!!!");
        IdlSqliteWriteTransaction::new(conn)
    }
}

#[cfg(test)]
mod tests {
    use crate::audit::AuditScope;
    use crate::be::idl_sqlite::{IdlSqlite, IdlSqliteTransaction};
    use crate::be::BackendConfig;

    #[test]
    fn test_idl_sqlite_verify() {
        let mut audit = AuditScope::new("run_test", uuid::Uuid::new_v4(), None);
        let cfg = BackendConfig::new_test();
        let be = IdlSqlite::new(&mut audit, &cfg, false).unwrap();
        let be_w = be.write();
        let r = be_w.verify();
        assert!(r.len() == 0);
    }
}
