//! Db executor actor

use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::types::ToSql;
use rusqlite::NO_PARAMS;
use serde_cbor;
use serde_json;
use std::convert::TryFrom;
use std::fs;

use crate::audit::AuditScope;
use crate::be::dbentry::DbEntry;
use crate::entry::{Entry, EntryCommitted, EntryNew, EntryValid};
use crate::error::{ConsistencyError, OperationError};
use crate::filter::{Filter, FilterValidResolved};

pub mod dbvalue;
pub mod dbentry;
mod idl;
mod mem_be;
mod sqlite_be;

#[derive(Debug)]
struct IdEntry {
    // TODO #20: for now this is i64 to make sqlite work, but entry is u64 for indexing reasons!
    id: i64,
    data: Vec<u8>,
}

pub struct Backend {
    pool: Pool<SqliteConnectionManager>,
}

pub struct BackendReadTransaction {
    committed: bool,
    conn: r2d2::PooledConnection<SqliteConnectionManager>,
}

pub struct BackendWriteTransaction {
    committed: bool,
    conn: r2d2::PooledConnection<SqliteConnectionManager>,
}

pub trait BackendTransaction {
    fn get_conn(&self) -> &r2d2::PooledConnection<r2d2_sqlite::SqliteConnectionManager>;

    // Take filter, and AuditScope ref?
    fn search(
        &self,
        au: &mut AuditScope,
        filt: &Filter<FilterValidResolved>,
    ) -> Result<Vec<Entry<EntryValid, EntryCommitted>>, OperationError> {
        // Do things
        // Alloc a vec for the entries.
        // TODO #8: Make this actually a good size for the result set ...
        // TODO #8: Actually compute indexes here.
        // So to make this use indexes, we can use the filter type and
        // destructure it to work out what we need to actually search (if
        // possible) to create the candidate set.
        // Unlike DS, even if we don't get the index back, we can just pass
        // to the in-memory filter test and be done.
        audit_segment!(au, || {
            // Do a final optimise of the filter
            let filt = filt.optimise();
            audit_log!(au, "filter optimised to --> {:?}", filt);

            let mut raw_entries: Vec<IdEntry> = Vec::new();
            {
                // Actually do a search now!
                // read them all
                let mut stmt = try_audit!(
                    au,
                    self.get_conn().prepare("SELECT id, data FROM id2entry"),
                    "SQLite Error {:?}",
                    OperationError::SQLiteError
                );
                let id2entry_iter = try_audit!(
                    au,
                    stmt.query_map(NO_PARAMS, |row| IdEntry {
                        id: row.get(0),
                        data: row.get(1),
                    }),
                    "SQLite Error {:?}",
                    OperationError::SQLiteError
                );

                for row in id2entry_iter {
                    // audit_log!(au, "raw entry: {:?}", row);
                    raw_entries.push(try_audit!(
                        au,
                        row,
                        "SQLite Error {:?}",
                        OperationError::SQLiteError
                    ));
                }
            }
            // Do other things
            // Now, de-serialise the raw_entries back to entries, and populate their ID's

            let entries: Result<Vec<Entry<EntryValid, EntryCommitted>>, _> = raw_entries
                .iter()
                .filter_map(|id_ent| {
                    // We need the matches here to satisfy the filter map
                    let db_e = match serde_cbor::from_slice(id_ent.data.as_slice())
                        .map_err(|_| OperationError::SerdeCborError)
                    {
                        Ok(v) => v,
                        Err(e) => return Some(Err(e)),
                    };
                    let id = match u64::try_from(id_ent.id)
                        .map_err(|_| OperationError::InvalidEntryID)
                    {
                        Ok(v) => v,
                        Err(e) => return Some(Err(e)),
                    };
                    let e =
                        match Entry::from_dbentry(db_e, id).ok_or(OperationError::CorruptedEntry) {
                            Ok(v) => v,
                            Err(e) => return Some(Err(e)),
                        };
                    if e.entry_match_no_index(&filt) {
                        Some(Ok(e))
                    } else {
                        None
                    }
                })
                .collect();

            entries
        })
    }

    /// Given a filter, assert some condition exists.
    /// Basically, this is a specialised case of search, where we don't need to
    /// load any candidates if they match. This is heavily used in uuid
    /// refint and attr uniqueness.
    fn exists(
        &self,
        au: &mut AuditScope,
        filt: &Filter<FilterValidResolved>,
    ) -> Result<bool, OperationError> {
        // Do a final optimise of the filter
        // At the moment, technically search will do this, but it won't always be the
        // case once this becomes a standalone function.
        let filt = filt.optimise();
        audit_log!(au, "filter optimised to --> {:?}", filt);

        let r = self.search(au, &filt);
        match r {
            Ok(v) => {
                if v.len() > 0 {
                    audit_log!(au, "candidate exists");
                    Ok(true)
                } else {
                    audit_log!(au, "candidate does not exist");
                    Ok(false)
                }
            }
            Err(e) => {
                audit_log!(au, "error processing exists {:?}", e);
                Err(e)
            }
        }
    }

    fn verify(&self) -> Vec<Result<(), ConsistencyError>> {
        Vec::new()
    }

    fn backup(&self, audit: &mut AuditScope, dst_path: &str) -> Result<(), OperationError> {
        // load all entries into RAM, may need to change this later
        // if the size of the database compared to RAM is an issue
        let mut raw_entries: Vec<IdEntry> = Vec::new();

        {
            let mut stmt = try_audit!(
                audit,
                self.get_conn().prepare("SELECT id, data FROM id2entry"),
                "sqlite error {:?}",
                OperationError::SQLiteError
            );

            let id2entry_iter = try_audit!(
                audit,
                stmt.query_map(NO_PARAMS, |row| IdEntry {
                    id: row.get(0),
                    data: row.get(1),
                }),
                "sqlite error {:?}",
                OperationError::SQLiteError
            );

            for row in id2entry_iter {
                raw_entries.push(row.map_err(|_| OperationError::SQLiteError)?);
            }
        }

        let entries: Result<Vec<DbEntry>, _> = raw_entries
            .iter()
            .map(|id_ent| {
                serde_cbor::from_slice(id_ent.data.as_slice())
                    .map_err(|_| OperationError::SerdeJsonError)
            })
            .collect();

        let entries = entries?;

        let serialized_entries = serde_json::to_string_pretty(&entries);

        let serialized_entries_str = try_audit!(
            audit,
            serialized_entries,
            "serde error {:?}",
            OperationError::SerdeJsonError
        );

        let result = fs::write(dst_path, serialized_entries_str);

        try_audit!(
            audit,
            result,
            "fs::write error {:?}",
            OperationError::FsError
        );

        Ok(())
    }
}

impl Drop for BackendReadTransaction {
    // Abort - so far this has proven reliable to use drop here.
    fn drop(self: &mut Self) {
        if !self.committed {
            debug!("Aborting BE RO txn");
            self.conn
                .execute("ROLLBACK TRANSACTION", NO_PARAMS)
                // We can't do this without expect.
                // We may need to change how we do transactions to not rely on drop if
                // it becomes and issue :(
                .expect("Unable to rollback transaction! Can not proceed!!!");
        }
    }
}

impl BackendReadTransaction {
    pub fn new(conn: r2d2::PooledConnection<SqliteConnectionManager>) -> Self {
        // Start the transaction
        debug!("Starting BE RO txn ...");
        // I'm happy for this to be an expect, because this is a huge failure
        // of the server ... but if it happens a lot we should consider making
        // this a Result<>
        //
        // There is no way to flag this is an RO operation.
        conn.execute("BEGIN TRANSACTION", NO_PARAMS)
            .expect("Unable to begin transaction!");
        BackendReadTransaction {
            committed: false,
            conn: conn,
        }
    }
}

impl BackendTransaction for BackendReadTransaction {
    fn get_conn(&self) -> &r2d2::PooledConnection<r2d2_sqlite::SqliteConnectionManager> {
        &self.conn
    }
}

static DBV_ID2ENTRY: &'static str = "id2entry";

impl Drop for BackendWriteTransaction {
    // Abort
    fn drop(self: &mut Self) {
        if !self.committed {
            debug!("Aborting BE WR txn");
            self.conn
                .execute("ROLLBACK TRANSACTION", NO_PARAMS)
                .expect("Unable to rollback transaction! Can not proceed!!!");
        }
    }
}

impl BackendTransaction for BackendWriteTransaction {
    fn get_conn(&self) -> &r2d2::PooledConnection<r2d2_sqlite::SqliteConnectionManager> {
        &self.conn
    }
}

impl BackendWriteTransaction {
    pub fn new(conn: r2d2::PooledConnection<SqliteConnectionManager>) -> Self {
        // Start the transaction
        debug!("Starting BE WR txn ...");
        conn.execute("BEGIN TRANSACTION", NO_PARAMS)
            .expect("Unable to begin transaction!");
        BackendWriteTransaction {
            committed: false,
            conn: conn,
        }
    }

    fn get_id2entry_max_id(&self) -> Result<i64, OperationError> {
        let mut stmt = self
            .conn
            .prepare("SELECT MAX(id) as id_max FROM id2entry")
            .map_err(|_| OperationError::SQLiteError)?;
        // This exists checks for if any rows WERE returned
        // that way we know to shortcut or not.
        let v = stmt
            .exists(NO_PARAMS)
            .map_err(|_| OperationError::SQLiteError)?;

        Ok(if v {
            // We have some rows, let get max!
            let i: Option<i64> = stmt
                .query_row(NO_PARAMS, |row| row.get(0))
                .map_err(|_| OperationError::SQLiteError)?;
            i.unwrap_or(0)
        } else {
            // No rows are present, return a 0.
            0
        })
    }

    fn internal_create(
        &self,
        au: &mut AuditScope,
        dbentries: &Vec<DbEntry>,
    ) -> Result<(), OperationError> {
        // Get the max id from the db. We store this ourselves to avoid max() calls.
        let mut id_max = self.get_id2entry_max_id()?;

        let ser_entries: Result<Vec<IdEntry>, _> = dbentries
            .iter()
            .map(|ser_db_e| {
                id_max = id_max + 1;
                let data =
                    serde_cbor::to_vec(&ser_db_e).map_err(|_| OperationError::SerdeCborError)?;

                Ok(IdEntry {
                    id: id_max,
                    data: data,
                })
            })
            .collect();

        let ser_entries = ser_entries?;
        {
            let mut stmt = try_audit!(
                au,
                self.conn
                    .prepare("INSERT INTO id2entry (id, data) VALUES (:id, :data)"),
                "rusqlite error {:?}",
                OperationError::SQLiteError
            );

            // write them all
            for ser_entry in ser_entries {
                try_audit!(
                    au,
                    stmt.execute_named(&[
                        (":id", &ser_entry.id as &ToSql),
                        (":data", &ser_entry.data as &ToSql)
                    ]),
                    "rusqlite error {:?}",
                    OperationError::SQLiteError
                );
            }
        }

        Ok(())
    }

    pub fn create(
        &self,
        au: &mut AuditScope,
        entries: &Vec<Entry<EntryValid, EntryNew>>,
    ) -> Result<(), OperationError> {
        // figured we would want a audit_segment to wrap internal_create so when doing profiling we can
        // tell which function is calling it. either this one or restore.
        audit_segment!(au, || {
            if entries.is_empty() {
                audit_log!(
                    au,
                    "No entries provided to BE to create, invalid server call!"
                );
                return Err(OperationError::EmptyRequest);
            }

            // Turn all the entries into relevent json/cbor types
            // we do this outside the txn to avoid blocking needlessly.
            // However, it could be pointless due to the extra string allocs ...

            let dbentries: Vec<_> = entries.iter().map(|e| e.into_dbentry()).collect();

            self.internal_create(au, &dbentries)

            // TODO #8: update indexes (as needed)
        })
    }

    pub fn modify(
        &self,
        au: &mut AuditScope,
        entries: &Vec<Entry<EntryValid, EntryCommitted>>,
    ) -> Result<(), OperationError> {
        if entries.is_empty() {
            audit_log!(
                au,
                "No entries provided to BE to modify, invalid server call!"
            );
            return Err(OperationError::EmptyRequest);
        }

        // Assert the Id's exist on the entry, and serialise them.
        // Now, that means the ID must be > 0!!!
        let ser_entries: Result<Vec<IdEntry>, _> = entries
            .iter()
            .map(|e| {
                let db_e = e.into_dbentry();

                let id = i64::try_from(e.get_id())
                    .map_err(|_| OperationError::InvalidEntryID)
                    .and_then(|id| {
                        if id == 0 {
                            Err(OperationError::InvalidEntryID)
                        } else {
                            Ok(id)
                        }
                    })?;

                let data = serde_cbor::to_vec(&db_e).map_err(|_| OperationError::SerdeCborError)?;

                Ok(IdEntry {
                    // TODO #8: Instead of getting these from the server entry struct , we could lookup
                    // uuid -> id in the index.
                    //
                    // relies on the uuid -> id index being correct (and implemented)
                    id: id,
                    data: data,
                })
            })
            .collect();

        let ser_entries = try_audit!(au, ser_entries);

        // audit_log!(au, "serialising: {:?}", ser_entries);

        // Simple: If the list of id's is not the same as the input list, we are missing id's
        //
        // The entry state checks prevent this from really ever being triggered, but we
        // still prefer paranoia :)
        if entries.len() != ser_entries.len() {
            return Err(OperationError::InvalidEntryState);
        }

        // Now, given the list of id's, update them
        {
            let mut stmt = try_audit!(
                au,
                self.conn
                    .prepare("UPDATE id2entry SET data = :data WHERE id = :id"),
                "RusqliteError: {:?}",
                OperationError::SQLiteError
            );

            for ser_ent in ser_entries.iter() {
                try_audit!(
                    au,
                    stmt.execute_named(&[(":id", &ser_ent.id), (":data", &ser_ent.data)]),
                    "RusqliteError: {:?}",
                    OperationError::SQLiteError
                );
            }
        }

        Ok(())
    }

    pub fn delete(
        &self,
        au: &mut AuditScope,
        entries: &Vec<Entry<EntryValid, EntryCommitted>>,
    ) -> Result<(), OperationError> {
        // Perform a search for the entries --> This is a problem for the caller
        audit_segment!(au, || {
            if entries.is_empty() {
                audit_log!(
                    au,
                    "No entries provided to BE to delete, invalid server call!"
                );
                return Err(OperationError::EmptyRequest);
            }

            // Assert the Id's exist on the entry.
            let id_list: Result<Vec<i64>, _> = entries
                .iter()
                .map(|e| {
                    i64::try_from(e.get_id())
                        .map_err(|_| OperationError::InvalidEntryID)
                        .and_then(|id| {
                            if id == 0 {
                                Err(OperationError::InvalidEntryID)
                            } else {
                                Ok(id)
                            }
                        })
                })
                .collect();

            let id_list = try_audit!(au, id_list);

            // Simple: If the list of id's is not the same as the input list, we are missing id's
            if entries.len() != id_list.len() {
                return Err(OperationError::InvalidEntryState);
            }

            // Now, given the list of id's, delete them.
            {
                // SQL doesn't say if the thing "does or does not exist anymore". As a result,
                // two deletes is a safe and valid operation. Given how we allocate ID's we are
                // probably okay with this.
                let mut stmt = try_audit!(
                    au,
                    self.conn.prepare("DELETE FROM id2entry WHERE id = :id"),
                    "SQLite Error {:?}",
                    OperationError::SQLiteError
                );

                for id in id_list.iter() {
                    stmt.execute(&[id])
                        .map_err(|_| OperationError::SQLiteError)?;
                }
            }

            Ok(())
        })
    }

    pub unsafe fn purge(&self, audit: &mut AuditScope) -> Result<(), OperationError> {
        // remove all entries from database
        try_audit!(
            audit,
            self.conn.execute("DELETE FROM id2entry", NO_PARAMS),
            "rustqlite error {:?}",
            OperationError::SQLiteError
        );

        Ok(())
    }

    pub fn restore(&self, audit: &mut AuditScope, src_path: &str) -> Result<(), OperationError> {
        // load all entries into RAM, may need to change this later
        // if the size of the database compared to RAM is an issue
        let serialized_string_option = fs::read_to_string(src_path);

        let serialized_string = try_audit!(
            audit,
            serialized_string_option,
            "fs::read_to_string {:?}",
            OperationError::FsError
        );

        try_audit!(audit, unsafe { self.purge(audit) });

        let entries_option: Result<Vec<DbEntry>, serde_json::Error> =
            serde_json::from_str(&serialized_string);

        let entries = try_audit!(
            audit,
            entries_option,
            "serde_json error {:?}",
            OperationError::SerdeJsonError
        );

        self.internal_create(audit, &entries)?;

        let vr = self.verify();
        if vr.len() == 0 {
            Ok(())
        } else {
            Err(OperationError::ConsistencyError(vr))
        }
        // TODO #8: run re-index after db is restored
    }

    pub fn commit(mut self) -> Result<(), OperationError> {
        debug!("Commiting BE txn");
        assert!(!self.committed);
        self.committed = true;
        self.conn
            .execute("COMMIT TRANSACTION", NO_PARAMS)
            .map(|_| ())
            .map_err(|e| {
                println!("{:?}", e);
                OperationError::BackendEngine
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

    pub fn setup(&self, audit: &mut AuditScope) -> Result<(), OperationError> {
        {
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
            audit_log!(audit, "dbv_id2entry initial == {}", dbv_id2entry);

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
                dbv_id2entry = 1;
                audit_log!(audit, "dbv_id2entry migrated -> {}", dbv_id2entry);
            }
            //   * if v1 -> complete.

            try_audit!(
                audit,
                self.conn.execute_named(
                    "INSERT OR REPLACE INTO db_version (id, version) VALUES(:id, :dbv_id2entry)",
                    &[(":id", &DBV_ID2ENTRY), (":dbv_id2entry", &dbv_id2entry)],
                ),
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
}

// In the future this will do the routing between the chosen backends etc.
impl Backend {
    pub fn new(audit: &mut AuditScope, path: &str, pool_size: u32) -> Result<Self, OperationError> {
        // this has a ::memory() type, but will path == "" work?
        audit_segment!(audit, || {
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
            let pool = builder2.build(manager).expect("Failed to create pool");
            let be = Backend { pool: pool };

            // Now complete our setup with a txn
            let r = {
                let be_txn = be.write();
                be_txn.setup(audit).and_then(|_| be_txn.commit())
            };

            audit_log!(audit, "be new setup: {:?}", r);

            match r {
                Ok(_) => Ok(be),
                Err(e) => Err(e),
            }
        })
    }

    pub fn read(&self) -> BackendReadTransaction {
        let conn = self
            .pool
            .get()
            .expect("Unable to get connection from pool!!!");
        BackendReadTransaction::new(conn)
    }

    pub fn write(&self) -> BackendWriteTransaction {
        let conn = self
            .pool
            .get()
            .expect("Unable to get connection from pool!!!");
        BackendWriteTransaction::new(conn)
    }
}

impl Clone for Backend {
    fn clone(&self) -> Self {
        // Make another Be and close the pool.
        Backend {
            pool: self.pool.clone(),
        }
    }
}

// What are the possible actions we'll recieve here?

#[cfg(test)]
mod tests {

    use std::fs;

    use super::super::audit::AuditScope;
    use super::super::entry::{Entry, EntryInvalid, EntryNew};
    use super::{Backend, BackendTransaction, BackendWriteTransaction, OperationError};

    macro_rules! run_test {
        ($test_fn:expr) => {{
            let mut audit = AuditScope::new("run_test");

            let be = Backend::new(&mut audit, "", 1).expect("Failed to setup backend");
            let be_txn = be.write();

            // Could wrap another future here for the future::ok bit...
            let r = $test_fn(&mut audit, &be_txn);
            // Commit, to guarantee it worked.
            assert!(be_txn.commit().is_ok());
            println!("{}", audit);
            r
        }};
    }

    macro_rules! entry_exists {
        ($audit:expr, $be:expr, $ent:expr) => {{
            let ei = unsafe { $ent.clone().to_valid_committed() };
            let filt = unsafe {
                ei.filter_from_attrs(&vec![String::from("userid")])
                    .expect("failed to generate filter")
                    .to_valid_resolved()
            };
            let entries = $be.search($audit, &filt).expect("failed to search");
            entries.first().is_some()
        }};
    }

    macro_rules! entry_attr_pres {
        ($audit:expr, $be:expr, $ent:expr, $attr:expr) => {{
            let ei = unsafe { $ent.clone().to_valid_committed() };
            let filt = unsafe {
                ei.filter_from_attrs(&vec![String::from("userid")])
                    .expect("failed to generate filter")
                    .to_valid_resolved()
            };
            let entries = $be.search($audit, &filt).expect("failed to search");
            match entries.first() {
                Some(ent) => ent.attribute_pres($attr),
                None => false,
            }
        }};
    }

    #[test]
    fn test_simple_create() {
        run_test!(|audit: &mut AuditScope, be: &BackendWriteTransaction| {
            audit_log!(audit, "Simple Create");

            let empty_result = be.create(audit, &Vec::new());
            audit_log!(audit, "{:?}", empty_result);
            assert_eq!(empty_result, Err(OperationError::EmptyRequest));

            let mut e: Entry<EntryInvalid, EntryNew> = Entry::new();
            e.add_ava("userid", "william");
            e.add_ava("uuid", "db237e8a-0079-4b8c-8a56-593b22aa44d1");
            let e = unsafe { e.to_valid_new() };

            let single_result = be.create(audit, &vec![e.clone()]);

            assert!(single_result.is_ok());

            // Construct a filter
            assert!(entry_exists!(audit, be, e));
        });
    }

    #[test]
    fn test_simple_search() {
        run_test!(|audit: &mut AuditScope, be: &BackendWriteTransaction| {
            audit_log!(audit, "Simple Search");

            let mut e: Entry<EntryInvalid, EntryNew> = Entry::new();
            e.add_ava("userid", "claire");
            e.add_ava("uuid", "db237e8a-0079-4b8c-8a56-593b22aa44d1");
            let e = unsafe { e.to_valid_new() };

            let single_result = be.create(audit, &vec![e.clone()]);
            assert!(single_result.is_ok());
            // Test a simple EQ search

            let filt = unsafe { filter_resolved!(f_eq("userid", "claire")) };

            let r = be.search(audit, &filt);
            assert!(r.expect("Search failed!").len() == 1);

            // Test empty search

            // Test class pres

            // Search with no results
        });
    }

    #[test]
    fn test_simple_modify() {
        run_test!(|audit: &mut AuditScope, be: &BackendWriteTransaction| {
            audit_log!(audit, "Simple Modify");
            // First create some entries (3?)
            let mut e1: Entry<EntryInvalid, EntryNew> = Entry::new();
            e1.add_ava("userid", "william");
            e1.add_ava("uuid", "db237e8a-0079-4b8c-8a56-593b22aa44d1");

            let mut e2: Entry<EntryInvalid, EntryNew> = Entry::new();
            e2.add_ava("userid", "alice");
            e2.add_ava("uuid", "4b6228ab-1dbe-42a4-a9f5-f6368222438e");

            let ve1 = unsafe { e1.clone().to_valid_new() };
            let ve2 = unsafe { e2.clone().to_valid_new() };

            assert!(be.create(audit, &vec![ve1, ve2]).is_ok());
            assert!(entry_exists!(audit, be, e1));
            assert!(entry_exists!(audit, be, e2));

            // You need to now retrieve the entries back out to get the entry id's
            let mut results = be
                .search(audit, unsafe { &filter_resolved!(f_pres("userid")) })
                .expect("Failed to search");

            // Get these out to usable entries.
            let r1 = results.remove(0);
            let r2 = results.remove(0);

            let mut r1 = r1.invalidate();
            let mut r2 = r2.invalidate();

            // Modify no id (err)
            // This is now impossible due to the state machine design.
            // However, with some unsafe ....
            let ue1 = unsafe { e1.clone().to_valid_committed() };
            assert!(be.modify(audit, &vec![ue1]).is_err());
            // Modify none
            assert!(be.modify(audit, &vec![]).is_err());

            // Make some changes to r1, r2.
            r1.add_ava("desc", "modified");
            r2.add_ava("desc", "modified");

            // Now ... cheat.

            let vr1 = unsafe { r1.to_valid_committed() };
            let vr2 = unsafe { r2.to_valid_committed() };

            // Modify single
            assert!(be.modify(audit, &vec![vr1.clone()]).is_ok());
            // Assert no other changes
            assert!(entry_attr_pres!(audit, be, vr1, "desc"));
            assert!(!entry_attr_pres!(audit, be, vr2, "desc"));

            // Modify both
            assert!(be.modify(audit, &vec![vr1.clone(), vr2.clone()]).is_ok());

            assert!(entry_attr_pres!(audit, be, vr1, "desc"));
            assert!(entry_attr_pres!(audit, be, vr2, "desc"));
        });
    }

    #[test]
    fn test_simple_delete() {
        run_test!(|audit: &mut AuditScope, be: &BackendWriteTransaction| {
            audit_log!(audit, "Simple Delete");

            // First create some entries (3?)
            let mut e1: Entry<EntryInvalid, EntryNew> = Entry::new();
            e1.add_ava("userid", "william");
            e1.add_ava("uuid", "db237e8a-0079-4b8c-8a56-593b22aa44d1");

            let mut e2: Entry<EntryInvalid, EntryNew> = Entry::new();
            e2.add_ava("userid", "alice");
            e2.add_ava("uuid", "4b6228ab-1dbe-42a4-a9f5-f6368222438e");

            let mut e3: Entry<EntryInvalid, EntryNew> = Entry::new();
            e3.add_ava("userid", "lucy");
            e3.add_ava("uuid", "7b23c99d-c06b-4a9a-a958-3afa56383e1d");

            let ve1 = unsafe { e1.clone().to_valid_new() };
            let ve2 = unsafe { e2.clone().to_valid_new() };
            let ve3 = unsafe { e3.clone().to_valid_new() };

            assert!(be.create(audit, &vec![ve1, ve2, ve3]).is_ok());
            assert!(entry_exists!(audit, be, e1));
            assert!(entry_exists!(audit, be, e2));
            assert!(entry_exists!(audit, be, e3));

            // You need to now retrieve the entries back out to get the entry id's
            let mut results = be
                .search(audit, unsafe { &filter_resolved!(f_pres("userid")) })
                .expect("Failed to search");

            // Get these out to usable entries.
            let r1 = results.remove(0);
            let r2 = results.remove(0);
            let r3 = results.remove(0);

            // Delete one
            assert!(be.delete(audit, &vec![r1.clone()]).is_ok());
            assert!(!entry_exists!(audit, be, r1));

            // delete none (no match filter)
            assert!(be.delete(audit, &vec![]).is_err());

            // Delete with no id
            // WARNING: Normally, this isn't possible, but we are pursposefully breaking
            // the state machine rules here!!!!
            let mut e4: Entry<EntryInvalid, EntryNew> = Entry::new();
            e4.add_ava("userid", "amy");
            e4.add_ava("uuid", "21d816b5-1f6a-4696-b7c1-6ed06d22ed81");

            let ve4 = unsafe { e4.clone().to_valid_committed() };

            assert!(be.delete(audit, &vec![ve4]).is_err());

            assert!(entry_exists!(audit, be, r2));
            assert!(entry_exists!(audit, be, r3));

            // delete batch
            assert!(be.delete(audit, &vec![r2.clone(), r3.clone()]).is_ok());

            assert!(!entry_exists!(audit, be, r2));
            assert!(!entry_exists!(audit, be, r3));

            // delete none (no entries left)
            // see fn delete for why this is ok, not err
            assert!(be.delete(audit, &vec![r2.clone(), r3.clone()]).is_ok());
        });
    }

    pub static DB_BACKUP_FILE_NAME: &'static str = "./.backup_test.db";

    #[test]
    fn test_backup_restore() {
        run_test!(|audit: &mut AuditScope, be: &BackendWriteTransaction| {
            // First create some entries (3?)
            let mut e1: Entry<EntryInvalid, EntryNew> = Entry::new();
            e1.add_ava("userid", "william");
            e1.add_ava("uuid", "db237e8a-0079-4b8c-8a56-593b22aa44d1");

            let mut e2: Entry<EntryInvalid, EntryNew> = Entry::new();
            e2.add_ava("userid", "alice");
            e2.add_ava("uuid", "4b6228ab-1dbe-42a4-a9f5-f6368222438e");

            let mut e3: Entry<EntryInvalid, EntryNew> = Entry::new();
            e3.add_ava("userid", "lucy");
            e3.add_ava("uuid", "7b23c99d-c06b-4a9a-a958-3afa56383e1d");

            let ve1 = unsafe { e1.clone().to_valid_new() };
            let ve2 = unsafe { e2.clone().to_valid_new() };
            let ve3 = unsafe { e3.clone().to_valid_new() };

            assert!(be.create(audit, &vec![ve1, ve2, ve3]).is_ok());
            assert!(entry_exists!(audit, be, e1));
            assert!(entry_exists!(audit, be, e2));
            assert!(entry_exists!(audit, be, e3));

            let result = fs::remove_file(DB_BACKUP_FILE_NAME);

            match result {
                Err(e) => {
                    // if the error is the file is not found, thats what we want so continue,
                    // otherwise return the error
                    match e.kind() {
                        std::io::ErrorKind::NotFound => {}
                        _ => (),
                    }
                }
                _ => (),
            }

            be.backup(audit, DB_BACKUP_FILE_NAME)
                .expect("Backup failed!");
            be.restore(audit, DB_BACKUP_FILE_NAME)
                .expect("Restore failed!");
        });
    }
}
