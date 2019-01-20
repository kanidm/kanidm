//! Db executor actor

use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::types::ToSql;
use rusqlite::NO_PARAMS;
use serde_json;
// use uuid;

use audit::AuditScope;
use entry::Entry;
use filter::Filter;

mod idl;
mod mem_be;
mod sqlite_be;

#[derive(Debug)]
struct IdEntry {
    // FIXME: This should be u64, but sqlite uses i32 ...
    // Should we use a bigint pk and just be done?
    id: i32,
    data: String,
}

/*
pub enum BackendType {
    Memory, // isn't memory just sqlite with file :memory: ?
    SQLite,
}
*/

#[derive(Debug, PartialEq)]
pub enum BackendError {
    EmptyRequest,
}

pub struct Backend {
    pool: Pool<SqliteConnectionManager>,
}

pub struct BackendTransaction {
    committed: bool,
    conn: r2d2::PooledConnection<SqliteConnectionManager>,
}

pub struct BackendWriteTransaction {
    committed: bool,
    conn: r2d2::PooledConnection<SqliteConnectionManager>,
}

pub trait BackendReadTransaction {
    fn get_conn(&self) -> &r2d2::PooledConnection<r2d2_sqlite::SqliteConnectionManager>;

    // Take filter, and AuditScope ref?
    fn search(&self, au: &mut AuditScope, filt: &Filter) -> Result<Vec<Entry>, BackendError> {
        // Do things
        // Alloc a vec for the entries.
        // FIXME: Make this actually a good size for the result set ...
        // FIXME: Actually compute indexes here.
        // So to make this use indexes, we can use the filter type and
        // destructure it to work out what we need to actually search (if
        // possible) to create the candidate set.
        // Unlike DS, even if we don't get the index back, we can just pass
        // to the in-memory filter test and be done.
        audit_segment!(au, || {
            let mut raw_entries: Vec<String> = Vec::new();
            {
                // Actually do a search now!
                // let conn = self.pool.get().unwrap();
                // Start a txn
                // conn.execute("BEGIN TRANSACTION", NO_PARAMS).unwrap();

                // read them all
                let mut stmt = self
                    .get_conn()
                    .prepare("SELECT id, data FROM id2entry")
                    .unwrap();
                let id2entry_iter = stmt
                    .query_map(NO_PARAMS, |row| IdEntry {
                        id: row.get(0),
                        data: row.get(1),
                    })
                    .unwrap();
                for row in id2entry_iter {
                    audit_log!(au, "raw entry: {:?}", row);
                    // FIXME: Handle this properly.
                    raw_entries.push(row.unwrap().data);
                }
                // Rollback, we should have done nothing.
                // conn.execute("ROLLBACK TRANSACTION", NO_PARAMS).unwrap();
            }
            // Do other things
            // Now, de-serialise the raw_entries back to entries
            let entries: Vec<Entry> = raw_entries
                .iter()
                .filter_map(|val| {
                    // TODO: Should we do better than unwrap?
                    let e: Entry = serde_json::from_str(val.as_str()).unwrap();
                    if filt.entry_match_no_index(&e) {
                        Some(e)
                    } else {
                        None
                    }
                })
                .collect();

            Ok(entries)
        })
    }

    /// Given a filter, assert some condition exists.
    /// Basically, this is a specialised case of search, where we don't need to
    /// load any candidates if they match. This is heavily used in uuid
    /// refint and attr uniqueness.
    fn exists(&self, au: &mut AuditScope, filt: &Filter) -> Result<bool, BackendError> {
        let r = self.search(au, filt);
        match r {
            Ok(v) => {
                if v.len() > 0 {
                    audit_log!(au, "candidate exists {:?}", filt);
                    Ok(true)
                } else {
                    audit_log!(au, "candidate does not exist {:?}", filt);
                    Ok(false)
                }
            }
            Err(e) => {
                audit_log!(au, "error processing filt {:?}, {:?}", filt, e);
                Err(e)
            }
        }
    }
}

impl Drop for BackendTransaction {
    // Abort
    // TODO: Is this correct for RO txn?
    fn drop(self: &mut Self) {
        if !self.committed {
            println!("Aborting txn");
            self.conn
                .execute("ROLLBACK TRANSACTION", NO_PARAMS)
                .unwrap();
        }
    }
}

impl BackendTransaction {
    pub fn new(conn: r2d2::PooledConnection<SqliteConnectionManager>) -> Self {
        // Start the transaction
        println!("Starting txn ...");
        // TODO: Way to flag that this will be a read?
        conn.execute("BEGIN TRANSACTION", NO_PARAMS).unwrap();
        BackendTransaction {
            committed: false,
            conn: conn,
        }
    }
}

impl BackendReadTransaction for BackendTransaction {
    fn get_conn(&self) -> &r2d2::PooledConnection<r2d2_sqlite::SqliteConnectionManager> {
        &self.conn
    }
}

static DBV_ID2ENTRY: &'static str = "id2entry";
static DBV_INDEX: &'static str = "index";

impl Drop for BackendWriteTransaction {
    // Abort
    fn drop(self: &mut Self) {
        if !self.committed {
            println!("Aborting txn");
            self.conn
                .execute("ROLLBACK TRANSACTION", NO_PARAMS)
                .unwrap();
        }
    }
}

impl BackendReadTransaction for BackendWriteTransaction {
    fn get_conn(&self) -> &r2d2::PooledConnection<r2d2_sqlite::SqliteConnectionManager> {
        &self.conn
    }
}

impl BackendWriteTransaction {
    pub fn new(conn: r2d2::PooledConnection<SqliteConnectionManager>) -> Self {
        // Start the transaction
        println!("Starting txn ...");
        // TODO: Way to flag that this will be a write?
        conn.execute("BEGIN TRANSACTION", NO_PARAMS).unwrap();
        BackendWriteTransaction {
            committed: false,
            conn: conn,
        }
    }

    pub fn create(&self, au: &mut AuditScope, entries: &Vec<Entry>) -> Result<(), BackendError> {
        audit_segment!(au, || {
            // Start be audit timer

            if entries.is_empty() {
                // TODO: Better error
                // End the timer
                return Err(BackendError::EmptyRequest);
            }

            // Turn all the entries into relevent json/cbor types
            // we do this outside the txn to avoid blocking needlessly.
            // However, it could be pointless due to the extra string allocs ...

            let ser_entries: Vec<String> = entries
                .iter()
                .map(|val| {
                    // TODO: Should we do better than unwrap?
                    serde_json::to_string(&val).unwrap()
                })
                .collect();

            audit_log!(au, "serialising: {:?}", ser_entries);

            // THIS IS PROBABLY THE BIT WHERE YOU NEED DB ABSTRACTION
            {
                // Start a txn
                // self.conn.execute("BEGIN TRANSACTION", NO_PARAMS).unwrap();

                // write them all
                for ser_entry in ser_entries {
                    self.conn
                        .execute(
                            "INSERT INTO id2entry (data) VALUES (?1)",
                            &[&ser_entry as &ToSql],
                        )
                        .unwrap();
                }

                // TODO: update indexes (as needed)
                // Commit the txn
                // conn.execute("COMMIT TRANSACTION", NO_PARAMS).unwrap();
            }

            Ok(())
        })
    }

    pub fn modify() {
        unimplemented!()
    }

    pub fn delete() {
        unimplemented!()
    }

    pub fn backup() {
        unimplemented!()
    }

    // Should this be offline only?
    pub fn restore() {
        unimplemented!()
    }

    pub fn commit(mut self) -> Result<(), ()> {
        println!("Commiting txn");
        assert!(!self.committed);
        self.committed = true;
        self.conn
            .execute("COMMIT TRANSACTION", NO_PARAMS)
            .map(|_| ())
            .map_err(|e| {
                println!("{:?}", e);
                ()
            })
    }

    // ===== inner helpers =====
    // Some of these are not self due to use in new()
    fn get_db_version_key(&self, key: &str) -> i32 {
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

    pub fn setup(&self, audit: &mut AuditScope) -> Result<(), ()> {
        {
            // self.conn.execute("BEGIN TRANSACTION", NO_PARAMS).unwrap();

            // conn.execute("PRAGMA journal_mode=WAL;", NO_PARAMS).unwrap();
            //
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
                    NO_PARAMS,
                )
                .unwrap();

            // If the table is empty, populate the versions as 0.
            let mut dbv_id2entry = self.get_db_version_key(DBV_ID2ENTRY);
            audit_log!(audit, "dbv_id2entry initial == {}", dbv_id2entry);

            // Check db_version here.
            //   * if 0 -> create v1.
            if dbv_id2entry == 0 {
                self.conn
                    .execute(
                        "CREATE TABLE IF NOT EXISTS id2entry (
                            id INTEGER PRIMARY KEY ASC,
                            data TEXT NOT NULL
                        )
                        ",
                        NO_PARAMS,
                    )
                    .unwrap();
                dbv_id2entry = 1;
                audit_log!(audit, "dbv_id2entry migrated -> {}", dbv_id2entry);
            }
            //   * if v1 -> complete.

            self.conn
                .execute_named(
                    "INSERT OR REPLACE INTO db_version (id, version) VALUES(:id, :dbv_id2entry)",
                    &[(":id", &DBV_ID2ENTRY), (":dbv_id2entry", &dbv_id2entry)],
                )
                .unwrap();

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
    pub fn new(audit: &mut AuditScope, path: &str) -> Result<Self, ()> {
        // this has a ::memory() type, but will path == "" work?
        audit_segment!(audit, || {
            let manager = SqliteConnectionManager::file(path);
            let builder1 = Pool::builder();
            let builder2 = if path == "" {
                // We are in a debug mode, with in memory. We MUST have only
                // a single DB thread, else we cause consistency issues.
                builder1.max_size(1)
            } else {
                // FIXME: Make this configurable
                builder1.max_size(8)
            };
            // Look at max_size and thread_pool here for perf later
            let pool = builder2.build(manager).expect("Failed to create pool");
            let be = Backend { pool: pool };

            // Now complete our setup with a txn
            let r = {
                let be_txn = be.write();
                be_txn.setup(audit);
                be_txn.commit()
            };

            audit_log!(audit, "be new setup: {:?}", r);

            match r {
                Ok(_) => Ok(be),
                Err(e) => Err(e),
            }
        })
    }

    pub fn read(&self) -> BackendTransaction {
        let conn = self.pool.get().unwrap();
        BackendTransaction::new(conn)
    }

    pub fn write(&self) -> BackendWriteTransaction {
        let conn = self.pool.get().unwrap();
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
    extern crate actix;
    use actix::prelude::*;

    extern crate futures;
    use futures::future;
    use futures::future::Future;

    extern crate tokio;

    use super::super::audit::AuditScope;
    use super::super::entry::Entry;
    use super::super::filter::Filter;
    use super::{
        Backend, BackendError, BackendReadTransaction, BackendTransaction, BackendWriteTransaction,
    };

    macro_rules! run_test {
        ($test_fn:expr) => {{
            let mut audit = AuditScope::new("run_test");

            let be = Backend::new(&mut audit, "").unwrap();
            let mut be_txn = be.write();

            // Could wrap another future here for the future::ok bit...
            let r = $test_fn(&mut audit, &be_txn);
            // Commit, to guarantee it worked.
            assert!(be_txn.commit().is_ok());
            println!("{}", audit);
            r
        }};
    }

    #[test]
    fn test_simple_create() {
        run_test!(|audit: &mut AuditScope, be: &BackendWriteTransaction| {
            audit_log!(audit, "Simple Create");

            let empty_result = be.create(audit, &Vec::new());
            audit_log!(audit, "{:?}", empty_result);
            assert_eq!(empty_result, Err(BackendError::EmptyRequest));

            let mut e: Entry = Entry::new();
            e.add_ava(String::from("userid"), String::from("william"));

            let single_result = be.create(audit, &vec![e]);

            assert!(single_result.is_ok());

            // Construct a filter
            let filt = Filter::Pres(String::from("userid"));
            let entries = be.search(audit, &filt).unwrap();

            // There should only be one entry so is this enough?
            assert!(entries.first().is_some());
            // Later we could check consistency of the entry saved ...
        });
    }

    #[test]
    fn test_simple_search() {
        run_test!(|audit: &mut AuditScope, be: &BackendWriteTransaction| {
            audit_log!(audit, "Simple Search");
        });
    }

    #[test]
    fn test_simple_modify() {
        run_test!(|audit: &mut AuditScope, be: &BackendWriteTransaction| {
            audit_log!(audit, "Simple Modify");
        });
    }

    #[test]
    fn test_simple_delete() {
        run_test!(|audit: &mut AuditScope, be: &BackendWriteTransaction| {
            audit_log!(audit, "Simple Delete");
        });
    }
}
