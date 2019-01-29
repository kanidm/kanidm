//! Db executor actor

use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::types::ToSql;
use rusqlite::NO_PARAMS;
use serde_json;
// use uuid;

use audit::AuditScope;
use entry::{Entry, EntryValid, EntryNew, EntryCommitted};
use filter::Filter;

mod idl;
mod mem_be;
mod sqlite_be;

#[derive(Debug)]
struct IdEntry {
    // FIXME: This should be u64, but sqlite uses i64 ...
    id: i64,
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
    EntryMissingId,
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
    fn search(&self, au: &mut AuditScope, filt: &Filter) -> Result<Vec<Entry<EntryValid, EntryCommitted>>, BackendError> {
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
            // Do a final optimise of the filter
            let filt = filt.optimise();

            let mut raw_entries: Vec<IdEntry> = Vec::new();
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
                    // FIXME: Handle possible errors correctly.
                    raw_entries.push(row.unwrap());
                }
            }
            // Do other things
            // Now, de-serialise the raw_entries back to entries, and populate their ID's
            let entries: Vec<Entry<EntryValid, EntryCommitted>> = raw_entries
                .iter()
                .filter_map(|id_ent| {
                    // TODO: Should we do better than unwrap?
                    let mut e: Entry<EntryValid, EntryCommitted> = serde_json::from_str(id_ent.data.as_str()).unwrap();
                    e.id = Some(id_ent.id);
                    if e.entry_match_no_index(&filt) {
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
        // Do a final optimise of the filter
        // At the moment, technically search will do this, but it won't always be the
        // case once this becomes a standalone function.
        let filt = filt.optimise();

        let r = self.search(au, &filt);
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
        println!("Starting RO txn ...");
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
// static DBV_INDEX: &'static str = "index";

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
        println!("Starting WR txn ...");
        // TODO: Way to flag that this will be a write?
        conn.execute("BEGIN TRANSACTION", NO_PARAMS).unwrap();
        BackendWriteTransaction {
            committed: false,
            conn: conn,
        }
    }

    fn get_id2entry_max_id(&self) -> i64 {
        let mut stmt = self.conn.prepare("SELECT MAX(id) as id_max FROM id2entry").unwrap();
        assert!(stmt.exists(NO_PARAMS).unwrap());

        let i: Option<i64> = stmt.query_row(NO_PARAMS, |row| row.get(0))
            .expect("failed to execute");
        match i {
            Some(e) => e,
            None => 0,
        }
    }

    pub fn create(&self, au: &mut AuditScope, entries: &Vec<Entry<EntryValid, EntryNew>>) -> Result<(), BackendError> {
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

            // Get the max id from the db. We store this ourselves to avoid max().
            let mut id_max = self.get_id2entry_max_id();

            let ser_entries: Vec<IdEntry> = entries
                .iter()
                .map(|val| {
                    // TODO: Should we do better than unwrap?
                    id_max = id_max + 1;
                    IdEntry {
                        id: id_max,
                        data: serde_json::to_string(&val).unwrap(),
                    }
                })
                .collect();

            audit_log!(au, "serialising: {:?}", ser_entries);

            // THIS IS PROBABLY THE BIT WHERE YOU NEED DB ABSTRACTION
            {
                // Start a txn
                // self.conn.execute("BEGIN TRANSACTION", NO_PARAMS).unwrap();

                // write them all
                for ser_entry in ser_entries {
                    // TODO: Prepared statement.
                    self.conn
                        .execute(
                            "INSERT INTO id2entry (id, data) VALUES (?1, ?2)",
                            &[&ser_entry.id as &ToSql, &ser_entry.data as &ToSql],
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

    pub fn modify(&self, au: &mut AuditScope, entries: &Vec<Entry<EntryValid, EntryCommitted>>) -> Result<(), BackendError> {
        if entries.is_empty() {
            // TODO: Better error
            return Err(BackendError::EmptyRequest);
        }

        // Assert the Id's exist on the entry, and serialise them.
        let ser_entries: Vec<IdEntry> = entries
            .iter()
            .filter_map(|e| {
                match e.id {
                    Some(id) => {
                        Some(IdEntry {
                            id: id,
                            // TODO: Should we do better than unwrap?
                            data: serde_json::to_string(&e).unwrap(),
                        })
                    }
                    None => None
                }
            })
            .collect();

        audit_log!(au, "serialising: {:?}", ser_entries);

        // Simple: If the list of id's is not the same as the input list, we are missing id's
        // TODO: This check won't be needed once I rebuild the entry state types.
        if entries.len() != ser_entries.len() {
            return Err(BackendError::EntryMissingId);
        }

        // Now, given the list of id's, update them
        {
            // TODO: ACTUALLY HANDLE THIS ERROR WILLIAM YOU LAZY SHIT.
            let mut stmt = self.conn.prepare("UPDATE id2entry SET data = :data WHERE id = :id").unwrap();

            ser_entries.iter().for_each(|ser_ent| {
                stmt.execute_named(&[
                    (":id", &ser_ent.id),
                    (":data", &ser_ent.data),
                ]).unwrap();
            });
        }

        Ok(())
    }

    pub fn delete(&self, au: &mut AuditScope, entries: &Vec<Entry<EntryValid, EntryCommitted>>) -> Result<(), BackendError> {
        // Perform a search for the entries --> This is a problem for the caller

        if entries.is_empty() {
            // TODO: Better error
            return Err(BackendError::EmptyRequest);
        }

        // Assert the Id's exist on the entry.
        let id_list: Vec<i64> = entries.iter()
            .filter_map(|entry| {
                entry.id
            })
            .collect();

        // Simple: If the list of id's is not the same as the input list, we are missing id's
        // TODO: This check won't be needed once I rebuild the entry state types.
        if entries.len() != id_list.len() {
            return Err(BackendError::EntryMissingId);
        }

        // Now, given the list of id's, delete them.
        {
            // SQL doesn't say if the thing "does or does not exist anymore". As a result,
            // two deletes is a safe and valid operation. Given how we allocate ID's we are
            // probably okay with this.

            // TODO: ACTUALLY HANDLE THIS ERROR WILLIAM YOU LAZY SHIT.
            let mut stmt = self.conn.prepare("DELETE FROM id2entry WHERE id = :id").unwrap();

            id_list.iter().for_each(|id| {
                stmt.execute(&[id]).unwrap();
            });
        }

        Ok(())
    }

    pub fn backup() -> Result<(), BackendError> {
        unimplemented!()
    }

    // Should this be offline only?
    pub fn restore() -> Result<(), BackendError> {
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
    use super::super::entry::{Entry, EntryInvalid, EntryValid, EntryNew, EntryCommitted};
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

    macro_rules! entry_exists {
        ($audit:expr, $be:expr, $ent:expr) => {{
            let ei = unsafe { $ent.clone().to_valid_committed() };
            let filt = ei.filter_from_attrs(&vec![String::from("userid")]).unwrap();
            let entries = $be.search($audit, &filt).unwrap();
            entries.first().is_some()
        }}
    }

    macro_rules! entry_attr_pres {
        ($audit:expr, $be:expr, $ent:expr, $attr:expr) => {{
            let ei = unsafe { $ent.clone().to_valid_committed() };
            let filt = ei.filter_from_attrs(&vec![String::from("userid")]).unwrap();
            let entries = $be.search($audit, &filt).unwrap();
            match entries.first() {
                Some(ent) => {
                    ent.attribute_pres($attr)
                }
                None => false
            }
        }}
    }

    #[test]
    fn test_simple_create() {
        run_test!(|audit: &mut AuditScope, be: &BackendWriteTransaction| {
            audit_log!(audit, "Simple Create");

            let empty_result = be.create(audit, &Vec::new());
            audit_log!(audit, "{:?}", empty_result);
            assert_eq!(empty_result, Err(BackendError::EmptyRequest));

            let mut e: Entry<EntryInvalid, EntryNew> = Entry::new();
            e.add_ava(String::from("userid"), String::from("william"));
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
        });
    }

    #[test]
    fn test_simple_modify() {
        run_test!(|audit: &mut AuditScope, be: &BackendWriteTransaction| {
            audit_log!(audit, "Simple Modify");
            // First create some entries (3?)
            let mut e1: Entry<EntryInvalid, EntryNew> = Entry::new();
            e1.add_ava(String::from("userid"), String::from("william"));

            let mut e2: Entry<EntryInvalid, EntryNew> = Entry::new();
            e2.add_ava(String::from("userid"), String::from("alice"));

            let ve1 = unsafe { e1.clone().to_valid_new() };
            let ve2 = unsafe { e2.clone().to_valid_new() };

            assert!(be.create(audit, &vec![ve1, ve2]).is_ok());
            assert!(entry_exists!(audit, be, e1));
            assert!(entry_exists!(audit, be, e2));

            // You need to now retrieve the entries back out to get the entry id's
            let mut results = be.search(audit, &Filter::Pres(String::from("userid"))).unwrap();

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
            r1.add_ava(String::from("desc"), String::from("modified"));
            r2.add_ava(String::from("desc"), String::from("modified"));

            // Now ... cheat.

            let vr1 = unsafe { r1.to_valid_committed() };
            let vr2 = unsafe { r2.to_valid_committed() };

            // Modify single
            assert!(be.modify(audit, &vec![vr1.clone()]).is_ok());
            // Assert no other changes
            assert!(entry_attr_pres!(audit, be, vr1, "desc"));
            assert!(! entry_attr_pres!(audit, be, vr2, "desc"));

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
            e1.add_ava(String::from("userid"), String::from("william"));

            let mut e2: Entry<EntryInvalid, EntryNew> = Entry::new();
            e2.add_ava(String::from("userid"), String::from("alice"));

            let mut e3: Entry<EntryInvalid, EntryNew> = Entry::new();
            e3.add_ava(String::from("userid"), String::from("lucy"));

            let ve1 = unsafe { e1.clone().to_valid_new() };
            let ve2 = unsafe { e2.clone().to_valid_new() };
            let ve3 = unsafe { e3.clone().to_valid_new() };

            assert!(be.create(audit, &vec![ve1, ve2, ve3]).is_ok());
            assert!(entry_exists!(audit, be, e1));
            assert!(entry_exists!(audit, be, e2));
            assert!(entry_exists!(audit, be, e3));


            // You need to now retrieve the entries back out to get the entry id's
            let mut results = be.search(audit, &Filter::Pres(String::from("userid"))).unwrap();

            // Get these out to usable entries.
            let r1 = results.remove(0);
            let r2 = results.remove(0);
            let r3 = results.remove(0);

            // Delete one
            assert!(be.delete(audit, &vec![r1.clone()]).is_ok());
            assert!(! entry_exists!(audit, be, r1));

            // delete none (no match filter)
            assert!(be.delete(audit, &vec![]).is_err());

            // Delete with no id
            // WARNING: Normally, this isn't possible, but we are pursposefully breaking
            // the state machine rules here!!!!
            let mut e4: Entry<EntryInvalid, EntryNew> = Entry::new();
            e4.add_ava(String::from("userid"), String::from("amy"));

            let ve4 = unsafe { e4.clone().to_valid_committed() };

            assert!(be.delete(audit, &vec![ve4]).is_err());

            assert!(entry_exists!(audit, be, r2));
            assert!(entry_exists!(audit, be, r3));

            // delete batch
            assert!(be.delete(audit, &vec![r2.clone(), r3.clone()]).is_ok());

            assert!(! entry_exists!(audit, be, r2));
            assert!(! entry_exists!(audit, be, r3));

            // delete none (no entries left)
            // see fn delete for why this is ok, not err
            assert!(be.delete(audit, &vec![r2.clone(), r3.clone()]).is_ok());

        });
    }
}
