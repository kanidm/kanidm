//! Db executor actor

use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::types::ToSql;
use rusqlite::NO_PARAMS;
use serde_json;
// use uuid;

use super::audit::AuditScope;
use super::entry::Entry;
use super::filter::Filter;

mod idl;
mod mem_be;
mod sqlite_be;

// This contacts the needed backend and starts it up

#[derive(Debug, PartialEq)]
pub struct BackendAuditScope {
    time_start: (),
    time_end: (),
}

impl BackendAuditScope {
    pub fn new() -> Self {
        BackendAuditScope {
            time_start: (),
            time_end: (),
        }
    }
}

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

// In the future this will do the routing between the chosen backends etc.
impl Backend {
    pub fn new(audit: &mut AuditScope, path: &str) -> Self {
        // this has a ::memory() type, but will path == "" work?
        audit_segment!(audit, || {
            let manager = SqliteConnectionManager::file(path);
            let builder1 = Pool::builder();
            let builder2 = if path == "" {
                builder1.max_size(1)
            } else {
                // FIXME: Make this configurable
                builder1.max_size(8)
            };
            // Look at max_size and thread_pool here for perf later
            let pool = builder2.build(manager).expect("Failed to create pool");

            {
                let conn = pool.get().unwrap();
                // Perform any migrations as required?
                // I think we only need the core table here, indexing will do it's own
                // thing later
                // conn.execute("PRAGMA journal_mode=WAL;", NO_PARAMS).unwrap();
                conn.execute(
                    "CREATE TABLE IF NOT EXISTS id2entry (
                        id INTEGER PRIMARY KEY ASC,
                        data TEXT NOT NULL
                    )
                    ",
                    NO_PARAMS,
                )
                .unwrap();

                // Create a version table for migration indication

                // Create the core db
            }

            Backend { pool: pool }
        })
    }

    pub fn create(
        &mut self,
        au: &mut AuditScope,
        entries: &Vec<Entry>,
    ) -> Result<BackendAuditScope, BackendError> {
        audit_segment!(au, || {
            let be_audit = BackendAuditScope::new();
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
                let conn = self.pool.get().unwrap();
                // Start a txn
                conn.execute("BEGIN TRANSACTION", NO_PARAMS).unwrap();

                // write them all
                for ser_entry in ser_entries {
                    conn.execute(
                        "INSERT INTO id2entry (data) VALUES (?1)",
                        &[&ser_entry as &ToSql],
                    )
                    .unwrap();
                }

                // TODO: update indexes (as needed)
                // Commit the txn
                conn.execute("COMMIT TRANSACTION", NO_PARAMS).unwrap();
            }

            Ok(be_audit)
        })
    }

    // Take filter, and AuditScope ref?
    pub fn search(&self, au: &mut AuditScope, filt: &Filter) -> Result<Vec<Entry>, BackendError> {
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
                let conn = self.pool.get().unwrap();
                // Start a txn
                conn.execute("BEGIN TRANSACTION", NO_PARAMS).unwrap();

                // read them all
                let mut stmt = conn.prepare("SELECT id, data FROM id2entry").unwrap();
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
                conn.execute("ROLLBACK TRANSACTION", NO_PARAMS).unwrap();
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
    pub fn exists(&self, au: &mut AuditScope, filt: &Filter) -> Result<bool, BackendError> {
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

    pub fn modify() {}

    pub fn delete() {}
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
    use super::super::log;
    use super::{Backend, BackendError};

    macro_rules! run_test {
        ($test_fn:expr) => {{
            System::run(|| {
                let mut audit = AuditScope::new("run_test");

                let test_log = log::start();

                let be = Backend::new(&mut audit, "");

                // Could wrap another future here for the future::ok bit...
                let fut = $test_fn(&mut audit, be);
                let comp_fut = fut.map_err(|()| ()).and_then(move |_r| {
                    test_log.do_send(audit);
                    println!("Stopping actix ...");
                    actix::System::current().stop();
                    future::result(Ok(()))
                });

                tokio::spawn(comp_fut);
            });
        }};
    }

    #[test]
    fn test_simple_create() {
        run_test!(|audit: &mut AuditScope, mut be: Backend| {
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

            // Check it's there

            future::ok(())
        });
    }

    #[test]
    fn test_simple_search() {
        run_test!(|audit: &mut AuditScope, be| {
            audit_log!(audit, "Simple Search");
            future::ok(())
        });
    }

    #[test]
    fn test_simple_modify() {
        run_test!(|audit: &mut AuditScope, be| {
            audit_log!(audit, "Simple Modify");
            future::ok(())
        });
    }

    #[test]
    fn test_simple_delete() {
        run_test!(|audit: &mut AuditScope, be| {
            audit_log!(audit, "Simple Delete");
            future::ok(())
        });
    }
}
