//! Db executor actor
use actix::prelude::*;

use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::types::ToSql;
use rusqlite::NO_PARAMS;
use serde_json;
// use uuid;

use super::entry::Entry;
use super::filter::Filter;
use super::log::EventLog;

mod idl;
mod mem_be;
mod sqlite_be;

// This contacts the needed backend and starts it up

#[derive(Debug, PartialEq)]
pub struct BackendAuditEvent {
    time_start: (),
    time_end: (),
}

impl BackendAuditEvent {
    pub fn new() -> Self {
        BackendAuditEvent {
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

pub enum BackendType {
    Memory, // isn't memory just sqlite with file :memory: ?
    SQLite,
}

#[derive(Debug, PartialEq)]
pub enum BackendError {
    EmptyRequest,
}

pub struct Backend {
    log: actix::Addr<EventLog>,
    pool: Pool<SqliteConnectionManager>,
}

// In the future this will do the routing betwene the chosen backends etc.
impl Backend {
    pub fn new(log: actix::Addr<EventLog>, path: &str) -> Self {
        // this has a ::memory() type, but will path == "" work?
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
            ).unwrap();

            // Create a version table for migration indication

            // Create the core db
        }

        log_event!(log, "Starting DB worker ...");
        Backend {
            log: log,
            pool: pool,
        }
    }

    pub fn create(&mut self, entries: Vec<Entry>) -> Result<BackendAuditEvent, BackendError> {
        log_event!(self.log, "Begin create");

        let be_audit = BackendAuditEvent::new();
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
            }).collect();

        log_event!(self.log, "serialising: {:?}", ser_entries);

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
                ).unwrap();
            }

            // TODO: update indexes (as needed)
            // Commit the txn
            conn.execute("COMMIT TRANSACTION", NO_PARAMS).unwrap();
        }

        log_event!(self.log, "End create");
        // End the timer?
        Ok(be_audit)
    }

    // Take filter, and AuditEvent ref?
    pub fn search(&self, filt: Filter) -> Vec<Entry> {
        // Do things
        // Alloc a vec for the entries.
        // FIXME: Make this actually a good size for the result set ...
        // FIXME: Actually compute indexes here.
        // So to make this use indexes, we can use the filter type and
        // destructure it to work out what we need to actually search (if
        // possible) to create the candidate set.
        // Unlike DS, even if we don't get the index back, we can just pass
        // to the in-memory filter test and be done.

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
                }).unwrap();
            for row in id2entry_iter {
                println!("{:?}", row);
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
            }).collect();

        entries
    }

    pub fn modify() {}

    pub fn delete() {}
}

impl Clone for Backend {
    fn clone(&self) -> Self {
        // Make another Be and close the pool.
        Backend {
            log: self.log.clone(),
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
    use futures::future::lazy;
    use futures::future::Future;

    extern crate tokio;

    use super::super::entry::Entry;
    use super::super::filter::Filter;
    use super::super::log::{self, EventLog, LogEvent};
    use super::{Backend, BackendError};

    macro_rules! run_test {
        ($test_fn:expr) => {{
            System::run(|| {
                let test_log = log::start();

                let mut be = Backend::new(test_log.clone(), "");

                // Could wrap another future here for the future::ok bit...
                let fut = $test_fn(test_log, be);
                let comp_fut = fut.map_err(|()| ()).and_then(|r| {
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
        run_test!(|log: actix::Addr<EventLog>, mut be: Backend| {
            log_event!(log, "Simple Create");

            let empty_result = be.create(Vec::new());
            log_event!(log, "{:?}", empty_result);
            assert_eq!(empty_result, Err(BackendError::EmptyRequest));

            let mut e: Entry = Entry::new();
            e.add_ava(String::from("userid"), String::from("william"))
                .unwrap();
            assert!(e.validate());

            let single_result = be.create(vec![e]);

            assert!(single_result.is_ok());

            // Construct a filter
            let filt = Filter::Pres(String::from("userid"));
            let entries = be.search(filt);
            println!("{:?}", entries);

            // There should only be one entry so is this enough?
            assert!(entries.first().is_some());
            // Later we could check consistency of the entry saved ...

            // Check it's there

            future::ok(())
        });
    }

    #[test]
    fn test_simple_search() {
        run_test!(|log: actix::Addr<EventLog>, be| {
            log_event!(log, "Simple Search");
            future::ok(())
        });
    }

    #[test]
    fn test_simple_modify() {
        run_test!(|log: actix::Addr<EventLog>, be| {
            log_event!(log, "Simple Modify");
            future::ok(())
        });
    }

    #[test]
    fn test_simple_delete() {
        run_test!(|log: actix::Addr<EventLog>, be| {
            log_event!(log, "Simple Delete");
            future::ok(())
        });
    }
}
