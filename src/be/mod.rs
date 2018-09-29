//! Db executor actor
use actix::prelude::*;
use diesel;
use diesel::prelude::*;
use diesel::r2d2::{self, ConnectionManager, Pool};
// use uuid;
use super::log::EventLog;


mod sqlite_be;
mod mem_be;
mod filter;

// HACK HACK HACK remove duplicate code
// Helper for internal logging.
macro_rules! log_event {
    ($log_addr:expr, $($arg:tt)*) => ({
        use std::fmt;
        use log::LogEvent;
        $log_addr.do_send(
            LogEvent {
                msg: fmt::format(
                    format_args!($($arg)*)
                )
            }
        )
    })
}

// This contacts the needed backend and starts it up

pub enum BackendType {
    Memory, // isn't memory just sqlite with file :memory: ?
    SQLite,
}

pub fn start(log: actix::Addr<EventLog>, _betype: BackendType, path: &str) -> actix::Addr<BackendActor> {
    // How can we allow different db names and types?
    let manager = ConnectionManager::<SqliteConnection>::new(path);
    let pool = r2d2::Pool::builder()
        .build(manager)
        .expect("Failed to create pool");

    SyncArbiter::start(8, move || {
        BackendActor::new(log.clone(), pool.clone())
    })
}

pub struct BackendActor {
    log: actix::Addr<EventLog>,
    pool: Pool<ConnectionManager<SqliteConnection>>
}

impl Actor for BackendActor {
    type Context = SyncContext<Self>;
}

// In the future this will do the routing betwene the chosen backends etc.
impl BackendActor {
    pub fn new(log: actix::Addr<EventLog>, pool: Pool<ConnectionManager<SqliteConnection>>) -> Self {
        log_event!(log, "Starting DB worker ...");
        BackendActor {
            log: log,
            pool: pool,
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_simple_create() {
        println!("It works!");
    }
}

