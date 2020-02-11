use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::NO_PARAMS;
use std::fmt;

pub struct Db {
    pool: Pool<SqliteConnectionManager>,
}

pub struct DbTxn {
    committed: bool,
    conn: r2d2::PooledConnection<SqliteConnectionManager>,
}

impl Db {
    pub fn new(path: &str) -> Result<Self, ()> {
        let manager = SqliteConnectionManager::file(path);
        // We only build a single thread. If we need more than one, we'll
        // need to re-do this to account for path = "" for debug.
        let builder1 = Pool::builder().max_size(1);
        let pool = builder1.build(manager).map_err(|e| {
            error!("r2d2 error {:?}", e);
            ()
        })?;

        Ok(Db {
            pool: pool
        })
    }

    pub fn write(&self) -> DbTxn {
        let conn = self
            .pool
            .get()
            .expect("Unable to get connection from pool!!!");
        DbTxn::new(conn)
    }
}

impl fmt::Debug for Db {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Db {{}}")
    }
}

impl DbTxn {
    pub fn new(conn: r2d2::PooledConnection<SqliteConnectionManager>) -> Self {
        // Start the transaction
        debug!("Starting db WR txn ...");
        conn.execute("BEGIN TRANSACTION", NO_PARAMS)
            .expect("Unable to begin transaction!");
        DbTxn {
            committed: false,
            conn,
        }
    }

    pub fn migrate(&self) -> Result<(), ()> {

        // Setup two tables - one for accounts, one for groups.
        // correctly index the columns.


        unimplemented!();
    }

    pub fn commit(mut self) -> Result<(), ()> {
        debug!("Commiting BE txn");
        assert!(!self.committed);
        self.committed = true;

        self.conn
            .execute("COMMIT TRANSACTION", NO_PARAMS)
            .map(|_| ())
            .map_err(|e| {
                debug!("sqlite commit failure -> {:?}", e);
                ()
            })
    }
}

impl fmt::Debug for DbTxn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DbTxn {{}}")
    }
}

impl Drop for DbTxn {
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
