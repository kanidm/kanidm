use kanidm_proto::v1::{UnixGroupToken, UnixUserToken};
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::NO_PARAMS;
use std::convert::TryFrom;
use std::fmt;

use std::sync::{Mutex, MutexGuard};

pub struct Db {
    pool: Pool<SqliteConnectionManager>,
    lock: Mutex<()>,
}

pub struct DbTxn<'a> {
    _guard: MutexGuard<'a, ()>,
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
            pool: pool,
            lock: Mutex::new(()),
        })
    }

    pub fn write(&self) -> DbTxn {
        let guard = self.lock.try_lock().expect("Unable to lock");
        let conn = self
            .pool
            .get()
            .expect("Unable to get connection from pool!!!");
        DbTxn::new(conn, guard)
    }
}

impl fmt::Debug for Db {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Db {{}}")
    }
}

impl<'a> DbTxn<'a> {
    pub fn new(
        conn: r2d2::PooledConnection<SqliteConnectionManager>,
        guard: MutexGuard<'a, ()>,
    ) -> Self {
        // Start the transaction
        debug!("Starting db WR txn ...");
        conn.execute("BEGIN TRANSACTION", NO_PARAMS)
            .expect("Unable to begin transaction!");
        DbTxn {
            committed: false,
            conn,
            _guard: guard,
        }
    }

    pub fn migrate(&self) -> Result<(), ()> {
        // Setup two tables - one for accounts, one for groups.
        // correctly index the columns.
        // Optional pw hash field
        self.conn
            .execute(
                "CREATE TABLE IF NOT EXISTS account_t (
                uuid TEXT PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                spn TEXT NOT NULL UNIQUE,
                gidnumber INTEGER NOT NULL UNIQUE,
                password BLOB,
                token BLOB NOT NULL,
                expiry NUMERIC NOT NULL
            )
            ",
                NO_PARAMS,
            )
            .map_err(|e| {
                error!("sqlite account_t create error -> {:?}", e);
                ()
            })?;

        self.conn
            .execute(
                "CREATE TABLE IF NOT EXISTS group_t (
                uuid TEXT PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                spn TEXT NOT NULL UNIQUE,
                gidnumber INTEGER NOT NULL UNIQUE,
                token BLOB NOT NULL,
                expiry NUMERIC NOT NULL
            )
            ",
                NO_PARAMS,
            )
            .map_err(|e| {
                error!("sqlite group_t create error -> {:?}", e);
                ()
            })?;

        Ok(())
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

    pub fn clear_cache(&self) -> Result<(), ()> {
        self.conn
            .execute("DELETE FROM group_t", NO_PARAMS)
            .map_err(|e| {
                debug!("sqlite delete group_t failure -> {:?}", e);
                ()
            })?;

        self.conn
            .execute("DELETE FROM account_t", NO_PARAMS)
            .map_err(|e| {
                debug!("sqlite delete group_t failure -> {:?}", e);
                ()
            })?;

        Ok(())
    }

    pub fn get_account(&self, account_id: &str) -> Result<Option<(UnixUserToken, u64)>, ()> {
        let mut stmt = self.conn
            .prepare(
        "SELECT token, expiry FROM account_t WHERE uuid = :account_id OR name = :account_id OR spn = :account_id"
            )
            .map_err(|e| {
                error!("sqlite select prepare failure -> {:?}", e);
                ()
            })?;

        // Makes tuple (token, expiry)
        let data_iter = stmt
            .query_map(&[account_id], |row| Ok((row.get(0)?, row.get(1)?)))
            .map_err(|e| {
                error!("sqlite query_map failure -> {:?}", e);
                ()
            })?;
        let data: Result<Vec<(Vec<u8>, i64)>, _> = data_iter
            .map(|v| {
                v.map_err(|e| {
                    error!("sqlite map failure -> {:?}", e);
                    ()
                })
            })
            .collect();

        let data = data?;

        // Assert only one result?
        if data.len() >= 2 {
            error!("invalid db state, multiple entries matched query?");
            return Err(());
        }

        let r: Result<Option<(_, _)>, ()> = data
            .first()
            .map(|(token, expiry)| {
                // token convert with cbor.
                let t = serde_cbor::from_slice(token.as_slice()).map_err(|e| {
                    error!("cbor error -> {:?}", e);
                    ()
                })?;
                let e = u64::try_from(*expiry).map_err(|e| {
                    error!("u64 convert error -> {:?}", e);
                    ()
                })?;
                Ok((t, e))
            })
            .transpose();

        r
    }

    pub fn update_account(&self, account: &UnixUserToken, expire: u64) -> Result<(), ()> {
        let data = serde_cbor::to_vec(account).map_err(|e| {
            error!("cbor error -> {:?}", e);
            ()
        })?;
        let expire = i64::try_from(expire).map_err(|e| {
            error!("i64 convert error -> {:?}", e);
            ()
        })?;

        let mut stmt = self.conn
            .prepare("INSERT OR REPLACE INTO account_t (uuid, name, spn, gidnumber, token, expiry) VALUES (:uuid, :name, :spn, :gidnumber, :token, :expiry)")
            .map_err(|e| {
                error!("sqlite prepare error -> {:?}", e);
                ()
            })?;

        stmt.execute_named(&[
            (":uuid", &account.uuid),
            (":name", &account.name),
            (":spn", &account.spn),
            (":gidnumber", &account.gidnumber),
            (":token", &data),
            (":expiry", &expire),
        ])
        .map(|r| {
            debug!("insert -> {:?}", r);
            ()
        })
        .map_err(|e| {
            error!("sqlite execute_named error -> {:?}", e);
            ()
        })
    }
}

impl<'a> fmt::Debug for DbTxn<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DbTxn {{}}")
    }
}

impl<'a> Drop for DbTxn<'a> {
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

#[cfg(test)]
mod tests {
    use super::Db;
    use kanidm_proto::v1::{UnixGroupToken, UnixUserToken};

    #[test]
    fn test_cache_db_account_basic() {
        let _ = env_logger::builder().is_test(true).try_init();
        let db = Db::new("").expect("failed to create.");
        let dbtxn = db.write();
        assert!(dbtxn.migrate().is_ok());

        let mut ut1 = UnixUserToken {
            name: "testuser".to_string(),
            spn: "testuser@example.com".to_string(),
            displayname: "Test User".to_string(),
            gidnumber: 2000,
            uuid: "0302b99c-f0f6-41ab-9492-852692b0fd16".to_string(),
            shell: None,
            groups: Vec::new(),
            sshkeys: vec!["key-a".to_string()],
        };

        // test finding no account
        let r1 = dbtxn.get_account("testuser").unwrap();
        assert!(r1.is_none());
        let r2 = dbtxn.get_account("testuser@example.com").unwrap();
        assert!(r2.is_none());
        let r3 = dbtxn
            .get_account("0302b99c-f0f6-41ab-9492-852692b0fd16")
            .unwrap();
        assert!(r3.is_none());
        /*
        let r4 = dbtxn.get_account("2000").unwrap();
        assert!(r4.is_none());
        */

        // test adding an account
        dbtxn.update_account(&ut1, 0).unwrap();

        // test we can get it.
        let r1 = dbtxn.get_account("testuser").unwrap();
        assert!(r1.is_some());
        let r2 = dbtxn.get_account("testuser@example.com").unwrap();
        assert!(r2.is_some());
        let r3 = dbtxn
            .get_account("0302b99c-f0f6-41ab-9492-852692b0fd16")
            .unwrap();
        assert!(r3.is_some());

        // test adding an account that was renamed
        ut1.name = "testuser2".to_string();
        ut1.spn = "testuser2@example.com".to_string();
        dbtxn.update_account(&ut1, 0).unwrap();

        // get the account
        let r1 = dbtxn.get_account("testuser").unwrap();
        assert!(r1.is_none());
        let r2 = dbtxn.get_account("testuser@example.com").unwrap();
        assert!(r2.is_none());
        let r1 = dbtxn.get_account("testuser2").unwrap();
        assert!(r1.is_some());
        let r2 = dbtxn.get_account("testuser2@example.com").unwrap();
        assert!(r2.is_some());
        let r3 = dbtxn
            .get_account("0302b99c-f0f6-41ab-9492-852692b0fd16")
            .unwrap();
        assert!(r3.is_some());

        // Clear cache
        assert!(dbtxn.clear_cache().is_ok());

        // should be nothing
        let r1 = dbtxn.get_account("testuser").unwrap();
        assert!(r1.is_none());
        let r2 = dbtxn.get_account("testuser@example.com").unwrap();
        assert!(r2.is_none());
        let r3 = dbtxn
            .get_account("0302b99c-f0f6-41ab-9492-852692b0fd16")
            .unwrap();
        assert!(r3.is_none());

        assert!(dbtxn.commit().is_ok());
    }

    #[test]
    fn test_cache_db_group_basic() {
        let _ = env_logger::builder().is_test(true).try_init();
        let db = Db::new("").expect("failed to create.");
        let dbtxn = db.write();
        assert!(dbtxn.migrate().is_ok());

        // test finding no account

        assert!(dbtxn.commit().is_ok());
        // unimplemented!();
    }
}
