use std::convert::TryFrom;
use std::fmt;
use std::time::Duration;

use kanidm_lib_crypto::CryptoPolicy;
use kanidm_lib_crypto::DbPasswordV1;
use kanidm_lib_crypto::Password;
use kanidm_proto::v1::{UnixGroupToken, UnixUserToken};
use libc::umask;
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use tokio::sync::{Mutex, MutexGuard};

use crate::cache::Id;

pub struct Db {
    pool: Pool<SqliteConnectionManager>,
    lock: Mutex<()>,
    crypto_policy: CryptoPolicy,
    require_tpm: Option<tpm::TpmConfig>,
}

pub struct DbTxn<'a> {
    _guard: MutexGuard<'a, ()>,
    committed: bool,
    conn: r2d2::PooledConnection<SqliteConnectionManager>,
    crypto_policy: &'a CryptoPolicy,
    require_tpm: Option<&'a tpm::TpmConfig>,
}

impl Db {
    pub fn new(path: &str, require_tpm: Option<&str>) -> Result<Self, ()> {
        let before = unsafe { umask(0o0027) };
        let manager = SqliteConnectionManager::file(path);
        let _ = unsafe { umask(before) };
        // We only build a single thread. If we need more than one, we'll
        // need to re-do this to account for path = "" for debug.
        let builder1 = Pool::builder().max_size(1);
        let pool = builder1.build(manager).map_err(|e| {
            error!("r2d2 error {:?}", e);
        })?;

        let crypto_policy = CryptoPolicy::time_target(Duration::from_millis(250));

        debug!("Configured {:?}", crypto_policy);

        // Test a tpm context.
        let require_tpm = if let Some(tcti_str) = require_tpm {
            #[cfg(feature = "tpm")]
            let r = Db::tpm_setup_context(
                tcti_str,
                pool.get().expect("Unable to get connection from pool!!!"),
            )?;

            #[cfg(not(feature = "tpm"))]
            warn!("require_tpm is set, but tpm was not built in. This instance will NOT cache passwords!");
            #[cfg(not(feature = "tpm"))]
            let r = tpm::TpmConfig {};

            Some(r)
        } else {
            None
        };

        Ok(Db {
            pool,
            lock: Mutex::new(()),
            crypto_policy,
            require_tpm,
        })
    }

    #[allow(clippy::expect_used)]
    pub async fn write(&self) -> DbTxn<'_> {
        let guard = self.lock.lock().await;
        let conn = self
            .pool
            .get()
            .expect("Unable to get connection from pool!!!");
        DbTxn::new(conn, guard, &self.crypto_policy, self.require_tpm.as_ref())
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
        crypto_policy: &'a CryptoPolicy,
        require_tpm: Option<&'a tpm::TpmConfig>,
    ) -> Self {
        // Start the transaction
        // debug!("Starting db WR txn ...");
        #[allow(clippy::expect_used)]
        conn.execute("BEGIN TRANSACTION", [])
            .expect("Unable to begin transaction!");
        DbTxn {
            committed: false,
            conn,
            _guard: guard,
            crypto_policy,
            require_tpm,
        }
    }

    /// This handles an error coming back from an sqlite event and dumps more information from it
    fn sqlite_error(&self, msg: &str, error: &rusqlite::Error) {
        error!(
            "sqlite {} error: {:?} db_path={:?}",
            msg,
            error,
            &self.conn.path()
        );
    }

    /// This handles an error coming back from an sqlite transaction and dumps a load of information from it
    fn sqlite_transaction_error(&self, error: &rusqlite::Error, _stmt: &rusqlite::Statement) {
        error!(
            "sqlite transaction error={:?} db_path={:?}",
            error,
            &self.conn.path(),
        );
        // TODO: one day figure out if there's an easy way to dump the transaction without the token...
    }

    pub fn migrate(&self) -> Result<(), ()> {
        self.conn.set_prepared_statement_cache_capacity(16);
        self.conn
            .prepare("PRAGMA journal_mode=WAL;")
            .and_then(|mut wal_stmt| wal_stmt.query([]).map(|_| ()))
            .map_err(|e| {
                self.sqlite_error("account_t create", &e);
            })?;

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
                [],
            )
            .map_err(|e| {
                self.sqlite_error("account_t create", &e);
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
                [],
            )
            .map_err(|e| {
                self.sqlite_error("group_t create", &e);
            })?;

        self.conn
            .execute(
                "CREATE TABLE IF NOT EXISTS memberof_t (
                g_uuid TEXT,
                a_uuid TEXT,
                FOREIGN KEY(g_uuid) REFERENCES group_t(uuid) ON DELETE CASCADE,
                FOREIGN KEY(a_uuid) REFERENCES account_t(uuid) ON DELETE CASCADE
            )
            ",
                [],
            )
            .map_err(|e| {
                self.sqlite_error("memberof_t create error", &e);
            })?;

        Ok(())
    }

    pub fn commit(mut self) -> Result<(), ()> {
        // debug!("Committing BE txn");
        if self.committed {
            error!("Invalid state, SQL transaction was already committed!");
            return Err(());
        }
        self.committed = true;

        self.conn
            .execute("COMMIT TRANSACTION", [])
            .map(|_| ())
            .map_err(|e| {
                self.sqlite_error("commit", &e);
            })
    }

    pub fn invalidate(&self) -> Result<(), ()> {
        self.conn
            .execute("UPDATE group_t SET expiry = 0", [])
            .map_err(|e| {
                self.sqlite_error("update group_t", &e);
            })?;

        self.conn
            .execute("UPDATE account_t SET expiry = 0", [])
            .map_err(|e| {
                self.sqlite_error("update account_t", &e);
            })?;

        Ok(())
    }

    pub fn clear_cache(&self) -> Result<(), ()> {
        self.conn.execute("DELETE FROM group_t", []).map_err(|e| {
            self.sqlite_error("delete group_t", &e);
        })?;

        self.conn
            .execute("DELETE FROM account_t", [])
            .map_err(|e| {
                self.sqlite_error("delete group_t", &e);
            })?;

        Ok(())
    }

    fn get_account_data_name(&self, account_id: &str) -> Result<Vec<(Vec<u8>, i64)>, ()> {
        let mut stmt = self.conn
            .prepare(
        "SELECT token, expiry FROM account_t WHERE uuid = :account_id OR name = :account_id OR spn = :account_id"
            )
            .map_err(|e| {
                self.sqlite_error("select prepare", &e);
            })?;

        // Makes tuple (token, expiry)
        let data_iter = stmt
            .query_map([account_id], |row| Ok((row.get(0)?, row.get(1)?)))
            .map_err(|e| {
                self.sqlite_error("query_map failure", &e);
            })?;
        let data: Result<Vec<(Vec<u8>, i64)>, _> = data_iter
            .map(|v| {
                v.map_err(|e| {
                    self.sqlite_error("map failure", &e);
                })
            })
            .collect();
        data
    }

    fn get_account_data_gid(&self, gid: u32) -> Result<Vec<(Vec<u8>, i64)>, ()> {
        let mut stmt = self
            .conn
            .prepare("SELECT token, expiry FROM account_t WHERE gidnumber = :gid")
            .map_err(|e| {
                self.sqlite_error("select prepare", &e);
            })?;

        // Makes tuple (token, expiry)
        let data_iter = stmt
            .query_map(params![gid], |row| Ok((row.get(0)?, row.get(1)?)))
            .map_err(|e| {
                self.sqlite_error("query_map", &e);
            })?;
        let data: Result<Vec<(Vec<u8>, i64)>, _> = data_iter
            .map(|v| {
                v.map_err(|e| {
                    self.sqlite_error("map", &e);
                })
            })
            .collect();
        data
    }

    pub fn get_account(&self, account_id: &Id) -> Result<Option<(UnixUserToken, u64)>, ()> {
        let data = match account_id {
            Id::Name(n) => self.get_account_data_name(n.as_str()),
            Id::Gid(g) => self.get_account_data_gid(*g),
        }?;

        // Assert only one result?
        if data.len() >= 2 {
            error!("invalid db state, multiple entries matched query?");
            return Err(());
        }

        if let Some((token, expiry)) = data.first() {
            // token convert with json.
            // If this errors, we specifically return Ok(None) because that triggers
            // the cache to refetch the token.
            match serde_json::from_slice(token.as_slice()) {
                Ok(t) => {
                    let e = u64::try_from(*expiry).map_err(|e| {
                        error!("u64 convert error -> {:?}", e);
                    })?;
                    Ok(Some((t, e)))
                }
                Err(e) => {
                    warn!("recoverable - json error -> {:?}", e);
                    Ok(None)
                }
            }
        } else {
            Ok(None)
        }
    }

    pub fn get_accounts(&self) -> Result<Vec<UnixUserToken>, ()> {
        let mut stmt = self
            .conn
            .prepare("SELECT token FROM account_t")
            .map_err(|e| {
                self.sqlite_error("select prepare", &e);
            })?;

        let data_iter = stmt.query_map([], |row| row.get(0)).map_err(|e| {
            self.sqlite_error("query_map", &e);
        })?;
        let data: Result<Vec<Vec<u8>>, _> = data_iter
            .map(|v| {
                v.map_err(|e| {
                    self.sqlite_error("map", &e);
                })
            })
            .collect();

        let data = data?;

        Ok(data
            .iter()
            // We filter map here so that anything invalid is skipped.
            .filter_map(|token| {
                // token convert with json.
                serde_json::from_slice(token.as_slice())
                    .map_err(|e| {
                        warn!("get_accounts json error -> {:?}", e);
                    })
                    .ok()
            })
            .collect())
    }

    pub fn update_account(&self, account: &UnixUserToken, expire: u64) -> Result<(), ()> {
        let data = serde_json::to_vec(account).map_err(|e| {
            error!("update_account json error -> {:?}", e);
        })?;
        let expire = i64::try_from(expire).map_err(|e| {
            error!("update_account i64 conversion error -> {:?}", e);
        })?;

        // This is needed because sqlites 'insert or replace into', will null the password field
        // if present, and upsert MUST match the exact conflicting column, so that means we have
        // to manually manage the update or insert :( :(

        // Find anything conflicting and purge it.
        self.conn.execute("DELETE FROM account_t WHERE NOT uuid = :uuid AND (name = :name OR spn = :spn OR gidnumber = :gidnumber)",
            named_params!{
                ":uuid": &account.uuid,
                ":name": &account.name,
                ":spn": &account.spn,
                ":gidnumber": &account.gidnumber,
            }
            )
            .map_err(|e| {
                self.sqlite_error("delete account_t duplicate", &e);
            })
            .map(|_| ())?;

        let updated = self.conn.execute(
                "UPDATE account_t SET name=:name, spn=:spn, gidnumber=:gidnumber, token=:token, expiry=:expiry WHERE uuid = :uuid",
            named_params!{
                ":uuid": &account.uuid,
                ":name": &account.name,
                ":spn": &account.spn,
                ":gidnumber": &account.gidnumber,
                ":token": &data,
                ":expiry": &expire,
            }
            )
            .map_err(|e| {
                self.sqlite_error("delete account_t duplicate", &e);
            })?;

        if updated == 0 {
            let mut stmt = self.conn
                .prepare("INSERT INTO account_t (uuid, name, spn, gidnumber, token, expiry) VALUES (:uuid, :name, :spn, :gidnumber, :token, :expiry) ON CONFLICT(uuid) DO UPDATE SET name=excluded.name, spn=excluded.name, gidnumber=excluded.gidnumber, token=excluded.token, expiry=excluded.expiry")
                .map_err(|e| {
                    self.sqlite_error("prepare", &e);
                })?;

            stmt.execute(named_params! {
                ":uuid": &account.uuid,
                ":name": &account.name,
                ":spn": &account.spn,
                ":gidnumber": &account.gidnumber,
                ":token": &data,
                ":expiry": &expire,
            })
            .map(|r| {
                debug!("insert -> {:?}", r);
            })
            .map_err(|error| {
                self.sqlite_transaction_error(&error, &stmt);
            })?;
        }

        // Now, we have to update the group memberships.

        // First remove everything that already exists:
        let mut stmt = self
            .conn
            .prepare("DELETE FROM memberof_t WHERE a_uuid = :a_uuid")
            .map_err(|e| {
                self.sqlite_error("prepare", &e);
            })?;
        stmt.execute([&account.uuid])
            .map(|r| {
                debug!("delete memberships -> {:?}", r);
            })
            .map_err(|error| {
                self.sqlite_transaction_error(&error, &stmt);
            })?;

        let mut stmt = self
            .conn
            .prepare("INSERT INTO memberof_t (a_uuid, g_uuid) VALUES (:a_uuid, :g_uuid)")
            .map_err(|e| {
                self.sqlite_error("prepare", &e);
            })?;
        // Now for each group, add the relation.
        account.groups.iter().try_for_each(|g| {
            stmt.execute(named_params! {
                ":a_uuid": &account.uuid,
                ":g_uuid": &g.uuid,
            })
            .map(|r| {
                debug!("insert membership -> {:?}", r);
            })
            .map_err(|error| {
                self.sqlite_transaction_error(&error, &stmt);
            })
        })
    }

    pub fn delete_account(&self, a_uuid: &str) -> Result<(), ()> {
        self.conn
            .execute(
                "DELETE FROM account_t WHERE uuid = :a_uuid",
                params![a_uuid],
            )
            .map(|_| ())
            .map_err(|e| {
                self.sqlite_error("memberof_t create", &e);
            })
    }

    pub fn update_account_password(&self, a_uuid: &str, cred: &str) -> Result<(), ()> {
        #[allow(unused_variables)]
        let pw = if let Some(tcti_str) = self.require_tpm {
            // Do nothing.
            #[cfg(not(feature = "tpm"))]
            return Ok(());

            #[cfg(feature = "tpm")]
            let pw = Db::tpm_new(self.crypto_policy, cred, tcti_str)?;
            #[cfg(feature = "tpm")]
            pw
        } else {
            Password::new(self.crypto_policy, cred).map_err(|e| {
                error!("password error -> {:?}", e);
            })?
        };

        let dbpw = pw.to_dbpasswordv1();
        let data = serde_json::to_vec(&dbpw).map_err(|e| {
            error!("json error -> {:?}", e);
        })?;

        self.conn
            .execute(
                "UPDATE account_t SET password = :data WHERE uuid = :a_uuid",
                named_params! {
                    ":a_uuid": &a_uuid,
                    ":data": &data,
                },
            )
            .map_err(|e| {
                self.sqlite_error("update account_t password", &e);
            })
            .map(|_| ())
    }

    pub fn check_account_password(&self, a_uuid: &str, cred: &str) -> Result<bool, ()> {
        #[cfg(not(feature = "tpm"))]
        if self.require_tpm.is_some() {
            return Ok(false);
        }

        let mut stmt = self
            .conn
            .prepare("SELECT password FROM account_t WHERE uuid = :a_uuid AND password IS NOT NULL")
            .map_err(|e| {
                self.sqlite_error("select prepare", &e);
            })?;

        // Makes tuple (token, expiry)
        let data_iter = stmt.query_map([a_uuid], |row| row.get(0)).map_err(|e| {
            self.sqlite_error("query_map", &e);
        })?;
        let data: Result<Vec<Vec<u8>>, _> = data_iter
            .map(|v| {
                v.map_err(|e| {
                    self.sqlite_error("map", &e);
                })
            })
            .collect();

        let data = data?;

        if data.is_empty() {
            info!("No cached password, failing authentication");
            return Ok(false);
        }

        if data.len() >= 2 {
            error!("invalid db state, multiple entries matched query?");
            return Err(());
        }

        let pw = data.first().map(|raw| {
            // Map the option from data.first.
            let dbpw: DbPasswordV1 = serde_json::from_slice(raw.as_slice()).map_err(|e| {
                error!("json error -> {:?}", e);
            })?;
            Password::try_from(dbpw)
        });

        let pw = match pw {
            Some(Ok(p)) => p,
            _ => return Ok(false),
        };

        #[allow(unused_variables)]
        if let Some(tcti_str) = self.require_tpm {
            #[cfg(feature = "tpm")]
            let r = Db::tpm_verify(pw, cred, tcti_str);

            // Do nothing.
            #[cfg(not(feature = "tpm"))]
            let r = Ok(false);

            r
        } else {
            pw.verify(cred).map_err(|e| {
                error!("password error -> {:?}", e);
            })
        }
    }

    fn get_group_data_name(&self, grp_id: &str) -> Result<Vec<(Vec<u8>, i64)>, ()> {
        let mut stmt = self.conn
            .prepare(
        "SELECT token, expiry FROM group_t WHERE uuid = :grp_id OR name = :grp_id OR spn = :grp_id"
            )
            .map_err(|e| {
                self.sqlite_error("select prepare", &e);
            })?;

        // Makes tuple (token, expiry)
        let data_iter = stmt
            .query_map([grp_id], |row| Ok((row.get(0)?, row.get(1)?)))
            .map_err(|e| {
                self.sqlite_error("query_map", &e);
            })?;
        let data: Result<Vec<(Vec<u8>, i64)>, _> = data_iter
            .map(|v| {
                v.map_err(|e| {
                    self.sqlite_error("map", &e);
                })
            })
            .collect();
        data
    }

    fn get_group_data_gid(&self, gid: u32) -> Result<Vec<(Vec<u8>, i64)>, ()> {
        let mut stmt = self
            .conn
            .prepare("SELECT token, expiry FROM group_t WHERE gidnumber = :gid")
            .map_err(|e| {
                self.sqlite_error("select prepare", &e);
            })?;

        // Makes tuple (token, expiry)
        let data_iter = stmt
            .query_map(params![gid], |row| Ok((row.get(0)?, row.get(1)?)))
            .map_err(|e| {
                self.sqlite_error("query_map", &e);
            })?;
        let data: Result<Vec<(Vec<u8>, i64)>, _> = data_iter
            .map(|v| {
                v.map_err(|e| {
                    self.sqlite_error("map", &e);
                })
            })
            .collect();
        data
    }

    pub fn get_group(&self, grp_id: &Id) -> Result<Option<(UnixGroupToken, u64)>, ()> {
        let data = match grp_id {
            Id::Name(n) => self.get_group_data_name(n.as_str()),
            Id::Gid(g) => self.get_group_data_gid(*g),
        }?;

        // Assert only one result?
        if data.len() >= 2 {
            error!("invalid db state, multiple entries matched query?");
            return Err(());
        }

        if let Some((token, expiry)) = data.first() {
            // token convert with json.
            // If this errors, we specifically return Ok(None) because that triggers
            // the cache to refetch the token.
            match serde_json::from_slice(token.as_slice()) {
                Ok(t) => {
                    let e = u64::try_from(*expiry).map_err(|e| {
                        error!("u64 convert error -> {:?}", e);
                    })?;
                    Ok(Some((t, e)))
                }
                Err(e) => {
                    warn!("recoverable - json error -> {:?}", e);
                    Ok(None)
                }
            }
        } else {
            Ok(None)
        }
    }

    pub fn get_group_members(&self, g_uuid: &str) -> Result<Vec<UnixUserToken>, ()> {
        let mut stmt = self
            .conn
            .prepare("SELECT account_t.token FROM (account_t, memberof_t) WHERE account_t.uuid = memberof_t.a_uuid AND memberof_t.g_uuid = :g_uuid")
            .map_err(|e| {
                self.sqlite_error("select prepare", &e);
            })?;

        let data_iter = stmt.query_map([g_uuid], |row| row.get(0)).map_err(|e| {
            self.sqlite_error("query_map", &e);
        })?;
        let data: Result<Vec<Vec<u8>>, _> = data_iter
            .map(|v| {
                v.map_err(|e| {
                    self.sqlite_error("map", &e);
                })
            })
            .collect();

        let data = data?;

        data.iter()
            .map(|token| {
                // token convert with json.
                // debug!("{:?}", token);
                serde_json::from_slice(token.as_slice()).map_err(|e| {
                    error!("json error -> {:?}", e);
                })
            })
            .collect()
    }

    pub fn get_groups(&self) -> Result<Vec<UnixGroupToken>, ()> {
        let mut stmt = self
            .conn
            .prepare("SELECT token FROM group_t")
            .map_err(|e| {
                self.sqlite_error("select prepare", &e);
            })?;

        let data_iter = stmt.query_map([], |row| row.get(0)).map_err(|e| {
            self.sqlite_error("query_map", &e);
        })?;
        let data: Result<Vec<Vec<u8>>, _> = data_iter
            .map(|v| {
                v.map_err(|e| {
                    self.sqlite_error("map", &e);
                })
            })
            .collect();

        let data = data?;

        Ok(data
            .iter()
            .filter_map(|token| {
                // token convert with json.
                // debug!("{:?}", token);
                serde_json::from_slice(token.as_slice())
                    .map_err(|e| {
                        error!("json error -> {:?}", e);
                    })
                    .ok()
            })
            .collect())
    }

    pub fn update_group(&self, grp: &UnixGroupToken, expire: u64) -> Result<(), ()> {
        let data = serde_json::to_vec(grp).map_err(|e| {
            error!("json error -> {:?}", e);
        })?;
        let expire = i64::try_from(expire).map_err(|e| {
            error!("i64 convert error -> {:?}", e);
        })?;

        let mut stmt = self.conn
            .prepare("INSERT OR REPLACE INTO group_t (uuid, name, spn, gidnumber, token, expiry) VALUES (:uuid, :name, :spn, :gidnumber, :token, :expiry)")
            .map_err(|e| {
                self.sqlite_error("prepare", &e);
            })?;

        stmt.execute(named_params! {
            ":uuid": &grp.uuid,
            ":name": &grp.name,
            ":spn": &grp.spn,
            ":gidnumber": &grp.gidnumber,
            ":token": &data,
            ":expiry": &expire,
        })
        .map(|r| {
            debug!("insert -> {:?}", r);
        })
        .map_err(|e| {
            self.sqlite_error("execute", &e);
        })
    }

    pub fn delete_group(&self, g_uuid: &str) -> Result<(), ()> {
        self.conn
            .execute("DELETE FROM group_t WHERE uuid = :g_uuid", [g_uuid])
            .map(|_| ())
            .map_err(|e| {
                self.sqlite_error("memberof_t create", &e);
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
    fn drop(&mut self) {
        if !self.committed {
            // debug!("Aborting BE WR txn");
            #[allow(clippy::expect_used)]
            self.conn
                .execute("ROLLBACK TRANSACTION", [])
                .expect("Unable to rollback transaction! Can not proceed!!!");
        }
    }
}

#[cfg(not(feature = "tpm"))]
pub(crate) mod tpm {
    pub struct TpmConfig {}
}

#[cfg(feature = "tpm")]
pub(crate) mod tpm {
    use super::Db;

    use r2d2_sqlite::SqliteConnectionManager;
    use rusqlite::OptionalExtension;

    use kanidm_lib_crypto::{CryptoError, CryptoPolicy, Password, TpmError};
    use tss_esapi::{utils::TpmsContext, Context, TctiNameConf};

    use std::str::FromStr;

    pub struct TpmConfig {
        tcti: TctiNameConf,
        ctx: TpmsContext,
    }

    impl Db {
        pub fn tpm_setup_context(
            tcti_str: &str,
            conn: r2d2::PooledConnection<SqliteConnectionManager>,
        ) -> Result<TpmConfig, ()> {
            let tcti = TctiNameConf::from_str(tcti_str).map_err(|e| {
                error!(tpm_err = ?e, "Failed to parse tcti name");
            })?;

            let mut context = Context::new(tcti.clone()).map_err(|e| {
                error!(tpm_err = ?e, "Failed to create tpm context");
            })?;

            conn.execute(
                "CREATE TABLE IF NOT EXISTS config_t (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )
                ",
                [],
            )
            .map_err(|e| {
                error!(sqlite_err = ?e, "update config_t tpm_ctx");
            })?;

            // Try and get the db context.
            let ctx_data: Option<Vec<u8>> = conn
                .query_row(
                    "SELECT value FROM config_t WHERE key='tpm2_ctx'",
                    [],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|e| {
                    error!(sqlite_err = ?e, "Failed to load tpm2_ctx");
                })
                .unwrap_or(None);

            trace!(ctx_data_present = %ctx_data.is_some());

            let ex_ctx = if let Some(ctx_data) = ctx_data {
                // Test loading, blank it out if it fails.
                // deserialise
                let maybe_ctx: TpmsContext =
                    serde_json::from_slice(ctx_data.as_slice()).map_err(|e| {
                        warn!("json error -> {:?}", e);
                    })?;

                // can it load?
                context
                    .execute_with_nullauth_session(|ctx| ctx.context_load(maybe_ctx.clone()))
                    .map_err(|e| {
                        error!(tpm_err = ?e, "Failed to load tpm context");
                    })?;

                Some(maybe_ctx)
            } else {
                None
            };

            let ctx = if let Some(existing_ctx) = ex_ctx {
                existing_ctx
            } else {
                // Need to regenerate for some reason
                info!("Creating new tpm ctx key");
                context
                    .execute_with_nullauth_session(|ctx| {
                        let key = Password::prepare_tpm_key(ctx)?;

                        ctx.context_save(key.into()).map_err(|e| e.into())
                    })
                    .map_err(|e: CryptoError| {
                        error!(tpm_err = ?e, "Failed to create tpm key");
                    })?
            };

            // Serialise it out.
            let data = serde_json::to_vec(&ctx).map_err(|e| {
                error!("json error -> {:?}", e);
            })?;

            // Update the tpm ctx str
            conn.execute(
                "UPDATE config_t SET value = :data WHERE key='tpm2_ctx'",
                named_params! {
                    ":data": &data,
                },
            )
            .map_err(|e| {
                error!(sqlite_err = ?e, "update config_t tpm_ctx");
            })
            .map(|_| ())?;

            Ok(TpmConfig { tcti, ctx })
        }

        pub fn tpm_new(
            policy: &CryptoPolicy,
            cred: &str,
            tpm_conf: &TpmConfig,
        ) -> Result<Password, ()> {
            let mut context = Context::new(tpm_conf.tcti.clone()).map_err(|e| {
                error!(tpm_err = ?e, "Failed to create tpm context");
            })?;

            context
                .execute_with_nullauth_session(|ctx| {
                    let key = ctx.context_load(tpm_conf.ctx.clone()).map_err(|e| {
                        error!(tpm_err = ?e, "Failed to load tpm context");
                        <TpmError as Into<CryptoError>>::into(e)
                    })?;

                    Password::new_argon2id_tpm(policy, cred, ctx, key)
                })
                .map_err(|e: CryptoError| {
                    error!(tpm_err = ?e, "Failed to create tpm bound password");
                })
        }

        pub fn tpm_verify(pw: Password, cred: &str, tpm_conf: &TpmConfig) -> Result<bool, ()> {
            let mut context = Context::new(tpm_conf.tcti.clone()).map_err(|e| {
                error!(tpm_err = ?e, "Failed to create tpm context");
            })?;

            context
                .execute_with_nullauth_session(|ctx| {
                    let key = ctx.context_load(tpm_conf.ctx.clone()).map_err(|e| {
                        error!(tpm_err = ?e, "Failed to load tpm context");
                        <TpmError as Into<CryptoError>>::into(e)
                    })?;

                    pw.verify_ctx(cred, Some((ctx, key)))
                })
                .map_err(|e: CryptoError| {
                    error!(tpm_err = ?e, "Failed to create tpm bound password");
                })
        }
    }
}

#[cfg(test)]
mod tests {
    use kanidm_proto::v1::{UnixGroupToken, UnixUserToken};

    use super::Db;
    use crate::cache::Id;

    const TESTACCOUNT1_PASSWORD_A: &str = "password a for account1 test";
    const TESTACCOUNT1_PASSWORD_B: &str = "password b for account1 test";

    #[tokio::test]
    async fn test_cache_db_account_basic() {
        sketching::test_init();
        let db = Db::new("", None).expect("failed to create.");
        let dbtxn = db.write().await;
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
            valid: true,
        };

        let id_name = Id::Name("testuser".to_string());
        let id_name2 = Id::Name("testuser2".to_string());
        let id_spn = Id::Name("testuser@example.com".to_string());
        let id_spn2 = Id::Name("testuser2@example.com".to_string());
        let id_uuid = Id::Name("0302b99c-f0f6-41ab-9492-852692b0fd16".to_string());
        let id_gid = Id::Gid(2000);

        // test finding no account
        let r1 = dbtxn.get_account(&id_name).unwrap();
        assert!(r1.is_none());
        let r2 = dbtxn.get_account(&id_spn).unwrap();
        assert!(r2.is_none());
        let r3 = dbtxn.get_account(&id_uuid).unwrap();
        assert!(r3.is_none());
        let r4 = dbtxn.get_account(&id_gid).unwrap();
        assert!(r4.is_none());

        // test adding an account
        dbtxn.update_account(&ut1, 0).unwrap();

        // test we can get it.
        let r1 = dbtxn.get_account(&id_name).unwrap();
        assert!(r1.is_some());
        let r2 = dbtxn.get_account(&id_spn).unwrap();
        assert!(r2.is_some());
        let r3 = dbtxn.get_account(&id_uuid).unwrap();
        assert!(r3.is_some());
        let r4 = dbtxn.get_account(&id_gid).unwrap();
        assert!(r4.is_some());

        // test adding an account that was renamed
        ut1.name = "testuser2".to_string();
        ut1.spn = "testuser2@example.com".to_string();
        dbtxn.update_account(&ut1, 0).unwrap();

        // get the account
        let r1 = dbtxn.get_account(&id_name).unwrap();
        assert!(r1.is_none());
        let r2 = dbtxn.get_account(&id_spn).unwrap();
        assert!(r2.is_none());
        let r1 = dbtxn.get_account(&id_name2).unwrap();
        assert!(r1.is_some());
        let r2 = dbtxn.get_account(&id_spn2).unwrap();
        assert!(r2.is_some());
        let r3 = dbtxn.get_account(&id_uuid).unwrap();
        assert!(r3.is_some());
        let r4 = dbtxn.get_account(&id_gid).unwrap();
        assert!(r4.is_some());

        // Clear cache
        assert!(dbtxn.clear_cache().is_ok());

        // should be nothing
        let r1 = dbtxn.get_account(&id_name2).unwrap();
        assert!(r1.is_none());
        let r2 = dbtxn.get_account(&id_spn2).unwrap();
        assert!(r2.is_none());
        let r3 = dbtxn.get_account(&id_uuid).unwrap();
        assert!(r3.is_none());
        let r4 = dbtxn.get_account(&id_gid).unwrap();
        assert!(r4.is_none());

        assert!(dbtxn.commit().is_ok());
    }

    #[tokio::test]
    async fn test_cache_db_group_basic() {
        sketching::test_init();
        let db = Db::new("", None).expect("failed to create.");
        let dbtxn = db.write().await;
        assert!(dbtxn.migrate().is_ok());

        let mut gt1 = UnixGroupToken {
            name: "testgroup".to_string(),
            spn: "testgroup@example.com".to_string(),
            gidnumber: 2000,
            uuid: "0302b99c-f0f6-41ab-9492-852692b0fd16".to_string(),
        };

        let id_name = Id::Name("testgroup".to_string());
        let id_name2 = Id::Name("testgroup2".to_string());
        let id_spn = Id::Name("testgroup@example.com".to_string());
        let id_spn2 = Id::Name("testgroup2@example.com".to_string());
        let id_uuid = Id::Name("0302b99c-f0f6-41ab-9492-852692b0fd16".to_string());
        let id_gid = Id::Gid(2000);

        // test finding no group
        let r1 = dbtxn.get_group(&id_name).unwrap();
        assert!(r1.is_none());
        let r2 = dbtxn.get_group(&id_spn).unwrap();
        assert!(r2.is_none());
        let r3 = dbtxn.get_group(&id_uuid).unwrap();
        assert!(r3.is_none());
        let r4 = dbtxn.get_group(&id_gid).unwrap();
        assert!(r4.is_none());

        // test adding a group
        dbtxn.update_group(&gt1, 0).unwrap();
        let r1 = dbtxn.get_group(&id_name).unwrap();
        assert!(r1.is_some());
        let r2 = dbtxn.get_group(&id_spn).unwrap();
        assert!(r2.is_some());
        let r3 = dbtxn.get_group(&id_uuid).unwrap();
        assert!(r3.is_some());
        let r4 = dbtxn.get_group(&id_gid).unwrap();
        assert!(r4.is_some());

        // add a group via update
        gt1.name = "testgroup2".to_string();
        gt1.spn = "testgroup2@example.com".to_string();
        dbtxn.update_group(&gt1, 0).unwrap();
        let r1 = dbtxn.get_group(&id_name).unwrap();
        assert!(r1.is_none());
        let r2 = dbtxn.get_group(&id_spn).unwrap();
        assert!(r2.is_none());
        let r1 = dbtxn.get_group(&id_name2).unwrap();
        assert!(r1.is_some());
        let r2 = dbtxn.get_group(&id_spn2).unwrap();
        assert!(r2.is_some());
        let r3 = dbtxn.get_group(&id_uuid).unwrap();
        assert!(r3.is_some());
        let r4 = dbtxn.get_group(&id_gid).unwrap();
        assert!(r4.is_some());

        // clear cache
        assert!(dbtxn.clear_cache().is_ok());

        // should be nothing.
        let r1 = dbtxn.get_group(&id_name2).unwrap();
        assert!(r1.is_none());
        let r2 = dbtxn.get_group(&id_spn2).unwrap();
        assert!(r2.is_none());
        let r3 = dbtxn.get_group(&id_uuid).unwrap();
        assert!(r3.is_none());
        let r4 = dbtxn.get_group(&id_gid).unwrap();
        assert!(r4.is_none());

        assert!(dbtxn.commit().is_ok());
    }

    #[tokio::test]
    async fn test_cache_db_account_group_update() {
        sketching::test_init();
        let db = Db::new("", None).expect("failed to create.");
        let dbtxn = db.write().await;
        assert!(dbtxn.migrate().is_ok());

        let gt1 = UnixGroupToken {
            name: "testuser".to_string(),
            spn: "testuser@example.com".to_string(),
            gidnumber: 2000,
            uuid: "0302b99c-f0f6-41ab-9492-852692b0fd16".to_string(),
        };

        let gt2 = UnixGroupToken {
            name: "testgroup".to_string(),
            spn: "testgroup@example.com".to_string(),
            gidnumber: 2001,
            uuid: "b500be97-8552-42a5-aca0-668bc5625705".to_string(),
        };

        let mut ut1 = UnixUserToken {
            name: "testuser".to_string(),
            spn: "testuser@example.com".to_string(),
            displayname: "Test User".to_string(),
            gidnumber: 2000,
            uuid: "0302b99c-f0f6-41ab-9492-852692b0fd16".to_string(),
            shell: None,
            groups: vec![gt1.clone(), gt2],
            sshkeys: vec!["key-a".to_string()],
            valid: true,
        };

        // First, add the groups.
        ut1.groups.iter().for_each(|g| {
            dbtxn.update_group(g, 0).unwrap();
        });

        // The add the account
        dbtxn.update_account(&ut1, 0).unwrap();

        // Now, get the memberships of the two groups.
        let m1 = dbtxn
            .get_group_members("0302b99c-f0f6-41ab-9492-852692b0fd16")
            .unwrap();
        let m2 = dbtxn
            .get_group_members("b500be97-8552-42a5-aca0-668bc5625705")
            .unwrap();
        assert!(m1[0].name == "testuser");
        assert!(m2[0].name == "testuser");

        // Now alter testuser, remove gt2, update.
        ut1.groups = vec![gt1];
        dbtxn.update_account(&ut1, 0).unwrap();

        // Check that the memberships have updated correctly.
        let m1 = dbtxn
            .get_group_members("0302b99c-f0f6-41ab-9492-852692b0fd16")
            .unwrap();
        let m2 = dbtxn
            .get_group_members("b500be97-8552-42a5-aca0-668bc5625705")
            .unwrap();
        assert!(m1[0].name == "testuser");
        assert!(m2.is_empty());

        assert!(dbtxn.commit().is_ok());
    }

    #[tokio::test]
    async fn test_cache_db_account_password() {
        sketching::test_init();

        #[cfg(feature = "tpm")]
        let tcti_str = Some("device:/dev/tpmrm0");

        #[cfg(not(feature = "tpm"))]
        let tcti_str = None;

        let db = Db::new("", tcti_str).expect("failed to create.");

        let dbtxn = db.write().await;
        assert!(dbtxn.migrate().is_ok());

        let uuid1 = "0302b99c-f0f6-41ab-9492-852692b0fd16";
        let mut ut1 = UnixUserToken {
            name: "testuser".to_string(),
            spn: "testuser@example.com".to_string(),
            displayname: "Test User".to_string(),
            gidnumber: 2000,
            uuid: "0302b99c-f0f6-41ab-9492-852692b0fd16".to_string(),
            shell: None,
            groups: Vec::new(),
            sshkeys: vec!["key-a".to_string()],
            valid: true,
        };

        // Test that with no account, is false
        assert!(dbtxn.check_account_password(uuid1, TESTACCOUNT1_PASSWORD_A) == Ok(false));
        // test adding an account
        dbtxn.update_account(&ut1, 0).unwrap();
        // check with no password is false.
        assert!(dbtxn.check_account_password(uuid1, TESTACCOUNT1_PASSWORD_A) == Ok(false));
        // update the pw
        assert!(dbtxn
            .update_account_password(uuid1, TESTACCOUNT1_PASSWORD_A)
            .is_ok());
        // Check it now works.
        assert!(dbtxn.check_account_password(uuid1, TESTACCOUNT1_PASSWORD_A) == Ok(true));
        assert!(dbtxn.check_account_password(uuid1, TESTACCOUNT1_PASSWORD_B) == Ok(false));
        // Update the pw
        assert!(dbtxn
            .update_account_password(uuid1, TESTACCOUNT1_PASSWORD_B)
            .is_ok());
        // Check it matches.
        assert!(dbtxn.check_account_password(uuid1, TESTACCOUNT1_PASSWORD_A) == Ok(false));
        assert!(dbtxn.check_account_password(uuid1, TESTACCOUNT1_PASSWORD_B) == Ok(true));

        // Check that updating the account does not break the password.
        ut1.displayname = "Test User Update".to_string();
        dbtxn.update_account(&ut1, 0).unwrap();
        assert!(dbtxn.check_account_password(uuid1, TESTACCOUNT1_PASSWORD_B) == Ok(true));

        assert!(dbtxn.commit().is_ok());
    }

    #[tokio::test]
    async fn test_cache_db_group_rename_duplicate() {
        sketching::test_init();
        let db = Db::new("", None).expect("failed to create.");
        let dbtxn = db.write().await;
        assert!(dbtxn.migrate().is_ok());

        let mut gt1 = UnixGroupToken {
            name: "testgroup".to_string(),
            spn: "testgroup@example.com".to_string(),
            gidnumber: 2000,
            uuid: "0302b99c-f0f6-41ab-9492-852692b0fd16".to_string(),
        };

        let gt2 = UnixGroupToken {
            name: "testgroup".to_string(),
            spn: "testgroup@example.com".to_string(),
            gidnumber: 2001,
            uuid: "799123b2-3802-4b19-b0b8-1ffae2aa9a4b".to_string(),
        };

        let id_name = Id::Name("testgroup".to_string());
        let id_name2 = Id::Name("testgroup2".to_string());

        // test finding no group
        let r1 = dbtxn.get_group(&id_name).unwrap();
        assert!(r1.is_none());

        // test adding a group
        dbtxn.update_group(&gt1, 0).unwrap();
        let r0 = dbtxn.get_group(&id_name).unwrap();
        assert!(r0.unwrap().0.uuid == "0302b99c-f0f6-41ab-9492-852692b0fd16");

        // Do the "rename" of gt1 which is what would allow gt2 to be valid.
        gt1.name = "testgroup2".to_string();
        gt1.spn = "testgroup2@example.com".to_string();
        // Now, add gt2 which dups on gt1 name/spn.
        dbtxn.update_group(&gt2, 0).unwrap();
        let r2 = dbtxn.get_group(&id_name).unwrap();
        assert!(r2.unwrap().0.uuid == "799123b2-3802-4b19-b0b8-1ffae2aa9a4b");
        let r3 = dbtxn.get_group(&id_name2).unwrap();
        assert!(r3.is_none());

        // Now finally update gt1
        dbtxn.update_group(&gt1, 0).unwrap();

        // Both now coexist
        let r4 = dbtxn.get_group(&id_name).unwrap();
        assert!(r4.unwrap().0.uuid == "799123b2-3802-4b19-b0b8-1ffae2aa9a4b");
        let r5 = dbtxn.get_group(&id_name2).unwrap();
        assert!(r5.unwrap().0.uuid == "0302b99c-f0f6-41ab-9492-852692b0fd16");

        assert!(dbtxn.commit().is_ok());
    }

    #[tokio::test]
    async fn test_cache_db_account_rename_duplicate() {
        sketching::test_init();
        let db = Db::new("", None).expect("failed to create.");
        let dbtxn = db.write().await;
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
            valid: true,
        };

        let ut2 = UnixUserToken {
            name: "testuser".to_string(),
            spn: "testuser@example.com".to_string(),
            displayname: "Test User".to_string(),
            gidnumber: 2001,
            uuid: "799123b2-3802-4b19-b0b8-1ffae2aa9a4b".to_string(),
            shell: None,
            groups: Vec::new(),
            sshkeys: vec!["key-a".to_string()],
            valid: true,
        };

        let id_name = Id::Name("testuser".to_string());
        let id_name2 = Id::Name("testuser2".to_string());

        // test finding no account
        let r1 = dbtxn.get_account(&id_name).unwrap();
        assert!(r1.is_none());

        // test adding an account
        dbtxn.update_account(&ut1, 0).unwrap();
        let r0 = dbtxn.get_account(&id_name).unwrap();
        assert!(r0.unwrap().0.uuid == "0302b99c-f0f6-41ab-9492-852692b0fd16");

        // Do the "rename" of gt1 which is what would allow gt2 to be valid.
        ut1.name = "testuser2".to_string();
        ut1.spn = "testuser2@example.com".to_string();
        // Now, add gt2 which dups on gt1 name/spn.
        dbtxn.update_account(&ut2, 0).unwrap();
        let r2 = dbtxn.get_account(&id_name).unwrap();
        assert!(r2.unwrap().0.uuid == "799123b2-3802-4b19-b0b8-1ffae2aa9a4b");
        let r3 = dbtxn.get_account(&id_name2).unwrap();
        assert!(r3.is_none());

        // Now finally update gt1
        dbtxn.update_account(&ut1, 0).unwrap();

        // Both now coexist
        let r4 = dbtxn.get_account(&id_name).unwrap();
        assert!(r4.unwrap().0.uuid == "799123b2-3802-4b19-b0b8-1ffae2aa9a4b");
        let r5 = dbtxn.get_account(&id_name2).unwrap();
        assert!(r5.unwrap().0.uuid == "0302b99c-f0f6-41ab-9492-852692b0fd16");

        assert!(dbtxn.commit().is_ok());
    }
}
