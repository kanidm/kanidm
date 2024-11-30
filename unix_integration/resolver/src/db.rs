use std::convert::TryFrom;
use std::fmt;

use crate::idprovider::interface::{GroupToken, Id, UserToken};
use async_trait::async_trait;
use libc::umask;
use rusqlite::{Connection, OptionalExtension};
use tokio::sync::{Mutex, MutexGuard};
use uuid::Uuid;

use serde::{de::DeserializeOwned, Serialize};

use kanidm_hsm_crypto::{LoadableHmacKey, LoadableMachineKey};

const DBV_MAIN: &str = "main";

#[async_trait]
pub trait Cache {
    type Txn<'db>
    where
        Self: 'db;

    async fn write<'db>(&'db self) -> Self::Txn<'db>;
}

#[async_trait]
pub trait KeyStore {
    type Txn<'db>
    where
        Self: 'db;

    async fn write_keystore<'db>(&'db self) -> Self::Txn<'db>;
}

#[derive(Debug)]
pub enum CacheError {
    Cryptography,
    SerdeJson,
    Parse,
    Sqlite,
    TooManyResults,
    TransactionInvalidState,
    Tpm,
}

pub struct Db {
    conn: Mutex<Connection>,
}

pub struct DbTxn<'a> {
    conn: MutexGuard<'a, Connection>,
    committed: bool,
}

pub struct KeyStoreTxn<'a, 'b> {
    db: &'b mut DbTxn<'a>,
}

impl<'a, 'b> From<&'b mut DbTxn<'a>> for KeyStoreTxn<'a, 'b> {
    fn from(db: &'b mut DbTxn<'a>) -> Self {
        Self { db }
    }
}

#[derive(Debug)]
/// Errors coming back from the `Db` struct
pub enum DbError {
    Sqlite,
    Tpm,
}

impl Db {
    pub fn new(path: &str) -> Result<Self, DbError> {
        let before = unsafe { umask(0o0027) };
        let conn = Connection::open(path).map_err(|e| {
            error!(err = ?e, "rusqulite error");
            DbError::Sqlite
        })?;
        let _ = unsafe { umask(before) };

        Ok(Db {
            conn: Mutex::new(conn),
        })
    }
}

#[async_trait]
impl Cache for Db {
    type Txn<'db> = DbTxn<'db>;

    #[allow(clippy::expect_used)]
    async fn write<'db>(&'db self) -> Self::Txn<'db> {
        let conn = self.conn.lock().await;
        DbTxn::new(conn)
    }
}

impl fmt::Debug for Db {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Db {{}}")
    }
}

impl<'a> DbTxn<'a> {
    fn new(conn: MutexGuard<'a, Connection>) -> Self {
        // Start the transaction
        // trace!("Starting db WR txn ...");
        #[allow(clippy::expect_used)]
        conn.execute("BEGIN TRANSACTION", [])
            .expect("Unable to begin transaction!");
        DbTxn {
            committed: false,
            conn,
        }
    }

    /// This handles an error coming back from an sqlite event and dumps more information from it
    fn sqlite_error(&self, msg: &str, error: &rusqlite::Error) -> CacheError {
        error!(
            "sqlite {} error: {:?} db_path={:?}",
            msg,
            error,
            &self.conn.path()
        );
        CacheError::Sqlite
    }

    /// This handles an error coming back from an sqlite transaction and dumps a load of information from it
    fn sqlite_transaction_error(
        &self,
        error: &rusqlite::Error,
        _stmt: &rusqlite::Statement,
    ) -> CacheError {
        error!(
            "sqlite transaction error={:?} db_path={:?}",
            error,
            &self.conn.path(),
        );
        // TODO: one day figure out if there's an easy way to dump the transaction without the token...
        CacheError::Sqlite
    }

    fn get_db_version(&self, key: &str) -> i64 {
        self.conn
            .query_row(
                "SELECT version FROM db_version_t WHERE id = :id",
                &[(":id", key)],
                |row| row.get(0),
            )
            .unwrap_or({
                // The value is missing, default to 0.
                0
            })
    }

    fn set_db_version(&self, key: &str, v: i64) -> Result<(), CacheError> {
        self.conn
            .execute(
                "INSERT OR REPLACE INTO db_version_t (id, version) VALUES(:id, :dbv)",
                named_params! {
                    ":id": &key,
                    ":dbv": v,
                },
            )
            .map(|_| ())
            .map_err(|e| self.sqlite_error("set db_version_t", &e))
    }

    fn get_account_data_name(
        &mut self,
        account_id: &str,
    ) -> Result<Vec<(Vec<u8>, i64)>, CacheError> {
        let mut stmt = self.conn
            .prepare(
        "SELECT token, expiry FROM account_t WHERE uuid = :account_id OR name = :account_id OR spn = :account_id"
            )
            .map_err(|e| {
                self.sqlite_error("select prepare", &e)
            })?;

        // Makes tuple (token, expiry)
        let data_iter = stmt
            .query_map([account_id], |row| Ok((row.get(0)?, row.get(1)?)))
            .map_err(|e| self.sqlite_error("query_map failure", &e))?;
        let data: Result<Vec<(Vec<u8>, i64)>, _> = data_iter
            .map(|v| v.map_err(|e| self.sqlite_error("map failure", &e)))
            .collect();
        data
    }

    fn get_account_data_gid(&mut self, gid: u32) -> Result<Vec<(Vec<u8>, i64)>, CacheError> {
        let mut stmt = self
            .conn
            .prepare("SELECT token, expiry FROM account_t WHERE gidnumber = :gid")
            .map_err(|e| self.sqlite_error("select prepare", &e))?;

        // Makes tuple (token, expiry)
        let data_iter = stmt
            .query_map(params![gid], |row| Ok((row.get(0)?, row.get(1)?)))
            .map_err(|e| self.sqlite_error("query_map", &e))?;
        let data: Result<Vec<(Vec<u8>, i64)>, _> = data_iter
            .map(|v| v.map_err(|e| self.sqlite_error("map", &e)))
            .collect();
        data
    }

    fn get_group_data_name(&mut self, grp_id: &str) -> Result<Vec<(Vec<u8>, i64)>, CacheError> {
        let mut stmt = self.conn
            .prepare(
                "SELECT token, expiry FROM group_t WHERE uuid = :grp_id OR name = :grp_id OR spn = :grp_id"
            )
            .map_err(|e| {
                self.sqlite_error("select prepare", &e)
            })?;

        // Makes tuple (token, expiry)
        let data_iter = stmt
            .query_map([grp_id], |row| Ok((row.get(0)?, row.get(1)?)))
            .map_err(|e| self.sqlite_error("query_map", &e))?;
        let data: Result<Vec<(Vec<u8>, i64)>, _> = data_iter
            .map(|v| v.map_err(|e| self.sqlite_error("map", &e)))
            .collect();
        data
    }

    fn get_group_data_gid(&mut self, gid: u32) -> Result<Vec<(Vec<u8>, i64)>, CacheError> {
        let mut stmt = self
            .conn
            .prepare("SELECT token, expiry FROM group_t WHERE gidnumber = :gid")
            .map_err(|e| self.sqlite_error("select prepare", &e))?;

        // Makes tuple (token, expiry)
        let data_iter = stmt
            .query_map(params![gid], |row| Ok((row.get(0)?, row.get(1)?)))
            .map_err(|e| self.sqlite_error("query_map", &e))?;
        let data: Result<Vec<(Vec<u8>, i64)>, _> = data_iter
            .map(|v| v.map_err(|e| self.sqlite_error("map", &e)))
            .collect();
        data
    }
}

impl KeyStoreTxn<'_, '_> {
    pub fn get_tagged_hsm_key<K: DeserializeOwned>(
        &mut self,
        tag: &str,
    ) -> Result<Option<K>, CacheError> {
        self.db.get_tagged_hsm_key(tag)
    }

    pub fn insert_tagged_hsm_key<K: Serialize>(
        &mut self,
        tag: &str,
        key: &K,
    ) -> Result<(), CacheError> {
        self.db.insert_tagged_hsm_key(tag, key)
    }

    pub fn delete_tagged_hsm_key(&mut self, tag: &str) -> Result<(), CacheError> {
        self.db.delete_tagged_hsm_key(tag)
    }
}

impl DbTxn<'_> {
    fn get_tagged_hsm_key<K: DeserializeOwned>(
        &mut self,
        tag: &str,
    ) -> Result<Option<K>, CacheError> {
        let mut stmt = self
            .conn
            .prepare("SELECT value FROM hsm_data_t WHERE key = :key")
            .map_err(|e| self.sqlite_error("select prepare", &e))?;

        let data: Option<Vec<u8>> = stmt
            .query_row(
                named_params! {
                    ":key": tag
                },
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| self.sqlite_error("query_row", &e))?;

        match data {
            Some(d) => Ok(serde_json::from_slice(d.as_slice())
                .map_err(|e| {
                    error!("json error -> {:?}", e);
                })
                .ok()),
            None => Ok(None),
        }
    }

    fn insert_tagged_hsm_key<K: Serialize>(
        &mut self,
        tag: &str,
        key: &K,
    ) -> Result<(), CacheError> {
        let data = serde_json::to_vec(key).map_err(|e| {
            error!("json error -> {:?}", e);
            CacheError::SerdeJson
        })?;

        let mut stmt = self
            .conn
            .prepare("INSERT OR REPLACE INTO hsm_data_t (key, value) VALUES (:key, :value)")
            .map_err(|e| self.sqlite_error("prepare", &e))?;

        stmt.execute(named_params! {
            ":key": tag,
            ":value": &data,
        })
        .map(|r| {
            trace!("insert -> {:?}", r);
        })
        .map_err(|e| self.sqlite_error("execute", &e))
    }

    fn delete_tagged_hsm_key(&mut self, tag: &str) -> Result<(), CacheError> {
        self.conn
            .execute(
                "DELETE FROM hsm_data_t where key = :key",
                named_params! {
                    ":key": tag,
                },
            )
            .map(|_| ())
            .map_err(|e| self.sqlite_error("delete hsm_data_t", &e))
    }
}

impl DbTxn<'_> {
    pub fn migrate(&mut self) -> Result<(), CacheError> {
        self.conn.set_prepared_statement_cache_capacity(16);
        self.conn
            .prepare("PRAGMA journal_mode=WAL;")
            .and_then(|mut wal_stmt| wal_stmt.query([]).map(|_| ()))
            .map_err(|e| self.sqlite_error("account_t create", &e))?;

        // This definition can never change.
        self.conn
            .execute(
                "CREATE TABLE IF NOT EXISTS db_version_t (
                    id TEXT PRIMARY KEY,
                    version INTEGER
                )",
                [],
            )
            .map_err(|e| self.sqlite_error("db_version_t create", &e))?;

        let db_version = self.get_db_version(DBV_MAIN);

        if db_version < 1 {
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
                .map_err(|e| self.sqlite_error("account_t create", &e))?;

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
                .map_err(|e| self.sqlite_error("group_t create", &e))?;

            // We defer group foreign keys here because we now manually cascade delete these when
            // required. This is because insert or replace into will always delete then add
            // which triggers this. So instead we defer and manually cascade.
            //
            // However, on accounts, we CAN delete cascade because accounts will always redefine
            // their memberships on updates so this is safe to cascade on this direction.
            self.conn
                .execute(
                    "CREATE TABLE IF NOT EXISTS memberof_t (
                    g_uuid TEXT,
                    a_uuid TEXT,
                    FOREIGN KEY(g_uuid) REFERENCES group_t(uuid) DEFERRABLE INITIALLY DEFERRED,
                    FOREIGN KEY(a_uuid) REFERENCES account_t(uuid) ON DELETE CASCADE
                )
                ",
                    [],
                )
                .map_err(|e| self.sqlite_error("memberof_t create error", &e))?;

            // Create the hsm_data store. These are all generally encrypted private
            // keys, and the hsm structures will decrypt these as required.
            self.conn
                .execute(
                    "CREATE TABLE IF NOT EXISTS hsm_int_t (
                        key TEXT PRIMARY KEY,
                        value BLOB NOT NULL
                    )
                    ",
                    [],
                )
                .map_err(|e| self.sqlite_error("hsm_int_t create error", &e))?;

            self.conn
                .execute(
                    "CREATE TABLE IF NOT EXISTS hsm_data_t (
                        key TEXT PRIMARY KEY,
                        value BLOB NOT NULL
                    )
                    ",
                    [],
                )
                .map_err(|e| self.sqlite_error("hsm_data_t create error", &e))?;

            // Since this is the 0th migration, we have to reset the HSM here.
            self.clear_hsm()?;
        }

        self.set_db_version(DBV_MAIN, 1)?;

        Ok(())
    }

    pub fn commit(mut self) -> Result<(), CacheError> {
        if self.committed {
            error!("Invalid state, SQL transaction was already committed!");
            return Err(CacheError::TransactionInvalidState);
        }
        self.committed = true;

        self.conn
            .execute("COMMIT TRANSACTION", [])
            .map(|_| ())
            .map_err(|e| self.sqlite_error("commit", &e))
    }

    pub fn invalidate(&mut self) -> Result<(), CacheError> {
        self.conn
            .execute("UPDATE group_t SET expiry = 0", [])
            .map_err(|e| self.sqlite_error("update group_t", &e))?;

        self.conn
            .execute("UPDATE account_t SET expiry = 0", [])
            .map_err(|e| self.sqlite_error("update account_t", &e))?;

        Ok(())
    }

    pub fn clear(&mut self) -> Result<(), CacheError> {
        self.conn
            .execute("DELETE FROM memberof_t", [])
            .map_err(|e| self.sqlite_error("delete memberof_t", &e))?;

        self.conn
            .execute("DELETE FROM group_t", [])
            .map_err(|e| self.sqlite_error("delete group_t", &e))?;

        self.conn
            .execute("DELETE FROM account_t", [])
            .map_err(|e| self.sqlite_error("delete group_t", &e))?;

        Ok(())
    }

    pub fn clear_hsm(&mut self) -> Result<(), CacheError> {
        self.clear()?;

        self.conn
            .execute("DELETE FROM hsm_int_t", [])
            .map_err(|e| self.sqlite_error("delete hsm_int_t", &e))?;

        self.conn
            .execute("DELETE FROM hsm_data_t", [])
            .map_err(|e| self.sqlite_error("delete hsm_data_t", &e))?;

        Ok(())
    }

    pub fn get_hsm_machine_key(&mut self) -> Result<Option<LoadableMachineKey>, CacheError> {
        let mut stmt = self
            .conn
            .prepare("SELECT value FROM hsm_int_t WHERE key = 'mk'")
            .map_err(|e| self.sqlite_error("select prepare", &e))?;

        let data: Option<Vec<u8>> = stmt
            .query_row([], |row| row.get(0))
            .optional()
            .map_err(|e| self.sqlite_error("query_row", &e))?;

        match data {
            Some(d) => Ok(serde_json::from_slice(d.as_slice())
                .map_err(|e| {
                    error!("json error -> {:?}", e);
                })
                .ok()),
            None => Ok(None),
        }
    }

    pub fn insert_hsm_machine_key(
        &mut self,
        machine_key: &LoadableMachineKey,
    ) -> Result<(), CacheError> {
        let data = serde_json::to_vec(machine_key).map_err(|e| {
            error!("insert_hsm_machine_key json error -> {:?}", e);
            CacheError::SerdeJson
        })?;

        let mut stmt = self
            .conn
            .prepare("INSERT OR REPLACE INTO hsm_int_t (key, value) VALUES (:key, :value)")
            .map_err(|e| self.sqlite_error("prepare", &e))?;

        stmt.execute(named_params! {
            ":key": "mk",
            ":value": &data,
        })
        .map(|r| {
            trace!("insert -> {:?}", r);
        })
        .map_err(|e| self.sqlite_error("execute", &e))
    }

    pub fn get_hsm_hmac_key(&mut self) -> Result<Option<LoadableHmacKey>, CacheError> {
        let mut stmt = self
            .conn
            .prepare("SELECT value FROM hsm_int_t WHERE key = 'hmac'")
            .map_err(|e| self.sqlite_error("select prepare", &e))?;

        let data: Option<Vec<u8>> = stmt
            .query_row([], |row| row.get(0))
            .optional()
            .map_err(|e| self.sqlite_error("query_row", &e))?;

        match data {
            Some(d) => Ok(serde_json::from_slice(d.as_slice())
                .map_err(|e| {
                    error!("json error -> {:?}", e);
                })
                .ok()),
            None => Ok(None),
        }
    }

    pub fn insert_hsm_hmac_key(&mut self, hmac_key: &LoadableHmacKey) -> Result<(), CacheError> {
        let data = serde_json::to_vec(hmac_key).map_err(|e| {
            error!("insert_hsm_hmac_key json error -> {:?}", e);
            CacheError::SerdeJson
        })?;

        let mut stmt = self
            .conn
            .prepare("INSERT OR REPLACE INTO hsm_int_t (key, value) VALUES (:key, :value)")
            .map_err(|e| self.sqlite_error("prepare", &e))?;

        stmt.execute(named_params! {
            ":key": "hmac",
            ":value": &data,
        })
        .map(|r| {
            trace!("insert -> {:?}", r);
        })
        .map_err(|e| self.sqlite_error("execute", &e))
    }

    pub fn get_account(&mut self, account_id: &Id) -> Result<Option<(UserToken, u64)>, CacheError> {
        let data = match account_id {
            Id::Name(n) => self.get_account_data_name(n.as_str()),
            Id::Gid(g) => self.get_account_data_gid(*g),
        }?;

        // Assert only one result?
        if data.len() >= 2 {
            error!("invalid db state, multiple entries matched query?");
            return Err(CacheError::TooManyResults);
        }

        if let Some((token, expiry)) = data.first() {
            // token convert with json.
            // If this errors, we specifically return Ok(None) because that triggers
            // the cache to refetch the token.
            match serde_json::from_slice(token.as_slice()) {
                Ok(t) => {
                    let e = u64::try_from(*expiry).map_err(|e| {
                        error!("u64 convert error -> {:?}", e);
                        CacheError::Parse
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

    pub fn get_accounts(&mut self) -> Result<Vec<UserToken>, CacheError> {
        let mut stmt = self
            .conn
            .prepare("SELECT token FROM account_t")
            .map_err(|e| self.sqlite_error("select prepare", &e))?;

        let data_iter = stmt
            .query_map([], |row| row.get(0))
            .map_err(|e| self.sqlite_error("query_map", &e))?;
        let data: Result<Vec<Vec<u8>>, _> = data_iter
            .map(|v| v.map_err(|e| self.sqlite_error("map", &e)))
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

    pub fn update_account(&mut self, account: &UserToken, expire: u64) -> Result<(), CacheError> {
        let data = serde_json::to_vec(account).map_err(|e| {
            error!("update_account json error -> {:?}", e);
            CacheError::SerdeJson
        })?;
        let expire = i64::try_from(expire).map_err(|e| {
            error!("update_account i64 conversion error -> {:?}", e);
            CacheError::Parse
        })?;

        // This is needed because sqlites 'insert or replace into', will null the password field
        // if present, and upsert MUST match the exact conflicting column, so that means we have
        // to manually manage the update or insert :( :(
        let account_uuid = account.uuid.as_hyphenated().to_string();

        // Find anything conflicting and purge it.
        self.conn.execute("DELETE FROM account_t WHERE NOT uuid = :uuid AND (name = :name OR spn = :spn OR gidnumber = :gidnumber)",
            named_params!{
                ":uuid": &account_uuid,
                ":name": &account.name,
                ":spn": &account.spn,
                ":gidnumber": &account.gidnumber,
            }
            )
            .map_err(|e| {
                self.sqlite_error("delete account_t duplicate", &e)
            })
            .map(|_| ())?;

        let updated = self.conn.execute(
                "UPDATE account_t SET name=:name, spn=:spn, gidnumber=:gidnumber, token=:token, expiry=:expiry WHERE uuid = :uuid",
            named_params!{
                ":uuid": &account_uuid,
                ":name": &account.name,
                ":spn": &account.spn,
                ":gidnumber": &account.gidnumber,
                ":token": &data,
                ":expiry": &expire,
            }
            )
            .map_err(|e| {
                self.sqlite_error("delete account_t duplicate", &e)
            })?;

        if updated == 0 {
            let mut stmt = self.conn
                .prepare("INSERT INTO account_t (uuid, name, spn, gidnumber, token, expiry) VALUES (:uuid, :name, :spn, :gidnumber, :token, :expiry) ON CONFLICT(uuid) DO UPDATE SET name=excluded.name, spn=excluded.name, gidnumber=excluded.gidnumber, token=excluded.token, expiry=excluded.expiry")
                .map_err(|e| {
                    self.sqlite_error("prepare", &e)
                })?;

            stmt.execute(named_params! {
                ":uuid": &account_uuid,
                ":name": &account.name,
                ":spn": &account.spn,
                ":gidnumber": &account.gidnumber,
                ":token": &data,
                ":expiry": &expire,
            })
            .map(|r| {
                trace!("insert -> {:?}", r);
            })
            .map_err(|error| self.sqlite_transaction_error(&error, &stmt))?;
        }

        // Now, we have to update the group memberships.

        // First remove everything that already exists:
        let mut stmt = self
            .conn
            .prepare("DELETE FROM memberof_t WHERE a_uuid = :a_uuid")
            .map_err(|e| self.sqlite_error("prepare", &e))?;

        stmt.execute([&account_uuid])
            .map(|r| {
                trace!("delete memberships -> {:?}", r);
            })
            .map_err(|error| self.sqlite_transaction_error(&error, &stmt))?;

        let mut stmt = self
            .conn
            .prepare("INSERT INTO memberof_t (a_uuid, g_uuid) VALUES (:a_uuid, :g_uuid)")
            .map_err(|e| self.sqlite_error("prepare", &e))?;
        // Now for each group, add the relation.
        account.groups.iter().try_for_each(|g| {
            stmt.execute(named_params! {
                ":a_uuid": &account_uuid,
                ":g_uuid": &g.uuid.as_hyphenated().to_string(),
            })
            .map(|r| {
                trace!("insert membership -> {:?}", r);
            })
            .map_err(|error| self.sqlite_transaction_error(&error, &stmt))
        })
    }

    pub fn delete_account(&mut self, a_uuid: Uuid) -> Result<(), CacheError> {
        let account_uuid = a_uuid.as_hyphenated().to_string();

        self.conn
            .execute(
                "DELETE FROM memberof_t WHERE a_uuid = :a_uuid",
                params![&account_uuid],
            )
            .map(|_| ())
            .map_err(|e| self.sqlite_error("account_t memberof_t cascade delete", &e))?;

        self.conn
            .execute(
                "DELETE FROM account_t WHERE uuid = :a_uuid",
                params![&account_uuid],
            )
            .map(|_| ())
            .map_err(|e| self.sqlite_error("account_t delete", &e))
    }

    pub fn get_group(&mut self, grp_id: &Id) -> Result<Option<(GroupToken, u64)>, CacheError> {
        let data = match grp_id {
            Id::Name(n) => self.get_group_data_name(n.as_str()),
            Id::Gid(g) => self.get_group_data_gid(*g),
        }?;

        // Assert only one result?
        if data.len() >= 2 {
            error!("invalid db state, multiple entries matched query?");
            return Err(CacheError::TooManyResults);
        }

        if let Some((token, expiry)) = data.first() {
            // token convert with json.
            // If this errors, we specifically return Ok(None) because that triggers
            // the cache to refetch the token.
            match serde_json::from_slice(token.as_slice()) {
                Ok(t) => {
                    let e = u64::try_from(*expiry).map_err(|e| {
                        error!("u64 convert error -> {:?}", e);
                        CacheError::Parse
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

    pub fn get_group_members(&mut self, g_uuid: Uuid) -> Result<Vec<UserToken>, CacheError> {
        let mut stmt = self
            .conn
            .prepare("SELECT account_t.token FROM (account_t, memberof_t) WHERE account_t.uuid = memberof_t.a_uuid AND memberof_t.g_uuid = :g_uuid")
            .map_err(|e| {
                self.sqlite_error("select prepare", &e)
            })?;

        let data_iter = stmt
            .query_map([g_uuid.as_hyphenated().to_string()], |row| row.get(0))
            .map_err(|e| self.sqlite_error("query_map", &e))?;
        let data: Result<Vec<Vec<u8>>, _> = data_iter
            .map(|v| v.map_err(|e| self.sqlite_error("map", &e)))
            .collect();

        let data = data?;

        data.iter()
            .map(|token| {
                // token convert with json.
                // trace!("{:?}", token);
                serde_json::from_slice(token.as_slice()).map_err(|e| {
                    error!("json error -> {:?}", e);
                    CacheError::SerdeJson
                })
            })
            .collect()
    }

    pub fn get_groups(&mut self) -> Result<Vec<GroupToken>, CacheError> {
        let mut stmt = self
            .conn
            .prepare("SELECT token FROM group_t")
            .map_err(|e| self.sqlite_error("select prepare", &e))?;

        let data_iter = stmt
            .query_map([], |row| row.get(0))
            .map_err(|e| self.sqlite_error("query_map", &e))?;
        let data: Result<Vec<Vec<u8>>, _> = data_iter
            .map(|v| v.map_err(|e| self.sqlite_error("map", &e)))
            .collect();

        let data = data?;

        Ok(data
            .iter()
            .filter_map(|token| {
                // token convert with json.
                // trace!("{:?}", token);
                serde_json::from_slice(token.as_slice())
                    .map_err(|e| {
                        error!("json error -> {:?}", e);
                    })
                    .ok()
            })
            .collect())
    }

    pub fn update_group(&mut self, grp: &GroupToken, expire: u64) -> Result<(), CacheError> {
        let data = serde_json::to_vec(grp).map_err(|e| {
            error!("json error -> {:?}", e);
            CacheError::SerdeJson
        })?;
        let expire = i64::try_from(expire).map_err(|e| {
            error!("i64 convert error -> {:?}", e);
            CacheError::Parse
        })?;

        let mut stmt = self.conn
            .prepare("INSERT OR REPLACE INTO group_t (uuid, name, spn, gidnumber, token, expiry) VALUES (:uuid, :name, :spn, :gidnumber, :token, :expiry)")
            .map_err(|e| {
                self.sqlite_error("prepare", &e)
            })?;

        // We have to to-str uuid as the sqlite impl makes it a blob which breaks our selects in get.
        stmt.execute(named_params! {
            ":uuid": &grp.uuid.as_hyphenated().to_string(),
            ":name": &grp.name,
            ":spn": &grp.spn,
            ":gidnumber": &grp.gidnumber,
            ":token": &data,
            ":expiry": &expire,
        })
        .map(|r| {
            trace!("insert -> {:?}", r);
        })
        .map_err(|e| self.sqlite_error("execute", &e))
    }

    pub fn delete_group(&mut self, g_uuid: Uuid) -> Result<(), CacheError> {
        let group_uuid = g_uuid.as_hyphenated().to_string();
        self.conn
            .execute(
                "DELETE FROM memberof_t WHERE g_uuid = :g_uuid",
                [&group_uuid],
            )
            .map(|_| ())
            .map_err(|e| self.sqlite_error("group_t memberof_t cascade delete", &e))?;
        self.conn
            .execute("DELETE FROM group_t WHERE uuid = :g_uuid", [&group_uuid])
            .map(|_| ())
            .map_err(|e| self.sqlite_error("group_t delete", &e))
    }
}

impl fmt::Debug for DbTxn<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DbTxn {{}}")
    }
}

impl Drop for DbTxn<'_> {
    // Abort
    fn drop(&mut self) {
        if !self.committed {
            // trace!("Aborting BE WR txn");
            #[allow(clippy::expect_used)]
            self.conn
                .execute("ROLLBACK TRANSACTION", [])
                .expect("Unable to rollback transaction! Can not proceed!!!");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Cache, Db};
    use crate::idprovider::interface::{GroupToken, Id, ProviderOrigin, UserToken};

    #[tokio::test]
    async fn test_cache_db_account_basic() {
        sketching::test_init();
        let db = Db::new("").expect("failed to create.");
        let mut dbtxn = db.write().await;
        assert!(dbtxn.migrate().is_ok());

        let mut ut1 = UserToken {
            provider: ProviderOrigin::System,
            name: "testuser".to_string(),
            spn: "testuser@example.com".to_string(),
            displayname: "Test User".to_string(),
            gidnumber: 2000,
            uuid: uuid::uuid!("0302b99c-f0f6-41ab-9492-852692b0fd16"),
            shell: None,
            groups: Vec::new(),
            sshkeys: vec!["key-a".to_string()],
            valid: true,
            extra_keys: Default::default(),
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
        assert!(dbtxn.clear().is_ok());

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
        let db = Db::new("").expect("failed to create.");
        let mut dbtxn = db.write().await;
        assert!(dbtxn.migrate().is_ok());

        let mut gt1 = GroupToken {
            provider: ProviderOrigin::System,
            name: "testgroup".to_string(),
            spn: "testgroup@example.com".to_string(),
            gidnumber: 2000,
            uuid: uuid::uuid!("0302b99c-f0f6-41ab-9492-852692b0fd16"),
            extra_keys: Default::default(),
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
        assert!(dbtxn.clear().is_ok());

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
        let db = Db::new("").expect("failed to create.");
        let mut dbtxn = db.write().await;
        assert!(dbtxn.migrate().is_ok());

        let gt1 = GroupToken {
            provider: ProviderOrigin::System,
            name: "testuser".to_string(),
            spn: "testuser@example.com".to_string(),
            gidnumber: 2000,
            uuid: uuid::uuid!("0302b99c-f0f6-41ab-9492-852692b0fd16"),
            extra_keys: Default::default(),
        };

        let gt2 = GroupToken {
            provider: ProviderOrigin::System,
            name: "testgroup".to_string(),
            spn: "testgroup@example.com".to_string(),
            gidnumber: 2001,
            uuid: uuid::uuid!("b500be97-8552-42a5-aca0-668bc5625705"),
            extra_keys: Default::default(),
        };

        let mut ut1 = UserToken {
            provider: ProviderOrigin::System,
            name: "testuser".to_string(),
            spn: "testuser@example.com".to_string(),
            displayname: "Test User".to_string(),
            gidnumber: 2000,
            uuid: uuid::uuid!("0302b99c-f0f6-41ab-9492-852692b0fd16"),
            shell: None,
            groups: vec![gt1.clone(), gt2],
            sshkeys: vec!["key-a".to_string()],
            valid: true,
            extra_keys: Default::default(),
        };

        // First, add the groups.
        ut1.groups.iter().for_each(|g| {
            dbtxn.update_group(g, 0).unwrap();
        });

        // The add the account
        dbtxn.update_account(&ut1, 0).unwrap();

        // Now, get the memberships of the two groups.
        let m1 = dbtxn
            .get_group_members(uuid::uuid!("0302b99c-f0f6-41ab-9492-852692b0fd16"))
            .unwrap();
        let m2 = dbtxn
            .get_group_members(uuid::uuid!("b500be97-8552-42a5-aca0-668bc5625705"))
            .unwrap();
        assert_eq!(m1[0].name, "testuser");
        assert_eq!(m2[0].name, "testuser");

        // Now alter testuser, remove gt2, update.
        ut1.groups = vec![gt1];
        dbtxn.update_account(&ut1, 0).unwrap();

        // Check that the memberships have updated correctly.
        let m1 = dbtxn
            .get_group_members(uuid::uuid!("0302b99c-f0f6-41ab-9492-852692b0fd16"))
            .unwrap();
        let m2 = dbtxn
            .get_group_members(uuid::uuid!("b500be97-8552-42a5-aca0-668bc5625705"))
            .unwrap();
        assert_eq!(m1[0].name, "testuser");
        assert!(m2.is_empty());

        assert!(dbtxn.commit().is_ok());
    }

    #[tokio::test]
    async fn test_cache_db_group_rename_duplicate() {
        sketching::test_init();
        let db = Db::new("").expect("failed to create.");
        let mut dbtxn = db.write().await;
        assert!(dbtxn.migrate().is_ok());

        let mut gt1 = GroupToken {
            provider: ProviderOrigin::System,
            name: "testgroup".to_string(),
            spn: "testgroup@example.com".to_string(),
            gidnumber: 2000,
            uuid: uuid::uuid!("0302b99c-f0f6-41ab-9492-852692b0fd16"),
            extra_keys: Default::default(),
        };

        let gt2 = GroupToken {
            provider: ProviderOrigin::System,
            name: "testgroup".to_string(),
            spn: "testgroup@example.com".to_string(),
            gidnumber: 2001,
            uuid: uuid::uuid!("799123b2-3802-4b19-b0b8-1ffae2aa9a4b"),
            extra_keys: Default::default(),
        };

        let id_name = Id::Name("testgroup".to_string());
        let id_name2 = Id::Name("testgroup2".to_string());

        // test finding no group
        let r1 = dbtxn.get_group(&id_name).unwrap();
        assert!(r1.is_none());

        // test adding a group
        dbtxn.update_group(&gt1, 0).unwrap();
        let r0 = dbtxn.get_group(&id_name).unwrap();
        assert_eq!(
            r0.unwrap().0.uuid,
            uuid::uuid!("0302b99c-f0f6-41ab-9492-852692b0fd16")
        );

        // Do the "rename" of gt1 which is what would allow gt2 to be valid.
        gt1.name = "testgroup2".to_string();
        gt1.spn = "testgroup2@example.com".to_string();
        // Now, add gt2 which dups on gt1 name/spn.
        dbtxn.update_group(&gt2, 0).unwrap();
        let r2 = dbtxn.get_group(&id_name).unwrap();
        assert_eq!(
            r2.unwrap().0.uuid,
            uuid::uuid!("799123b2-3802-4b19-b0b8-1ffae2aa9a4b")
        );
        let r3 = dbtxn.get_group(&id_name2).unwrap();
        assert!(r3.is_none());

        // Now finally update gt1
        dbtxn.update_group(&gt1, 0).unwrap();

        // Both now coexist
        let r4 = dbtxn.get_group(&id_name).unwrap();
        assert_eq!(
            r4.unwrap().0.uuid,
            uuid::uuid!("799123b2-3802-4b19-b0b8-1ffae2aa9a4b")
        );
        let r5 = dbtxn.get_group(&id_name2).unwrap();
        assert_eq!(
            r5.unwrap().0.uuid,
            uuid::uuid!("0302b99c-f0f6-41ab-9492-852692b0fd16")
        );

        assert!(dbtxn.commit().is_ok());
    }

    #[tokio::test]
    async fn test_cache_db_account_rename_duplicate() {
        sketching::test_init();
        let db = Db::new("").expect("failed to create.");
        let mut dbtxn = db.write().await;
        assert!(dbtxn.migrate().is_ok());

        let mut ut1 = UserToken {
            provider: ProviderOrigin::System,
            name: "testuser".to_string(),
            spn: "testuser@example.com".to_string(),
            displayname: "Test User".to_string(),
            gidnumber: 2000,
            uuid: uuid::uuid!("0302b99c-f0f6-41ab-9492-852692b0fd16"),
            shell: None,
            groups: Vec::new(),
            sshkeys: vec!["key-a".to_string()],
            valid: true,
            extra_keys: Default::default(),
        };

        let ut2 = UserToken {
            provider: ProviderOrigin::System,
            name: "testuser".to_string(),
            spn: "testuser@example.com".to_string(),
            displayname: "Test User".to_string(),
            gidnumber: 2001,
            uuid: uuid::uuid!("799123b2-3802-4b19-b0b8-1ffae2aa9a4b"),
            shell: None,
            groups: Vec::new(),
            sshkeys: vec!["key-a".to_string()],
            valid: true,
            extra_keys: Default::default(),
        };

        let id_name = Id::Name("testuser".to_string());
        let id_name2 = Id::Name("testuser2".to_string());

        // test finding no account
        let r1 = dbtxn.get_account(&id_name).unwrap();
        assert!(r1.is_none());

        // test adding an account
        dbtxn.update_account(&ut1, 0).unwrap();
        let r0 = dbtxn.get_account(&id_name).unwrap();
        assert_eq!(
            r0.unwrap().0.uuid,
            uuid::uuid!("0302b99c-f0f6-41ab-9492-852692b0fd16")
        );

        // Do the "rename" of gt1 which is what would allow gt2 to be valid.
        ut1.name = "testuser2".to_string();
        ut1.spn = "testuser2@example.com".to_string();
        // Now, add gt2 which dups on gt1 name/spn.
        dbtxn.update_account(&ut2, 0).unwrap();
        let r2 = dbtxn.get_account(&id_name).unwrap();
        assert_eq!(
            r2.unwrap().0.uuid,
            uuid::uuid!("799123b2-3802-4b19-b0b8-1ffae2aa9a4b")
        );
        let r3 = dbtxn.get_account(&id_name2).unwrap();
        assert!(r3.is_none());

        // Now finally update gt1
        dbtxn.update_account(&ut1, 0).unwrap();

        // Both now coexist
        let r4 = dbtxn.get_account(&id_name).unwrap();
        assert_eq!(
            r4.unwrap().0.uuid,
            uuid::uuid!("799123b2-3802-4b19-b0b8-1ffae2aa9a4b")
        );
        let r5 = dbtxn.get_account(&id_name2).unwrap();
        assert_eq!(
            r5.unwrap().0.uuid,
            uuid::uuid!("0302b99c-f0f6-41ab-9492-852692b0fd16")
        );

        assert!(dbtxn.commit().is_ok());
    }
}
