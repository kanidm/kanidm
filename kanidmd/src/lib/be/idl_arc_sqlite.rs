use crate::audit::AuditScope;
use crate::entry::{Entry, EntryCommitted, EntrySealed};
use crate::value::IndexType;
use concread::cache::arc::{Arc, ArcReadTxn, ArcWriteTxn};
use idlset::IDLBitRange;
use kanidm_proto::v1::{ConsistencyError, OperationError};
use uuid::Uuid;
use crate::be::idl_sqlite::{
    IdlSqlite, IdlSqliteReadTransaction, IdlSqliteTransaction, IdlSqliteWriteTransaction,
};
use crate::be::{IdRawEntry, IDL};

const DEFAULT_CACHE_SIZE: usize = 1024;
const DEFAULT_IDL_CACHE_RATIO: usize = 16;


pub struct IdlArcSqlite {
    db: IdlSqlite,
    entry_cache: Arc<u64, Box<Entry<EntrySealed, EntryCommitted>>>,
    //              attr  itype       idx_key
    idl_cache: Arc<(String, IndexType, String), Box<IDL>>,
}

pub struct IdlArcSqliteReadTransaction {
    db: IdlSqliteReadTransaction,
    entry_cache: ArcReadTxn<u64, Box<Entry<EntrySealed, EntryCommitted>>>,
    idl_cache: ArcReadTxn<(String, IndexType, String), Box<IDL>>,
}

pub struct IdlArcSqliteWriteTransaction<'a> {
    db: IdlSqliteWriteTransaction,
    entry_cache: ArcWriteTxn<'a, u64, Box<Entry<EntrySealed, EntryCommitted>>>,
    idl_cache: ArcWriteTxn<'a, (String, IndexType, String), Box<IDL>>,
}

pub trait IdlArcSqliteTransaction {
    fn get_identry(
        &mut self,
        au: &mut AuditScope,
        idl: &IDL,
    ) -> Result<Vec<Entry<EntrySealed, EntryCommitted>>, OperationError>;

    fn get_identry_raw(
        &self,
        au: &mut AuditScope,
        idl: &IDL,
    ) -> Result<Vec<IdRawEntry>, OperationError> {
        unimplemented!();
    }

    fn exists_idx(
        &self,
        audit: &mut AuditScope,
        attr: &str,
        itype: &IndexType,
    ) -> Result<bool, OperationError> {
        unimplemented!();
    }

    fn get_idl(
        &self,
        audit: &mut AuditScope,
        attr: &str,
        itype: &IndexType,
        idx_key: &str,
    ) -> Result<Option<IDLBitRange>, OperationError> {
        unimplemented!();
    }

    fn get_db_s_uuid(&self) -> Result<Option<Uuid>, OperationError>;

    fn get_db_d_uuid(&self) -> Result<Option<Uuid>, OperationError>;

    fn verify(&self) -> Vec<Result<(), ConsistencyError>>;
}

impl IdlArcSqliteTransaction for IdlArcSqliteReadTransaction {
    fn get_identry(
        &mut self,
        au: &mut AuditScope,
        idl: &IDL,
    ) -> Result<Vec<Entry<EntrySealed, EntryCommitted>>, OperationError> {
        unimplemented!();
    }

    fn get_db_s_uuid(&self) -> Result<Option<Uuid>, OperationError> {
        self.db.get_db_s_uuid()
    }

    fn get_db_d_uuid(&self) -> Result<Option<Uuid>, OperationError> {
        self.db.get_db_d_uuid()
    }

    fn verify(&self) -> Vec<Result<(), ConsistencyError>> {
        self.db.verify()
    }
}

impl<'a> IdlArcSqliteTransaction for IdlArcSqliteWriteTransaction<'a> {
    fn get_identry(
        &mut self,
        au: &mut AuditScope,
        idl: &IDL,
    ) -> Result<Vec<Entry<EntrySealed, EntryCommitted>>, OperationError> {
        match idl {
            IDL::Partial(idli) | IDL::Indexed(idli) => {
                let mut result: Vec<Entry<_, _>> = Vec::new();
                let mut nidl = IDLBitRange::new();

                idli.into_iter().for_each(|i| {
                    // For all the id's in idl.
                    // is it in the cache?
                    match self.entry_cache.get(&i) {
                        Some(eref) => {
                            result.push(eref.as_ref().clone())
                        }
                        None => {
                            unsafe {
                                nidl.push_id(i)
                            }
                        }
                    }
                });

                // Now, get anything from nidl that is needed.
                let mut db_result = self.db.get_identry(au, &IDL::Partial(nidl))?;

                // Clone everything from db_result into the cache.
                db_result.iter().for_each(|e| {
                    self.entry_cache.insert(e.get_id(), Box::new(e.clone()));
                });

                // Merge the two vecs
                result.append(&mut db_result);

                // Return
                Ok(result)
            }
            IDL::ALLIDS => {
                self.db.get_identry(au, idl)
            }
        }
    }

    fn get_db_s_uuid(&self) -> Result<Option<Uuid>, OperationError> {
        self.db.get_db_s_uuid()
    }

    fn get_db_d_uuid(&self) -> Result<Option<Uuid>, OperationError> {
        self.db.get_db_d_uuid()
    }

    fn verify(&self) -> Vec<Result<(), ConsistencyError>> {
        self.db.verify()
    }
}

impl<'a> IdlArcSqliteWriteTransaction<'a> {
    pub fn commit(self, audit: &mut AuditScope) -> Result<(), OperationError> {
        let IdlArcSqliteWriteTransaction {
            db,
            entry_cache,
            idl_cache,
        } = self;
        // Undo the caches in the reverse order.
        db.commit(audit)
            .and_then(|r| {
                idl_cache.commit();
                entry_cache.commit();
                Ok(r)
            })
    }

    pub fn get_id2entry_max_id(&self) -> Result<u64, OperationError> {
        // TODO: We could cache this too, and have this via the setup call
        // to get the init value, using the ArcCell.
        self.db.get_id2entry_max_id()
    }

    pub fn write_identries<'b, I>(
        &'b self,
        au: &mut AuditScope,
        entries: I,
    ) -> Result<(), OperationError>
    where
        I: Iterator<Item = &'b Entry<EntrySealed, EntryCommitted>>,
    {
        unimplemented!();
    }

    pub fn write_identries_raw<I>(
        &self,
        au: &mut AuditScope,
        mut entries: I,
    ) -> Result<(), OperationError>
    where
        I: Iterator<Item = IdRawEntry>,
    {
        unimplemented!();
    }

    pub fn delete_identry<I>(&self, au: &mut AuditScope, mut idl: I) -> Result<(), OperationError>
    where
        I: Iterator<Item = u64>,
    {
        unimplemented!();
    }

    pub fn write_idl(
        &self,
        audit: &mut AuditScope,
        attr: &str,
        itype: &IndexType,
        idx_key: &str,
        idl: &IDLBitRange,
    ) -> Result<(), OperationError> {
        unimplemented!();
    }

    pub fn create_name2uuid(&self, audit: &mut AuditScope) -> Result<(), OperationError> {
        self.db.create_name2uuid(audit)
    }

    pub fn create_uuid2name(&self, audit: &mut AuditScope) -> Result<(), OperationError> {
        self.db.create_uuid2name(audit)
    }

    pub fn create_idx(
        &self,
        audit: &mut AuditScope,
        attr: &str,
        itype: &IndexType,
    ) -> Result<(), OperationError> {
        // We don't need to affect this, so pass it down.
        self.db.create_idx(audit, attr, itype)
    }

    pub fn list_idxs(&self, audit: &mut AuditScope) -> Result<Vec<String>, OperationError> {
        // This is only used in tests, so bypass the cache.
        self.db.list_idxs(audit)
    }

    pub unsafe fn purge_idxs(&mut self, audit: &mut AuditScope) -> Result<(), OperationError> {
        self.db.purge_idxs(audit)
            .and_then(|r| {
                self.idl_cache.clear();
                Ok(r)
            })
    }

    pub unsafe fn purge_id2entry(&mut self, audit: &mut AuditScope) -> Result<(), OperationError> {
        self.db.purge_id2entry(audit)
            .and_then(|r| {
                self.entry_cache.clear();
                Ok(r)
            })
    }

    pub fn write_db_s_uuid(&self, nsid: Uuid) -> Result<(), OperationError> {
        self.db.write_db_s_uuid(nsid)
    }

    pub fn write_db_d_uuid(&self, nsid: Uuid) -> Result<(), OperationError> {
        self.db.write_db_d_uuid(nsid)
    }

    pub(crate) fn get_db_index_version(&self) -> i64 {
        self.db.get_db_index_version()
    }

    pub(crate) fn set_db_index_version(&self, v: i64) -> Result<(), OperationError> {
        self.db.set_db_index_version(v)
    }

    pub fn setup(&self, audit: &mut AuditScope) -> Result<(), OperationError> {
        self.db.setup(audit)
    }
}

impl IdlArcSqlite {
    pub fn new(audit: &mut AuditScope, path: &str, pool_size: u32) -> Result<Self, OperationError> {
        let db = IdlSqlite::new(audit, path, pool_size)?;
        let entry_cache = Arc::new(DEFAULT_CACHE_SIZE);
        // The idl cache should have smaller items, and is critical for fast searches
        // so we allow it to have a higher ratio of items relative to the entries.
        let idl_cache = Arc::new(DEFAULT_CACHE_SIZE * DEFAULT_IDL_CACHE_RATIO);

        Ok(IdlArcSqlite {
            db,
            entry_cache,
            idl_cache,
        })
    }

    pub fn read(&self) -> IdlArcSqliteReadTransaction {
        // IMPORTANT! Always take entrycache FIRST
        let entry_cache_read = self.entry_cache.read();
        let idl_cache_read = self.idl_cache.read();
        let db_read = self.db.read();
        IdlArcSqliteReadTransaction {
            db: db_read,
            entry_cache: entry_cache_read,
            idl_cache: idl_cache_read,
        }
    }

    pub fn write(&self) -> IdlArcSqliteWriteTransaction {
        // IMPORTANT! Always take entrycache FIRST
        let entry_cache_write = self.entry_cache.write();
        let idl_cache_write = self.idl_cache.write();
        let db_write = self.db.write();
        IdlArcSqliteWriteTransaction {
            db: db_write,
            entry_cache: entry_cache_write,
            idl_cache: idl_cache_write,
        }
    }
}
