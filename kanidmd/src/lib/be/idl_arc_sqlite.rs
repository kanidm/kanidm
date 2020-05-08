use crate::audit::AuditScope;
use crate::entry::{Entry, EntryCommitted, EntrySealed};
use crate::value::IndexType;
use concread::cache::arc::{Arc, ArcReadTxn, ArcWriteTxn};
use idlset::IDLBitRange;
use kanidm_proto::v1::{ConsistencyError, OperationError};
use uuid::Uuid;

const DEFAULT_CACHE_SIZE: usize = 1024;

use crate::be::idl_sqlite::{
    IdlSqlite, IdlSqliteReadTransaction, IdlSqliteTransaction, IdlSqliteWriteTransaction,
};
use crate::be::{IdRawEntry, IDL};

pub struct IdlArcSqlite {
    db: IdlSqlite,
    entry_cache: Arc<u64, Entry<EntrySealed, EntryCommitted>>,
    //              attr  itype       idx_key
    idl_cache: Arc<(String, IndexType, String), IDL>,
}

pub struct IdlArcSqliteReadTransaction {
    db: IdlSqliteReadTransaction,
    entry_cache: ArcReadTxn<u64, Entry<EntrySealed, EntryCommitted>>,
    idl_cache: ArcReadTxn<(String, IndexType, String), IDL>,
}

pub struct IdlArcSqliteWriteTransaction<'a> {
    db: IdlSqliteWriteTransaction,
    entry_cache: ArcWriteTxn<'a, u64, Entry<EntrySealed, EntryCommitted>>,
    idl_cache: ArcWriteTxn<'a, (String, IndexType, String), IDL>,
}

pub trait IdlArcSqliteTransaction {
    fn get_identry(
        &self,
        au: &mut AuditScope,
        idl: &IDL,
    ) -> Result<Vec<Entry<EntrySealed, EntryCommitted>>, OperationError> {
        unimplemented!();
    }

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

    fn get_db_s_uuid(&self) -> Result<Option<Uuid>, OperationError> {
        unimplemented!();
    }

    fn get_db_d_uuid(&self) -> Result<Option<Uuid>, OperationError> {
        unimplemented!();
    }

    fn verify(&self) -> Vec<Result<(), ConsistencyError>> {
        unimplemented!();
    }
}

impl IdlArcSqliteTransaction for IdlArcSqliteReadTransaction {}

impl<'a> IdlArcSqliteTransaction for IdlArcSqliteWriteTransaction<'a> {}

impl<'a> IdlArcSqliteWriteTransaction<'a> {
    pub fn commit(mut self, audit: &mut AuditScope) -> Result<(), OperationError> {
        unimplemented!();
    }

    pub fn get_id2entry_max_id(&self) -> Result<u64, OperationError> {
        unimplemented!();
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
        unimplemented!();
    }

    pub fn create_uuid2name(&self, audit: &mut AuditScope) -> Result<(), OperationError> {
        unimplemented!();
    }

    pub fn create_idx(
        &self,
        audit: &mut AuditScope,
        attr: &str,
        itype: &IndexType,
    ) -> Result<(), OperationError> {
        unimplemented!();
    }

    pub fn list_idxs(&self, audit: &mut AuditScope) -> Result<Vec<String>, OperationError> {
        unimplemented!();
    }

    pub unsafe fn purge_idxs(&self, audit: &mut AuditScope) -> Result<(), OperationError> {
        unimplemented!();
    }

    pub unsafe fn purge_id2entry(&self, audit: &mut AuditScope) -> Result<(), OperationError> {
        unimplemented!();
    }

    pub fn write_db_s_uuid(&self, nsid: Uuid) -> Result<(), OperationError> {
        unimplemented!();
    }

    pub fn write_db_d_uuid(&self, nsid: Uuid) -> Result<(), OperationError> {
        unimplemented!();
    }

    pub(crate) fn get_db_index_version(&self) -> i64 {
        unimplemented!();
    }

    pub(crate) fn set_db_index_version(&self, v: i64) -> Result<(), OperationError> {
        unimplemented!();
    }

    pub fn setup(&self, audit: &mut AuditScope) -> Result<(), OperationError> {
        unimplemented!();
    }
}

impl IdlArcSqlite {
    pub fn new(audit: &mut AuditScope, path: &str, pool_size: u32) -> Result<Self, OperationError> {
        let db = IdlSqlite::new(audit, path, pool_size)?;
        let entry_cache = Arc::new(1024);
        let idl_cache = Arc::new(2048);

        Ok(IdlArcSqlite {
            db,
            entry_cache,
            idl_cache,
        })
    }

    pub fn read(&self) -> IdlArcSqliteReadTransaction {
        unimplemented!();
    }

    pub fn write(&self) -> IdlArcSqliteWriteTransaction {
        unimplemented!();
    }
}
