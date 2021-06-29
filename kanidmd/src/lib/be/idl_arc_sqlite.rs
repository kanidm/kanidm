use crate::audit::AuditScope;
use crate::be::idl_sqlite::{
    IdlSqlite, IdlSqliteReadTransaction, IdlSqliteTransaction, IdlSqliteWriteTransaction,
};
use crate::be::idxkey::{IdlCacheKey, IdlCacheKeyRef, IdlCacheKeyToRef};
use crate::be::{BackendConfig, IdList, IdRawEntry};
use crate::entry::{Entry, EntryCommitted, EntrySealed};
use crate::value::IndexType;
use crate::value::Value;
use concread::arcache::{ARCache, ARCacheReadTxn, ARCacheWriteTxn};
use concread::cowcell::*;
use idlset::{v2::IDLBitRange, AndNot};
use kanidm_proto::v1::{ConsistencyError, OperationError};
use std::collections::BTreeSet;
use std::ops::DerefMut;
use std::time::Duration;
use uuid::Uuid;

// use std::borrow::Borrow;

// Appears to take about ~500MB on some stress tests
const DEFAULT_CACHE_TARGET: usize = 2048;
const DEFAULT_IDL_CACHE_RATIO: usize = 32;
const DEFAULT_NAME_CACHE_RATIO: usize = 8;
const DEFAULT_CACHE_RMISS: usize = 8;
const DEFAULT_CACHE_WMISS: usize = 8;

#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
enum NameCacheKey {
    Name2Uuid(String),
    Uuid2Rdn(Uuid),
    Uuid2Spn(Uuid),
}

#[derive(Debug, Clone)]
enum NameCacheValue {
    U(Uuid),
    R(String),
    S(Box<Value>),
}

pub struct IdlArcSqlite {
    db: IdlSqlite,
    entry_cache: ARCache<u64, Box<Entry<EntrySealed, EntryCommitted>>>,
    idl_cache: ARCache<IdlCacheKey, Box<IDLBitRange>>,
    name_cache: ARCache<NameCacheKey, NameCacheValue>,
    op_ts_max: CowCell<Option<Duration>>,
    allids: CowCell<IDLBitRange>,
    maxid: CowCell<u64>,
}

pub struct IdlArcSqliteReadTransaction<'a> {
    db: IdlSqliteReadTransaction,
    entry_cache: ARCacheReadTxn<'a, u64, Box<Entry<EntrySealed, EntryCommitted>>>,
    idl_cache: ARCacheReadTxn<'a, IdlCacheKey, Box<IDLBitRange>>,
    name_cache: ARCacheReadTxn<'a, NameCacheKey, NameCacheValue>,
    allids: CowCellReadTxn<IDLBitRange>,
}

pub struct IdlArcSqliteWriteTransaction<'a> {
    db: IdlSqliteWriteTransaction,
    entry_cache: ARCacheWriteTxn<'a, u64, Box<Entry<EntrySealed, EntryCommitted>>>,
    idl_cache: ARCacheWriteTxn<'a, IdlCacheKey, Box<IDLBitRange>>,
    name_cache: ARCacheWriteTxn<'a, NameCacheKey, NameCacheValue>,
    op_ts_max: CowCellWriteTxn<'a, Option<Duration>>,
    allids: CowCellWriteTxn<'a, IDLBitRange>,
    maxid: CowCellWriteTxn<'a, u64>,
}

macro_rules! get_identry {
    (
        $self:expr,
        $au:expr,
        $idl:expr,
        $is_read_op:expr
    ) => {{
        lperf_trace_segment!($au, "be::idl_arc_sqlite::get_identry", || {
            let mut result: Vec<Entry<_, _>> = Vec::new();
            match $idl {
                IdList::Partial(idli) | IdList::PartialThreshold(idli) | IdList::Indexed(idli) => {
                    let mut nidl = IDLBitRange::new();

                    idli.into_iter().for_each(|i| {
                        // For all the id's in idl.
                        // is it in the cache?
                        match $self.entry_cache.get(&i) {
                            Some(eref) => result.push(eref.as_ref().clone()),
                            None => unsafe { nidl.push_id(i) },
                        }
                    });

                    if !nidl.is_empty() {
                        // Now, get anything from nidl that is needed.
                        let mut db_result = $self.db.get_identry($au, &IdList::Partial(nidl))?;
                        // Clone everything from db_result into the cache.
                        if $is_read_op {
                            db_result.iter().for_each(|e| {
                                $self.entry_cache.insert(e.get_id(), Box::new(e.clone()));
                            });
                        }
                        // Merge the two vecs
                        result.append(&mut db_result);
                    }
                }
                IdList::AllIds => {
                    // VERY similar to above, but we skip adding the entries to the cache
                    // on miss to prevent scan/invalidation attacks.
                    let idli = (*$self.allids).clone();
                    let mut nidl = IDLBitRange::new();

                    (&idli)
                        .into_iter()
                        .for_each(|i| match $self.entry_cache.get(&i) {
                            Some(eref) => result.push(eref.as_ref().clone()),
                            None => unsafe { nidl.push_id(i) },
                        });

                    if !nidl.is_empty() {
                        // Now, get anything from nidl that is needed.
                        let mut db_result = $self.db.get_identry($au, &IdList::Partial(nidl))?;
                        // Merge the two vecs
                        result.append(&mut db_result);
                    }
                }
            };
            // Return
            Ok(result)
        })
    }};
}

macro_rules! get_identry_raw {
    (
        $self:expr,
        $au:expr,
        $idl:expr
    ) => {{
        // As a cache we have no concept of this, so we just bypass to the db.
        $self.db.get_identry_raw($au, $idl)
    }};
}

macro_rules! exists_idx {
    (
        $self:expr,
        $audit:expr,
        $attr:expr,
        $itype:expr
    ) => {{
        // As a cache we have no concept of this, so we just bypass to the db.
        $self.db.exists_idx($audit, $attr, $itype)
    }};
}

macro_rules! get_idl {
    (
        $self:expr,
        $audit:expr,
        $attr:expr,
        $itype:expr,
        $idx_key:expr
    ) => {{
        lperf_trace_segment!($audit, "be::idl_arc_sqlite::get_idl", || {
            // SEE ALSO #259: Find a way to implement borrow for this properly.
            // I don't think this is possible. When we make this dyn, the arc
            // needs the dyn trait to be sized so that it *could* claim a clone
            // for hit tracking reasons. That also means that we need From and
            // some other traits that just seem incompatible. And in the end,
            // we clone a few times in arc, and if we miss we need to insert anyway
            //
            // So the best path could be to replace IdlCacheKey with a compressed
            // or smaller type. Perhaps even a small cache of the IdlCacheKeys that
            // are allocated to reduce some allocs? Probably over thinking it at
            // this point.
            //
            // First attempt to get from this cache.
            let cache_key = IdlCacheKeyRef {
                a: $attr,
                i: $itype,
                k: $idx_key,
            };
            let cache_r = $self.idl_cache.get(&cache_key as &dyn IdlCacheKeyToRef);
            // If hit, continue.
            if let Some(ref data) = cache_r {
                ltrace!(
                    $audit,
                    "Got cached idl for index {:?} {:?} -> {}",
                    $itype,
                    $attr,
                    data
                );
                return Ok(Some(data.as_ref().clone()));
            }
            // If miss, get from db *and* insert to the cache.
            let db_r = $self.db.get_idl($audit, $attr, $itype, $idx_key)?;
            if let Some(ref idl) = db_r {
                let ncache_key = IdlCacheKey {
                    a: $attr.into(),
                    i: $itype.clone(),
                    k: $idx_key.into(),
                };
                $self.idl_cache.insert(ncache_key, Box::new(idl.clone()))
            }
            Ok(db_r)
        })
    }};
}

macro_rules! name2uuid {
    (
        $self:expr,
        $audit:expr,
        $name:expr
    ) => {{
        lperf_trace_segment!($audit, "be::idl_arc_sqlite::name2uuid", || {
            let cache_key = NameCacheKey::Name2Uuid($name.to_string());
            let cache_r = $self.name_cache.get(&cache_key);
            if let Some(NameCacheValue::U(uuid)) = cache_r {
                ltrace!($audit, "Got cached uuid for name2uuid");
                return Ok(Some(uuid.clone()));
            }

            let db_r = $self.db.name2uuid($audit, $name)?;
            if let Some(uuid) = db_r {
                $self
                    .name_cache
                    .insert(cache_key, NameCacheValue::U(uuid.clone()))
            }
            Ok(db_r)
        })
    }};
}

macro_rules! uuid2spn {
    (
        $self:expr,
        $audit:expr,
        $uuid:expr
    ) => {{
        lperf_trace_segment!($audit, "be::idl_arc_sqlite::name2uuid", || {
            let cache_key = NameCacheKey::Uuid2Spn(*$uuid);
            let cache_r = $self.name_cache.get(&cache_key);
            if let Some(NameCacheValue::S(ref spn)) = cache_r {
                ltrace!($audit, "Got cached spn for uuid2spn");
                return Ok(Some(spn.as_ref().clone()));
            }

            let db_r = $self.db.uuid2spn($audit, $uuid)?;
            if let Some(ref data) = db_r {
                $self
                    .name_cache
                    .insert(cache_key, NameCacheValue::S(Box::new(data.clone())))
            }
            Ok(db_r)
        })
    }};
}

macro_rules! uuid2rdn {
    (
        $self:expr,
        $audit:expr,
        $uuid:expr
    ) => {{
        lperf_trace_segment!($audit, "be::idl_arc_sqlite::name2uuid", || {
            let cache_key = NameCacheKey::Uuid2Rdn(*$uuid);
            let cache_r = $self.name_cache.get(&cache_key);
            if let Some(NameCacheValue::R(ref rdn)) = cache_r {
                ltrace!($audit, "Got cached rdn for uuid2rdn");
                return Ok(Some(rdn.clone()));
            }

            let db_r = $self.db.uuid2rdn($audit, $uuid)?;
            if let Some(ref data) = db_r {
                $self
                    .name_cache
                    .insert(cache_key, NameCacheValue::R(data.clone()))
            }
            Ok(db_r)
        })
    }};
}

macro_rules! verify {
    (
        $self:expr,
        $audit:expr
    ) => {{
        let mut r = $self.db.verify();
        if r.is_empty() && !$self.is_dirty() {
            // Check allids.
            match $self.db.get_allids($audit) {
                Ok(db_allids) => {
                    if !db_allids.is_compressed() || !(*($self).allids).is_compressed() {
                        ladmin_warning!($audit, "Inconsistent ALLIDS compression state");
                        r.push(Err(ConsistencyError::BackendAllIdsSync))
                    }
                    if db_allids != (*($self).allids) {
                        ladmin_warning!($audit, "Inconsistent ALLIDS set");
                        ladmin_warning!(
                            $audit,
                            "db_allids: {:?}",
                            (&db_allids).andnot(&($self).allids)
                        );
                        ladmin_warning!(
                            $audit,
                            "arc_allids: {:?}",
                            (&(*($self).allids)).andnot(&db_allids)
                        );
                        r.push(Err(ConsistencyError::BackendAllIdsSync))
                    }
                }
                Err(_) => r.push(Err(ConsistencyError::Unknown)),
            };
        };
        r
    }};
}

pub trait IdlArcSqliteTransaction {
    fn get_identry(
        &mut self,
        au: &mut AuditScope,
        idl: &IdList,
    ) -> Result<Vec<Entry<EntrySealed, EntryCommitted>>, OperationError>;

    fn get_identry_raw(
        &self,
        au: &mut AuditScope,
        idl: &IdList,
    ) -> Result<Vec<IdRawEntry>, OperationError>;

    fn exists_idx(
        &mut self,
        audit: &mut AuditScope,
        attr: &str,
        itype: &IndexType,
    ) -> Result<bool, OperationError>;

    fn get_idl(
        &mut self,
        audit: &mut AuditScope,
        attr: &str,
        itype: &IndexType,
        idx_key: &str,
    ) -> Result<Option<IDLBitRange>, OperationError>;

    fn get_db_s_uuid(&self) -> Result<Option<Uuid>, OperationError>;

    fn get_db_d_uuid(&self) -> Result<Option<Uuid>, OperationError>;

    fn verify(&self, audit: &mut AuditScope) -> Vec<Result<(), ConsistencyError>>;

    fn is_dirty(&self) -> bool;

    fn name2uuid(
        &mut self,
        audit: &mut AuditScope,
        name: &str,
    ) -> Result<Option<Uuid>, OperationError>;

    fn uuid2spn(
        &mut self,
        audit: &mut AuditScope,
        uuid: &Uuid,
    ) -> Result<Option<Value>, OperationError>;

    fn uuid2rdn(
        &mut self,
        audit: &mut AuditScope,
        uuid: &Uuid,
    ) -> Result<Option<String>, OperationError>;

    fn list_idxs(&self, audit: &mut AuditScope) -> Result<Vec<String>, OperationError>;

    fn list_id2entry(&self, audit: &mut AuditScope) -> Result<Vec<(u64, String)>, OperationError>;

    fn list_index_content(
        &self,
        audit: &mut AuditScope,
        index_name: &str,
    ) -> Result<Vec<(String, IDLBitRange)>, OperationError>;

    fn get_id2entry(
        &self,
        audit: &mut AuditScope,
        id: u64,
    ) -> Result<(u64, String), OperationError>;
}

impl<'a> IdlArcSqliteTransaction for IdlArcSqliteReadTransaction<'a> {
    fn get_identry(
        &mut self,
        au: &mut AuditScope,
        idl: &IdList,
    ) -> Result<Vec<Entry<EntrySealed, EntryCommitted>>, OperationError> {
        get_identry!(self, au, idl, true)
    }

    fn get_identry_raw(
        &self,
        au: &mut AuditScope,
        idl: &IdList,
    ) -> Result<Vec<IdRawEntry>, OperationError> {
        get_identry_raw!(self, au, idl)
    }

    fn exists_idx(
        &mut self,
        audit: &mut AuditScope,
        attr: &str,
        itype: &IndexType,
    ) -> Result<bool, OperationError> {
        exists_idx!(self, audit, attr, itype)
    }

    fn get_idl(
        &mut self,
        audit: &mut AuditScope,
        attr: &str,
        itype: &IndexType,
        idx_key: &str,
    ) -> Result<Option<IDLBitRange>, OperationError> {
        get_idl!(self, audit, attr, itype, idx_key)
    }

    fn get_db_s_uuid(&self) -> Result<Option<Uuid>, OperationError> {
        self.db.get_db_s_uuid()
    }

    fn get_db_d_uuid(&self) -> Result<Option<Uuid>, OperationError> {
        self.db.get_db_d_uuid()
    }

    fn verify(&self, audit: &mut AuditScope) -> Vec<Result<(), ConsistencyError>> {
        verify!(self, audit)
    }

    fn is_dirty(&self) -> bool {
        false
    }

    fn name2uuid(
        &mut self,
        audit: &mut AuditScope,
        name: &str,
    ) -> Result<Option<Uuid>, OperationError> {
        name2uuid!(self, audit, name)
    }

    fn uuid2spn(
        &mut self,
        audit: &mut AuditScope,
        uuid: &Uuid,
    ) -> Result<Option<Value>, OperationError> {
        uuid2spn!(self, audit, uuid)
    }

    fn uuid2rdn(
        &mut self,
        audit: &mut AuditScope,
        uuid: &Uuid,
    ) -> Result<Option<String>, OperationError> {
        uuid2rdn!(self, audit, uuid)
    }

    fn list_idxs(&self, audit: &mut AuditScope) -> Result<Vec<String>, OperationError> {
        // This is only used in tests or debug tools, so bypass the cache.
        self.db.list_idxs(audit)
    }

    fn list_id2entry(&self, audit: &mut AuditScope) -> Result<Vec<(u64, String)>, OperationError> {
        // This is only used in tests or debug tools, so bypass the cache.
        self.db.list_id2entry(audit)
    }

    fn list_index_content(
        &self,
        audit: &mut AuditScope,
        index_name: &str,
    ) -> Result<Vec<(String, IDLBitRange)>, OperationError> {
        // This is only used in tests or debug tools, so bypass the cache.
        self.db.list_index_content(audit, index_name)
    }

    fn get_id2entry(
        &self,
        audit: &mut AuditScope,
        id: u64,
    ) -> Result<(u64, String), OperationError> {
        // This is only used in tests or debug tools, so bypass the cache.
        self.db.get_id2entry(audit, id)
    }
}

impl<'a> IdlArcSqliteTransaction for IdlArcSqliteWriteTransaction<'a> {
    fn get_identry(
        &mut self,
        au: &mut AuditScope,
        idl: &IdList,
    ) -> Result<Vec<Entry<EntrySealed, EntryCommitted>>, OperationError> {
        get_identry!(self, au, idl, false)
    }

    fn get_identry_raw(
        &self,
        au: &mut AuditScope,
        idl: &IdList,
    ) -> Result<Vec<IdRawEntry>, OperationError> {
        get_identry_raw!(self, au, idl)
    }

    fn exists_idx(
        &mut self,
        audit: &mut AuditScope,
        attr: &str,
        itype: &IndexType,
    ) -> Result<bool, OperationError> {
        exists_idx!(self, audit, attr, itype)
    }

    fn get_idl(
        &mut self,
        audit: &mut AuditScope,
        attr: &str,
        itype: &IndexType,
        idx_key: &str,
    ) -> Result<Option<IDLBitRange>, OperationError> {
        get_idl!(self, audit, attr, itype, idx_key)
    }

    fn get_db_s_uuid(&self) -> Result<Option<Uuid>, OperationError> {
        self.db.get_db_s_uuid()
    }

    fn get_db_d_uuid(&self) -> Result<Option<Uuid>, OperationError> {
        self.db.get_db_d_uuid()
    }

    fn verify(&self, audit: &mut AuditScope) -> Vec<Result<(), ConsistencyError>> {
        verify!(self, audit)
    }

    fn is_dirty(&self) -> bool {
        self.entry_cache.is_dirty()
    }

    fn name2uuid(
        &mut self,
        audit: &mut AuditScope,
        name: &str,
    ) -> Result<Option<Uuid>, OperationError> {
        name2uuid!(self, audit, name)
    }

    fn uuid2spn(
        &mut self,
        audit: &mut AuditScope,
        uuid: &Uuid,
    ) -> Result<Option<Value>, OperationError> {
        uuid2spn!(self, audit, uuid)
    }

    fn uuid2rdn(
        &mut self,
        audit: &mut AuditScope,
        uuid: &Uuid,
    ) -> Result<Option<String>, OperationError> {
        uuid2rdn!(self, audit, uuid)
    }

    fn list_idxs(&self, audit: &mut AuditScope) -> Result<Vec<String>, OperationError> {
        // This is only used in tests or debug tools, so bypass the cache.
        self.db.list_idxs(audit)
    }

    fn list_id2entry(&self, audit: &mut AuditScope) -> Result<Vec<(u64, String)>, OperationError> {
        // This is only used in tests or debug tools, so bypass the cache.
        self.db.list_id2entry(audit)
    }

    fn list_index_content(
        &self,
        audit: &mut AuditScope,
        index_name: &str,
    ) -> Result<Vec<(String, IDLBitRange)>, OperationError> {
        // This is only used in tests or debug tools, so bypass the cache.
        self.db.list_index_content(audit, index_name)
    }

    fn get_id2entry(
        &self,
        audit: &mut AuditScope,
        id: u64,
    ) -> Result<(u64, String), OperationError> {
        // This is only used in tests or debug tools, so bypass the cache.
        self.db.get_id2entry(audit, id)
    }
}

impl<'a> IdlArcSqliteWriteTransaction<'a> {
    pub fn commit(self, audit: &mut AuditScope) -> Result<(), OperationError> {
        lperf_trace_segment!(audit, "be::idl_arc_sqlite::commit", || {
            let IdlArcSqliteWriteTransaction {
                db,
                mut entry_cache,
                mut idl_cache,
                mut name_cache,
                op_ts_max,
                allids,
                maxid,
            } = self;

            // Write any dirty items to the disk.
            lperf_trace_segment!(audit, "be::idl_arc_sqlite::commit<entry>", || {
                entry_cache
                    .iter_mut_mark_clean()
                    .try_for_each(|(k, v)| match v {
                        Some(e) => db.write_identry(audit, e),
                        None => db.delete_identry(audit, *k),
                    })
            })
            .map_err(|e| {
                ladmin_error!(audit, "Failed to sync entry cache to sqlite {:?}", e);
                e
            })?;

            lperf_trace_segment!(audit, "be::idl_arc_sqlite::commit<idl>", || {
                idl_cache.iter_mut_mark_clean().try_for_each(|(k, v)| {
                    match v {
                        Some(idl) => db.write_idl(audit, k.a.as_str(), &k.i, k.k.as_str(), idl),
                        #[allow(clippy::unreachable)]
                        None => {
                            // Due to how we remove items, we always write an empty idl
                            // to the cache, so this should never be none.
                            //
                            // If it is none, this means we have memory corruption so we MUST
                            // panic.
                            unreachable!();
                        }
                    }
                })
            })
            .map_err(|e| {
                ladmin_error!(audit, "Failed to sync idl cache to sqlite {:?}", e);
                e
            })?;

            lperf_trace_segment!(audit, "be::idl_arc_sqlite::commit<names>", || {
                name_cache
                    .iter_mut_mark_clean()
                    .try_for_each(|(k, v)| match (k, v) {
                        (NameCacheKey::Name2Uuid(k), Some(NameCacheValue::U(v))) => {
                            db.write_name2uuid_add(audit, k, v)
                        }
                        (NameCacheKey::Name2Uuid(k), None) => db.write_name2uuid_rem(audit, k),
                        (NameCacheKey::Uuid2Spn(uuid), Some(NameCacheValue::S(v))) => {
                            db.write_uuid2spn(audit, uuid, Some(v))
                        }
                        (NameCacheKey::Uuid2Spn(uuid), None) => {
                            db.write_uuid2spn(audit, uuid, None)
                        }
                        (NameCacheKey::Uuid2Rdn(uuid), Some(NameCacheValue::R(v))) => {
                            db.write_uuid2rdn(audit, uuid, Some(v))
                        }
                        (NameCacheKey::Uuid2Rdn(uuid), None) => {
                            db.write_uuid2rdn(audit, uuid, None)
                        }

                        _ => Err(OperationError::InvalidCacheState),
                    })
            })
            .map_err(|e| {
                ladmin_error!(audit, "Failed to sync name cache to sqlite {:?}", e);
                e
            })?;

            // Undo the caches in the reverse order.
            db.commit(audit).map(|()| {
                op_ts_max.commit();
                name_cache.commit();
                idl_cache.commit();
                entry_cache.commit();
                allids.commit();
                maxid.commit();
            })
        })
    }

    pub fn get_id2entry_max_id(&self) -> Result<u64, OperationError> {
        Ok(*self.maxid)
    }

    pub fn set_id2entry_max_id(&mut self, mid: u64) {
        assert!(mid > *self.maxid);
        *self.maxid = mid;
    }

    pub fn write_identries<'b, I>(
        &'b mut self,
        au: &mut AuditScope,
        mut entries: I,
    ) -> Result<(), OperationError>
    where
        I: Iterator<Item = &'b Entry<EntrySealed, EntryCommitted>>,
    {
        lperf_trace_segment!(au, "be::idl_arc_sqlite::write_identries", || {
            entries.try_for_each(|e| {
                ltrace!(au, "Inserting {:?} to cache", e.get_id());
                if e.get_id() == 0 {
                    Err(OperationError::InvalidEntryId)
                } else {
                    (*self.allids).insert_id(e.get_id());
                    self.entry_cache
                        .insert_dirty(e.get_id(), Box::new(e.clone()));
                    Ok(())
                }
            })
        })
    }

    pub fn write_identries_raw<I>(
        &mut self,
        audit: &mut AuditScope,
        entries: I,
    ) -> Result<(), OperationError>
    where
        I: Iterator<Item = IdRawEntry>,
    {
        // Drop the entry cache.
        self.entry_cache.clear();
        // Write the raw ents
        self.db
            .write_identries_raw(audit, entries)
            .and_then(|()| self.db.get_allids(audit))
            .map(|mut ids| {
                // Update allids since we cleared them and need to reset it in the cache.
                std::mem::swap(self.allids.deref_mut(), &mut ids);
            })
    }

    pub fn delete_identry<I>(
        &mut self,
        au: &mut AuditScope,
        mut idl: I,
    ) -> Result<(), OperationError>
    where
        I: Iterator<Item = u64>,
    {
        lperf_trace_segment!(au, "be::idl_arc_sqlite::delete_identry", || {
            idl.try_for_each(|i| {
                ltrace!(au, "Removing {:?} from cache", i);
                if i == 0 {
                    Err(OperationError::InvalidEntryId)
                } else {
                    (*self.allids).remove_id(i);
                    self.entry_cache.remove_dirty(i);
                    Ok(())
                }
            })
        })
    }

    pub fn write_idl(
        &mut self,
        audit: &mut AuditScope,
        attr: &str,
        itype: &IndexType,
        idx_key: &str,
        idl: &IDLBitRange,
    ) -> Result<(), OperationError> {
        lperf_trace_segment!(audit, "be::idl_arc_sqlite::write_idl", || {
            let cache_key = IdlCacheKey {
                a: attr.into(),
                i: itype.clone(),
                k: idx_key.into(),
            };
            // On idl == 0 the db will remove this, and synthesise an empty IdList on a miss
            // but we can cache this as a new empty IdList instead, so that we can avoid the
            // db lookup on this idl.
            if idl.is_empty() {
                self.idl_cache
                    .insert_dirty(cache_key, Box::new(IDLBitRange::new()));
            } else {
                self.idl_cache
                    .insert_dirty(cache_key, Box::new(idl.clone()));
            }
            // self.db.write_idl(audit, attr, itype, idx_key, idl)
            Ok(())
        })
    }

    pub fn optimise_dirty_idls(&mut self, audit: &mut AuditScope) {
        self.idl_cache.iter_mut_dirty().for_each(|(k, maybe_idl)| {
            if let Some(idl) = maybe_idl {
                if idl.maybe_compress() {
                    lfilter_info!(audit, "Compressed idl -> {:?} ", k);
                }
            }
        })
    }

    pub fn create_name2uuid(&self, audit: &mut AuditScope) -> Result<(), OperationError> {
        self.db.create_name2uuid(audit)
    }

    pub fn write_name2uuid_add(
        &mut self,
        audit: &mut AuditScope,
        uuid: &Uuid,
        add: BTreeSet<String>,
    ) -> Result<(), OperationError> {
        lperf_trace_segment!(audit, "be::idl_arc_sqlite::write_name2uuid_add", || {
            /*
            self.db
                .write_name2uuid_add(audit, uuid, &add)
                .and_then(|_| {
            */

            add.into_iter().for_each(|k| {
                let cache_key = NameCacheKey::Name2Uuid(k);
                let cache_value = NameCacheValue::U(*uuid);
                self.name_cache.insert_dirty(cache_key, cache_value)
            });
            Ok(())
            /*
                })
            */
        })
    }

    pub fn write_name2uuid_rem(
        &mut self,
        audit: &mut AuditScope,
        rem: BTreeSet<String>,
    ) -> Result<(), OperationError> {
        lperf_trace_segment!(audit, "be::idl_arc_sqlite::write_name2uuid_add", || {
            // self.db.write_name2uuid_rem(audit, &rem).and_then(|_| {
            rem.into_iter().for_each(|k| {
                let cache_key = NameCacheKey::Name2Uuid(k);
                self.name_cache.remove_dirty(cache_key)
            });
            Ok(())
            // })
        })
    }

    pub fn create_uuid2spn(&self, audit: &mut AuditScope) -> Result<(), OperationError> {
        self.db.create_uuid2spn(audit)
    }

    pub fn write_uuid2spn(
        &mut self,
        audit: &mut AuditScope,
        uuid: &Uuid,
        k: Option<Value>,
    ) -> Result<(), OperationError> {
        lperf_trace_segment!(audit, "be::idl_arc_sqlite::write_uuid2spn", || {
            /*
            self.db
                .write_uuid2spn(audit, uuid, k.as_ref())
                .and_then(|_| {
            */
            let cache_key = NameCacheKey::Uuid2Spn(*uuid);
            match k {
                Some(v) => self
                    .name_cache
                    .insert_dirty(cache_key, NameCacheValue::S(Box::new(v))),
                None => self.name_cache.remove_dirty(cache_key),
            }
            Ok(())
            /*
                })
            */
        })
    }

    pub fn create_uuid2rdn(&self, audit: &mut AuditScope) -> Result<(), OperationError> {
        self.db.create_uuid2rdn(audit)
    }

    pub fn write_uuid2rdn(
        &mut self,
        audit: &mut AuditScope,
        uuid: &Uuid,
        k: Option<String>,
    ) -> Result<(), OperationError> {
        lperf_trace_segment!(audit, "be::idl_arc_sqlite::write_uuid2rdn", || {
            /*
            self.db
                .write_uuid2rdn(audit, uuid, k.as_ref())
                .and_then(|_| {
            */
            let cache_key = NameCacheKey::Uuid2Rdn(*uuid);
            match k {
                Some(s) => self
                    .name_cache
                    .insert_dirty(cache_key, NameCacheValue::R(s)),
                None => self.name_cache.remove_dirty(cache_key),
            }
            Ok(())
            /*
                })
            */
        })
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

    pub unsafe fn purge_idxs(&mut self, audit: &mut AuditScope) -> Result<(), OperationError> {
        self.db.purge_idxs(audit).map(|()| {
            self.idl_cache.clear();
        })
    }

    pub unsafe fn purge_id2entry(&mut self, audit: &mut AuditScope) -> Result<(), OperationError> {
        self.db.purge_id2entry(audit).map(|()| {
            let mut ids = IDLBitRange::new();
            ids.compress();
            std::mem::swap(self.allids.deref_mut(), &mut ids);
            self.entry_cache.clear();
        })
    }

    pub fn write_db_s_uuid(&self, nsid: Uuid) -> Result<(), OperationError> {
        self.db.write_db_s_uuid(nsid)
    }

    pub fn write_db_d_uuid(&self, nsid: Uuid) -> Result<(), OperationError> {
        self.db.write_db_d_uuid(nsid)
    }

    pub fn set_db_ts_max(&mut self, ts: &Duration) -> Result<(), OperationError> {
        *self.op_ts_max = Some(*ts);
        self.db.set_db_ts_max(ts)
    }

    pub fn get_db_ts_max(&self) -> Result<Option<Duration>, OperationError> {
        match *self.op_ts_max {
            Some(ts) => Ok(Some(ts)),
            None => self.db.get_db_ts_max(),
        }
    }

    pub(crate) fn get_db_index_version(&self) -> i64 {
        self.db.get_db_index_version()
    }

    pub(crate) fn set_db_index_version(&self, v: i64) -> Result<(), OperationError> {
        self.db.set_db_index_version(v)
    }

    pub fn setup(&mut self, audit: &mut AuditScope) -> Result<(), OperationError> {
        self.db
            .setup(audit)
            .and_then(|()| self.db.get_allids(audit))
            .map(|mut ids| {
                std::mem::swap(self.allids.deref_mut(), &mut ids);
            })
            .and_then(|()| self.db.get_id2entry_max_id())
            .map(|mid| {
                *self.maxid = mid;
            })
    }
}

impl IdlArcSqlite {
    pub fn new(
        audit: &mut AuditScope,
        cfg: &BackendConfig,
        vacuum: bool,
    ) -> Result<Self, OperationError> {
        let db = IdlSqlite::new(audit, cfg, vacuum)?;

        // Autotune heuristic.
        let mut cache_size = match cfg.arcsize {
            Some(v) => v,
            None => {
                // For now I've noticed about 20% of the number of entries
                // works well, but it may not be perfect ...
                let tmpsize = db
                    .get_allids_count(audit)
                    .map(|c| {
                        (if c > 0 {
                            // We want one fifth of this.
                            c / 5
                        } else {
                            c
                        }) as usize
                    })
                    .unwrap_or(DEFAULT_CACHE_TARGET);
                // if our calculation's too small anyway, just set it to the minimum target
                if tmpsize < DEFAULT_CACHE_TARGET {
                    DEFAULT_CACHE_TARGET
                } else {
                    tmpsize
                }
            }
        };

        if cache_size < DEFAULT_CACHE_TARGET {
            cache_size = DEFAULT_CACHE_TARGET;
            ladmin_warning!(
                audit,
                "Configured Arc Cache size too low {} - setting to {} ...",
                &cache_size,
                DEFAULT_CACHE_TARGET
            );
        }

        let entry_cache = ARCache::new(
            cache_size,
            cfg.pool_size as usize,
            DEFAULT_CACHE_RMISS,
            DEFAULT_CACHE_WMISS,
            false,
        );
        // The idl cache should have smaller items, and is critical for fast searches
        // so we allow it to have a higher ratio of items relative to the entries.
        let idl_cache = ARCache::new(
            cache_size * DEFAULT_IDL_CACHE_RATIO,
            cfg.pool_size as usize,
            DEFAULT_CACHE_RMISS,
            DEFAULT_CACHE_WMISS,
            false,
        );

        let name_cache = ARCache::new(
            cache_size * DEFAULT_NAME_CACHE_RATIO,
            cfg.pool_size as usize,
            DEFAULT_CACHE_RMISS,
            DEFAULT_CACHE_WMISS,
            true,
        );

        let allids = CowCell::new(IDLBitRange::new());

        let maxid = CowCell::new(0);

        let op_ts_max = CowCell::new(None);

        Ok(IdlArcSqlite {
            db,
            entry_cache,
            idl_cache,
            name_cache,
            op_ts_max,
            allids,
            maxid,
        })
    }

    pub fn read(&self) -> IdlArcSqliteReadTransaction {
        // IMPORTANT! Always take entrycache FIRST
        let entry_cache_read = self.entry_cache.read();
        let idl_cache_read = self.idl_cache.read();
        let name_cache_read = self.name_cache.read();
        let allids_read = self.allids.read();
        let db_read = self.db.read();

        IdlArcSqliteReadTransaction {
            db: db_read,
            entry_cache: entry_cache_read,
            idl_cache: idl_cache_read,
            name_cache: name_cache_read,
            allids: allids_read,
        }
    }

    pub fn write(&self) -> IdlArcSqliteWriteTransaction {
        // IMPORTANT! Always take entrycache FIRST
        let entry_cache_write = self.entry_cache.write();
        let idl_cache_write = self.idl_cache.write();
        let name_cache_write = self.name_cache.write();
        let op_ts_max_write = self.op_ts_max.write();
        let allids_write = self.allids.write();
        let maxid_write = self.maxid.write();
        let db_write = self.db.write();
        IdlArcSqliteWriteTransaction {
            db: db_write,
            entry_cache: entry_cache_write,
            idl_cache: idl_cache_write,
            name_cache: name_cache_write,
            op_ts_max: op_ts_max_write,
            allids: allids_write,
            maxid: maxid_write,
        }
    }

    /*
    pub fn stats_audit(&self, audit: &mut AuditScope) {
        let entry_stats = self.entry_cache.view_stats();
        let idl_stats = self.idl_cache.view_stats();
        ladmin_info!(audit, "entry_cache stats -> {:?}", *entry_stats);
        ladmin_info!(audit, "idl_cache stats -> {:?}", *idl_stats);
    }
    */
}
