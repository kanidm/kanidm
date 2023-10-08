use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::convert::TryInto;
use std::ops::DerefMut;
use std::sync::Arc;
use std::time::Duration;

use concread::arcache::{ARCache, ARCacheBuilder, ARCacheReadTxn, ARCacheWriteTxn};
use concread::cowcell::*;
use hashbrown::HashMap;
use idlset::v2::IDLBitRange;
use idlset::AndNot;
use kanidm_proto::v1::{ConsistencyError, OperationError};
use tracing::trace;
use uuid::Uuid;

use crate::be::idl_sqlite::{
    IdlSqlite, IdlSqliteReadTransaction, IdlSqliteTransaction, IdlSqliteWriteTransaction,
};
use crate::be::idxkey::{
    IdlCacheKey, IdlCacheKeyRef, IdlCacheKeyToRef, IdxKey, IdxKeyRef, IdxKeyToRef, IdxSlope,
};
use crate::be::keystorage::{KeyHandle, KeyHandleId};
use crate::be::{BackendConfig, IdList, IdRawEntry};
use crate::entry::{Entry, EntryCommitted, EntrySealed};
use crate::prelude::*;
use crate::value::{IndexType, Value};

// use std::borrow::Borrow;

// Appears to take about ~500MB on some stress tests
const DEFAULT_CACHE_TARGET: usize = 2048;
const DEFAULT_IDL_CACHE_RATIO: usize = 32;
const DEFAULT_NAME_CACHE_RATIO: usize = 8;
const DEFAULT_CACHE_RMISS: usize = 0;
const DEFAULT_CACHE_WMISS: usize = 4;

#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
enum NameCacheKey {
    Name2Uuid(String),
    ExternalId2Uuid(String),
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
    entry_cache: ARCache<u64, Arc<EntrySealedCommitted>>,
    idl_cache: ARCache<IdlCacheKey, Box<IDLBitRange>>,
    name_cache: ARCache<NameCacheKey, NameCacheValue>,
    op_ts_max: CowCell<Option<Duration>>,
    allids: CowCell<IDLBitRange>,
    maxid: CowCell<u64>,
    keyhandles: CowCell<HashMap<KeyHandleId, KeyHandle>>,
}

pub struct IdlArcSqliteReadTransaction<'a> {
    db: IdlSqliteReadTransaction,
    entry_cache: ARCacheReadTxn<'a, u64, Arc<EntrySealedCommitted>, ()>,
    idl_cache: ARCacheReadTxn<'a, IdlCacheKey, Box<IDLBitRange>, ()>,
    name_cache: ARCacheReadTxn<'a, NameCacheKey, NameCacheValue, ()>,
    allids: CowCellReadTxn<IDLBitRange>,
}

pub struct IdlArcSqliteWriteTransaction<'a> {
    pub(super) db: IdlSqliteWriteTransaction,
    entry_cache: ARCacheWriteTxn<'a, u64, Arc<EntrySealedCommitted>, ()>,
    idl_cache: ARCacheWriteTxn<'a, IdlCacheKey, Box<IDLBitRange>, ()>,
    name_cache: ARCacheWriteTxn<'a, NameCacheKey, NameCacheValue, ()>,
    op_ts_max: CowCellWriteTxn<'a, Option<Duration>>,
    allids: CowCellWriteTxn<'a, IDLBitRange>,
    maxid: CowCellWriteTxn<'a, u64>,
    pub(super) keyhandles: CowCellWriteTxn<'a, HashMap<KeyHandleId, KeyHandle>>,
}

macro_rules! get_identry {
    (
        $self:expr,
        $idl:expr,
        $is_read_op:expr
    ) => {{
        let mut result: Vec<Arc<EntrySealedCommitted>> = Vec::new();
        match $idl {
            IdList::Partial(idli) | IdList::PartialThreshold(idli) | IdList::Indexed(idli) => {
                let mut nidl = IDLBitRange::new();

                idli.into_iter().for_each(|i| {
                    // For all the id's in idl.
                    // is it in the cache?
                    match $self.entry_cache.get(&i) {
                        Some(eref) => result.push(eref.clone()),
                        None => unsafe { nidl.push_id(i) },
                    }
                });

                if !nidl.is_empty() {
                    // Now, get anything from nidl that is needed.
                    let mut db_result = $self.db.get_identry(&IdList::Partial(nidl))?;
                    // Clone everything from db_result into the cache.
                    if $is_read_op {
                        db_result.iter().for_each(|e| {
                            $self.entry_cache.insert(e.get_id(), e.clone());
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
                        Some(eref) => result.push(eref.clone()),
                        None => unsafe { nidl.push_id(i) },
                    });

                if !nidl.is_empty() {
                    // Now, get anything from nidl that is needed.
                    let mut db_result = $self.db.get_identry(&IdList::Partial(nidl))?;
                    // Merge the two vecs
                    result.append(&mut db_result);
                }
            }
        };
        // Return
        Ok(result)
    }};
}

macro_rules! get_identry_raw {
    (
        $self:expr,
        $idl:expr
    ) => {{
        // As a cache we have no concept of this, so we just bypass to the db.
        $self.db.get_identry_raw($idl)
    }};
}

macro_rules! exists_idx {
    (
        $self:expr,
        $attr:expr,
        $itype:expr
    ) => {{
        // As a cache we have no concept of this, so we just bypass to the db.
        $self.db.exists_idx($attr, $itype)
    }};
}

macro_rules! get_idl {
    (
        $self:expr,
        $attr:expr,
        $itype:expr,
        $idx_key:expr
    ) => {{
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
            trace!(
                cached_index = ?$itype,
                attr = ?$attr,
                idl = %data,
            );
            return Ok(Some(data.as_ref().clone()));
        }
        // If miss, get from db *and* insert to the cache.
        let db_r = $self.db.get_idl($attr, $itype, $idx_key)?;
        if let Some(ref idl) = db_r {
            let ncache_key = IdlCacheKey {
                a: $attr.into(),
                i: $itype.clone(),
                k: $idx_key.into(),
            };
            $self.idl_cache.insert(ncache_key, Box::new(idl.clone()))
        }
        Ok(db_r)
    }};
}

macro_rules! name2uuid {
    (
        $self:expr,
        $name:expr
    ) => {{
        let cache_key = NameCacheKey::Name2Uuid($name.to_string());
        let cache_r = $self.name_cache.get(&cache_key);
        if let Some(NameCacheValue::U(uuid)) = cache_r {
            trace!(?uuid, "Got cached name2uuid");
            return Ok(Some(uuid.clone()));
        } else {
            trace!("Cache miss uuid for name2uuid");
        }

        let db_r = $self.db.name2uuid($name)?;
        if let Some(uuid) = db_r {
            $self
                .name_cache
                .insert(cache_key, NameCacheValue::U(uuid.clone()))
        }
        Ok(db_r)
    }};
}

macro_rules! externalid2uuid {
    (
        $self:expr,
        $name:expr
    ) => {{
        let cache_key = NameCacheKey::ExternalId2Uuid($name.to_string());
        let cache_r = $self.name_cache.get(&cache_key);
        if let Some(NameCacheValue::U(uuid)) = cache_r {
            trace!(?uuid, "Got cached externalid2uuid");
            return Ok(Some(uuid.clone()));
        } else {
            trace!("Cache miss uuid for externalid2uuid");
        }

        let db_r = $self.db.externalid2uuid($name)?;
        if let Some(uuid) = db_r {
            $self
                .name_cache
                .insert(cache_key, NameCacheValue::U(uuid.clone()))
        }
        Ok(db_r)
    }};
}

macro_rules! uuid2spn {
    (
        $self:expr,
        $uuid:expr
    ) => {{
        let cache_key = NameCacheKey::Uuid2Spn($uuid);
        let cache_r = $self.name_cache.get(&cache_key);
        if let Some(NameCacheValue::S(ref spn)) = cache_r {
            trace!(?spn, "Got cached uuid2spn");
            return Ok(Some(spn.as_ref().clone()));
        } else {
            trace!("Cache miss spn for uuid2spn");
        }

        let db_r = $self.db.uuid2spn($uuid)?;
        if let Some(ref data) = db_r {
            $self
                .name_cache
                .insert(cache_key, NameCacheValue::S(Box::new(data.clone())))
        }
        Ok(db_r)
    }};
}

macro_rules! uuid2rdn {
    (
        $self:expr,
        $uuid:expr
    ) => {{
        let cache_key = NameCacheKey::Uuid2Rdn($uuid);
        let cache_r = $self.name_cache.get(&cache_key);
        if let Some(NameCacheValue::R(ref rdn)) = cache_r {
            return Ok(Some(rdn.clone()));
        } else {
            trace!("Cache miss rdn for uuid2rdn");
        }

        let db_r = $self.db.uuid2rdn($uuid)?;
        if let Some(ref data) = db_r {
            $self
                .name_cache
                .insert(cache_key, NameCacheValue::R(data.clone()))
        }
        Ok(db_r)
    }};
}

macro_rules! verify {
    (
        $self:expr
    ) => {{
        let mut r = $self.db.verify();
        if r.is_empty() && !$self.is_dirty() {
            // Check allids.
            match $self.db.get_allids() {
                Ok(db_allids) => {
                    if !db_allids.is_compressed() || !(*($self).allids).is_compressed() {
                        admin_warn!("Inconsistent ALLIDS compression state");
                        r.push(Err(ConsistencyError::BackendAllIdsSync))
                    }
                    if db_allids != (*($self).allids) {
                        // might want to redo how large key-values are formatted considering what this could look like
                        admin_warn!(
                            db_allids = ?(&db_allids).andnot(&($self).allids),
                            arc_allids = ?(&(*($self).allids)).andnot(&db_allids),
                            "Inconsistent ALLIDS set"
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
        idl: &IdList,
    ) -> Result<Vec<Arc<EntrySealedCommitted>>, OperationError>;

    fn get_identry_raw(&self, idl: &IdList) -> Result<Vec<IdRawEntry>, OperationError>;

    fn exists_idx(&mut self, attr: &str, itype: IndexType) -> Result<bool, OperationError>;

    fn get_idl(
        &mut self,
        attr: &str,
        itype: IndexType,
        idx_key: &str,
    ) -> Result<Option<IDLBitRange>, OperationError>;

    fn get_db_s_uuid(&self) -> Result<Option<Uuid>, OperationError>;

    fn get_db_d_uuid(&self) -> Result<Option<Uuid>, OperationError>;

    fn get_db_ts_max(&self) -> Result<Option<Duration>, OperationError>;

    fn get_key_handles(&mut self) -> Result<BTreeMap<KeyHandleId, KeyHandle>, OperationError>;

    fn verify(&self) -> Vec<Result<(), ConsistencyError>>;

    fn is_dirty(&self) -> bool;

    fn name2uuid(&mut self, name: &str) -> Result<Option<Uuid>, OperationError>;

    fn externalid2uuid(&mut self, name: &str) -> Result<Option<Uuid>, OperationError>;

    fn uuid2spn(&mut self, uuid: Uuid) -> Result<Option<Value>, OperationError>;

    fn uuid2rdn(&mut self, uuid: Uuid) -> Result<Option<String>, OperationError>;

    fn list_idxs(&self) -> Result<Vec<String>, OperationError>;

    fn list_id2entry(&self) -> Result<Vec<(u64, String)>, OperationError>;

    fn list_quarantined(&self) -> Result<Vec<(u64, String)>, OperationError>;

    fn list_index_content(
        &self,
        index_name: &str,
    ) -> Result<Vec<(String, IDLBitRange)>, OperationError>;

    fn get_id2entry(&self, id: u64) -> Result<(u64, String), OperationError>;
}

impl<'a> IdlArcSqliteTransaction for IdlArcSqliteReadTransaction<'a> {
    fn get_identry(
        &mut self,
        idl: &IdList,
    ) -> Result<Vec<Arc<EntrySealedCommitted>>, OperationError> {
        get_identry!(self, idl, true)
    }

    fn get_identry_raw(&self, idl: &IdList) -> Result<Vec<IdRawEntry>, OperationError> {
        get_identry_raw!(self, idl)
    }

    fn exists_idx(&mut self, attr: &str, itype: IndexType) -> Result<bool, OperationError> {
        exists_idx!(self, attr, itype)
    }

    #[instrument(level = "trace", skip_all)]
    fn get_idl(
        &mut self,
        attr: &str,
        itype: IndexType,
        idx_key: &str,
    ) -> Result<Option<IDLBitRange>, OperationError> {
        get_idl!(self, attr, itype, idx_key)
    }

    fn get_db_s_uuid(&self) -> Result<Option<Uuid>, OperationError> {
        self.db.get_db_s_uuid()
    }

    fn get_db_d_uuid(&self) -> Result<Option<Uuid>, OperationError> {
        self.db.get_db_d_uuid()
    }

    fn get_db_ts_max(&self) -> Result<Option<Duration>, OperationError> {
        self.db.get_db_ts_max()
    }

    fn get_key_handles(&mut self) -> Result<BTreeMap<KeyHandleId, KeyHandle>, OperationError> {
        self.db.get_key_handles()
    }

    fn verify(&self) -> Vec<Result<(), ConsistencyError>> {
        verify!(self)
    }

    fn is_dirty(&self) -> bool {
        false
    }

    fn name2uuid(&mut self, name: &str) -> Result<Option<Uuid>, OperationError> {
        name2uuid!(self, name)
    }

    fn externalid2uuid(&mut self, name: &str) -> Result<Option<Uuid>, OperationError> {
        externalid2uuid!(self, name)
    }

    fn uuid2spn(&mut self, uuid: Uuid) -> Result<Option<Value>, OperationError> {
        uuid2spn!(self, uuid)
    }

    fn uuid2rdn(&mut self, uuid: Uuid) -> Result<Option<String>, OperationError> {
        uuid2rdn!(self, uuid)
    }

    fn list_idxs(&self) -> Result<Vec<String>, OperationError> {
        // This is only used in tests or debug tools, so bypass the cache.
        self.db.list_idxs()
    }

    fn list_id2entry(&self) -> Result<Vec<(u64, String)>, OperationError> {
        // This is only used in tests or debug tools, so bypass the cache.
        self.db.list_id2entry()
    }

    fn list_quarantined(&self) -> Result<Vec<(u64, String)>, OperationError> {
        // No cache of quarantined entries.
        self.db.list_quarantined()
    }

    fn list_index_content(
        &self,
        index_name: &str,
    ) -> Result<Vec<(String, IDLBitRange)>, OperationError> {
        // This is only used in tests or debug tools, so bypass the cache.
        self.db.list_index_content(index_name)
    }

    fn get_id2entry(&self, id: u64) -> Result<(u64, String), OperationError> {
        // This is only used in tests or debug tools, so bypass the cache.
        self.db.get_id2entry(id)
    }
}

impl<'a> IdlArcSqliteTransaction for IdlArcSqliteWriteTransaction<'a> {
    fn get_identry(
        &mut self,
        idl: &IdList,
    ) -> Result<Vec<Arc<EntrySealedCommitted>>, OperationError> {
        get_identry!(self, idl, false)
    }

    fn get_identry_raw(&self, idl: &IdList) -> Result<Vec<IdRawEntry>, OperationError> {
        get_identry_raw!(self, idl)
    }

    fn exists_idx(&mut self, attr: &str, itype: IndexType) -> Result<bool, OperationError> {
        exists_idx!(self, attr, itype)
    }

    #[instrument(level = "trace", skip_all)]
    fn get_idl(
        &mut self,
        attr: &str,
        itype: IndexType,
        idx_key: &str,
    ) -> Result<Option<IDLBitRange>, OperationError> {
        get_idl!(self, attr, itype, idx_key)
    }

    fn get_db_s_uuid(&self) -> Result<Option<Uuid>, OperationError> {
        self.db.get_db_s_uuid()
    }

    fn get_db_d_uuid(&self) -> Result<Option<Uuid>, OperationError> {
        self.db.get_db_d_uuid()
    }

    fn get_db_ts_max(&self) -> Result<Option<Duration>, OperationError> {
        match *self.op_ts_max {
            Some(ts) => Ok(Some(ts)),
            None => self.db.get_db_ts_max(),
        }
    }

    fn get_key_handles(&mut self) -> Result<BTreeMap<KeyHandleId, KeyHandle>, OperationError> {
        self.db.get_key_handles()
    }

    fn verify(&self) -> Vec<Result<(), ConsistencyError>> {
        verify!(self)
    }

    fn is_dirty(&self) -> bool {
        self.entry_cache.is_dirty()
    }

    fn name2uuid(&mut self, name: &str) -> Result<Option<Uuid>, OperationError> {
        name2uuid!(self, name)
    }

    fn externalid2uuid(&mut self, name: &str) -> Result<Option<Uuid>, OperationError> {
        externalid2uuid!(self, name)
    }

    fn uuid2spn(&mut self, uuid: Uuid) -> Result<Option<Value>, OperationError> {
        uuid2spn!(self, uuid)
    }

    fn uuid2rdn(&mut self, uuid: Uuid) -> Result<Option<String>, OperationError> {
        uuid2rdn!(self, uuid)
    }

    fn list_idxs(&self) -> Result<Vec<String>, OperationError> {
        // This is only used in tests or debug tools, so bypass the cache.
        self.db.list_idxs()
    }

    fn list_id2entry(&self) -> Result<Vec<(u64, String)>, OperationError> {
        // This is only used in tests or debug tools, so bypass the cache.
        self.db.list_id2entry()
    }

    fn list_quarantined(&self) -> Result<Vec<(u64, String)>, OperationError> {
        // No cache of quarantined entries.
        self.db.list_quarantined()
    }

    fn list_index_content(
        &self,
        index_name: &str,
    ) -> Result<Vec<(String, IDLBitRange)>, OperationError> {
        // This is only used in tests or debug tools, so bypass the cache.
        self.db.list_index_content(index_name)
    }

    fn get_id2entry(&self, id: u64) -> Result<(u64, String), OperationError> {
        // This is only used in tests or debug tools, so bypass the cache.
        self.db.get_id2entry(id)
    }
}

impl<'a> IdlArcSqliteWriteTransaction<'a> {
    #[cfg(any(test, debug_assertions))]
    #[instrument(level = "debug", name = "idl_arc_sqlite::clear_cache", skip_all)]
    pub fn clear_cache(&mut self) -> Result<(), OperationError> {
        // I'm not sure rn if I want to reload these? If we reload these we kind of
        // prevent verifications of the cached value working, but we also should
        // clear these to check the db version of the value. Perhaps some extra
        // dedicated testing needed?
        /*
         *self.op_ts_max = self.db.get_db_ts_max()?;
         *self.allids = self.db.get_allids()?;
         *self.maxid = self.get_id2entry_max_id()?;
         */
        self.entry_cache.clear();
        self.idl_cache.clear();
        self.name_cache.clear();
        Ok(())
    }

    #[instrument(level = "debug", name = "idl_arc_sqlite::commit", skip_all)]
    pub fn commit(self) -> Result<(), OperationError> {
        let IdlArcSqliteWriteTransaction {
            db,
            mut entry_cache,
            mut idl_cache,
            mut name_cache,
            op_ts_max,
            allids,
            maxid,
            keyhandles,
        } = self;

        // Write any dirty items to the disk.
        entry_cache
            .iter_mut_mark_clean()
            .try_for_each(|(k, v)| match v {
                Some(e) => db.write_identry(e),
                None => db.delete_identry(*k),
            })
            .map_err(|e| {
                admin_error!(?e, "Failed to sync entry cache to sqlite");
                e
            })?;

        idl_cache
            .iter_mut_mark_clean()
            .try_for_each(|(k, v)| {
                match v {
                    Some(idl) => db.write_idl(k.a.as_str(), k.i, k.k.as_str(), idl),
                    #[allow(clippy::unreachable)]
                    None => {
                        // Due to how we remove items, we always write an empty idl
                        // to the cache, so this should never be none.
                        //
                        // If it is none, this means we have memory corruption so we MUST
                        // panic.
                        // Why is `v` the `Option` type then?
                        unreachable!();
                    }
                }
            })
            .map_err(|e| {
                admin_error!(?e, "Failed to sync idl cache to sqlite");
                e
            })?;

        name_cache
            .iter_mut_mark_clean()
            .try_for_each(|(k, v)| match (k, v) {
                (NameCacheKey::Name2Uuid(k), Some(NameCacheValue::U(v))) => {
                    db.write_name2uuid_add(k, *v)
                }
                (NameCacheKey::Name2Uuid(k), None) => db.write_name2uuid_rem(k),
                (NameCacheKey::ExternalId2Uuid(k), Some(NameCacheValue::U(v))) => {
                    db.write_externalid2uuid_add(k, *v)
                }
                (NameCacheKey::ExternalId2Uuid(k), None) => db.write_externalid2uuid_rem(k),
                (NameCacheKey::Uuid2Spn(uuid), Some(NameCacheValue::S(v))) => {
                    db.write_uuid2spn(*uuid, Some(v))
                }
                (NameCacheKey::Uuid2Spn(uuid), None) => db.write_uuid2spn(*uuid, None),
                (NameCacheKey::Uuid2Rdn(uuid), Some(NameCacheValue::R(v))) => {
                    db.write_uuid2rdn(*uuid, Some(v))
                }
                (NameCacheKey::Uuid2Rdn(uuid), None) => db.write_uuid2rdn(*uuid, None),

                _ => Err(OperationError::InvalidCacheState),
            })
            .map_err(|e| {
                admin_error!(?e, "Failed to sync name cache to sqlite");
                e
            })?;

        // Ensure the db commit succeeds first.
        db.commit()?;

        // Can no longer fail from this point.
        op_ts_max.commit();
        name_cache.commit();
        idl_cache.commit();
        allids.commit();
        maxid.commit();
        keyhandles.commit();
        // Unlock the entry cache last to remove contention on everything else.
        entry_cache.commit();

        Ok(())
    }

    pub fn get_db_ruv(&self) -> Result<BTreeSet<Cid>, OperationError> {
        self.db.get_db_ruv()
    }

    pub fn write_db_ruv<I, J>(&mut self, added: I, removed: J) -> Result<(), OperationError>
    where
        I: Iterator<Item = Cid>,
        J: Iterator<Item = Cid>,
    {
        self.db.write_db_ruv(added, removed)
    }

    pub fn get_id2entry_max_id(&self) -> Result<u64, OperationError> {
        Ok(*self.maxid)
    }

    pub fn set_id2entry_max_id(&mut self, mid: u64) {
        assert!(mid > *self.maxid);
        *self.maxid = mid;
    }

    pub fn write_identries<'b, I>(&'b mut self, mut entries: I) -> Result<(), OperationError>
    where
        I: Iterator<Item = &'b Entry<EntrySealed, EntryCommitted>>,
    {
        entries.try_for_each(|e| {
            trace!("Inserting {:?} to cache", e.get_id());
            if e.get_id() == 0 {
                Err(OperationError::InvalidEntryId)
            } else {
                (*self.allids).insert_id(e.get_id());
                self.entry_cache
                    .insert_dirty(e.get_id(), Arc::new(e.clone()));
                Ok(())
            }
        })
    }

    pub fn write_identries_raw<I>(&mut self, entries: I) -> Result<(), OperationError>
    where
        I: Iterator<Item = IdRawEntry>,
    {
        // Drop the entry cache.
        self.entry_cache.clear();
        // Write the raw ents
        self.db
            .write_identries_raw(entries)
            .and_then(|()| self.db.get_allids())
            .map(|mut ids| {
                // Update allids since we cleared them and need to reset it in the cache.
                std::mem::swap(self.allids.deref_mut(), &mut ids);
            })
    }

    pub fn delete_identry<I>(&mut self, mut idl: I) -> Result<(), OperationError>
    where
        I: Iterator<Item = u64>,
    {
        idl.try_for_each(|i| {
            trace!("Removing {:?} from cache", i);
            if i == 0 {
                Err(OperationError::InvalidEntryId)
            } else {
                (*self.allids).remove_id(i);
                self.entry_cache.remove_dirty(i);
                Ok(())
            }
        })
    }

    pub fn write_idl(
        &mut self,
        attr: &str,
        itype: IndexType,
        idx_key: &str,
        idl: &IDLBitRange,
    ) -> Result<(), OperationError> {
        let cache_key = IdlCacheKey {
            a: attr.into(),
            i: itype,
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
    }

    pub fn optimise_dirty_idls(&mut self) {
        self.idl_cache.iter_mut_dirty().for_each(|(k, maybe_idl)| {
            if let Some(idl) = maybe_idl {
                if idl.maybe_compress() {
                    trace!(?k, "Compressed idl");
                }
            }
        })
    }

    pub fn is_idx_slopeyness_generated(&self) -> Result<bool, OperationError> {
        self.db.is_idx_slopeyness_generated()
    }

    pub fn get_idx_slope(&self, ikey: &IdxKey) -> Result<Option<IdxSlope>, OperationError> {
        self.db.get_idx_slope(ikey)
    }

    /// Index Slope Analysis. For the purpose of external modules you can consider this as a
    /// module that generates "weights" for each index that we have. Smaller values are faster
    /// indexes - larger values are more costly ones. This is not intended to yield perfect
    /// weights. The intent is to separate over obviously more effective indexes rather than
    /// to min-max the fine tuning of these. Consider name=foo vs class=*. name=foo will always
    /// be better than class=*, but comparing name=foo to spn=foo is "much over muchness" since
    /// both are really fast.
    pub fn analyse_idx_slopes(&mut self) -> Result<(), OperationError> {
        /*
         * Inside of this analysis there are two major factors we need to understand
         *
         * * What is the variation of idl lengths within an index?
         * * How man keys are stored in this index?
         *
         * Since we have the filter2idl threshold, we want to find "what is the smallest
         * and most unique index asap so we can exit faster". This allows us to avoid
         * loading larger most costly indexes that either have large idls, high variation
         * or few keys and are likely to miss and have to go out to disk.
         *
         * A few methods were proposed, but thanks to advice from Perri Boulton (psychology
         * researcher with a background in statistics), we were able to device a reasonable
         * approach.
         *
         * These are commented in line to help understand the process.
         */

        /*
         * Step 1 - we have an index like "idx_eq_member". It has data that looks somewhat
         * like:
         *
         *  key    | idl
         *  -------+------------
         *  uuid_a | [1, 2, 3, ...]
         *  -------+------------
         *  uuid_b | [4, 5, 6, ...]
         *
         * We need to collect this into a single vec of "how long is each idl". Since we have
         * each idl in the vec, the length of the vec is also the number of keys in the set.
         * This yields for us:
         *
         *   idx_eq_member: [4.0, 5.0, ...]
         * where each f64 value is the float representation of the length of idl.
         *
         * We then assemble these to a map so we have each idxkey and it's associated list
         * of idl lens.
         */

        let mut data: HashMap<IdxKey, Vec<f64>> = HashMap::new();
        self.idl_cache.iter_dirty().for_each(|(k, maybe_idl)| {
            if let Some(idl) = maybe_idl {
                let idl_len: u32 = idl.len().try_into().unwrap_or(u32::MAX);
                // Convert to something we can use.
                let idl_len = f64::from(idl_len);

                let kref = IdxKeyRef::new(&k.a, &k.i);
                if idl_len > 0.0 {
                    // It's worth looking at. Anything len 0 will be removed.
                    if let Some(lens) = data.get_mut(&kref as &dyn IdxKeyToRef) {
                        lens.push(idl_len)
                    } else {
                        data.insert(kref.as_key(), vec![idl_len]);
                    }
                }
            }
        });

        /*
        * So now for each of our sets:
        *
        *   idx_eq_member: [4.0, 5.0, ...]
        *   idx_eq_name  : [1.0, 1.0, 1.0, ...]
        *
        * To get the variability, we calculate the normal distribution of the set of values
        * and then using this variance we use the 1st deviation (~85%) value to assert that
        * 85% or more of the values in this set will be "equal or less" than this length.*
        *
        * So given say:
        *  [1.0, 1.0, 1.0, 1.0]
        * We know that the sd_1 will be 1.0. Given:
        *  [1.0, 1.0, 2.0, 3.0]
        * We know that it will be ~2.57 (mean 1.75 + sd of 0.82).
        *
        * The other factor is number of keys. This is thankfully easy! We have that from
        * vec.len().
        *
        * We can now calculate the index slope. Why is it a slope you ask? Because we
        * plot the data out on a graph, with "variability" on the y axis, and number of
        * keys on the x.
        *
        * Lets plot our data we just added.
        *
        *    |
        *  4 +
        *    |
        *  3 +
        *    |
        *  2 +           *  eq_member
        *    |
        *  1 +           *  eq_name
        *    |
        *    +--+--+--+--+--
        *       1  2  3  4
        *
        * Now, if we were to connect a line from (0,0) to each point we get a line with an angle.
        *
        *    |
        *  4 +
        *    |
        *  3 +
        *    |
        *  2 +           *  eq_member
        *    |
        *  1 +           *  eq_name
        *    |/---------/
        *    +--+--+--+--+--
        *       1  2  3  4

        *    |
        *  4 +
        *    |
        *  3 +
        *    |
        *  2 +           *  eq_member
        *    |        /--/
        *  1 +    /--/   *  eq_name
        *    |/--/
        *    +--+--+--+--+--
        *       1  2  3  4
        *
        * (Look it's ascii art, don't judge.).
        *
        * Point is that eq_member is "steeper" and eq_name is "shallower". This is what we call
        * the "slopeyness" aka the jank of the line, or more precisely, the angle.
        *
        * Now we need a way to numerically compare these lines. Since the points could be
        * anywhere on our graph:
        *
        *    |
        *  4 +  *
        *    |
        *  3 +         *
        *    |
        *  2 +     *
        *    |
        *  1 +           *
        *    |
        *    +--+--+--+--+--
        *       1  2  3  4
        *
        * While we can see what's obvious or best here, a computer has to know it. So we now
        * assume that these points construct a triangle, going through (0,0), (x, 0) and (x, y).
        *
        *
        *                Λ│
        *               ╱ │
        *              ╱  │
        *             ╱   │
        *            ╱    │
        *           ╱     │
        *          ╱      │
        *         ╱       │ sd_1
        *        ╱        │
        *       ╱         │
        *      ───────────┼
        *         nkeys
        *
        * Since this is right angled we can use arctan to work out the degrees of the line. This
        * gives us a value from 1.0 to 90.0 (We clamp to a minimum of 1.0, because we use 0 as "None"
        * in the NonZeroU8 type in filter.rs, which allows ZST optimisation)
        *
        * The problem is that we have to go from float to u8 - this means we lose decimal precision
        * in the conversion. To lessen this, we multiply by 2 to give some extra weight to each angle
        * to minimise this loss and then we convert.
        *
        * And there we have it! A slope factor of the index! A way to compare these sets quickly
        * at query optimisation time to minimise index access.
        */
        let slopes: HashMap<_, _> = data
            .into_iter()
            .filter_map(|(k, lens)| {
                let slope_factor = Self::calculate_sd_slope(&lens);
                if slope_factor == 0 || slope_factor == IdxSlope::MAX {
                    None
                } else {
                    Some((k, slope_factor))
                }
            })
            .collect();
        trace!(?slopes, "Generated slopes");
        // Write the data down
        self.db.store_idx_slope_analysis(&slopes)
    }

    fn calculate_sd_slope(data: &[f64]) -> IdxSlope {
        let (n_keys, sd_1) = if data.len() >= 2 {
            // We can only do SD on sets greater than 2
            let l: u32 = data.len().try_into().unwrap_or(u32::MAX);
            let c = f64::from(l);
            let mean = data.iter().take(u32::MAX as usize).sum::<f64>() / c;
            let variance: f64 = data
                .iter()
                .take(u32::MAX as usize)
                .map(|len| {
                    let delta = mean - len;
                    delta * delta
                })
                .sum::<f64>()
                / (c - 1.0);

            let sd = variance.sqrt();

            // This is saying ~85% of values will be at least this len or less.
            let sd_1 = mean + sd;
            (c, sd_1)
        } else if data.len() == 1 {
            (1.0, data[0])
        } else {
            // Can't resolve.
            return IdxSlope::MAX;
        };

        // Now we know sd_1 and number of keys. We can use this as a triangle to work out
        // the angle along the hypotenuse. We use this angle - or slope - to show which
        // elements have the smallest sd_1 and most keys available. Then because this
        // is bound between 0.0 -> 90.0, we "unfurl" this around a half circle by multiplying
        // by 2. This gives us a little more precision when we drop the decimal point.
        let sf = (sd_1 / n_keys).atan().to_degrees() * 2.8;

        // Now these are fractions, and we can't use those in u8, so we clamp the min/max values
        // that we expect to be yielded.
        let sf = sf.clamp(1.0, 254.0);
        if !sf.is_finite() {
            IdxSlope::MAX
        } else {
            // SAFETY
            // `sf` is clamped between 1.0 and 180.0 above, ensuring it is
            // always in range.
            unsafe { sf.to_int_unchecked::<IdxSlope>() }
        }
    }

    pub fn quarantine_entry(&self, id: u64) -> Result<(), OperationError> {
        self.db.quarantine_entry(id)
    }

    pub fn restore_quarantined(&self, id: u64) -> Result<(), OperationError> {
        self.db.restore_quarantined(id)
    }

    pub fn create_name2uuid(&self) -> Result<(), OperationError> {
        self.db.create_name2uuid()
    }

    pub fn write_name2uuid_add(
        &mut self,
        uuid: Uuid,
        add: BTreeSet<String>,
    ) -> Result<(), OperationError> {
        add.into_iter().for_each(|k| {
            let cache_key = NameCacheKey::Name2Uuid(k);
            let cache_value = NameCacheValue::U(uuid);
            self.name_cache.insert_dirty(cache_key, cache_value)
        });
        Ok(())
    }

    pub fn write_name2uuid_rem(&mut self, rem: BTreeSet<String>) -> Result<(), OperationError> {
        rem.into_iter().for_each(|k| {
            // why not just a for loop here...
            let cache_key = NameCacheKey::Name2Uuid(k);
            self.name_cache.remove_dirty(cache_key)
        });
        Ok(())
    }

    pub fn create_externalid2uuid(&self) -> Result<(), OperationError> {
        self.db.create_externalid2uuid()
    }

    pub fn write_externalid2uuid_add(
        &mut self,
        uuid: Uuid,
        add: String,
    ) -> Result<(), OperationError> {
        let cache_key = NameCacheKey::ExternalId2Uuid(add);
        let cache_value = NameCacheValue::U(uuid);
        self.name_cache.insert_dirty(cache_key, cache_value);
        Ok(())
    }

    pub fn write_externalid2uuid_rem(&mut self, rem: String) -> Result<(), OperationError> {
        let cache_key = NameCacheKey::ExternalId2Uuid(rem);
        self.name_cache.remove_dirty(cache_key);
        Ok(())
    }

    pub fn create_uuid2spn(&self) -> Result<(), OperationError> {
        self.db.create_uuid2spn()
    }

    pub fn write_uuid2spn(&mut self, uuid: Uuid, k: Option<Value>) -> Result<(), OperationError> {
        let cache_key = NameCacheKey::Uuid2Spn(uuid);
        match k {
            Some(v) => self
                .name_cache
                .insert_dirty(cache_key, NameCacheValue::S(Box::new(v))),
            None => self.name_cache.remove_dirty(cache_key),
        }
        Ok(())
    }

    pub fn create_uuid2rdn(&self) -> Result<(), OperationError> {
        self.db.create_uuid2rdn()
    }

    pub fn write_uuid2rdn(&mut self, uuid: Uuid, k: Option<String>) -> Result<(), OperationError> {
        let cache_key = NameCacheKey::Uuid2Rdn(uuid);
        match k {
            Some(s) => self
                .name_cache
                .insert_dirty(cache_key, NameCacheValue::R(s)),
            None => self.name_cache.remove_dirty(cache_key),
        }
        Ok(())
    }

    pub fn create_idx(&self, attr: Attribute, itype: IndexType) -> Result<(), OperationError> {
        // We don't need to affect this, so pass it down.
        self.db.create_idx(attr, itype)
    }

    /// ⚠️  - This function will destroy all indexes in the database.
    ///
    /// It should only be called internally by the backend in limited and
    /// specific situations.
    #[instrument(level = "trace", skip_all)]
    pub fn danger_purge_idxs(&mut self) -> Result<(), OperationError> {
        warn!("CLEARING CACHE");
        self.db.danger_purge_idxs().map(|()| {
            self.idl_cache.clear();
            self.name_cache.clear();
        })
    }

    /// ⚠️  - This function will destroy all entries in the database.
    ///
    /// It should only be called internally by the backend in limited and
    /// specific situations.
    #[instrument(level = "trace", skip_all)]
    pub fn danger_purge_id2entry(&mut self) -> Result<(), OperationError> {
        self.db.danger_purge_id2entry().map(|()| {
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

    pub fn set_db_ts_max(&mut self, ts: Duration) -> Result<(), OperationError> {
        *self.op_ts_max = Some(ts);
        self.db.set_db_ts_max(ts)
    }

    pub(crate) fn get_db_index_version(&self) -> Result<i64, OperationError> {
        self.db.get_db_index_version()
    }

    pub(crate) fn set_db_index_version(&self, v: i64) -> Result<(), OperationError> {
        self.db.set_db_index_version(v)
    }

    pub fn setup(&mut self) -> Result<(), OperationError> {
        self.db
            .setup()
            .and_then(|()| self.db.get_allids())
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
    pub fn new(cfg: &BackendConfig, vacuum: bool) -> Result<Self, OperationError> {
        let db = IdlSqlite::new(cfg, vacuum)?;

        // Autotune heuristic.
        let mut cache_size = cfg.arcsize.unwrap_or_else(|| {
            // Due to changes in concread, we can now scale this up! We now aim for 120%
            // of entries.
            db.get_allids_count()
                .map(|c| {
                    let tmpsize = ((c / 5) as usize) * 6;
                    // if our calculation's too small anyway, just set it to the minimum target
                    std::cmp::max(tmpsize, DEFAULT_CACHE_TARGET)
                })
                .unwrap_or(DEFAULT_CACHE_TARGET)
        });

        if cache_size < DEFAULT_CACHE_TARGET {
            admin_warn!(
                old = cache_size,
                new = DEFAULT_CACHE_TARGET,
                "Configured Arc Cache size too low, increasing..."
            );
            cache_size = DEFAULT_CACHE_TARGET; // this being above the log was an uncaught bug
        }

        let entry_cache = ARCacheBuilder::new()
            .set_expected_workload(
                cache_size,
                cfg.pool_size as usize,
                DEFAULT_CACHE_RMISS,
                DEFAULT_CACHE_WMISS,
                false,
            )
            .set_reader_quiesce(true)
            .build()
            .ok_or_else(|| {
                admin_error!("Failed to construct entry_cache");
                OperationError::InvalidState
            })?;
        // The idl cache should have smaller items, and is critical for fast searches
        // so we allow it to have a higher ratio of items relative to the entries.
        let idl_cache = ARCacheBuilder::new()
            .set_expected_workload(
                cache_size * DEFAULT_IDL_CACHE_RATIO,
                cfg.pool_size as usize,
                DEFAULT_CACHE_RMISS,
                DEFAULT_CACHE_WMISS,
                false,
            )
            .set_reader_quiesce(true)
            .build()
            .ok_or_else(|| {
                admin_error!("Failed to construct idl_cache");
                OperationError::InvalidState
            })?;

        let name_cache = ARCacheBuilder::new()
            .set_expected_workload(
                cache_size * DEFAULT_NAME_CACHE_RATIO,
                cfg.pool_size as usize,
                DEFAULT_CACHE_RMISS,
                DEFAULT_CACHE_WMISS,
                true,
            )
            .set_reader_quiesce(true)
            .build()
            .ok_or_else(|| {
                admin_error!("Failed to construct name_cache");
                OperationError::InvalidState
            })?;

        let allids = CowCell::new(IDLBitRange::new());

        let maxid = CowCell::new(0);

        let keyhandles = CowCell::new(HashMap::default());

        let op_ts_max = CowCell::new(None);

        Ok(IdlArcSqlite {
            db,
            entry_cache,
            idl_cache,
            name_cache,
            op_ts_max,
            allids,
            maxid,
            keyhandles,
        })
    }

    pub fn try_quiesce(&self) {
        self.entry_cache.try_quiesce();
        self.idl_cache.try_quiesce();
        self.name_cache.try_quiesce();
    }

    pub fn read(&self) -> Result<IdlArcSqliteReadTransaction, OperationError> {
        // IMPORTANT! Always take entrycache FIRST
        let entry_cache_read = self.entry_cache.read();
        let db_read = self.db.read()?;
        let idl_cache_read = self.idl_cache.read();
        let name_cache_read = self.name_cache.read();
        let allids_read = self.allids.read();

        Ok(IdlArcSqliteReadTransaction {
            db: db_read,
            entry_cache: entry_cache_read,
            idl_cache: idl_cache_read,
            name_cache: name_cache_read,
            allids: allids_read,
        })
    }

    pub fn write(&self) -> Result<IdlArcSqliteWriteTransaction, OperationError> {
        // IMPORTANT! Always take entrycache FIRST
        let entry_cache_write = self.entry_cache.write();
        let db_write = self.db.write()?;
        let idl_cache_write = self.idl_cache.write();
        let name_cache_write = self.name_cache.write();
        let op_ts_max_write = self.op_ts_max.write();
        let allids_write = self.allids.write();
        let maxid_write = self.maxid.write();
        let keyhandles_write = self.keyhandles.write();

        Ok(IdlArcSqliteWriteTransaction {
            db: db_write,
            entry_cache: entry_cache_write,
            idl_cache: idl_cache_write,
            name_cache: name_cache_write,
            op_ts_max: op_ts_max_write,
            allids: allids_write,
            maxid: maxid_write,
            keyhandles: keyhandles_write,
        })
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
