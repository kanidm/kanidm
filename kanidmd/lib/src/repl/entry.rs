use super::cid::Cid;
use crate::entry::Eattrs;
use crate::prelude::*;
use crate::schema::SchemaTransaction;
// use crate::valueset;

#[derive(Debug, Clone)]
pub struct EntryChangeState {}

impl EntryChangeState {
    pub fn new(_cid: Cid, _attrs: &Eattrs, _schema: &dyn SchemaTransaction) -> Self {
        todo!();
    }

    pub fn new_without_schema(_cid: Cid, _attrs: &Eattrs) -> Self {
        todo!();
    }

    pub fn change_ava(&mut self, _cid: &Cid, _attr: &str) {
        todo!();
    }

    pub fn recycled(&mut self, _cid: &Cid) {
        todo!();
    }

    pub fn revive(&mut self, _cid: &Cid) {
        todo!();
    }

    pub fn tombstone(&mut self, _cid: &Cid, _attrs: &Eattrs) {
        todo!();
    }

    pub fn contains_tail_cid(&self, _cid: &Cid) -> bool {
        todo!();
        /*
        if let Some(tail_cid) = self.changes.keys().next_back() {
            if tail_cid == cid {
                return true;
            }
        };
        false
        */
    }

    pub fn cid_iter(&self) -> impl Iterator<Item = &Cid> {
        // self.changes.keys()
        None.iter()
    }

    pub fn is_live(&self) -> bool {
        todo!()
    }

    #[instrument(level = "trace", name = "verify", skip_all)]
    pub fn verify(
        &self,
        _schema: &dyn SchemaTransaction,
        _expected_attrs: &Eattrs,
        _entry_id: u64,
        _results: &mut Vec<Result<(), ConsistencyError>>,
    ) {
        todo!();
    }
}
