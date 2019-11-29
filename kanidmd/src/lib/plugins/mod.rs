use crate::audit::AuditScope;
use crate::entry::{Entry, EntryCommitted, EntryInvalid, EntryNew, EntryValid};
use crate::event::{CreateEvent, DeleteEvent, ModifyEvent};
use crate::server::{QueryServerReadTransaction, QueryServerWriteTransaction};
use kanidm_proto::v1::{ConsistencyError, OperationError};

#[macro_use]
mod macros;

mod attrunique;
mod base;
mod domain;
mod failure;
mod memberof;
mod protected;
mod recycle;
mod refint;
mod spn;

trait Plugin {
    fn id() -> &'static str;

    fn pre_create_transform(
        _au: &mut AuditScope,
        _qs: &mut QueryServerWriteTransaction,
        _cand: &mut Vec<Entry<EntryInvalid, EntryNew>>,
        _ce: &CreateEvent,
    ) -> Result<(), OperationError> {
        debug!(
            "plugin {} has an unimplemented pre_create_transform!",
            Self::id()
        );
        Err(OperationError::InvalidState)
    }

    fn pre_create(
        _au: &mut AuditScope,
        _qs: &mut QueryServerWriteTransaction,
        // List of what we will commit that is valid?
        _cand: &Vec<Entry<EntryValid, EntryNew>>,
        _ce: &CreateEvent,
    ) -> Result<(), OperationError> {
        debug!("plugin {} has an unimplemented pre_create!", Self::id());
        Err(OperationError::InvalidState)
    }

    fn post_create(
        _au: &mut AuditScope,
        _qs: &mut QueryServerWriteTransaction,
        // List of what we commited that was valid?
        _cand: &Vec<Entry<EntryValid, EntryCommitted>>,
        _ce: &CreateEvent,
    ) -> Result<(), OperationError> {
        debug!("plugin {} has an unimplemented post_create!", Self::id());
        Err(OperationError::InvalidState)
    }

    fn pre_modify(
        _au: &mut AuditScope,
        _qs: &mut QueryServerWriteTransaction,
        _cand: &mut Vec<Entry<EntryInvalid, EntryCommitted>>,
        _me: &ModifyEvent,
    ) -> Result<(), OperationError> {
        debug!("plugin {} has an unimplemented pre_modify!", Self::id());
        Err(OperationError::InvalidState)
    }

    fn post_modify(
        _au: &mut AuditScope,
        _qs: &mut QueryServerWriteTransaction,
        // List of what we modified that was valid?
        _pre_cand: &Vec<Entry<EntryValid, EntryCommitted>>,
        _cand: &Vec<Entry<EntryValid, EntryCommitted>>,
        _ce: &ModifyEvent,
    ) -> Result<(), OperationError> {
        debug!("plugin {} has an unimplemented post_modify!", Self::id());
        Err(OperationError::InvalidState)
    }

    fn pre_delete(
        _au: &mut AuditScope,
        _qs: &mut QueryServerWriteTransaction,
        _cand: &mut Vec<Entry<EntryInvalid, EntryCommitted>>,
        _de: &DeleteEvent,
    ) -> Result<(), OperationError> {
        debug!("plugin {} has an unimplemented pre_delete!", Self::id());
        Err(OperationError::InvalidState)
    }

    fn post_delete(
        _au: &mut AuditScope,
        _qs: &mut QueryServerWriteTransaction,
        // List of what we delete that was valid?
        _cand: &Vec<Entry<EntryValid, EntryCommitted>>,
        _ce: &DeleteEvent,
    ) -> Result<(), OperationError> {
        debug!("plugin {} has an unimplemented post_delete!", Self::id());
        Err(OperationError::InvalidState)
    }

    fn verify(
        _au: &mut AuditScope,
        _qs: &QueryServerReadTransaction,
    ) -> Vec<Result<(), ConsistencyError>> {
        debug!("plugin {} has an unimplemented verify!", Self::id());
        vec![Err(ConsistencyError::Unknown)]
    }
}

pub struct Plugins {}

// Should this be a function instead, to allow inlining and better debug?
// Probably not - I use this to generate the audit scope of the plugin from the type
// and the ty can't really be "passed" to the fns with fn pointer stuff.

macro_rules! run_pre_create_transform_plugin {
    (
        $au:ident,
        $qs:ident,
        $cand:ident,
        $ce:ident,
        $target_plugin:ty
    ) => {{
        let mut audit_scope = AuditScope::new(<$target_plugin>::id());
        let r = audit_segment!(audit_scope, || <$target_plugin>::pre_create_transform(
            &mut audit_scope,
            $qs,
            $cand,
            $ce,
        ));
        $au.append_scope(audit_scope);
        r
    }};
}

macro_rules! run_pre_create_plugin {
    (
        $au:ident,
        $qs:ident,
        $cand:ident,
        $ce:ident,
        $target_plugin:ty
    ) => {{
        let mut audit_scope = AuditScope::new(<$target_plugin>::id());
        let r = audit_segment!(audit_scope, || <$target_plugin>::pre_create(
            &mut audit_scope,
            $qs,
            $cand,
            $ce,
        ));
        $au.append_scope(audit_scope);
        r
    }};
}

macro_rules! run_post_create_plugin {
    (
        $au:ident,
        $qs:ident,
        $cand:ident,
        $ce:ident,
        $target_plugin:ty
    ) => {{
        let mut audit_scope = AuditScope::new(<$target_plugin>::id());
        let r = audit_segment!(audit_scope, || <$target_plugin>::post_create(
            &mut audit_scope,
            $qs,
            $cand,
            $ce,
        ));
        $au.append_scope(audit_scope);
        r
    }};
}

macro_rules! run_pre_modify_plugin {
    (
        $au:ident,
        $qs:ident,
        $cand:ident,
        $ce:ident,
        $target_plugin:ty
    ) => {{
        let mut audit_scope = AuditScope::new(<$target_plugin>::id());
        let r = audit_segment!(audit_scope, || <$target_plugin>::pre_modify(
            &mut audit_scope,
            $qs,
            $cand,
            $ce
        ));
        $au.append_scope(audit_scope);
        r
    }};
}

macro_rules! run_post_modify_plugin {
    (
        $au:ident,
        $qs:ident,
        $pre_cand:ident,
        $cand:ident,
        $ce:ident,
        $target_plugin:ty
    ) => {{
        let mut audit_scope = AuditScope::new(<$target_plugin>::id());
        let r = audit_segment!(audit_scope, || <$target_plugin>::post_modify(
            &mut audit_scope,
            $qs,
            $pre_cand,
            $cand,
            $ce
        ));
        $au.append_scope(audit_scope);
        r
    }};
}

macro_rules! run_pre_delete_plugin {
    (
        $au:ident,
        $qs:ident,
        $cand:ident,
        $ce:ident,
        $target_plugin:ty
    ) => {{
        let mut audit_scope = AuditScope::new(<$target_plugin>::id());
        let r = audit_segment!(audit_scope, || <$target_plugin>::pre_delete(
            &mut audit_scope,
            $qs,
            $cand,
            $ce,
        ));
        $au.append_scope(audit_scope);
        r
    }};
}

macro_rules! run_post_delete_plugin {
    (
        $au:ident,
        $qs:ident,
        $cand:ident,
        $ce:ident,
        $target_plugin:ty
    ) => {{
        let mut audit_scope = AuditScope::new(<$target_plugin>::id());
        let r = audit_segment!(audit_scope, || <$target_plugin>::post_delete(
            &mut audit_scope,
            $qs,
            $cand,
            $ce,
        ));
        $au.append_scope(audit_scope);
        r
    }};
}

macro_rules! run_verify_plugin {
    (
        $au:ident,
        $qs:ident,
        $results:expr,
        $target_plugin:ty
    ) => {{
        let mut audit_scope = AuditScope::new(<$target_plugin>::id());
        let mut r = audit_segment!(audit_scope, || <$target_plugin>::verify(
            &mut audit_scope,
            $qs,
        ));
        $results.append(&mut r);
        $au.append_scope(audit_scope);
    }};
}

impl Plugins {
    pub fn run_pre_create_transform(
        au: &mut AuditScope,
        qs: &mut QueryServerWriteTransaction,
        cand: &mut Vec<Entry<EntryInvalid, EntryNew>>,
        ce: &CreateEvent,
    ) -> Result<(), OperationError> {
        audit_segment!(au, || {
            let res = run_pre_create_transform_plugin!(au, qs, cand, ce, base::Base)
                .and_then(|_| run_pre_create_transform_plugin!(au, qs, cand, ce, domain::Domain))
                .and_then(|_| run_pre_create_transform_plugin!(au, qs, cand, ce, spn::Spn))
                .and_then(|_| {
                    run_pre_create_transform_plugin!(au, qs, cand, ce, attrunique::AttrUnique)
                });
            res
        })
    }

    pub fn run_pre_create(
        au: &mut AuditScope,
        qs: &mut QueryServerWriteTransaction,
        cand: &Vec<Entry<EntryValid, EntryNew>>,
        ce: &CreateEvent,
    ) -> Result<(), OperationError> {
        audit_segment!(au, || {
            let res = run_pre_create_plugin!(au, qs, cand, ce, protected::Protected);

            res
        })
    }

    pub fn run_post_create(
        au: &mut AuditScope,
        qs: &mut QueryServerWriteTransaction,
        cand: &Vec<Entry<EntryValid, EntryCommitted>>,
        ce: &CreateEvent,
    ) -> Result<(), OperationError> {
        audit_segment!(au, || {
            let res = run_post_create_plugin!(au, qs, cand, ce, refint::ReferentialIntegrity)
                .and_then(|_| run_post_create_plugin!(au, qs, cand, ce, memberof::MemberOf));

            res
        })
    }

    pub fn run_pre_modify(
        au: &mut AuditScope,
        qs: &mut QueryServerWriteTransaction,
        cand: &mut Vec<Entry<EntryInvalid, EntryCommitted>>,
        me: &ModifyEvent,
    ) -> Result<(), OperationError> {
        audit_segment!(au, || {
            let res = run_pre_modify_plugin!(au, qs, cand, me, protected::Protected)
                .and_then(|_| run_pre_modify_plugin!(au, qs, cand, me, base::Base))
                .and_then(|_| run_pre_modify_plugin!(au, qs, cand, me, spn::Spn))
                .and_then(|_| run_pre_modify_plugin!(au, qs, cand, me, attrunique::AttrUnique));

            res
        })
    }

    pub fn run_post_modify(
        au: &mut AuditScope,
        qs: &mut QueryServerWriteTransaction,
        pre_cand: &Vec<Entry<EntryValid, EntryCommitted>>,
        cand: &Vec<Entry<EntryValid, EntryCommitted>>,
        me: &ModifyEvent,
    ) -> Result<(), OperationError> {
        audit_segment!(au, || {
            let res =
                run_post_modify_plugin!(au, qs, pre_cand, cand, me, refint::ReferentialIntegrity)
                    .and_then(|_| {
                        run_post_modify_plugin!(au, qs, pre_cand, cand, me, memberof::MemberOf)
                    })
                    .and_then(|_| run_post_modify_plugin!(au, qs, pre_cand, cand, me, spn::Spn));
            res
        })
    }

    pub fn run_pre_delete(
        au: &mut AuditScope,
        qs: &mut QueryServerWriteTransaction,
        cand: &mut Vec<Entry<EntryInvalid, EntryCommitted>>,
        de: &DeleteEvent,
    ) -> Result<(), OperationError> {
        audit_segment!(au, || {
            let res = run_pre_delete_plugin!(au, qs, cand, de, protected::Protected);
            res
        })
    }

    pub fn run_post_delete(
        au: &mut AuditScope,
        qs: &mut QueryServerWriteTransaction,
        cand: &Vec<Entry<EntryValid, EntryCommitted>>,
        de: &DeleteEvent,
    ) -> Result<(), OperationError> {
        audit_segment!(au, || {
            let res = run_post_delete_plugin!(au, qs, cand, de, refint::ReferentialIntegrity)
                .and_then(|_| run_post_delete_plugin!(au, qs, cand, de, memberof::MemberOf));

            res
        })
    }

    pub fn run_verify(
        au: &mut AuditScope,
        qs: &QueryServerReadTransaction,
    ) -> Vec<Result<(), ConsistencyError>> {
        let mut results = Vec::new();
        run_verify_plugin!(au, qs, &mut results, base::Base);
        run_verify_plugin!(au, qs, &mut results, attrunique::AttrUnique);
        run_verify_plugin!(au, qs, &mut results, refint::ReferentialIntegrity);
        run_verify_plugin!(au, qs, &mut results, memberof::MemberOf);
        run_verify_plugin!(au, qs, &mut results, spn::Spn);
        results
    }
}
