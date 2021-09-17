//! plugins allow an `Event` to be inspected and transformed during the write
//! paths of the server. This allows richer expression of some concepts and
//! helps to ensure that data is always in specific known states within the
//! `QueryServer`

use crate::entry::{Entry, EntryCommitted, EntryInvalid, EntryNew, EntrySealed};
use crate::event::{CreateEvent, DeleteEvent, ModifyEvent};
use crate::prelude::*;
use kanidm_proto::v1::{ConsistencyError, OperationError};
use std::sync::Arc;
use tracing::trace_span;

mod attrunique;
mod base;
mod domain;
mod failure;
mod gidnumber;
mod memberof;
mod oauth2;
mod password_import;
mod protected;
mod recycle;
mod refint;
mod spn;

trait Plugin {
    fn id() -> &'static str;

    fn pre_create_transform(
        au: &mut AuditScope,
        _qs: &QueryServerWriteTransaction,
        _cand: &mut Vec<Entry<EntryInvalid, EntryNew>>,
        _ce: &CreateEvent,
    ) -> Result<(), OperationError> {
        admin_error!(
            "plugin {} has an unimplemented pre_create_transform!",
            Self::id()
        );
        Err(OperationError::InvalidState)
    }

    fn pre_create(
        au: &mut AuditScope,
        _qs: &QueryServerWriteTransaction,
        // List of what we will commit that is valid?
        _cand: &[Entry<EntrySealed, EntryNew>],
        _ce: &CreateEvent,
    ) -> Result<(), OperationError> {
        admin_error!("plugin {} has an unimplemented pre_create!", Self::id());
        Err(OperationError::InvalidState)
    }

    fn post_create(
        au: &mut AuditScope,
        _qs: &QueryServerWriteTransaction,
        // List of what we commited that was valid?
        _cand: &[Entry<EntrySealed, EntryCommitted>],
        _ce: &CreateEvent,
    ) -> Result<(), OperationError> {
        admin_error!("plugin {} has an unimplemented post_create!", Self::id());
        Err(OperationError::InvalidState)
    }

    fn pre_modify(
        au: &mut AuditScope,
        _qs: &QueryServerWriteTransaction,
        _cand: &mut Vec<Entry<EntryInvalid, EntryCommitted>>,
        _me: &ModifyEvent,
    ) -> Result<(), OperationError> {
        admin_error!("plugin {} has an unimplemented pre_modify!", Self::id());
        Err(OperationError::InvalidState)
    }

    fn post_modify(
        au: &mut AuditScope,
        _qs: &QueryServerWriteTransaction,
        // List of what we modified that was valid?
        _pre_cand: &[Arc<Entry<EntrySealed, EntryCommitted>>],
        _cand: &[Entry<EntrySealed, EntryCommitted>],
        _ce: &ModifyEvent,
    ) -> Result<(), OperationError> {
        admin_error!("plugin {} has an unimplemented post_modify!", Self::id());
        Err(OperationError::InvalidState)
    }

    fn pre_delete(
        au: &mut AuditScope,
        _qs: &QueryServerWriteTransaction,
        _cand: &mut Vec<Entry<EntryInvalid, EntryCommitted>>,
        _de: &DeleteEvent,
    ) -> Result<(), OperationError> {
        admin_error!("plugin {} has an unimplemented pre_delete!", Self::id());
        Err(OperationError::InvalidState)
    }

    fn post_delete(
        au: &mut AuditScope,
        _qs: &QueryServerWriteTransaction,
        // List of what we delete that was valid?
        _cand: &[Entry<EntrySealed, EntryCommitted>],
        _ce: &DeleteEvent,
    ) -> Result<(), OperationError> {
        admin_error!("plugin {} has an unimplemented post_delete!", Self::id());
        Err(OperationError::InvalidState)
    }

    fn verify(
        au: &mut AuditScope,
        _qs: &QueryServerReadTransaction,
    ) -> Vec<Result<(), ConsistencyError>> {
        admin_error!("plugin {} has an unimplemented verify!", Self::id());
        vec![Err(ConsistencyError::Unknown)]
    }
}

pub struct Plugins {}

macro_rules! run_verify_plugin {
    (
        $au:ident,
        $qs:ident,
        $results:expr,
        $target_plugin:ty
    ) => {{
        let mut r = <$target_plugin>::verify($au, $qs);
        $results.append(&mut r);
    }};
}

impl Plugins {
    pub fn run_pre_create_transform(
        au: &mut AuditScope,
        qs: &QueryServerWriteTransaction,
        cand: &mut Vec<Entry<EntryInvalid, EntryNew>>,
        ce: &CreateEvent,
    ) -> Result<(), OperationError> {
        spanned!("plugins::run_pre_create_transform", {
            base::Base::pre_create_transform(au, qs, cand, ce)
                .and_then(|_| {
                    password_import::PasswordImport::pre_create_transform(au, qs, cand, ce)
                })
                .and_then(|_| oauth2::Oauth2Secrets::pre_create_transform(au, qs, cand, ce))
                .and_then(|_| gidnumber::GidNumber::pre_create_transform(au, qs, cand, ce))
                .and_then(|_| domain::Domain::pre_create_transform(au, qs, cand, ce))
                .and_then(|_| spn::Spn::pre_create_transform(au, qs, cand, ce))
                // Should always be last
                .and_then(|_| attrunique::AttrUnique::pre_create_transform(au, qs, cand, ce))
        })
    }

    pub fn run_pre_create(
        au: &mut AuditScope,
        qs: &QueryServerWriteTransaction,
        cand: &[Entry<EntrySealed, EntryNew>],
        ce: &CreateEvent,
    ) -> Result<(), OperationError> {
        spanned!("plugins::run_pre_create", {
            protected::Protected::pre_create(au, qs, cand, ce)
        })
    }

    pub fn run_post_create(
        au: &mut AuditScope,
        qs: &QueryServerWriteTransaction,
        cand: &[Entry<EntrySealed, EntryCommitted>],
        ce: &CreateEvent,
    ) -> Result<(), OperationError> {
        spanned!("plugins::run_post_create", {
            refint::ReferentialIntegrity::post_create(au, qs, cand, ce)
                .and_then(|_| memberof::MemberOf::post_create(au, qs, cand, ce))
        })
    }

    pub fn run_pre_modify(
        au: &mut AuditScope,
        qs: &QueryServerWriteTransaction,
        cand: &mut Vec<Entry<EntryInvalid, EntryCommitted>>,
        me: &ModifyEvent,
    ) -> Result<(), OperationError> {
        spanned!("plugins::run_pre_modify", {
            protected::Protected::pre_modify(au, qs, cand, me)
                .and_then(|_| base::Base::pre_modify(au, qs, cand, me))
                .and_then(|_| password_import::PasswordImport::pre_modify(au, qs, cand, me))
                .and_then(|_| oauth2::Oauth2Secrets::pre_modify(au, qs, cand, me))
                .and_then(|_| gidnumber::GidNumber::pre_modify(au, qs, cand, me))
                .and_then(|_| spn::Spn::pre_modify(au, qs, cand, me))
                // attr unique should always be last
                .and_then(|_| attrunique::AttrUnique::pre_modify(au, qs, cand, me))
        })
    }

    pub fn run_post_modify(
        au: &mut AuditScope,
        qs: &QueryServerWriteTransaction,
        pre_cand: &[Arc<Entry<EntrySealed, EntryCommitted>>],
        cand: &[Entry<EntrySealed, EntryCommitted>],
        me: &ModifyEvent,
    ) -> Result<(), OperationError> {
        spanned!("plugins::run_post_modify", {
            refint::ReferentialIntegrity::post_modify(au, qs, pre_cand, cand, me)
                .and_then(|_| memberof::MemberOf::post_modify(au, qs, pre_cand, cand, me))
                .and_then(|_| spn::Spn::post_modify(au, qs, pre_cand, cand, me))
        })
    }

    pub fn run_pre_delete(
        au: &mut AuditScope,
        qs: &QueryServerWriteTransaction,
        cand: &mut Vec<Entry<EntryInvalid, EntryCommitted>>,
        de: &DeleteEvent,
    ) -> Result<(), OperationError> {
        spanned!("plugins::run_pre_delete", {
            protected::Protected::pre_delete(au, qs, cand, de)
        })
    }

    pub fn run_post_delete(
        au: &mut AuditScope,
        qs: &QueryServerWriteTransaction,
        cand: &[Entry<EntrySealed, EntryCommitted>],
        de: &DeleteEvent,
    ) -> Result<(), OperationError> {
        spanned!("plugins::run_post_delete", {
            refint::ReferentialIntegrity::post_delete(au, qs, cand, de)
                .and_then(|_| memberof::MemberOf::post_delete(au, qs, cand, de))
        })
    }

    pub fn run_verify(
        au: &mut AuditScope,
        qs: &QueryServerReadTransaction,
    ) -> Vec<Result<(), ConsistencyError>> {
        let _entered = trace_span!("plugins::run_verify").entered();
        spanned!("plugins::run_verify", {
            let mut results = Vec::new();
            run_verify_plugin!(au, qs, &mut results, base::Base);
            run_verify_plugin!(au, qs, &mut results, attrunique::AttrUnique);
            run_verify_plugin!(au, qs, &mut results, refint::ReferentialIntegrity);
            run_verify_plugin!(au, qs, &mut results, memberof::MemberOf);
            run_verify_plugin!(au, qs, &mut results, spn::Spn);
            results
        })
    }
}
