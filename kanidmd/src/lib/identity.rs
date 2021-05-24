// Contains a structure representing the current authenticated
// identity (or anonymous, or admin, both of which are in mem).

#[derive(Debug, Clone)]
/// Limits on the resources a single event can consume. These are defined per-event
/// as they are derived from the userAuthToken based on that individual session
pub(crate) struct Limits {
    pub unindexed_allow: bool,
    pub search_max_results: usize,
    pub search_max_filter_test: usize,
    pub filter_max_elements: usize,
}

impl Limits {
    pub fn unlimited() -> Self {
        Limits {
            unindexed_allow: true,
            search_max_results: usize::MAX,
            search_max_filter_test: usize::MAX,
            filter_max_elements: usize::MAX,
        }
    }

    // From a userauthtoken
    pub fn from_uat(uat: &UserAuthToken) -> Self {
        Limits {
            unindexed_allow: uat.lim_uidx,
            search_max_results: uat.lim_rmax,
            search_max_filter_test: uat.lim_pmax,
            filter_max_elements: uat.lim_fmax,
        }
    }
}

pub struct IdentUser {
    entry: Entry<EntrySealed, EntryCommitted>,
    // IpAddr?
    // Other metadata?
}

pub enum IdentType {
    User(IdentUser),
    Internal,
}

#[derive(Debug, Clone, PartialEq, Hash, Ord, PartialOrd, Eq)]
pub enum IdentityId {
    // Time stamp of the originating event.
    // The uuid of the originiating user
    User(Uuid),
    Internal,
}

impl From<&IdentType> for IdentityId {
    fn from(idt: &IdentType) -> Self {
        match idt {
            IdentType::Internal => IdentityId::Internal,
            IdentType::User(e) => IdentityId::User(*e.get_uuid()),
        }
    }
}


pub struct Identity {
    pub ident: IdentType,
    pub(crate) limits: Limits,
}

impl std::fmt::Display for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match &self.ident {
            IdentType::Internal => write!(f, "Internal"),
            IdentType::User(e) => {
                let nv = e.get_uuid2spn();
                write!(
                    f,
                    "User( {}, {} ) ",
                    nv.to_proto_string_clone(),
                    e.get_uuid().to_hyphenated_ref()
                )
            }
        }
    }
}

impl Identity {
    pub fn from_ro_uat(
        audit: &mut AuditScope,
        qs: &QueryServerReadTransaction,
        uat: Option<&UserAuthToken>,
    ) -> Result<Self, OperationError> {
        ltrace!(audit, "from_ro_uat -> {:?}", uat);
        let uat = uat.ok_or(OperationError::NotAuthenticated)?;
        /*
        let u = Uuid::parse_str(uat.uuid.as_str()).map_err(|_| {
            ladmin_error!(audit, "from_ro_uat invalid uat uuid");
            OperationError::InvalidUuid
        })?;
        */

        if time::OffsetDateTime::unix_epoch() + qs.ts >= uat.expiry {
            lsecurity!(audit, "Invalid Session UAT");
            return Err(OperationError::SessionExpired);
        }

        let e = qs.internal_search_uuid(audit, &uat.uuid).map_err(|e| {
            ladmin_error!(audit, "from_ro_uat failed {:?}", e);
            e
        })?;
        // TODO #64: Now apply claims from the uat into the Entry
        // to allow filtering.

        // TODO #59: If the account is expiredy, do not allow the event
        // to proceed

        let limits = Limits::from_uat(uat);
        Ok(Event {
            origin: IdentType::User(e),
            limits,
        })
    }

    pub fn from_rw_uat(
        audit: &mut AuditScope,
        qs: &QueryServerWriteTransaction,
        uat: Option<&UserAuthToken>,
    ) -> Result<Self, OperationError> {
        ltrace!(audit, "from_rw_uat -> {:?}", uat);
        let uat = uat.ok_or(OperationError::NotAuthenticated)?;
        /*
        let u = Uuid::parse_str(uat.uuid.as_str()).map_err(|_| {
            ladmin_error!(audit, "from_rw_uat invalid uat uuid");
            OperationError::InvalidUuid
        })?;
        */

        if time::OffsetDateTime::unix_epoch() + qs.ts >= uat.expiry {
            lsecurity!(audit, "Invalid Session UAT");
            return Err(OperationError::SessionExpired);
        }

        let e = qs.internal_search_uuid(audit, &uat.uuid).map_err(|e| {
            ladmin_error!(audit, "from_rw_uat failed {:?}", e);
            e
        })?;
        // TODO #64: Now apply claims from the uat into the Entry
        // to allow filtering.

        // TODO #59: If the account is expiredy, do not allow the event
        // to proceed

        let limits = Limits::from_uat(uat);
        Ok(Event {
            origin: IdentType::User(e),
            limits,
        })
    }

    pub fn from_internal() -> Self {
        Identity {
            origin: IdentType::Internal,
            limits: Limits::unlimited(),
        }
    }

    #[cfg(test)]
    pub fn from_impersonate_entry(e: Entry<EntrySealed, EntryCommitted>) -> Self {
        Event {
            origin: IdentType::User(e),
            limits: Limits::unlimited(),
        }
    }

    #[cfg(test)]
    pub unsafe fn from_impersonate_entry_ser(e: &str) -> Self {
        let ei: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(e);
        Self::from_impersonate_entry(ei.into_sealed_committed())
    }

    pub fn from_impersonate(ident: &Self) -> Self {
        // TODO #64 ?: In the future, we could change some of this data
        // to reflect the fact we are infact impersonating the action
        // rather than the user explicitly requesting it. Could matter
        // to audits and logs to determine what happened.
        ident.clone()
    }

    pub fn is_internal(&self) -> bool {
        matches!(self.origin, IdentType::Internal)
    }

    pub fn get_uuid(&self) -> Option<Uuid> {
        match &self.origin {
            IdentType::Internal => None,
            IdentType::User(e) => Some(*e.get_uuid()),
        }
    }

    pub fn get_event_origin_id(&self) -> EventOriginId {
        IdentType::from(&self.origin)
    }
}
