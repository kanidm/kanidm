use crate::prelude::*;
use kanidm_proto::v1::OperationError;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub(crate) struct Application {
    pub name: String,
    pub uuid: Uuid,
}

impl Application {
    pub(crate) fn try_from_entry_ro(
        value: &Entry<EntrySealed, EntryCommitted>,
        _qs: &mut QueryServerReadTransaction,
    ) -> Result<Self, OperationError> {
        if !value.attribute_equality(Attribute::Class, &EntryClass::Application.to_partialvalue()) {
            return Err(OperationError::InvalidAccountState(
                "Missing class: application".to_string(),
            ));
        }

        let name = value
            .get_ava_single_iname(Attribute::Name)
            .map(|s| s.to_string())
            .ok_or_else(|| {
                OperationError::InvalidAccountState(format!(
                    "Missing attribute: {}",
                    Attribute::Name
                ))
            })?;

        let uuid = value.get_uuid();

        Ok(Application { name, uuid })
    }
}
