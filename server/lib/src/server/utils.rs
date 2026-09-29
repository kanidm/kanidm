use crate::{
    prelude::*,
    valueset::{ValueSetDateTime, ValueSetEmailAddress, ValueSetIutf8, ValueSetMessage},
};
use kanidm_proto::v1::OutboundMessage;

impl QueryServerWriteTransaction<'_> {
    pub(crate) fn queue_message(
        &mut self,
        ident: &Identity,
        message: OutboundMessage,
        to_address: String,
    ) -> Result<Uuid, OperationError> {
        let curtime_odt = self.get_curtime_odt();
        let delete_after_odt = curtime_odt + DEFAULT_MESSAGE_RETENTION;

        let message_uuid = Uuid::new_v4();

        let e_msg = EntryInitNew::from_iter([
            (
                Attribute::Class,
                ValueSetIutf8::new(EntryClass::OutboundMessage.into()) as ValueSet,
            ),
            (Attribute::Uuid, ValueSetUuid::new(message_uuid)),
            (Attribute::SendAfter, ValueSetDateTime::new(curtime_odt)),
            (
                Attribute::DeleteAfter,
                ValueSetDateTime::new(delete_after_odt),
            ),
            (Attribute::MessageTemplate, ValueSetMessage::new(message)),
            (
                Attribute::MailDestination,
                ValueSetEmailAddress::new(to_address),
            ),
        ]);

        self.impersonate_create(ident, vec![e_msg]).map(|()| {
            debug!(?message_uuid, "Queued");
            message_uuid
        })
    }
}
