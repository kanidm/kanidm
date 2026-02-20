use crate::prelude::*;
use crate::valueset::{ValueSetDateTime, ValueSetEmailAddress, ValueSetIutf8, ValueSetMessage};
use kanidm_proto::v1::OutboundMessage;

impl QueryServerWriteTransaction<'_> {
    pub(crate) fn queue_message(
        &mut self,
        ident: &Identity,
        message: OutboundMessage,
        to_address: String,
    ) -> Result<(), OperationError> {
        let curtime_odt = self.get_curtime_odt();
        let delete_after_odt = curtime_odt + DEFAULT_MESSAGE_RETENTION;

        let mut e_msg: EntryInitNew = Entry::new();
        e_msg.set_ava_set(
            &Attribute::Class,
            ValueSetIutf8::new(EntryClass::OutboundMessage.into()),
        );
        e_msg.set_ava_set(&Attribute::SendAfter, ValueSetDateTime::new(curtime_odt));
        e_msg.set_ava_set(
            &Attribute::DeleteAfter,
            ValueSetDateTime::new(delete_after_odt),
        );
        e_msg.set_ava_set(&Attribute::MessageTemplate, ValueSetMessage::new(message));
        e_msg.set_ava_set(
            &Attribute::MailDestination,
            ValueSetEmailAddress::new(to_address),
        );

        self.impersonate_create(ident, vec![e_msg])
    }
}
