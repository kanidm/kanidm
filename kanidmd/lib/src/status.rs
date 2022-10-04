//! An actor that shows the servers current status and statistics. (TODO).

use uuid::Uuid;

use crate::prelude::*;

pub struct StatusRequestEvent {
    pub eventid: Uuid,
}

pub struct StatusActor {}

impl StatusActor {
    pub fn start() -> &'static Self {
        let x = Box::new(StatusActor {});

        let x_ptr = Box::into_raw(x);
        unsafe { &(*x_ptr) }
    }

    pub async fn handle_request(&self, _event: StatusRequestEvent) -> bool {
        admin_info!("status handler complete");
        true
    }
}
