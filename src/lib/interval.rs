use actix::prelude::*;
use std::time::Duration;

use constants::PURGE_TIMEOUT;
use event::PurgeEvent;
use server::QueryServer;

pub struct IntervalActor {
    // Store any addresses we require
    server: actix::Addr<QueryServer>,
}

impl IntervalActor {
    pub fn new(server: actix::Addr<QueryServer>) -> Self {
        IntervalActor { server: server }
    }

    // Define new events here
    fn purge_tombstones(&mut self) {
        // Make a purge request ...
        let pe = PurgeEvent::new();
        self.server.do_send(pe)
    }
}

impl Actor for IntervalActor {
    type Context = actix::Context<Self>;

    fn started(&mut self, ctx: &mut Self::Context) {
        ctx.run_interval(Duration::from_secs(PURGE_TIMEOUT), move |act, _ctx| {
            act.purge_tombstones();
        });
    }
}
