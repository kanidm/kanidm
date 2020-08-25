use actix::prelude::*;

pub struct ServerCtx {
    system: System,
}

impl ServerCtx {
    pub fn new(
        system: System,
    ) -> Self {
        ServerCtx {
            system,
        }
    }

    pub fn current(&self) -> System {
        self.system.clone()
    }

    #[allow(clippy::expect_used)]
    pub fn stop(self) {
        // stop the actix system
        self.system.stop();
    }
}
