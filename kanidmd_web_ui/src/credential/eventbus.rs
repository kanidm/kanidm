use std::collections::HashSet;

use kanidm_proto::v1::CUStatus;
use serde::{Deserialize, Serialize};
use yew_agent::{HandlerId, Public, Worker, WorkerLink};

#[derive(Serialize, Deserialize, Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum EventBusMsg {
    UpdateStatus { status: CUStatus },
    Error { emsg: String, kopid: Option<String> },
}

pub struct EventBus {
    link: WorkerLink<EventBus>,
    subscribers: HashSet<HandlerId>,
}

impl Worker for EventBus {
    type Input = EventBusMsg;
    type Message = ();
    type Output = EventBusMsg;
    type Reach = Public<Self>;

    fn create(link: WorkerLink<Self>) -> Self {
        Self {
            link,
            subscribers: HashSet::new(),
        }
    }

    fn update(&mut self, _msg: Self::Message) {}

    fn handle_input(&mut self, msg: Self::Input, _id: HandlerId) {
        for sub in self.subscribers.iter() {
            self.link.respond(*sub, msg.clone());
        }
    }

    fn connected(&mut self, id: HandlerId) {
        self.subscribers.insert(id);
    }

    fn disconnected(&mut self, id: HandlerId) {
        self.subscribers.remove(&id);
    }
}
