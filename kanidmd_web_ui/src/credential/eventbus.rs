use serde::{Deserialize, Serialize};
use std::collections::HashSet;

use yew_agent::{Agent, AgentLink, Context, HandlerId};

use kanidm_proto::v1::CUStatus;

#[derive(Serialize, Deserialize, Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum EventBusMsg {
    UpdateStatus { status: CUStatus },
    Error { emsg: String, kopid: Option<String> },
}

pub struct EventBus {
    link: AgentLink<EventBus>,
    subscribers: HashSet<HandlerId>,
}

impl Agent for EventBus {
    type Reach = Context<Self>;
    type Message = ();
    type Input = EventBusMsg;
    type Output = EventBusMsg;

    fn create(link: AgentLink<Self>) -> Self {
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
