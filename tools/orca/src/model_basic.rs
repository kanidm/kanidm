use crate::model::{
    Transition,
    TransitionAction,
    TransitionResult,
    ActorModel
};

enum State {
    Unauthenticated,
    Authenticated,
}

pub struct ActorBasic {
    state: State,
}

impl ActorBasic {
    pub fn new() -> Self {
        ActorBasic {
            state: State::Unauthenticated
        }
    }
}

impl ActorModel for ActorBasic {
    fn next_transition(&mut self) -> Transition {
        match self.state {
            State::Unauthenticated => {
                Transition {
                    delay: None,
                    action: TransitionAction::Login
                }
            }
            State::Authenticated => {
                Transition {
                    delay: None,
                    action: TransitionAction::Logout
                }
            }
        }
    }

    fn next_state(&mut self, result: TransitionResult) {
        // Is this a design flaw? We probably need to know what the state was that we
        // requested to move to?
        match (&self.state, result) {
            (State::Unauthenticated, TransitionResult::Ok) => {
                self.state = State::Authenticated;
            }
            (State::Unauthenticated, TransitionResult::Error) => {
                self.state = State::Unauthenticated;
            }
            (State::Authenticated, TransitionResult::Ok) => {
                self.state = State::Unauthenticated;
            }
            (State::Authenticated, TransitionResult::Error) => {
                self.state = State::Unauthenticated;
            }
        }
    }
}


