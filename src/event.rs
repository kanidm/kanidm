use actix::prelude::*;

// This structure tracks and event lifecycle, and is eventually
// sent to the logging system where it's structured and written
// out to the current logging BE.
#[derive(Debug)]
pub struct Event {
    time_start: (),
    time_end: (),
    // vec of start/end points of various parts of the event?
    // We probably need some functions for this. Is there a way in rust
    // to automatically annotate line numbers of code?

    // This could probably store the request parameters too?
    // The parallel in 389 would be operation struct
}

impl Message for Event {
    type Result = ();
}

