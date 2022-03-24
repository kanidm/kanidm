use std::time::{Duration, Instant};

pub struct Timer {
    duration: Duration,
    start: Instant,
}

impl Timer {
    pub fn new() -> Self {
        Timer {
            duration: Duration::default(),
            start: Instant::now(),
        }
    }

    pub fn pause(&mut self) {
        let stop = Instant::now();
        self.duration += stop - self.start;
    }

    pub fn unpause(&mut self) {
        self.start = Instant::now();
    }

    pub fn duration(self) -> Duration {
        self.duration
    }
}
