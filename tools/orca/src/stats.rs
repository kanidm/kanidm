
use crate::error::Error;
use crate::run::EventRecord;
use crossbeam::queue::{SegQueue, ArrayQueue};
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::thread;

use mathru::statistics::distrib::{Continuous, Normal};

#[derive(Debug)]
pub enum TestPhase {
    Start(Instant),
    End(Instant),
    StopNow,
}

pub trait DataCollector {
    fn run(
        &mut self,
        stats_queue: Arc<SegQueue<EventRecord>>,
        ctrl: Arc<ArrayQueue<TestPhase>>,
    ) -> Result<(), Error>;
}

pub struct BasicStatistics {
}

impl BasicStatistics {
    pub fn new() -> Box<dyn DataCollector + Send> {
        Box::new(BasicStatistics {
        })
    }
}

impl DataCollector for BasicStatistics {
    fn run(
        &mut self,
        stats_queue: Arc<SegQueue<EventRecord>>,
        ctrl: Arc<ArrayQueue<TestPhase>>,
    ) -> Result<(), Error> {
        debug!("Started statistics collector");

        // Wait for an event on ctrl. We use small amounts of backoff if none are
        // present yet.
        let start = loop {
            match ctrl.pop() {
                Some(TestPhase::Start(start)) => {
                    break start;
                }
                Some(TestPhase::End(_)) => {
                    // Invalid state.
                    return Err(Error::InvalidState);
                }
                Some(TestPhase::StopNow) => {
                    // We have been told to stop immediately.
                    return Ok(());
                }
                None => thread::sleep(Duration::from_millis(100)),
            }
        };

        // Due to the design of this collector, we don't do anything until the end of the test.
        let end = loop {
            match ctrl.pop() {
                Some(TestPhase::Start(_)) => {
                    // Invalid state.
                    return Err(Error::InvalidState);
                }
                Some(TestPhase::End(end)) => {
                    break end;
                }
                Some(TestPhase::StopNow) => {
                    // We have been told to stop immediately.
                    return Ok(());
                }
                None => thread::sleep(Duration::from_millis(100)),
            }
        };

        let mut count: usize = 0;
        let mut optimes = Vec::new();

        // We will drain this now.
        while let Some(event_record) = stats_queue.pop() {
            if event_record.start < start || event_record.start > end {
                // Skip event, outside of the test time window
                continue;
            }

            count += 1;

            optimes.push(event_record.duration.as_secs_f64());
        }

        info!("Received {} events", count);

        let distrib: Normal<f64> = Normal::from_data(&optimes);
        let sd = distrib.variance().sqrt();

        info!("mean: {} seconds", distrib.mean());
        info!("variance: {}", distrib.variance());
        info!("SD: {} seconds", sd);
        info!("95%: {}", distrib.mean() + (2.0 * sd));

        debug!("Ended statistics collector");

        Ok(())
    }
}


