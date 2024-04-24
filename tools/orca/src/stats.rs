use crate::error::Error;
use crate::run::{EventDetail, EventRecord};
use crossbeam::queue::{ArrayQueue, SegQueue};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

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

enum OpKind {
    WriteOp,
    ReadOp,
    Other, //TODO! does this make sense?
}

impl From<EventDetail> for OpKind {
    fn from(value: EventDetail) -> Self {
        match value {
            EventDetail::PersonGetSelfMemberOf | EventDetail::PersonGetSelfAccount => {
                OpKind::ReadOp
            }
            EventDetail::PersonSetSelfMail | EventDetail::PersonSelfSetPassword => OpKind::WriteOp,
            EventDetail::Error
            | EventDetail::Login
            | EventDetail::Logout
            | EventDetail::PersonReauth => OpKind::Other,
        }
    }
}
pub struct BasicStatistics {}

impl BasicStatistics {
    #[allow(clippy::new_ret_no_self)]
    pub fn new() -> Box<dyn DataCollector + Send> {
        Box::new(BasicStatistics {})
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
                    error!("invalid state");
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
                    warn!("requested to stop now!");
                    // We have been told to stop immediately.
                    return Ok(());
                }
                None => thread::sleep(Duration::from_millis(100)),
            }
        };

        info!("start statistics processing ...");

        let mut readop_times = Vec::new();
        let mut writeop_times = Vec::new();

        // We will drain this now.
        while let Some(event_record) = stats_queue.pop() {
            if event_record.start < start || event_record.start > end {
                // Skip event, outside of the test time window
                continue;
            }

            match OpKind::from(event_record.details) {
                OpKind::ReadOp => {
                    readop_times.push(event_record.duration.as_secs_f64());
                }
                OpKind::WriteOp => {
                    writeop_times.push(event_record.duration.as_secs_f64());
                }
                OpKind::Other => {}
            }
        }

        info!("Received {} read events", readop_times.len());

        let readop_distrib: Normal<f64> = Normal::from_data(&readop_times);
        let sd = readop_distrib.variance().sqrt();

        info!("mean: {} seconds", readop_distrib.mean());
        info!("variance: {}", readop_distrib.variance());
        info!("SD: {} seconds", sd);
        info!("95%: {}", readop_distrib.mean() + (2.0 * sd));

        info!("Received {} write events", writeop_times.len());

        let writeop_distrib: Normal<f64> = Normal::from_data(&writeop_times);
        let sd = writeop_distrib.variance().sqrt();

        info!("mean: {} seconds", writeop_distrib.mean());
        info!("variance: {}", writeop_distrib.variance());
        info!("SD: {} seconds", sd);
        info!("95%: {}", writeop_distrib.mean() + (2.0 * sd));

        debug!("Ended statistics collector");

        Ok(())
    }
}
