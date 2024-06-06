use crate::error::Error;
use crate::run::{EventDetail, EventRecord};
use chrono::Local;
use crossbeam::queue::{ArrayQueue, SegQueue};
use csv::Writer;
use serde::Serialize;
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
pub struct BasicStatistics {
    person_count: usize,
    group_count: usize,
    node_count: usize,
}

impl BasicStatistics {
    #[allow(clippy::new_ret_no_self)]
    pub fn new(
        person_count: usize,
        group_count: usize,
        node_count: usize,
    ) -> Box<dyn DataCollector + Send> {
        Box::new(BasicStatistics {
            person_count,
            group_count,
            node_count,
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

        if readop_times.is_empty() && writeop_times.is_empty() {
            error!("For some weird reason no read and write operations were recorded, exiting...");
            return Err(Error::InvalidState);
        }

        if writeop_times.is_empty() {
            error!("For some weird reason no write operations were recorded, exiting...");
            return Err(Error::InvalidState);
        }

        if readop_times.is_empty() {
            error!("For some weird reason no read operations were recorded, exiting...");
            return Err(Error::InvalidState);
        }

        let stats = StatsContainer::new(
            &readop_times,
            &writeop_times,
            self.node_count,
            self.person_count,
            self.group_count,
        );

        info!(
            "Server configuration was: {} nodes, {} users and {} groups",
            self.node_count, self.person_count, self.group_count
        );

        info!("Received {} read events", stats.read_events);

        info!("mean: {} seconds", stats.read_mean);
        info!("variance: {}", stats.read_variance);
        info!("SD: {} seconds", stats.read_sd);
        info!("95%: {}", stats.read_95);

        info!("Received {} write events", stats.write_events);

        info!("mean: {} seconds", stats.write_mean);
        info!("variance: {}", stats.write_variance);
        info!("SD: {} seconds", stats.write_sd);
        info!("95%: {}", stats.write_95);

        let now = Local::now();
        let filepath = format!("orca-run-{}.csv", now.to_rfc3339());

        info!("Now saving stats as '{filepath}'");

        let mut wrt = Writer::from_path(filepath).map_err(|_| Error::Io)?;
        wrt.serialize(stats).map_err(|_| Error::Io)?;

        debug!("Ended statistics collector");

        Ok(())
    }
}

#[derive(Serialize)]
struct StatsContainer {
    node_count: usize,
    person_count: usize,
    group_count: usize,
    read_events: usize,
    read_sd: f64,
    read_mean: f64,
    read_variance: f64,
    read_95: f64,
    write_events: usize,
    write_sd: f64,
    write_mean: f64,
    write_variance: f64,
    write_95: f64,
}

impl StatsContainer {
    fn new(
        readop_times: &Vec<f64>,
        writeop_times: &Vec<f64>,
        node_count: usize,
        person_count: usize,
        group_count: usize,
    ) -> Self {
        let readop_distrib: Normal<f64> = Normal::from_data(readop_times);
        let read_sd = readop_distrib.variance().sqrt();
        let writeop_distrib: Normal<f64> = Normal::from_data(writeop_times);
        let write_sd = writeop_distrib.variance().sqrt();

        StatsContainer {
            person_count,
            group_count,
            node_count,
            read_events: readop_times.len(),
            read_sd: readop_distrib.variance().sqrt(),
            read_mean: readop_distrib.mean(),
            read_variance: readop_distrib.variance(),
            read_95: readop_distrib.mean() + (2.0 * read_sd),
            write_events: writeop_times.len(),
            write_sd: writeop_distrib.variance().sqrt(),
            write_mean: writeop_distrib.mean(),
            write_variance: writeop_distrib.variance(),
            write_95: writeop_distrib.mean() + (2.0 * write_sd),
        }
    }
}
