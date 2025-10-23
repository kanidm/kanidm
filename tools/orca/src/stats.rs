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
        dump_raw_data: bool,
    ) -> Result<(), Error>;
}

enum OpKind {
    WriteOp,
    ReadOp,
    ReplicationDelay,
    Auth, //TODO! does this make sense?
    Error,
}

impl From<EventDetail> for OpKind {
    fn from(value: EventDetail) -> Self {
        match value {
            EventDetail::PersonGetSelfMemberOf | EventDetail::PersonGetSelfAccount => {
                OpKind::ReadOp
            }
            EventDetail::PersonSetSelfMail
            | EventDetail::PersonSetSelfPassword
            | EventDetail::PersonCreateGroup
            | EventDetail::PersonAddGroupMembers => OpKind::WriteOp,
            EventDetail::Login | EventDetail::Logout | EventDetail::PersonReauth => OpKind::Auth,
            EventDetail::GroupReplicationDelay => OpKind::ReplicationDelay,
            EventDetail::Error => OpKind::Error,
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
        dump_raw_data: bool,
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
        let mut replication_delays = Vec::new();
        let mut raw_stats = Vec::new();

        // We will drain this now.
        while let Some(event_record) = stats_queue.pop() {
            if event_record.start < start || event_record.start > end {
                // Skip event, outside of the test time window
                continue;
            }

            if dump_raw_data {
                raw_stats.push(SerializableEventRecord::from_event_record(
                    &event_record,
                    start,
                ));
            }

            match OpKind::from(event_record.details) {
                OpKind::ReadOp => {
                    readop_times.push(event_record.duration.as_secs_f64());
                }
                OpKind::WriteOp => {
                    writeop_times.push(event_record.duration.as_secs_f64());
                }
                OpKind::ReplicationDelay => {
                    replication_delays.push(event_record.duration.as_secs_f64())
                }
                OpKind::Auth => {}
                OpKind::Error => {}
            }
        }

        if readop_times.is_empty() && writeop_times.is_empty() && replication_delays.is_empty() {
            error!("For some weird reason no valid data was recorded in this benchmark, bailing out...");
            return Err(Error::InvalidState);
        }

        let stats = StatsContainer::new(
            &readop_times,
            &writeop_times,
            &replication_delays,
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
        info!("variance: {} seconds", stats.read_variance);
        info!("SD: {} seconds", stats.read_sd);
        info!("95%: {}", stats.read_95);

        info!("Received {} write events", stats.write_events);

        info!("mean: {} seconds", stats.write_mean);
        info!("variance: {} seconds", stats.write_variance);
        info!("SD: {} seconds", stats.write_sd);
        info!("95%: {}", stats.write_95);

        info!(
            "Received {} replication delays",
            stats.replication_delay_events
        );

        info!("mean: {} seconds", stats.replication_delay_mean);
        info!("variance: {} seconds", stats.replication_delay_variance);
        info!("SD: {} seconds", stats.replication_delay_sd);
        info!("95%: {}", stats.replication_delay_95);

        let now = Local::now();
        let filepath = format!("orca-run-{}.csv", now.to_rfc3339());

        info!("Now saving stats as '{filepath}'");

        let mut wrt = Writer::from_path(filepath).map_err(|_| Error::Io)?;
        wrt.serialize(stats).map_err(|_| Error::Io)?;

        if dump_raw_data {
            let raw_data_filepath = format!("orca-run-{}-raw.csv", now.to_rfc3339());
            info!("Now saving raw data as '{raw_data_filepath}'");

            let mut wrt = Writer::from_path(raw_data_filepath).map_err(|_| Error::Io)?;

            for record in raw_stats.iter() {
                wrt.serialize(record).map_err(|_| Error::Io)?;
            }
        }

        debug!("Ended statistics collector");

        Ok(())
    }
}

#[derive(Serialize)]
struct SerializableEventRecord {
    time_from_start_ms: u128,
    duration_ms: u128,
    details: EventDetail,
}

impl SerializableEventRecord {
    fn from_event_record(event_record: &EventRecord, test_start: Instant) -> Self {
        SerializableEventRecord {
            time_from_start_ms: event_record.start.duration_since(test_start).as_millis(),
            duration_ms: event_record.duration.as_millis(),
            details: event_record.details.clone(),
        }
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
    replication_delay_events: usize,
    replication_delay_sd: f64,
    replication_delay_mean: f64,
    replication_delay_variance: f64,
    replication_delay_95: f64,
}

// These should help prevent confusion when using 'compute_stats_from_timings_vec'
type EventCount = usize;
type Mean = f64;
type Sd = f64;
type Variance = f64;
type Percentile95 = f64;

impl StatsContainer {
    fn new(
        readop_times: &[f64],
        writeop_times: &[f64],
        replication_delays: &[f64],
        node_count: usize,
        person_count: usize,
        group_count: usize,
    ) -> Self {
        let (read_events, read_mean, read_variance, read_sd, read_95) =
            Self::compute_stats_from_timings_vec(readop_times);

        let (write_events, write_mean, write_variance, write_sd, write_95) =
            Self::compute_stats_from_timings_vec(writeop_times);

        let (
            replication_delay_events,
            replication_delay_mean,
            replication_delay_variance,
            replication_delay_sd,
            replication_delay_95,
        ) = Self::compute_stats_from_timings_vec(replication_delays);

        StatsContainer {
            person_count,
            group_count,
            node_count,
            read_events,
            read_sd,
            read_mean,
            read_variance,
            read_95,
            write_events,
            write_sd,
            write_mean,
            write_variance,
            write_95,
            replication_delay_events,
            replication_delay_sd,
            replication_delay_mean,
            replication_delay_variance,
            replication_delay_95,
        }
    }

    fn compute_stats_from_timings_vec(
        op_times: &[f64],
    ) -> (EventCount, Mean, Variance, Sd, Percentile95) {
        let op_times_len = op_times.len();
        if op_times_len >= 2 {
            let distr = Normal::from_data(op_times);
            let mean = distr.mean();
            let variance = distr.variance();
            let sd = variance.sqrt();
            let percentile_95 = mean + 2. * sd;
            (op_times_len, mean, variance, sd, percentile_95)
        } else {
            (0, 0., 0., 0., 0.)
        }
    }
}
