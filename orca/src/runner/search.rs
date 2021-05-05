use crate::data::{Entity, OpType, TestData};
use crate::profile::Profile;
use crate::{TargetServer, TargetServerBuilder};
use crossbeam::channel::{unbounded, RecvTimeoutError};
use mathru::statistics::distrib::Continuous;
use mathru::statistics::distrib::Normal;
use rand::seq::IteratorRandom;
use rand::seq::SliceRandom;
use std::fs::File;
use std::io::BufWriter;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::broadcast;
use tokio::task;

#[derive(Debug, Clone)]
enum TestPhase {
    WarmUp,
    // Running,
    Shutdown,
}

#[derive(Serialize, Deserialize)]
struct CsvRow {
    start: f64,
    duration: f64,
    count: usize,
}

fn basic_arbiter(
    mut broadcast_rx: tokio::sync::broadcast::Receiver<TestPhase>,
    raw_results_rx: crossbeam::channel::Receiver<(Duration, Duration, usize)>,
    warmup_seconds: u32,
) -> Vec<(Duration, Duration, usize)> {
    info!("Starting test arbiter ...");

    // Wait on the message that the workers have started the warm up.
    let bcast_msg = async_std::task::block_on(broadcast_rx.recv()).unwrap();

    if !matches!(bcast_msg, TestPhase::WarmUp) {
        error!("Invalid broadcast state to arbiter");
        return Vec::new();
    }

    // Wait for warmup seconds.
    // end of warmup

    let end_of_warmup = Instant::now() + Duration::from_secs(warmup_seconds as u64);

    let mut count = 0;

    loop {
        match raw_results_rx.recv_deadline(end_of_warmup) {
            // We are currently discarding results.
            Ok(_) => {
                count += 1;
            }
            Err(RecvTimeoutError::Timeout) => {
                break;
            }
            Err(_) => {
                error!("Worker channel error");
                return Vec::new();
            }
        }
    }

    info!("Warmup has passed, collecting data");

    let mut results = Vec::with_capacity(count * 4);

    // Now we are running, so collect our data.
    let end_of_test = Instant::now() + Duration::from_secs(10);

    loop {
        match raw_results_rx.recv_deadline(end_of_test) {
            // We are currently discarding results.
            Ok(datum) => results.push(datum),
            Err(RecvTimeoutError::Timeout) => {
                break;
            }
            Err(_) => {
                error!("Worker channel error");
                return Vec::new();
            }
        }
    }

    info!(
        "Stopping test arbiter. Gathered {} datapoints",
        results.len()
    );
    results
}

async fn basic_worker(
    test_start: Instant,
    builder: TargetServerBuilder,
    name: String,
    pw: String,
    searches: Arc<Vec<Vec<String>>>,
    mut broadcast_rx: tokio::sync::broadcast::Receiver<TestPhase>,
    raw_results_tx: crossbeam::channel::Sender<(Duration, Duration, usize)>,
) {
    debug!("Starting worker ...");

    let server = match builder.build() {
        Ok(s) => s,
        Err(_) => {
            error!("Failed to build client");
            return;
        }
    };

    if let Err(_) = server.open_user_connection(test_start, &name, &pw).await {
        error!("Failed to authenticate connection");
        return;
    }

    loop {
        // While nothing in broadcast.
        match broadcast_rx.try_recv() {
            Ok(TestPhase::Shutdown) => {
                // Complete.
                break;
            }
            Err(tokio::sync::broadcast::error::TryRecvError::Empty) | Ok(_) => {
                // Ignore
            }
            Err(_) => {
                error!("broadcast error");
                return;
            }
        }
        let s = {
            let mut rng = rand::thread_rng();
            searches.as_slice().choose(&mut rng).unwrap()
        };

        // Ensure we are logged out.
        server.close_connection().await;

        // Search something!
        let cr = match server.open_user_connection(test_start, &name, &pw).await {
            Ok(r) => r,
            Err(_) => {
                error!("Failed to authenticate connection");
                continue;
            }
        };
        let sr = match server.search(test_start, s.as_slice()).await {
            Ok(r) => r,
            Err(_) => {
                error!("Search Error");
                continue;
            }
        };
        // Append results
        let r = (cr.0, cr.1 + sr.1, sr.2);
        let _ = raw_results_tx.send(r);
    }
    // Done
    debug!("Stopping worker ...");
}

pub(crate) async fn basic(
    data: TestData,
    profile: Profile,
    server: TargetServer,
    result_path: PathBuf,
) -> Result<(), ()> {
    // From all the data, process and find all the search events.
    // Create these into an Arc<vec> so they can be sampled from by workers.
    let searches: Vec<Vec<String>> = data
        .connections
        .iter()
        .flat_map(|conn| conn.ops.iter())
        .filter_map(|op| {
            if let OpType::Search(list) = &op.op_type {
                // Now get each name.
                let names: Vec<String> = list
                    .iter()
                    .map(|u| data.all_entities.get(u).unwrap().get_name().to_string())
                    .collect();
                Some(names)
            } else {
                None
            }
        })
        .collect();

    let searches = Arc::new(searches);

    // We need a channel for all the results.
    let (raw_results_tx, raw_results_rx) = unbounded();

    // Setup a broadcast for the notifications.
    let (broadcast_tx, broadcast_rx) = broadcast::channel(2);

    // Start an arbiter that will control the test.
    // This should use spawn blocking.
    let warmup_seconds = profile.search_basic_config.warmup_seconds;
    let arbiter_join_handle =
        task::spawn_blocking(move || basic_arbiter(broadcast_rx, raw_results_rx, warmup_seconds));

    // Get out our conn details
    let mut rng = rand::thread_rng();
    // But only if they exist from the start.
    let accs = data
        .accounts
        .intersection(&data.precreate)
        .choose_multiple(&mut rng, profile.search_basic_config.workers as usize);

    let mut accs: Vec<_> = accs
        .into_iter()
        .filter_map(|u| {
            let e = data.all_entities.get(u).unwrap();
            if let Entity::Account(aref) = e {
                Some((aref.name.clone(), aref.password.clone()))
            } else {
                None
            }
        })
        .collect();

    if accs.len() == 0 {
        error!("No accounts found in data set, unable to proceed");
        return Err(());
    }

    while accs.len() < (profile.search_basic_config.workers as usize) {
        let mut dup = accs.clone();
        accs.append(&mut dup);
    }

    let test_start = Instant::now();

    // Start up as many async as workers requested.
    for i in 0..profile.search_basic_config.workers {
        // give each worker
        // * server connection
        let builder = server.builder();
        // Which is authenticated ...
        let name = accs[i as usize].0.clone();
        let pw = accs[i as usize].1.clone();
        // * arc searches
        let searches_c = searches.clone();
        // * the broadcast reciever.
        let broadcast_rx_c = broadcast_tx.subscribe();
        // * the result queue
        let raw_results_tx_c = raw_results_tx.clone();
        task::spawn(async move {
            basic_worker(
                test_start,
                builder,
                name,
                pw,
                searches_c,
                broadcast_rx_c,
                raw_results_tx_c,
            )
            .await
        });
    }

    // Tell the arbiter to start the warm up counter now.
    broadcast_tx
        .send(TestPhase::WarmUp)
        .map_err(|_| error!("Unable to broadcast warmup state change"))?;

    // Wait on the arbiter, it will return our results when it's ready.
    let raw_results = arbiter_join_handle.await.map_err(|_| {
        error!("Test arbiter was unable to rejoin.");
    })?;

    // Now signal the workers to stop. We don't care if this fails.
    let _ = broadcast_tx
        .send(TestPhase::Shutdown)
        .map_err(|_| error!("Unable to broadcast stop state change"));

    // Now we can finalise our data, based on what analysis we can actually do here.
    process_raw_results(&raw_results);

    // Write the raw results out.

    let result_name = format!("basic_{}.csv", server.rname());
    let result_path = result_path.join(result_name);

    let result_file = match File::create(&result_path) {
        Ok(f) => f,
        Err(e) => {
            error!("Failed to open {} - {:?}", result_path.to_str().unwrap(), e);
            return Err(());
        }
    };

    let mut wtr = csv::Writer::from_writer(BufWriter::new(result_file));

    raw_results
        .into_iter()
        .try_for_each(|(s, d, c)| {
            wtr.serialize(CsvRow {
                start: s.as_secs_f64(),
                duration: d.as_secs_f64(),
                count: c,
            })
        })
        .map_err(|e| error!("csv error {:?}", e))?;

    wtr.flush().map_err(|e| error!("csv error {:?}", e))?;

    Ok(())
}

fn process_raw_results(raw_results: &Vec<(Duration, Duration, usize)>) {
    // Do nerd shit.

    // Get the times
    let optimes: Vec<_> = raw_results
        .iter()
        .map(|(_, d, _)| d.as_secs_f64())
        .collect();

    let distrib: Normal<f64> = Normal::from_data(&optimes);
    let sd = distrib.variance().sqrt();

    info!("mean: {} seconds", distrib.mean());
    info!("variance: {}", distrib.variance());
    info!("SD: {} seconds", sd);
    info!("95%: {}", distrib.mean() + (2.0 * sd));
}
