#![deny(warnings)]
#![warn(unused_extern_crates)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::unreachable)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::trivially_copy_pass_by_ref)]

use std::fs::File;
use std::io::prelude::*;
use std::io::BufWriter;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use kanidm_proto::v1::Modify;

use log::{debug, error, info};
use rayon::prelude::*;
use structopt::StructOpt;

include!("opt/badlist_preprocess.rs");

fn main() {
    let opt = BadlistProcOpt::from_args();
    if opt.debug {
        ::std::env::set_var("RUST_LOG", "kanidm=debug,kanidm_client=debug");
    } else {
        ::std::env::set_var("RUST_LOG", "kanidm=info,kanidm_client=info");
    }
    env_logger::init();

    if opt.modlist {
        debug!("Running in modlist generation mode");
    } else {
        debug!("Running in list filtering mode");
    }
    info!("Kanidm badlist preprocessor - this may take a long time ...");

    // We open the file early to find out if we can create it or not.
    let fileout = match File::create(opt.outfile) {
        Ok(f) => f,
        Err(e) => {
            error!("Failed to create file - {:?}", e);
            return;
        }
    };

    // Build a temp struct for all the pws.
    // Shellexpand all of these.
    /*
    let expanded_paths: Vec<_> = opt.password_list.iter()
        .map(|p| {
            shellexpand::tilde(p).into_owned()
        })
        .collect();
    debug!("Using paths -> {:?}", expanded_paths);
    */

    let mut pwset: Vec<String> = Vec::new();

    // Read them all in, remove blank lines.
    for f in opt.password_list.iter() {
        let mut file = match File::open(f) {
            Ok(v) => v,
            Err(_) => {
                info!("Skipping file -> {:?}", f);
                continue;
            }
        };
        let mut contents = String::new();
        match file.read_to_string(&mut contents) {
            Ok(_) => {}
            Err(e) => {
                error!("{:?} -> {:?}", f, e);
                continue;
            }
        }
        let mut inner_pw: Vec<_> = contents.as_str().lines().map(|s| s.to_string()).collect();
        pwset.append(&mut inner_pw);
    }

    debug!("Deduplicating pre-set ...");
    pwset.sort_unstable();
    pwset.dedup();

    info!("Have {} pws to process", pwset.len());
    let count: AtomicUsize = AtomicUsize::new(0);
    // Create an empty slice for empty site options, not needed in this context.
    let site_opts: Vec<&str> = Vec::new();
    // Run zxcbvn over them with filter, use btreeset to remove dups if any
    let mut filt_pwset: Vec<_> = pwset
        .into_par_iter()
        .inspect(|_| {
            let tc = count.fetch_add(1, Ordering::AcqRel);
            if tc % 1000 == 0 {
                info!("{} ...", tc)
            }
        })
        .filter(|v| {
            if v.is_empty() {
                return false;
            }
            if v.len() < 10 {
                return false;
            }
            match zxcvbn::zxcvbn(v.as_str(), site_opts.as_slice()) {
                // score of 2 or less is too weak and we'd already reject it.
                Ok(r) => r.score() >= 3,
                Err(e) => {
                    error!("zxcvbn unable to process '{}' - {:?}", v.as_str(), e);
                    error!("adding to badlist anyway ...");
                    true
                }
            }
        })
        .collect();

    // Now sort and dedup
    debug!("Deduplicating results ...");
    filt_pwset.sort_unstable();
    filt_pwset.dedup();

    debug!("Starting file write ...");

    // Now we write these out.
    let bwrite = BufWriter::new(fileout);

    //  All remaining are either
    if opt.modlist {
        // - written to a file ready for modify, with a modify command printed.
        let modlist: Vec<Modify> = filt_pwset
            .into_iter()
            .map(|p| Modify::Present("badlist_password".to_string(), p))
            .collect();
        match serde_json::to_writer(bwrite, &modlist) {
            Ok(_) =>
                info!("next step: kanidm raw modify -D admin '{{\"Eq\": [\"uuid\", \"00000000-0000-0000-0000-ffffff000026\"]}}' <outfile>"),
            Err(e) => {
                error!("Failed to serialised modifications - {:?}", e)
            }
        }
    } else {
        // - printed in json format
        if let Err(e) = serde_json::to_writer_pretty(bwrite, &filt_pwset) {
            error!("Failed to serialised badlist - {:?}", e)
        }
    }
}
