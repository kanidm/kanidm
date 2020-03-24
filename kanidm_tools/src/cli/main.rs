use std::error::Error;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::path::PathBuf;


use log::debug;
use serde::de::DeserializeOwned;
use shellexpand;
use structopt::StructOpt;

use kanidm_cli::ClientOpt;


fn read_file<T: DeserializeOwned, P: AsRef<Path>>(path: P) -> Result<T, Box<dyn Error>> {
    let f = File::open(path)?;
    let r = BufReader::new(f);

    let t: T = serde_json::from_reader(r)?;
    Ok(t)
}

fn main() {
    let opt = ClientOpt::from_args();

    if opt.debug() {
        ::std::env::set_var("RUST_LOG", "kanidm=debug,kanidm_client=debug");
    } else {
        ::std::env::set_var("RUST_LOG", "kanidm=info,kanidm_client=info");
    }
    env_logger::init();

    opt.exec()
}
