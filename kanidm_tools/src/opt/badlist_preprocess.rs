
#[derive(Debug, StructOpt)]
struct BadlistProcOpt {
    #[structopt(short = "d", long = "debug")]
    debug: bool,
    #[structopt(short = "m", long = "modlist")]
    modlist: bool,
    #[structopt(short = "o", long = "output")]
    outfile: PathBuf,
    #[structopt(parse(from_os_str))]
    password_list: Vec<PathBuf>,
}
