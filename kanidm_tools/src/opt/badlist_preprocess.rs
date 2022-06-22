#[derive(Debug, Parser)]
struct BadlistProcOpt {
    #[clap(short, long)]
    debug: bool,
    #[clap(short, long)]
    modlist: bool,
    #[clap(short, long = "output")]
    outfile: PathBuf,
    #[clap(parse(from_os_str))]
    password_list: Vec<PathBuf>,
}
