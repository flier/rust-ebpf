#[macro_use]
extern crate log;

use failure::Error;
use structopt::StructOpt;

use ebpf_loader;

const KERNEL: &[u8] = include_bytes!(env!("KERNEL"));

#[derive(Debug, StructOpt)]
#[structopt(name = "xdp-fwd", about = "An example of XDP packet forwarding.")]
struct Opt {
    /// Detach program
    #[structopt(short = "d", long)]
    detach: bool,

    /// Direct table lookups (skip fib rules)
    #[structopt(short = "D", long)]
    direct: bool,

    /// Interface name list
    interfaces: Vec<String>,
}

fn main() -> Result<(), Error> {
    pretty_env_logger::init();

    let opt = Opt::from_args();
    debug!("{:?}", opt);

    let m = ebpf_loader::parse(KERNEL)?;
    debug!(
        "kernel loaded from {}, {} bytes, {} license, {} programs, {} maps",
        env!("KERNEL"),
        KERNEL.len(),
        m.license.as_ref().map(|s| s.as_ref()).unwrap_or("N/A"),
        m.programs.len(),
        m.maps.len(),
    );
    trace!("loaded kernel: {:#?}", m);

    let prog_name = if opt.direct {
        "xdp_fwd_direct"
    } else {
        "xdp_fwd"
    };
    let prog = m
        .programs
        .iter()
        .find(|prog| prog.title == prog_name)
        .expect("program not found");
    let map = m
        .maps
        .iter()
        .find(|map| map.name == "tx_port")
        .expect("map not found");

    if !opt.detach {}

    Ok(())
}
