#[macro_use]
extern crate log;
extern crate failure;
extern crate ebpf_loader;

use failure::Error;

const KERNEL: &[u8] = include_bytes!(env!("KERNEL"));

fn main() -> Result<(), Error> {
    pretty_env_logger::init();

    debug!(
        "load kernel ({} bytes) from {}",
        KERNEL.len(),
        env!("KERNEL")
    );

    let m = ebpf_loader::parse(KERNEL)?;

    trace!("loaded kernel: {:#?}", m);

    Ok(())
}
