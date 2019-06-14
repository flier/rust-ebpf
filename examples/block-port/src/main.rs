#[macro_use]
extern crate log;

use failure::Error;

use ebpf_loader;

const KERNEL: &[u8] = include_bytes!(env!("KERNEL"));

fn main() -> Result<(), Error> {
    pretty_env_logger::init();

    debug!(
        "load kernel ({} bytes) from {}",
        KERNEL.len(),
        env!("KERNEL")
    );

    let m = ebpf_loader::parse(KERNEL)?;

    Ok(())
}
