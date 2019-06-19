use failure::Error;
use log::info;

use ebpf_build::Builder;

fn main() -> Result<(), Error> {
    pretty_env_logger::init();

    Builder::new()
        .kernel("src/kernel.rs")
        .build()
        .map(|filename| info!("generated eBPF kernel @ {:?}", filename))
        .map_err(|err| err.context("build eBPF kernel").into())
}
