#[macro_use]
extern crate log;
extern crate failure;
extern crate pretty_env_logger;
extern crate ebpf_build;

use failure::Error;

use ebpf_build::Builder;

fn main() -> Result<(), Error> {
    pretty_env_logger::init();

    Builder::new()
        .kernel("src/kernel.rs")
        .build()
        .map(|filename| info!("generated eBPF kernel @ {:?}", filename))
        .map_err(|err| err.context("build eBPF kernel").into())
}
