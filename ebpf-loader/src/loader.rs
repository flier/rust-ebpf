use std::fs::File;
use std::io::prelude::*;
use std::path::Path;

use failure::Error;

use ebpf_core::Object;

use crate::parser::parse;

pub fn load<P: AsRef<Path>>(path: P) -> Result<Object, Error> {
    debug!("load eBPF object from {:?}", path.as_ref());

    let mut f = File::open(path)?;
    let mut buf = Vec::new();
    f.read_to_end(&mut buf)?;

    parse(&buf)
}

#[derive(Debug)]
pub struct Loader {}
