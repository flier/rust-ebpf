#[macro_use]
extern crate log;

mod elf;

use std::fs::File;
use std::io::prelude::*;
use std::path::Path;

use failure::{bail, Error};

use ebpf_core::Object;

pub fn load<P: AsRef<Path>>(path: P) -> Result<Object, Error> {
    debug!("load eBPF object from {:?}", path.as_ref());

    let mut f = File::open(path)?;
    let mut buf = Vec::new();

    f.read_to_end(&mut buf)?;

    parse(&buf)
}

pub fn parse<B: AsRef<[u8]>>(buf: B) -> Result<Object, Error> {
    use goblin::Object;

    let buf = buf.as_ref();
    match Object::parse(buf)? {
        Object::Elf(elf) => Parser { obj: elf }.parse(buf),
        Object::PE(_pe) => unimplemented!(),
        Object::Mach(_mach) => unimplemented!(),
        Object::Archive(_archive) => unimplemented!(),
        Object::Unknown(magic) => bail!("unknown format, magic: {}", magic),
    }
}

struct Parser<T> {
    obj: T,
}
