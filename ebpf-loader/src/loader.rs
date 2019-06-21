use std::fs::File;
use std::io::prelude::*;
use std::path::Path;

use failure::{Error, ResultExt};

use ebpf_core::{Map, Object};

use crate::parser::parse;

pub fn load<P: AsRef<Path>>(path: P) -> Result<Object, Error> {
    debug!("load eBPF object from {:?}", path.as_ref());

    let mut f = File::open(path)?;
    let mut buf = Vec::new();
    f.read_to_end(&mut buf)?;

    parse(&buf).and_then(|mut obj| Loader::new().load(&mut obj).map(|_| obj))
}

#[derive(Debug)]
pub struct Loader {}

impl Loader {
    pub fn new() -> Self {
        Loader {}
    }

    pub fn load(&self, obj: &mut Object) -> Result<(), Error> {
        self.create_maps(&obj.maps).context("create map")?;

        Ok(())
    }
}

cfg_if! {
    if #[cfg(target_os = "linux")] {
        use crate::syscall;

        impl Loader {
            fn create_maps(&self, maps: &[Map]) -> Result<(), Error> {
                for map in maps {
                    let fd = unsafe { syscall::create_map(&map)? };
                }

                Ok(())
            }
        }
    }
}
