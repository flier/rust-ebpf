#[macro_use]
extern crate bitflags;
#[macro_use]
extern crate derive_more;
#[macro_use]
extern crate num_derive;
pub extern crate ebpf_sys as ffi;

pub mod map;
pub mod prog;

pub use map::Map;
pub use prog::{Insn, Opcode, Program};

pub const BPF_LICENSE_SEC: &str = "license";
pub const BPF_VERSION_SEC: &str = "version";
pub const BPF_MAPS_SEC: &str = "maps";

pub const BTF_ELF_SEC: &str = ".BTF";
pub const BTF_EXT_ELF_SEC: &str = ".BTF.ext";

#[derive(Debug, Default)]
pub struct Object {
    pub license: Option<String>,
    pub version: Option<u32>,
    pub programs: Vec<Program>,
    pub maps: Vec<Map>,
}
