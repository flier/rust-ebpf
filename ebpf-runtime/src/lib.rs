#![recursion_limit = "128"]
#![allow(non_camel_case_types)]

#[macro_use]
extern crate bitflags;
#[macro_use]
extern crate ebpf_derive;

pub use untrusted;

#[macro_use]
mod macros;
mod errors;
pub mod helpers;
pub mod kernel;

pub use self::errors::EbpfError;

pub use ebpf_core::map::{Flags as MapFlags, Spec as MapSpec, Type as MapType};
pub use ebpf_derive::*;

pub mod ffi {
    pub use ebpf_sys::*;

    pub type sk_msg_buff = ();
}

pub type be16 = u16;
pub type be32 = u32;
pub type be64 = u64;
pub type sum16 = u16;
pub type wsum = u32;
