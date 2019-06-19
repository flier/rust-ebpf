#![recursion_limit = "128"]
#![allow(non_camel_case_types)]

mod helpers;
pub use helpers::*;

pub use ebpf_core::map::{Flags as MapFlags, Spec as MapSpec, Type as MapType};
pub use ebpf_derive::*;
pub use ebpf_sys as ffi;

pub type be16 = u16;
pub type be32 = u32;
pub type be64 = u64;
pub type sum16 = u16;
pub type wsum = u32;

#[macro_export]
macro_rules! version {
    ($version:literal) => {
        #[no_mangle]
        #[link_section = "version"]
        pub static _version: u32 = $version;
    };
}

#[macro_export]
macro_rules! map {
    () => {};
    ( $name:ident : $ty:ident { [ $key:ty ] $value:ty ; $capacity:expr } $($rest:tt)* ) => {
        #[no_mangle]
        #[link_section = "maps"]
        pub static $name: $crate::MapSpec = $crate::MapSpec {
            ty: $crate::MapType::$ty,
            key_size: mem::size_of::<$key>() as u32,
            value_size: mem::size_of::<$value>() as u32,
            capacity: $capacity,
            flags: $crate::MapFlags::empty(),
        };

        map!{ $($rest)* }
    };
}
