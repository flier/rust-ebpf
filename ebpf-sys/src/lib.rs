#![allow(clippy::cast_lossless)]
#![allow(clippy::trivially_copy_pass_by_ref)]
#![allow(clippy::unreadable_literal)]
#![allow(clippy::useless_transmute)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

#[macro_use]
extern crate cfg_if;

cfg_if! {
    if #[cfg(feature = "gen")] {
        include!(concat!(env!("OUT_DIR"), "/raw.rs"));
    } else {
        mod raw;

        pub use raw::*;
    }
}

cfg_if! {
    if #[cfg(all(feature = "gen", target_os = "linux"))] {
        pub mod kernel {
            include!(concat!(env!("OUT_DIR"), "/kernel.rs"));
        }
    } else {
        pub mod kernel;
    }
}

pub use kernel::{bpf_perf_event_data, bpf_sock_ops_kern, pt_regs, sk_buff, xdp_buff};

pub type sk_msg_buff = ();

macro_rules! BIT {
    ($shift:expr) => {
        (1 << $shift)
    };
}

/* DIRECT:  Skip the FIB rules and go to FIB table associated with device
 * OUTPUT:  Do lookup from egress perspective; default is ingress
 */
pub const BPF_FIB_LOOKUP_DIRECT: u32 = BIT!(0);
pub const BPF_FIB_LOOKUP_OUTPUT: u32 = BIT!(1);
