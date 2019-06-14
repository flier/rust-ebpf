#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

#[macro_use]
extern crate cfg_if;

cfg_if! {
    if #[cfg(feature = "gen")] {
        include!(concat!(env!("OUT_DIR"), "/raw.rs"));
    } else {
        include!("raw.rs");
    }
}

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
