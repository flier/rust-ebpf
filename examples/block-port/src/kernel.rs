#![no_std]

#[macro_use]
extern crate ebpf_runtime;
extern crate xdp_runtime;

use xdp_runtime::{Action, Metadata, net::ether};

license! { "GPL" }
version! { 0xFFFFFFFE }

#[program(name = "xdp/balancer")]
pub unsafe extern "C" fn handle_ingress(md: &Metadata) -> Action {
    Action::Pass
}
