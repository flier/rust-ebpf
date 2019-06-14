#[macro_use]
extern crate ebpf_runtime;
extern crate xdp_runtime;

use xdp_runtime::{Action, Metadata};

const ETH_ALEN: usize = 6;

const ETH_P_IP: u16 = 0x8000;
const ETH_P_IPV6: u16 = 0x86DD;

const IPPROTO_TCP: u16 = 6;
const IPPROTO_UDP: u16 = 17;

license! { "GPL" }

version! { 0xFFFFFFFE }

#[repr(C)]
struct eth_hdr {
    eth_dest: [u8; ETH_ALEN],
    eth_source: [u8; ETH_ALEN],
    eth_proto: u16,
}

#[no_mangle]
#[link_section = "xdp/balancer"]
pub unsafe extern "C" fn handle_ingress(md: &Metadata) -> Action {
    match md.as_ptr::<eth_hdr>() {
        Some(eth) => match u16::from_be(eth.eth_proto) {
            ETH_P_IP => Action::Pass,
            ETH_P_IPV6 => Action::Pass,
            _ => Action::Pass,
        },
        _ => Action::Drop,
    }
}
