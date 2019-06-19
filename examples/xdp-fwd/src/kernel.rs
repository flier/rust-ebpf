extern crate untrusted;
#[macro_use]
extern crate ebpf_runtime;
extern crate xdp_runtime;

use std::mem;

use ebpf_runtime::{ffi, bpf_fib_lookup};
use untrusted::{EndOfInput, Reader};
use xdp_runtime::{Action, Metadata, net::{ether, ipv4, ipv6, sock, Readable}};

license! { "GPL" }
version! { 0xFFFFFFFE }
map! {
    tx_port: DevMap { [i32]i32; 64 }
}

#[program(name = "xdp_fwd")]
pub unsafe extern "C" fn xdp_fwd_prog(md: &Metadata) -> Action {
    xdp_fwd_flags(md, 0)
}

#[program(name = "xdp_fwd_direct")]
pub unsafe extern "C" fn xdp_fwd_direct_prog(md: &Metadata) -> Action {
    xdp_fwd_flags(md, ffi::BPF_FIB_LOOKUP_DIRECT)
}

fn xdp_fwd_flags(md: &Metadata, flags: u32) -> Action {
    md.input()
        .ok_or(Action::Drop)
        .and_then(|input| {
            input.read_all(Action::Drop, |reader| {
                read_packet(md, reader, flags).map_err(|_| Action::Drop)
            })
        })
        .unwrap_or(Action::Drop)
}

fn read_packet(md: &Metadata, r: &mut Reader, flags: u32) -> Result<Action, EndOfInput> {
    let mut fib_params: ffi::bpf_fib_lookup = unsafe { mem::zeroed() };
    let eth = ether::Header::read(r)?;

    match eth.proto() {
        ether::ETH_P_IP => {
            let iph = ipv4::Header::read(r)?;

            fib_params.family = sock::AF_INET;
            fib_params.__bindgen_anon_1.tos = iph.tos;
            fib_params.l4_protocol = iph.protocol;
            fib_params.tot_len = iph.total_len();
            fib_params.__bindgen_anon_2.ipv4_src = iph.saddr.into();
            fib_params.__bindgen_anon_3.ipv4_dst = iph.daddr.into();
        }
        ether::ETH_P_IPV6 => {
            let ip6h = ipv6::Header::read(r)?;

            fib_params.family= sock::AF_INET6;
            fib_params.__bindgen_anon_1.flowinfo = ip6h.flowinfo();
            fib_params.l4_protocol = ip6h.nexthdr;
            fib_params.tot_len = ip6h.payload_len();
            fib_params.__bindgen_anon_2.ipv6_src = ip6h.saddr.into();
            fib_params.__bindgen_anon_3.ipv6_dst = ip6h.daddr.into();
        }
        _ => {}
    }

    fib_params.ifindex = md.ingress_ifindex;

    let rc = bpf_fib_lookup(md.as_ptr() as *const _, &fib_params, mem::size_of::<ffi::bpf_fib_lookup>() as i32, flags);

    Ok(Action::Pass)
}
