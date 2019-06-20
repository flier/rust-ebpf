#![no_std]

extern crate untrusted;
#[macro_use]
extern crate ebpf_runtime;
extern crate xdp_runtime;

use core::ptr::NonNull;

use ebpf_runtime::{
    sum16,
    kernel::fib,
    EbpfError::{self, *},
};
use xdp_runtime::{
    net::{ether, ipv4, ipv6, sock, Readable},
    Action, Metadata, redirect_map,
};

license! { "GPL" }
version! { 0xFFFFFFFE }
map! {
    tx_port: DevMap { [i32]i32; 64 }
}

#[program(name = "xdp_fwd")]
pub unsafe extern "C" fn xdp_fwd_prog(md: &Metadata) -> Action {
    xdp_fwd_flags(md, fib::Lookup::empty())
}

#[program(name = "xdp_fwd_direct")]
pub unsafe extern "C" fn xdp_fwd_direct_prog(md: &Metadata) -> Action {
    xdp_fwd_flags(md, fib::Lookup::DIRECT)
}

fn xdp_fwd_flags(md: &Metadata, flags: fib::Lookup) -> Action {
    md.input()
        .ok_or(Action::Drop)
        .and_then(|input| {
            input.read_all(Action::Drop, |reader| {
                read_packet(md, reader, flags).map_err(|_| Action::Drop)
            })
        })
        .unwrap_or(Action::Drop)
}

enum Packet {
    Ipv4(NonNull<ipv4::Header>),
    Ipv6(NonNull<ipv6::Header>),
}

fn read_packet(md: &Metadata, r: &mut untrusted::Reader, flags: fib::Lookup) -> Result<Action, EbpfError> {
    let mut fib_params = fib::Params::default();
    let mut eth = ether::Header::read(r)?;

    let packet = match unsafe { eth.as_ref().proto() } {
        ether::ETH_P_IP => {
            let hdr = ipv4::Header::read(r).map_err(|_| EndOfInput)?;
            let iph = unsafe { hdr.as_ref() };

            fib_params.family = sock::AF_INET;
            fib_params.with_tos(iph.tos);
            fib_params.l4_protocol = iph.protocol;
            fib_params.tot_len = iph.total_len();
            fib_params.with_ipv4_src(iph.saddr);
            fib_params.with_ipv4_dst(iph.daddr);

            Packet::Ipv4(hdr)
        }
        ether::ETH_P_IPV6 => {
            let hdr = ipv6::Header::read(r).map_err(|_| EndOfInput)?;;
            let ip6h = unsafe { hdr.as_ref() };

            fib_params.family = sock::AF_INET6;
            fib_params.with_flowinfo(ip6h.flowinfo());
            fib_params.l4_protocol = ip6h.nexthdr;
            fib_params.tot_len = ip6h.payload_len();
            fib_params.with_ipv6_src(ip6h.saddr);
            fib_params.with_ipv6_dst(ip6h.daddr);

            Packet::Ipv6(hdr)
        }
        _ => {
            return Ok(Action::Pass);
        }
    };

    fib_params.ifindex = md.ingress_ifindex;

    if fib::lookup(md, &mut fib_params, flags).is_ok() {
        match packet {
            Packet::Ipv4(mut hdr) => {
                let iph = unsafe { hdr.as_mut() };

                let check = iph.check as u32 + 0x0100u32.to_be();

                iph.check = (check + if check >= 0xFFFF { 1 } else { 0}) as sum16;
                iph.ttl -= 1;
            }
            Packet::Ipv6(mut hdr) => {
                let ip6h = unsafe { hdr.as_mut() };

                ip6h.hop_limit -= 1;
            }
        }

        let eth = unsafe { eth.as_mut() };

        eth.dest = fib_params.dmac.into();
        eth.source = fib_params.smac.into();

        Ok(redirect_map(&tx_port, fib_params.ifindex))
    } else {
        Ok(Action::Pass)
    }
}
