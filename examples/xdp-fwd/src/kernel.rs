extern crate untrusted;
#[macro_use]
extern crate ebpf_runtime;
extern crate xdp_runtime;

use std::mem;

use ebpf_runtime::ffi;
use untrusted::{EndOfInput, Reader};
use xdp_runtime::{Action, Metadata};

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
                read_packet(reader, flags).map_err(|_| Action::Drop)
            })
        })
        .unwrap_or(Action::Drop)
}

fn read_packet(r: &mut Reader, flags: u32) -> Result<Action, EndOfInput> {
    r.skip_to_end();

    Ok(Action::Pass)
}
