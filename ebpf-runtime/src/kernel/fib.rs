use core::convert::{AsMut, TryFrom};
use core::mem;

use crate::{be32, ffi, helpers::bpf_fib_lookup, trivial};

bitflags! {
    pub struct Lookup: u32 {
        /// Do a direct table lookup vs full lookup using FIB rules.
        const DIRECT = ffi::BPF_FIB_LOOKUP_DIRECT;
        /// Perform lookup from an egress perspective (default is ingress).
        const OUTPUT = ffi::BPF_FIB_LOOKUP_OUTPUT;
    }
}

trivial! {
    pub struct Params(ffi::bpf_fib_lookup);
}

impl Params {
    #[inline]
    pub fn with_tos(&mut self, tos: u8) -> &mut Self {
        self.__bindgen_anon_1.tos = tos;
        self
    }

    #[inline]
    pub fn with_flowinfo(&mut self, flowinfo: be32) -> &mut Self {
        self.__bindgen_anon_1.flowinfo = flowinfo;
        self
    }

    #[inline]
    pub fn with_rt_metric(&mut self, rt_metric: u32) -> &mut Self {
        self.__bindgen_anon_1.rt_metric = rt_metric;
        self
    }

    #[inline]
    pub fn with_ipv4_src<T: Into<be32>>(&mut self, addr: T) -> &mut Self {
        self.__bindgen_anon_2.ipv4_src = addr.into();
        self
    }

    #[inline]
    pub fn with_ipv4_dst<T: Into<be32>>(&mut self, addr: T) -> &mut Self {
        self.__bindgen_anon_3.ipv4_dst = addr.into();
        self
    }

    #[inline]
    pub fn with_ipv6_src<T: Into<[u32; 4]>>(&mut self, addr: T) -> &mut Self {
        self.__bindgen_anon_2.ipv6_src = addr.into();
        self
    }

    #[inline]
    pub fn with_ipv6_dst<T: Into<[u32; 4]>>(&mut self, addr: T) -> &mut Self {
        self.__bindgen_anon_3.ipv6_dst = addr.into();
        self
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum LookupRet {
    InvalidParam,
    Drop(Reason),
    UnknownReason(i32),
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, TryFrom)]
pub enum Reason {
    /// lookup successful
    Success = ffi::BPF_FIB_LKUP_RET_SUCCESS,
    /// dest is blackholed; can be dropped
    BlackHole = ffi::BPF_FIB_LKUP_RET_BLACKHOLE,
    /// dest is unreachable; can be dropped
    Unreachable = ffi::BPF_FIB_LKUP_RET_UNREACHABLE,
    /// dest not allowed; can be dropped
    Prohibit = ffi::BPF_FIB_LKUP_RET_PROHIBIT,
    /// packet is not forwarded
    NotForwarded = ffi::BPF_FIB_LKUP_RET_NOT_FWDED,
    /// fwding is not enabled on ingress
    ForwardingDisabled = ffi::BPF_FIB_LKUP_RET_FWD_DISABLED,
    /// fwd requires encapsulation
    UnsupportLwt = ffi::BPF_FIB_LKUP_RET_UNSUPP_LWT,
    /// no neighbor entry for nh
    NoNeighbor = ffi::BPF_FIB_LKUP_RET_NO_NEIGH,
    /// fragmentation required to fwd
    FragNeeded = ffi::BPF_FIB_LKUP_RET_FRAG_NEEDED,
}

pub trait Context {
    type CType;

    fn as_ptr(&self) -> *mut Self::CType;
}

impl Context for *mut ffi::xdp_md {
    type CType = ffi::xdp_md;

    #[inline]
    fn as_ptr(&self) -> *mut Self::CType {
        *self
    }
}

impl Context for *mut ffi::sk_buff {
    type CType = ffi::sk_buff;

    #[inline]
    fn as_ptr(&self) -> *mut Self::CType {
        *self
    }
}

#[inline]
pub fn lookup<C, P>(ctx: C, params: &mut P, flags: Lookup) -> Result<(), LookupRet>
where
    C: Context,
    P: AsMut<ffi::bpf_fib_lookup>,
{
    let ret = bpf_fib_lookup(
        ctx.as_ptr() as *mut _,
        params.as_mut() as *mut _,
        mem::size_of::<ffi::bpf_fib_lookup>() as i32,
        flags.bits(),
    );

    if ret < 0 {
        Err(LookupRet::InvalidParam)
    } else if ret == 0 {
        Ok(())
    } else {
        Err(Reason::try_from(ret as u32)
            .map(LookupRet::Drop)
            .unwrap_or_else(|ret| LookupRet::UnknownReason(ret as i32)))
    }
}
