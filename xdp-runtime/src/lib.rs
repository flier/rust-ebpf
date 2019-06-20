#![cfg_attr(not(feature = "std"), no_std)]

pub mod net;

mod kernel;
pub use kernel::*;

use core::ops::Deref;
use core::ptr::NonNull;
use core::slice;

use ebpf_runtime::{
    ffi, helpers,
    kernel::fib,
    untrusted::{self, Input},
    MapSpec, TryFrom,
};

pub const XDP_PACKET_HEADROOM: usize = 256;

/// User return codes for XDP prog type.
///
/// A valid XDP program must return one of these defined values.
/// All other return codes are reserved for future use.
/// Unknown return codes will result in packet drops and a warning via bpf_warn_invalid_xdp_action().
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, TryFrom)]
pub enum Action {
    Aborted = ffi::xdp_action_XDP_ABORTED,
    Drop = ffi::xdp_action_XDP_DROP,
    Pass = ffi::xdp_action_XDP_PASS,
    Tx = ffi::xdp_action_XDP_TX,
    Redirect = ffi::xdp_action_XDP_REDIRECT,
}

/// user accessible metadata for XDP packet hook
#[repr(transparent)]
#[derive(Debug)]
pub struct Metadata(NonNull<ffi::xdp_md>);

impl Deref for Metadata {
    type Target = ffi::xdp_md;

    #[inline]
    fn deref(&self) -> &Self::Target {
        unsafe { self.0.as_ref() }
    }
}

impl fib::Context for &Metadata {
    type CType = ffi::xdp_md;

    #[inline]
    fn as_ptr(&self) -> *mut Self::CType {
        self.0.as_ptr()
    }
}

impl Metadata {
    #[inline]
    pub fn as_ptr(&self) -> *const ffi::xdp_md {
        self.0.as_ptr() as *const _
    }

    #[inline]
    pub fn input(&self) -> Option<Input> {
        unsafe { self.data().map(Input::from) }
    }

    #[inline]
    pub unsafe fn data(&self) -> Option<&[u8]> {
        let md = self.0.as_ref();

        if md.data != 0 && md.data < md.data_end {
            Some(slice::from_raw_parts(
                md.data as *const u8,
                (md.data_end - md.data) as usize,
            ))
        } else {
            None
        }
    }

    #[inline]
    pub unsafe fn data_mut(&self) -> Option<&mut [u8]> {
        let md = self.0.as_ref();

        if md.data != 0 && md.data < md.data_end {
            Some(slice::from_raw_parts_mut(
                md.data as *mut u8,
                (md.data_end - md.data) as usize,
            ))
        } else {
            None
        }
    }
}
