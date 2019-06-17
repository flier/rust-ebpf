#![cfg_attr(not(feature = "std"), no_std)]

#[macro_use]
extern crate cfg_if;

pub mod net;

use core::mem;
use core::slice;

use untrusted::Input;

pub const XDP_PACKET_HEADROOM: usize = 256;

/// User return codes for XDP prog type.
///
/// A valid XDP program must return one of these defined values.
/// All other return codes are reserved for future use.
/// Unknown return codes will result in packet drops and a warning via bpf_warn_invalid_xdp_action().
#[repr(i32)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Action {
    Aborted,
    Drop,
    Pass,
    Tx,
    Redirect,
}

/// user accessible metadata for XDP packet hook
pub struct Metadata {
    pub data: u32,
    pub data_end: u32,
    pub data_meta: u32,
    pub ingress_ifindex: u32, /* rxq->dev->ifindex */
    pub rx_queue_index: u32,  /* rxq->queue_index  */
}

impl Metadata {
    #[inline]
    pub fn input(&self) -> Option<Input> {
        unsafe { self.data().map(Input::from) }
    }

    #[inline]
    pub unsafe fn data(&self) -> Option<&[u8]> {
        if self.data != 0 && self.data < self.data_end {
            Some(slice::from_raw_parts(
                self.data as *const u8,
                (self.data_end - self.data) as usize,
            ))
        } else {
            None
        }
    }

    #[inline]
    pub unsafe fn data_mut(&self) -> Option<&mut [u8]> {
        if self.data != 0 && self.data < self.data_end {
            Some(slice::from_raw_parts_mut(
                self.data as *mut u8,
                (self.data_end - self.data) as usize,
            ))
        } else {
            None
        }
    }

    #[inline]
    pub unsafe fn as_ptr<T>(&self) -> Option<&mut T> {
        if self.data != 0
            && self.data < self.data_end
            && (self.data_end - self.data) >= mem::size_of::<T>() as u32
        {
            (self.data as *mut T).as_mut()
        } else {
            None
        }
    }
}
