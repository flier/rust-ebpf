use core::convert::From;
use core::fmt;

use crate::net::{be16, be32, sum16, Readable};

#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
pub struct Header {
    pub verion_ihl: u8,
    pub tos: u8,
    pub tot_len: be16,
    pub id: be16,
    pub frag_off: be16,
    pub ttl: u8,
    pub protocol: u8,
    pub check: sum16,
    pub saddr: Addr,
    pub daddr: Addr,
    /*The options start here. */
}

impl Readable for Header {}

impl Header {
    pub fn total_len(&self) -> u16 {
        u16::from_be(self.tot_len)
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union Addr {
    pub octets: [u8; 4],
    pub hextets: [u16; 2],
    pub quadlet: be32,
}

impl Addr {
    pub fn octets(&self) -> [u8; 4] {
        unsafe { self.octets }
    }

    pub fn hextets(&self) -> [u16; 2] {
        unsafe { self.hextets }
    }

    pub fn quadlet(&self) -> be32 {
        unsafe { self.quadlet }
    }
}

macro_rules! impl_from {
	($name:ident : $ty:ty) => {
		impl From<$ty> for Addr {
			fn from($name: $ty) -> Self {
				Addr { $name }
			}
		}

		impl From<Addr> for $ty {
			fn from(addr: Addr) -> $ty {
				unsafe { addr.$name }
			}
		}
	};
}

impl_from!(octets: [u8; 4]);
impl_from!(hextets: [u16; 2]);
impl_from!(quadlet: be32);

impl fmt::Display for Addr {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let octets = unsafe { self.octets };

        write!(
            fmt,
            "{}.{}.{}.{}",
            octets[0], octets[1], octets[2], octets[3]
        )
    }
}

impl fmt::Debug for Addr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}
