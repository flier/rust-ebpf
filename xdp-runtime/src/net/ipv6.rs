#![allow(clippy::many_single_char_names)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::range_plus_one)]

use core::fmt;
use core::ops::Range;

use ebpf_runtime::{be16, be32};

use crate::net::Readable;

pub const IPV6_FLOWINFO_MASK: be32 = 0x0FFF_FFFFu32.to_be();

#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
pub struct Header {
    pub version_priority: u8,
    pub flow_lbl: [u8; 3],
    pub payload_len: be16,
    pub nexthdr: u8,
    pub hop_limit: u8,
    pub saddr: Addr,
    pub daddr: Addr,
}

impl Readable for Header {}

impl Header {
    #[inline]
    pub fn flowinfo(&self) -> u32 {
        let &[a, b, c] = &self.flow_lbl;
        let bytes = [self.version_priority, a, b, c];

        u32::from_be_bytes(bytes) & IPV6_FLOWINFO_MASK
    }

    #[inline]
    pub fn payload_len(&self) -> u16 {
        u16::from_be(self.payload_len)
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union Addr {
    pub octets: [u8; 16],
    pub hextets: [u16; 8],
    pub quadlets: [u32; 4],
}

impl Addr {
    #[inline]
    pub const fn new(a: u16, b: u16, c: u16, d: u16, e: u16, f: u16, g: u16, h: u16) -> Addr {
        Addr {
            hextets: [a, b, c, d, e, f, g, h],
        }
    }

    #[inline]
    pub fn octets(&self) -> [u8; 16] {
        unsafe { self.octets }
    }

    #[inline]
    pub fn hextets(&self) -> [u16; 8] {
        unsafe { self.hextets }
    }

    #[inline]
    pub fn quadlets(&self) -> [u32; 4] {
        unsafe { self.quadlets }
    }
}

macro_rules! impl_from {
    ($name:ident : $ty:ty) => {
        impl From<$ty> for Addr {
            #[inline]
            fn from($name: $ty) -> Self {
                Addr { $name }
            }
        }

        impl From<Addr> for $ty {
            #[inline]
            fn from(addr: Addr) -> $ty {
                unsafe { addr.$name }
            }
        }
    };
}

impl_from!(octets: [u8; 16]);
impl_from!(hextets: [u16; 8]);
impl_from!(quadlets: [u32; 4]);

impl fmt::Display for Addr {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let hextets = unsafe { self.hextets };

        match hextets {
            // We need special cases for :: and ::1, otherwise they're formatted as ::0.0.0.[01]
            [0, 0, 0, 0, 0, 0, 0, 0] => write!(fmt, "::"),
            [0, 0, 0, 0, 0, 0, 0, 1] => write!(fmt, "::1"),
            // Ipv4 Compatible address
            [0, 0, 0, 0, 0, 0, g, h] => write!(
                fmt,
                "::{}.{}.{}.{}",
                (g >> 8) as u8,
                g as u8,
                (h >> 8) as u8,
                h as u8
            ),
            // Ipv4-Mapped address
            [0, 0, 0, 0, 0, 0xffff, g, h] => write!(
                fmt,
                "::ffff:{}.{}.{}.{}",
                (g >> 8) as u8,
                g as u8,
                (h >> 8) as u8,
                h as u8
            ),
            _ => {
                match hextets.iter().enumerate().fold(
                    (None, None),
                    |(current, longest): (Option<Range<usize>>, Option<Range<usize>>), (i, &u)| {
                        if u == 0 {
                            let current = current
                                .as_ref()
                                .map_or_else(|| i..i + 1, |ref range| range.start..i + 1);
                            let longest = match longest {
                                Some(ref longest) if longest.len() >= current.len() => longest,
                                _ => &current,
                            };

                            (Some(current.clone()), Some(longest.clone()))
                        } else {
                            (None, longest)
                        }
                    },
                ) {
                    (_, Some(ref zeros)) if zeros.len() > 1 => {
                        for (i, b) in hextets[..zeros.start].iter().enumerate() {
                            if i > 0 {
                                fmt.write_str(":")?;
                            }
                            write!(fmt, "{:x}", b)?;
                        }
                        fmt.write_str("::")?;
                        for (i, b) in hextets[zeros.end..].iter().enumerate() {
                            if i > 0 {
                                fmt.write_str(":")?;
                            }
                            write!(fmt, "{:x}", b)?;
                        }
                        Ok(())
                    }
                    _ => {
                        let &[a, b, c, d, e, f, g, h] = &hextets;

                        write!(
                            fmt,
                            "{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
                            a, b, c, d, e, f, g, h
                        )
                    }
                }
            }
        }
    }
}

impl fmt::Debug for Addr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv6_addr_to_string() {
        // ipv4-mapped address
        let a1 = Addr::new(0, 0, 0, 0, 0, 0xffff, 0xc000, 0x280);
        assert_eq!(a1.to_string(), "::ffff:192.0.2.128");

        // ipv4-compatible address
        let a1 = Addr::new(0, 0, 0, 0, 0, 0, 0xc000, 0x280);
        assert_eq!(a1.to_string(), "::192.0.2.128");

        // v6 address with no zero segments
        assert_eq!(
            Addr::new(8, 9, 10, 11, 12, 13, 14, 15).to_string(),
            "8:9:a:b:c:d:e:f"
        );

        // reduce a single run of zeros
        assert_eq!(
            "ae::ffff:102:304",
            Addr::new(0xae, 0, 0, 0, 0, 0xffff, 0x0102, 0x0304).to_string()
        );

        // don't reduce just a single zero segment
        assert_eq!(
            "1:2:3:4:5:6:0:8",
            Addr::new(1, 2, 3, 4, 5, 6, 0, 8).to_string()
        );

        // 'any' address
        assert_eq!("::", Addr::new(0, 0, 0, 0, 0, 0, 0, 0).to_string());

        // loopback address
        assert_eq!("::1", Addr::new(0, 0, 0, 0, 0, 0, 0, 1).to_string());

        // ends in zeros
        assert_eq!("1::", Addr::new(1, 0, 0, 0, 0, 0, 0, 0).to_string());

        // two runs of zeros, second one is longer
        assert_eq!("1:0:0:4::8", Addr::new(1, 0, 0, 4, 0, 0, 0, 8).to_string());

        // two runs of zeros, equal length
        assert_eq!(
            "1::4:5:0:0:8",
            Addr::new(1, 0, 0, 4, 5, 0, 0, 8).to_string()
        );
    }

}
