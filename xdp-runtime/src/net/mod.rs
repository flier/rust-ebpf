#![allow(non_camel_case_types)]

pub mod ether;
pub mod ipv4;
pub mod ipv6;
pub mod sock;

use core::mem;

use untrusted::{EndOfInput, Reader};

pub type be16 = u16;
pub type be32 = u32;
pub type sum16 = be16;

pub trait Readable: Sized {
    fn read<'a, 'b>(reader: &'a mut Reader) -> Result<&'b Self, EndOfInput> {
        let input = reader.read_bytes(mem::size_of::<Self>())?;

        unsafe {
            (input.as_slice_less_safe().as_ptr() as *const Self)
                .as_ref()
                .ok_or(EndOfInput)
        }
    }
}
