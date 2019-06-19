pub mod ether;
pub mod ipv4;
pub mod ipv6;
pub mod sock;

use core::mem;

use untrusted::{EndOfInput, Reader};

pub trait Readable: Sized {
    #[inline]
    fn read<'a, 'b>(reader: &'a mut Reader) -> Result<&'b Self, EndOfInput> {
        let input = reader.read_bytes(mem::size_of::<Self>())?;

        unsafe {
            (input.as_slice_less_safe().as_ptr() as *const Self)
                .as_ref()
                .ok_or(EndOfInput)
        }
    }
}
