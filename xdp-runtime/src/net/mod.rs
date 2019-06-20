pub mod ether;
pub mod ipv4;
pub mod ipv6;
pub mod sock;

use core::mem;
use core::ptr::NonNull;

use crate::untrusted::{EndOfInput, Reader};

pub trait Readable: Sized {
    #[inline]
    fn read<'a, 'b>(reader: &'a mut Reader) -> Result<NonNull<Self>, EndOfInput> {
        let input = reader.read_bytes(mem::size_of::<Self>())?;

        Ok(unsafe { NonNull::new_unchecked(input.as_slice_less_safe().as_ptr() as *mut _) })
    }
}
