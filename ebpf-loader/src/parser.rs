use failure::{bail, Error};

use ebpf_core::{Attach, Object, Type};

pub fn parse<B: AsRef<[u8]>>(buf: B) -> Result<Object, Error> {
    use goblin::Object;

    let buf = buf.as_ref();

    let obj = match Object::parse(buf)? {
        Object::Elf(elf) => Parser::new(elf).parse(buf)?,
        Object::PE(_pe) => unimplemented!(),
        Object::Mach(_mach) => unimplemented!(),
        Object::Archive(_archive) => unimplemented!(),
        Object::Unknown(magic) => bail!("unknown format, magic: {}", magic),
    };

    if obj.programs.is_empty() {
        bail!("object file doesn't contain eBPF program");
    }

    Ok(obj)
}

#[derive(Debug)]
pub struct Parser<T> {
    pub obj: T,
    pub prog_type: Option<Type>,
    pub expected_attach_type: Option<Attach>,
}

impl<T> Parser<T> {
    fn new(obj: T) -> Self {
        Parser {
            obj,
            prog_type: None,
            expected_attach_type: None,
        }
    }
}
