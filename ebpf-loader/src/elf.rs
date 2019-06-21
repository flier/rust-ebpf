use std::convert::TryInto;
use std::ffi::CStr;
use std::mem;
use std::ptr;
use std::slice;

use failure::{bail, format_err, Error, Fail, ResultExt};
use goblin::elf::{
    header::{EM_BPF, ET_REL},
    section_header::{SectionHeader, SHT_PROGBITS, SHT_REL},
    sym::{Sym, STB_GLOBAL},
};

use ebpf_core::{
    ffi, prog, Attach, Insn, Map, Object, Opcode, Program, Type, BPF_LICENSE_SEC, BPF_MAPS_SEC,
    BPF_VERSION_SEC, BTF_ELF_SEC, BTF_EXT_ELF_SEC,
};

use crate::prog::prog_type_by_name;
use crate::Parser;

impl<'a> Parser<goblin::elf::Elf<'a>> {
    pub fn parse(&self, buf: &[u8]) -> Result<Object, Error> {
        if self.obj.header.e_type != ET_REL || self.obj.header.e_machine != EM_BPF {
            bail!("not an eBPF object file");
        }

        if self.obj.header.endianness()? != scroll::NATIVE {
            bail!("endianness mismatch.")
        }

        let mut license = None;
        let mut version = None;
        let mut programs = vec![];
        let mut maps_section = None;
        let mut text_section = None;

        for (idx, sec) in self.obj.section_headers.iter().enumerate() {
            let name = self.resolve_name(sec.sh_name)?;
            trace!("parse `{}` section: {:?}", name, sec);

            let section_data = || {
                buf.get(sec.file_range()).ok_or_else(|| {
                    format_err!(
                        "`{}` section data {:?} out of bound",
                        name,
                        sec.file_range()
                    )
                })
            };

            match name {
                BPF_LICENSE_SEC if sec.sh_type == SHT_PROGBITS => {
                    license = Some(
                        CStr::from_bytes_with_nul(section_data()?)?
                            .to_str()?
                            .to_owned(),
                    );

                    debug!("kernel license: {}", license.as_ref().unwrap());
                }
                BPF_VERSION_SEC if sec.sh_type == SHT_PROGBITS => {
                    version = Some(u32::from_ne_bytes(section_data()?.try_into()?));

                    debug!("kernel version: {:x}", version.as_ref().unwrap());
                }
                BPF_MAPS_SEC => {
                    debug!("`{}` section", name);

                    maps_section = Some((idx, sec));
                }
                BTF_ELF_SEC => {
                    // TODO btf__new
                    debug!("`{}` section", name);
                }
                BTF_EXT_ELF_SEC => {
                    // TODO btf_ext_data
                    debug!("`{}` section", name);
                }
                _ if sec.sh_type == SHT_PROGBITS && sec.is_executable() && sec.sh_size > 0 => {
                    if name == ".text" {
                        text_section = Some(idx);
                    }

                    let (ty, attach) = prog_type_by_name(name).unwrap_or((Type::Unspec, None));
                    let insns = unsafe {
                        let data = buf.as_ptr().add(sec.sh_offset as usize);
                        let len = sec.sh_size as usize / mem::size_of::<Insn>();

                        slice::from_raw_parts(data as *const _, len)
                    };

                    debug!(
                        "{:?} kernel program #{} @ section `{}` with {} insns",
                        ty,
                        idx,
                        name,
                        insns.len()
                    );

                    programs.push((name, ty, attach, idx, insns.to_vec()));
                }
                _ if sec.sh_type == SHT_REL => {}
                _ => {
                    trace!("ignore `{}` section", name);
                }
            }
        }

        let maps = if let Some((idx, sec)) = maps_section {
            self.init_maps(buf, idx, sec)?
        } else {
            Vec::new()
        };

        let mut programs = self
            .resolve_program_names(programs, text_section)
            .context("resolve program names")?;

        self.relocate_programs(
            &mut programs,
            &maps,
            maps_section.map(|(idx, _)| idx),
            text_section,
        )?;

        Ok(Object {
            license,
            version,
            programs,
            maps,
        })
    }

    fn init_maps(&self, buf: &[u8], idx: usize, sec: &SectionHeader) -> Result<Vec<Map>, Error> {
        let mut maps = Vec::new();

        let data = buf.get(sec.file_range()).ok_or_else(|| {
            format_err!("`maps` section data {:?} out of bound", sec.file_range())
        })?;

        let nr_maps = self
            .obj
            .syms
            .iter()
            .filter(|sym| sym.st_shndx == idx)
            .count();
        let map_def_sz = data.len() / nr_maps;

        for sym in self.obj.syms.iter().filter(|sym| sym.st_shndx == idx) {
            let name = self
                .obj
                .strtab
                .get(sym.st_name)
                .transpose()?
                .ok_or_else(|| format_err!("resolve map name failed, idx={:x}", sym.st_name))?;

            let mut map_def: ffi::bpf_map_def = unsafe { mem::zeroed() };

            unsafe {
                ptr::copy_nonoverlapping(
                    data.as_ptr() as *const u8,
                    &mut map_def as *mut _ as *mut u8,
                    mem::size_of::<ffi::bpf_map_def>().min(map_def_sz),
                )
            }

            if map_def_sz > mem::size_of::<ffi::bpf_map_def>()
                && data[mem::size_of::<ffi::bpf_map_def>()..]
                    .iter()
                    .any(|&b| b != 0)
            {
                bail!("maps section has unrecognized, non-zero options");
            }

            let map = Map::with_def(name, sym.st_value as usize, &map_def)?;

            debug!(
                "#{} map `{}` @ section `{}`: {:?}",
                maps.len(),
                name,
                self.resolve_name(sec.sh_name)?,
                map
            );

            maps.push(map)
        }

        maps.sort_by_cached_key(|map| map.offset);

        Ok(maps)
    }

    fn resolve_program_names(
        &self,
        programs: impl IntoIterator<Item = (&'a str, Type, Option<Attach>, usize, Vec<Insn>)>,
        text_section: Option<usize>,
    ) -> Result<Vec<Program>, Error> {
        programs
            .into_iter()
            .map(|(title, ty, attach, idx, insns)| {
                let name = self
                    .resolve_symbol(|sym| sym.st_shndx == idx && sym.st_bind() == STB_GLOBAL)
                    .and_then(|sym| self.resolve_name(sym.st_name))
                    .or_else(|_| {
                        if text_section == Some(idx) {
                            Ok(".text")
                        } else {
                            Err(format_err!("program `{}` symbol not found", title))
                        }
                    })?;

                debug!(
                    "#{} program `{}` @ secion `{}` with {} insns",
                    idx,
                    name,
                    title,
                    insns.len()
                );

                Ok(Program::new(name, ty, attach, title, idx, insns))
            })
            .collect::<Result<Vec<_>, _>>()
    }

    fn resolve_symbol<P: FnMut(&Sym) -> bool>(&self, predicate: P) -> Result<Sym, Error> {
        self.obj
            .syms
            .iter()
            .find(predicate)
            .ok_or_else(|| format_err!("symbol not found"))
    }

    fn resolve_name(&self, idx: usize) -> Result<&str, Error> {
        self.obj
            .strtab
            .get(idx)
            .ok_or_else(|| format_err!("index out of bound"))?
            .map_err(|err| err.context("read string").into())
    }

    fn relocate_programs(
        &self,
        programs: &mut [Program],
        maps: &[Map],
        maps_idx: Option<usize>,
        text_idx: Option<usize>,
    ) -> Result<(), Error> {
        for (idx, sec) in &self.obj.shdr_relocs {
            if let Some(prog) = programs.iter_mut().find(|prog| prog.idx == *idx) {
                trace!("relocate program #{} `{}`", prog.idx, prog.name);

                for reloc in sec.iter() {
                    let sym = self.resolve_symbol(|sym| sym.st_shndx == reloc.r_sym)?;

                    trace!(
                        "reloc for #{}, value = {}, name = {}",
                        reloc.r_sym,
                        sym.st_value,
                        sym.st_name
                    );

                    if Some(sym.st_shndx) != maps_idx && Some(sym.st_shndx) != text_idx {
                        bail!("program '{}' contains non-map related relo data pointing to section #{}", prog.name, sym.st_shndx);
                    }

                    let insn_idx = reloc.r_offset as usize / mem::size_of::<Insn>();

                    trace!("reloc insn #{}", insn_idx);

                    if Opcode::from_bits_truncate(prog.insns[insn_idx].code)
                        != Opcode::LD | Opcode::IMM | Opcode::DW
                    {
                        bail!(
                            "invalid relocate for insns[{}].code = {:?}",
                            insn_idx,
                            prog.insns[insn_idx].code
                        );
                    }

                    let map_idx = maps
                        .iter()
                        .position(|map| map.offset == sym.st_value as usize)
                        .ok_or_else(|| format_err!("map @ {} not found", sym.st_value))?;

                    prog.relocs.push(prog::Reloc::LD64 { insn_idx, map_idx })
                }
            }
        }

        Ok(())
    }
}
