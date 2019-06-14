use crate::ffi;

#[derive(Debug, Default)]
pub struct Program {
    pub name: String,
    pub title: String,
    pub idx: usize,
    pub insns: Vec<Insn>,
    pub relocs: Vec<Reloc>,
}

impl Program {
    pub fn new<S: Into<String>>(name: S, title: S, idx: usize, insns: Vec<Insn>) -> Self {
        Program {
            name: name.into(),
            title: title.into(),
            idx,
            insns,
            relocs: Vec::new(),
        }
    }
}

#[derive(Debug)]
pub enum Reloc {
    LD64 { insn_idx: usize, map_idx: usize },
    CALL { insn_idx: usize, text_off: usize },
}

#[repr(C, packed)]
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Insn {
    /// opcode
    pub code: u8,
    /// dest register
    pub reg: u8,
    /// signed offset
    pub off: i16,
    /// signed immediate constant
    pub imm: i32,
}

bitflags! {
    #[derive(Default)]
    pub struct Opcode: u8 {
        // Instruction classes
        const CLASS_MASK = 0x07;
        const LD = ffi::BPF_LD as u8;
        const LDX = ffi::BPF_LDX as u8;
        const ST = ffi::BPF_ST as u8;
        const STX = ffi::BPF_STX as u8;
        const ALU = ffi::BPF_ALU as u8;
        const JMP = ffi::BPF_JMP as u8;
        const RET = ffi::BPF_RET as u8;
        const MISC = ffi::BPF_MISC as u8;

        // ld/ldx fields
        const SIZE_MASK = 0x18;
        const W = ffi::BPF_W as u8; /* 32-bit */
        const H = ffi::BPF_H as u8; /* 16-bit */
        const B = ffi::BPF_B as u8; /*  8-bit */
        const DW = ffi::BPF_DW as u8; /* 64-bit */

        const MODE_MASK = 0xe0;
        const IMM = ffi::BPF_IMM as u8;
        const ABS = ffi::BPF_ABS as u8;
        const IND = ffi::BPF_IND as u8;
        const MEM = ffi::BPF_MEM as u8;
        const LEN = ffi::BPF_LEN as u8;
        const MSH = ffi::BPF_MSH as u8;

        /* alu/jmp fields */
        const BPF_OP_MASK = 0xf0;
        const ADD = ffi::BPF_ADD as u8;
        const SUB = ffi::BPF_SUB as u8;
        const MUL = ffi::BPF_MUL as u8;
        const DIV = ffi::BPF_DIV as u8;
        const OR = ffi::BPF_OR as u8;
        const AND = ffi::BPF_AND as u8;
        const LSH = ffi::BPF_LSH as u8;
        const RSH = ffi::BPF_RSH as u8;
        const NEG = ffi::BPF_NEG as u8;
        const MOD = ffi::BPF_MOD as u8;
        const XOR = ffi::BPF_XOR as u8;

        const JA = ffi::BPF_JA as u8;
        const JEQ = ffi::BPF_JEQ as u8;
        const JGT = ffi::BPF_JGT as u8;
        const JGE = ffi::BPF_JGE as u8;
        const JET = ffi::BPF_JSET as u8;

        const BPF_SRC_MASK = 0x08;
        const K = ffi::BPF_K as u8;
        const X = ffi::BPF_X as u8;

        /* instruction classes */
        const JMP32 = ffi::BPF_JMP32 as u8;	/* jmp mode in word width */
        const ALU64 = ffi::BPF_ALU64 as u8;	/* alu mode in double word width */

        /* ld/ldx fields */
        const XADD = ffi::BPF_XADD as u8;	/* exclusive add */

        /* alu/jmp fields */
        const MOV = ffi::BPF_MOV as u8;	    /* mov reg to reg */
        const ARSH = ffi::BPF_ARSH as u8;	/* sign extending arithmetic shift right */

        /* change endianness of a register */
        const END = ffi::BPF_END as u8;	    /* flags for endianness conversion: */
        const TO_LE= ffi::BPF_TO_LE as u8;	/* convert to little-endian */
        const TO_BE = ffi::BPF_TO_BE as u8;	/* convert to big-endian */
        const FROM_LE = ffi::BPF_FROM_LE as u8;
        const FROM_BE = ffi::BPF_FROM_BE as u8;

        /* jmp encodings */
        const JNE = ffi::BPF_JNE as u8;	    /* jump != */
        const JLT = ffi::BPF_JLT as u8;	    /* LT is unsigned, '<' */
        const JLE = ffi::BPF_JLE as u8;	    /* LE is unsigned, '<=' */
        const JSGT = ffi::BPF_JSGT as u8;	/* SGT is signed '>', GT in x86 */
        const JSGE = ffi::BPF_JSGE as u8;	/* SGE is signed '>=', GE in x86 */
        const JSLT = ffi::BPF_JSLT as u8;	/* SLT is signed, '<' */
        const JSLE = ffi::BPF_JSLE as u8;	/* SLE is signed, '<=' */
        const CALL = ffi::BPF_CALL as u8;	/* function call */
        const EXIT = ffi::BPF_EXIT as u8;	/* function return */
    }
}
