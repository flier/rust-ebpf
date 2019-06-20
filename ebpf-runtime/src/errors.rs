use failure::Fail;

#[derive(Debug, Fail)]
pub enum EbpfError {
    #[fail(display = "invalid input params")]
    InvalidParam,

    #[fail(display = "unexpected return value: {}", _0)]
    UnexpectedReturn(i32),

    #[fail(display = "unexpected end of input")]
    EndOfInput,
}

impl From<untrusted::EndOfInput> for EbpfError {
    #[inline]
    fn from(_: untrusted::EndOfInput) -> Self {
        EbpfError::EndOfInput
    }
}
