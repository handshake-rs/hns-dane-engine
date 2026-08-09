use thiserror::Error;

#[derive(Debug, Error, Eq, PartialEq)]
pub enum ParseError {
    #[error("unexpected end of input")]
    UnexpectedEof,
    #[error("trailing bytes after parse")]
    TrailingBytes,
    #[error("length exceeds configured parser limit")]
    LengthLimit,
    #[error("invalid DNS label")]
    InvalidDnsLabel,
    #[error("invalid DNS compression pointer")]
    InvalidDnsPointer,
    #[error("invalid SVCB/HTTPS resource record data")]
    InvalidSvcb,
}

pub struct Reader<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, offset: 0 }
    }

    pub fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.offset)
    }

    pub fn offset(&self) -> usize {
        self.offset
    }

    pub fn ensure_finished(&self) -> Result<(), ParseError> {
        if self.remaining() == 0 {
            Ok(())
        } else {
            Err(ParseError::TrailingBytes)
        }
    }

    pub fn read_u8(&mut self) -> Result<u8, ParseError> {
        Ok(self.read_array::<1>()?[0])
    }

    pub fn read_u16_be(&mut self) -> Result<u16, ParseError> {
        Ok(u16::from_be_bytes(self.read_array()?))
    }

    pub fn read_u32_be(&mut self) -> Result<u32, ParseError> {
        Ok(u32::from_be_bytes(self.read_array()?))
    }

    pub fn read_u32_le(&mut self) -> Result<u32, ParseError> {
        Ok(u32::from_le_bytes(self.read_array()?))
    }

    pub fn read_u64_le(&mut self) -> Result<u64, ParseError> {
        Ok(u64::from_le_bytes(self.read_array()?))
    }

    pub fn read_bytes(&mut self, len: usize) -> Result<&'a [u8], ParseError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(ParseError::LengthLimit)?;
        if end > self.data.len() {
            return Err(ParseError::UnexpectedEof);
        }

        let out = &self.data[self.offset..end];
        self.offset = end;
        Ok(out)
    }

    pub fn read_array<const N: usize>(&mut self) -> Result<[u8; N], ParseError> {
        let bytes = self.read_bytes(N)?;
        let mut out = [0u8; N];
        out.copy_from_slice(bytes);
        Ok(out)
    }
}
