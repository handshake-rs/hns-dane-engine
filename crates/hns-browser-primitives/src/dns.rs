use crate::bytes::{ParseError, Reader};

pub const MAX_DNS_NAME_LEN: usize = 253;
pub const MAX_DNS_LABEL_LEN: usize = 63;
pub const MAX_RDATA_LEN: usize = 65_535;
pub const MAX_DNS_QUESTIONS: usize = 16;
pub const MAX_DNS_RECORDS: usize = 2_048;

pub const SVCB_PARAM_MANDATORY: u16 = 0;
pub const SVCB_PARAM_ALPN: u16 = 1;
pub const SVCB_PARAM_NO_DEFAULT_ALPN: u16 = 2;
pub const SVCB_PARAM_PORT: u16 = 3;
pub const SVCB_PARAM_IPV4HINT: u16 = 4;
pub const SVCB_PARAM_ECH: u16 = 5;
pub const SVCB_PARAM_IPV6HINT: u16 = 6;
pub const SVCB_PARAM_DOHPATH: u16 = 7;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsName(Vec<String>);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DnsHeader {
    pub id: u16,
    pub flags: DnsFlags,
    pub question_count: u16,
    pub answer_count: u16,
    pub authority_count: u16,
    pub additional_count: u16,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DnsFlags {
    bits: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsQuestion {
    pub name: DnsName,
    pub record_type: RecordType,
    pub class: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsMessage {
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<ResourceRecord>,
    pub authorities: Vec<ResourceRecord>,
    pub additionals: Vec<ResourceRecord>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsEncodeConfig {
    pub max_message_len: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecordType {
    A,
    Ns,
    Cname,
    Soa,
    Txt,
    Aaaa,
    Srv,
    Ds,
    Rrsig,
    Nsec,
    Dnskey,
    Nsec3,
    Tlsa,
    Svcb,
    Https,
    Unknown(u16),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResourceRecord {
    pub name: DnsName,
    pub record_type: RecordType,
    pub class: u16,
    pub ttl: u32,
    pub rdata: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SvcbRecord {
    pub svc_priority: u16,
    pub target_name: DnsName,
    pub params: Vec<SvcParam>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SvcParam {
    pub key: u16,
    pub value: Vec<u8>,
}

impl DnsName {
    pub fn root() -> Self {
        Self(Vec::new())
    }

    pub fn parse_wire(message: &[u8], offset: usize) -> Result<(Self, usize), ParseError> {
        let mut labels = Vec::new();
        let mut cursor = offset;
        let mut consumed = None;
        let mut jumps = 0u8;

        loop {
            let length = *message.get(cursor).ok_or(ParseError::UnexpectedEof)?;
            cursor += 1;

            if length & 0xc0 == 0xc0 {
                let next = *message.get(cursor).ok_or(ParseError::UnexpectedEof)?;
                cursor += 1;
                let pointer = (((length & 0x3f) as usize) << 8) | next as usize;
                if pointer >= message.len() {
                    return Err(ParseError::InvalidDnsPointer);
                }
                consumed.get_or_insert(cursor);
                cursor = pointer;
                jumps = jumps.checked_add(1).ok_or(ParseError::InvalidDnsPointer)?;
                if jumps > 16 {
                    return Err(ParseError::InvalidDnsPointer);
                }
                continue;
            }

            if length & 0xc0 != 0 {
                return Err(ParseError::InvalidDnsLabel);
            }

            if length == 0 {
                let end = consumed.unwrap_or(cursor);
                return Ok((Self(labels), end));
            }

            if length as usize > MAX_DNS_LABEL_LEN {
                return Err(ParseError::InvalidDnsLabel);
            }

            let end = cursor
                .checked_add(length as usize)
                .ok_or(ParseError::LengthLimit)?;
            let label_bytes = message.get(cursor..end).ok_or(ParseError::UnexpectedEof)?;
            if !is_valid_dns_label(label_bytes) {
                return Err(ParseError::InvalidDnsLabel);
            }

            let label = std::str::from_utf8(label_bytes)
                .map_err(|_| ParseError::InvalidDnsLabel)?
                .to_ascii_lowercase();
            labels.push(label);

            // RFC 1035 permits a complete wire name of 255 octets, including
            // the terminating root label. MAX_DNS_NAME_LEN is the 253-byte
            // presentation form, so length octets may total one byte more.
            if labels.iter().map(|label| label.len() + 1).sum::<usize>() > MAX_DNS_NAME_LEN + 1 {
                return Err(ParseError::LengthLimit);
            }

            cursor = end;
        }
    }

    pub fn labels(&self) -> &[String] {
        &self.0
    }

    pub fn from_ascii(name: &str) -> Result<Self, ParseError> {
        let trimmed = name.trim().trim_end_matches('.');
        if trimmed.is_empty() {
            return Ok(Self::root());
        }

        let mut labels = Vec::new();
        for label in trimmed.split('.') {
            if label.is_empty()
                || label.len() > MAX_DNS_LABEL_LEN
                || !is_valid_dns_label(label.as_bytes())
            {
                return Err(ParseError::InvalidDnsLabel);
            }
            labels.push(label.to_ascii_lowercase());
        }

        let name = Self(labels);
        if name.wire_len() > MAX_DNS_NAME_LEN + 2 {
            return Err(ParseError::LengthLimit);
        }

        Ok(name)
    }

    pub fn encode_wire(&self, out: &mut Vec<u8>) -> Result<(), ParseError> {
        for label in &self.0 {
            if label.len() > MAX_DNS_LABEL_LEN {
                return Err(ParseError::InvalidDnsLabel);
            }
            out.push(label.len() as u8);
            out.extend(label.as_bytes());
        }
        out.push(0);
        Ok(())
    }

    fn wire_len(&self) -> usize {
        if self.0.is_empty() {
            1
        } else {
            self.0.iter().map(|label| label.len() + 1).sum::<usize>() + 1
        }
    }
}

impl DnsHeader {
    pub fn parse(data: &[u8]) -> Result<Self, ParseError> {
        let mut reader = Reader::new(data);
        Ok(Self {
            id: reader.read_u16_be()?,
            flags: DnsFlags::new(reader.read_u16_be()?),
            question_count: reader.read_u16_be()?,
            answer_count: reader.read_u16_be()?,
            authority_count: reader.read_u16_be()?,
            additional_count: reader.read_u16_be()?,
        })
    }
}

impl DnsFlags {
    pub const fn new(bits: u16) -> Self {
        Self { bits }
    }

    pub const fn bits(self) -> u16 {
        self.bits
    }

    pub const fn is_response(self) -> bool {
        self.bits & 0x8000 != 0
    }

    pub const fn opcode(self) -> u8 {
        ((self.bits >> 11) & 0x0f) as u8
    }

    pub const fn authoritative_answer(self) -> bool {
        self.bits & 0x0400 != 0
    }

    pub const fn truncated(self) -> bool {
        self.bits & 0x0200 != 0
    }

    pub const fn recursion_desired(self) -> bool {
        self.bits & 0x0100 != 0
    }

    pub const fn recursion_available(self) -> bool {
        self.bits & 0x0080 != 0
    }

    pub const fn rcode(self) -> u8 {
        (self.bits & 0x000f) as u8
    }
}

impl std::fmt::Display for DnsName {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.0.is_empty() {
            formatter.write_str(".")
        } else {
            formatter.write_str(&self.0.join("."))
        }
    }
}

impl RecordType {
    pub fn from_code(code: u16) -> Self {
        match code {
            1 => Self::A,
            2 => Self::Ns,
            5 => Self::Cname,
            6 => Self::Soa,
            16 => Self::Txt,
            28 => Self::Aaaa,
            33 => Self::Srv,
            43 => Self::Ds,
            46 => Self::Rrsig,
            47 => Self::Nsec,
            48 => Self::Dnskey,
            50 => Self::Nsec3,
            52 => Self::Tlsa,
            64 => Self::Svcb,
            65 => Self::Https,
            other => Self::Unknown(other),
        }
    }

    pub fn code(self) -> u16 {
        match self {
            Self::A => 1,
            Self::Ns => 2,
            Self::Cname => 5,
            Self::Soa => 6,
            Self::Txt => 16,
            Self::Aaaa => 28,
            Self::Srv => 33,
            Self::Ds => 43,
            Self::Rrsig => 46,
            Self::Nsec => 47,
            Self::Dnskey => 48,
            Self::Nsec3 => 50,
            Self::Tlsa => 52,
            Self::Svcb => 64,
            Self::Https => 65,
            Self::Unknown(code) => code,
        }
    }
}

impl ResourceRecord {
    pub fn parse(message: &[u8], offset: usize) -> Result<(Self, usize), ParseError> {
        let (name, mut cursor) = DnsName::parse_wire(message, offset)?;
        let fixed = message
            .get(cursor..cursor.checked_add(10).ok_or(ParseError::LengthLimit)?)
            .ok_or(ParseError::UnexpectedEof)?;
        let record_type = RecordType::from_code(u16::from_be_bytes([fixed[0], fixed[1]]));
        let class = u16::from_be_bytes([fixed[2], fixed[3]]);
        let ttl = u32::from_be_bytes([fixed[4], fixed[5], fixed[6], fixed[7]]);
        let rdlength = u16::from_be_bytes([fixed[8], fixed[9]]) as usize;
        if rdlength > MAX_RDATA_LEN {
            return Err(ParseError::LengthLimit);
        }

        cursor += 10;
        let end = cursor
            .checked_add(rdlength)
            .ok_or(ParseError::LengthLimit)?;
        let rdata_start = cursor;
        let raw_rdata = message.get(cursor..end).ok_or(ParseError::UnexpectedEof)?;
        let rdata = normalize_record_rdata(message, rdata_start, end, record_type, raw_rdata)?;

        Ok((
            Self {
                name,
                record_type,
                class,
                ttl,
                rdata,
            },
            end,
        ))
    }

    pub fn encode(&self, out: &mut Vec<u8>) -> Result<(), ParseError> {
        if self.rdata.len() > u16::MAX as usize {
            return Err(ParseError::LengthLimit);
        }

        self.name.encode_wire(out)?;
        write_u16_be(out, self.record_type.code());
        write_u16_be(out, self.class);
        write_u32_be(out, self.ttl);
        write_u16_be(out, self.rdata.len() as u16);
        out.extend(&self.rdata);
        Ok(())
    }
}

impl SvcbRecord {
    pub fn parse_rdata(rdata: &[u8]) -> Result<Self, ParseError> {
        if rdata.len() < 3 {
            return Err(ParseError::InvalidSvcb);
        }

        let svc_priority = u16::from_be_bytes([rdata[0], rdata[1]]);
        let (target_name, mut cursor) = parse_uncompressed_dns_name(rdata, 2)?;
        let mut params = Vec::new();
        let mut previous_key = None;

        while cursor < rdata.len() {
            let fixed = rdata
                .get(cursor..cursor.checked_add(4).ok_or(ParseError::LengthLimit)?)
                .ok_or(ParseError::InvalidSvcb)?;
            let key = u16::from_be_bytes([fixed[0], fixed[1]]);
            let length = u16::from_be_bytes([fixed[2], fixed[3]]) as usize;
            cursor += 4;

            if previous_key.is_some_and(|previous| key <= previous) {
                return Err(ParseError::InvalidSvcb);
            }
            previous_key = Some(key);

            let end = cursor.checked_add(length).ok_or(ParseError::LengthLimit)?;
            let value = rdata.get(cursor..end).ok_or(ParseError::InvalidSvcb)?;
            validate_svc_param_value(key, value)?;
            params.push(SvcParam {
                key,
                value: value.to_vec(),
            });
            cursor = end;
        }

        Ok(Self {
            svc_priority,
            target_name,
            params,
        })
    }

    pub fn from_record(record: &ResourceRecord) -> Result<Self, ParseError> {
        if !matches!(record.record_type, RecordType::Svcb | RecordType::Https) {
            return Err(ParseError::InvalidSvcb);
        }
        Self::parse_rdata(&record.rdata)
    }

    pub fn is_alias_mode(&self) -> bool {
        self.svc_priority == 0
    }

    pub fn param(&self, key: u16) -> Option<&[u8]> {
        self.params
            .iter()
            .find(|param| param.key == key)
            .map(|param| param.value.as_slice())
    }

    pub fn alpn_ids(&self) -> Result<Vec<Vec<u8>>, ParseError> {
        let Some(value) = self.param(SVCB_PARAM_ALPN) else {
            return Ok(Vec::new());
        };
        parse_alpn_ids(value)
    }

    pub fn port(&self) -> Result<Option<u16>, ParseError> {
        let Some(value) = self.param(SVCB_PARAM_PORT) else {
            return Ok(None);
        };
        if value.len() != 2 {
            return Err(ParseError::InvalidSvcb);
        }
        Ok(Some(u16::from_be_bytes([value[0], value[1]])))
    }
}

impl DnsQuestion {
    pub fn parse(message: &[u8], offset: usize) -> Result<(Self, usize), ParseError> {
        let (name, cursor) = DnsName::parse_wire(message, offset)?;
        let fixed = message
            .get(cursor..cursor.checked_add(4).ok_or(ParseError::LengthLimit)?)
            .ok_or(ParseError::UnexpectedEof)?;
        Ok((
            Self {
                name,
                record_type: RecordType::from_code(u16::from_be_bytes([fixed[0], fixed[1]])),
                class: u16::from_be_bytes([fixed[2], fixed[3]]),
            },
            cursor + 4,
        ))
    }

    pub fn encode(&self, out: &mut Vec<u8>) -> Result<(), ParseError> {
        self.name.encode_wire(out)?;
        write_u16_be(out, self.record_type.code());
        write_u16_be(out, self.class);
        Ok(())
    }
}

impl DnsMessage {
    pub fn response_for_query(
        query: &DnsMessage,
        answers: Vec<ResourceRecord>,
    ) -> Result<Self, ParseError> {
        if query.questions.len() > MAX_DNS_QUESTIONS || answers.len() > MAX_DNS_RECORDS {
            return Err(ParseError::LengthLimit);
        }

        Ok(Self {
            header: DnsHeader {
                id: query.header.id,
                flags: DnsFlags::new(0x8400),
                question_count: query.questions.len() as u16,
                answer_count: answers.len() as u16,
                authority_count: 0,
                additional_count: 0,
            },
            questions: query.questions.clone(),
            answers,
            authorities: Vec::new(),
            additionals: Vec::new(),
        })
    }

    pub fn parse(message: &[u8]) -> Result<Self, ParseError> {
        if message.len() < 12 {
            return Err(ParseError::UnexpectedEof);
        }

        let header = DnsHeader::parse(&message[..12])?;
        if header.question_count as usize > MAX_DNS_QUESTIONS {
            return Err(ParseError::LengthLimit);
        }

        let total_records = header.answer_count as usize
            + header.authority_count as usize
            + header.additional_count as usize;
        if total_records > MAX_DNS_RECORDS {
            return Err(ParseError::LengthLimit);
        }

        let mut cursor = 12;
        let mut questions = Vec::with_capacity(header.question_count as usize);
        for _ in 0..header.question_count {
            let (question, next) = DnsQuestion::parse(message, cursor)?;
            questions.push(question);
            cursor = next;
        }

        let (answers, next) = parse_records(message, cursor, header.answer_count)?;
        let (authorities, next) = parse_records(message, next, header.authority_count)?;
        let (additionals, next) = parse_records(message, next, header.additional_count)?;

        if next != message.len() {
            return Err(ParseError::TrailingBytes);
        }

        Ok(Self {
            header,
            questions,
            answers,
            authorities,
            additionals,
        })
    }

    pub fn encode(&self, config: &DnsEncodeConfig) -> Result<Vec<u8>, ParseError> {
        if self.questions.len() > MAX_DNS_QUESTIONS || self.total_records() > MAX_DNS_RECORDS {
            return Err(ParseError::LengthLimit);
        }

        let mut out = Vec::with_capacity(512.min(config.max_message_len));
        write_u16_be(&mut out, self.header.id);
        write_u16_be(&mut out, self.header.flags.bits());
        write_u16_be(&mut out, self.questions.len() as u16);
        write_u16_be(&mut out, self.answers.len() as u16);
        write_u16_be(&mut out, self.authorities.len() as u16);
        write_u16_be(&mut out, self.additionals.len() as u16);

        for question in &self.questions {
            question.encode(&mut out)?;
        }
        for record in &self.answers {
            record.encode(&mut out)?;
        }
        for record in &self.authorities {
            record.encode(&mut out)?;
        }
        for record in &self.additionals {
            record.encode(&mut out)?;
        }

        if out.len() > config.max_message_len {
            return Err(ParseError::LengthLimit);
        }

        Ok(out)
    }

    fn total_records(&self) -> usize {
        self.answers.len() + self.authorities.len() + self.additionals.len()
    }
}

impl Default for DnsEncodeConfig {
    fn default() -> Self {
        Self {
            max_message_len: 1232,
        }
    }
}

fn parse_records(
    message: &[u8],
    mut cursor: usize,
    count: u16,
) -> Result<(Vec<ResourceRecord>, usize), ParseError> {
    let mut records = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let (record, next) = ResourceRecord::parse(message, cursor)?;
        records.push(record);
        cursor = next;
    }

    Ok((records, cursor))
}

fn normalize_record_rdata(
    message: &[u8],
    start: usize,
    end: usize,
    record_type: RecordType,
    rdata: &[u8],
) -> Result<Vec<u8>, ParseError> {
    match record_type {
        RecordType::Ns | RecordType::Cname => normalize_exact_name_rdata(message, start, end),
        RecordType::Soa => normalize_soa_rdata(message, start, end),
        RecordType::Rrsig if rdata.get(18).is_some_and(|byte| byte & 0xc0 == 0xc0) => {
            normalize_prefixed_name_rdata(message, start, end, 18)
        }
        _ => Ok(rdata.to_vec()),
    }
}

fn normalize_exact_name_rdata(
    message: &[u8],
    start: usize,
    end: usize,
) -> Result<Vec<u8>, ParseError> {
    let (name, next) = DnsName::parse_wire(message, start)?;
    if next > end {
        return Err(ParseError::UnexpectedEof);
    }
    if next != end {
        return Err(ParseError::TrailingBytes);
    }

    let mut out = Vec::new();
    name.encode_wire(&mut out)?;
    Ok(out)
}

fn normalize_soa_rdata(message: &[u8], start: usize, end: usize) -> Result<Vec<u8>, ParseError> {
    let (mname, rname_start) = DnsName::parse_wire(message, start)?;
    if rname_start > end {
        return Err(ParseError::UnexpectedEof);
    }
    let (rname, fixed_start) = DnsName::parse_wire(message, rname_start)?;
    if fixed_start > end {
        return Err(ParseError::UnexpectedEof);
    }

    match end
        .checked_sub(fixed_start)
        .ok_or(ParseError::LengthLimit)?
    {
        0..=19 => return Err(ParseError::UnexpectedEof),
        20 => {}
        _ => return Err(ParseError::TrailingBytes),
    }

    let mut out = Vec::new();
    mname.encode_wire(&mut out)?;
    rname.encode_wire(&mut out)?;
    out.extend(
        message
            .get(fixed_start..end)
            .ok_or(ParseError::UnexpectedEof)?,
    );
    Ok(out)
}

fn normalize_prefixed_name_rdata(
    message: &[u8],
    start: usize,
    end: usize,
    prefix_len: usize,
) -> Result<Vec<u8>, ParseError> {
    let name_start = start
        .checked_add(prefix_len)
        .ok_or(ParseError::LengthLimit)?;
    if name_start >= end {
        return Err(ParseError::UnexpectedEof);
    }
    let (name, next) = DnsName::parse_wire(message, name_start)?;
    if next > end {
        return Err(ParseError::UnexpectedEof);
    }

    let mut out = Vec::new();
    out.extend(
        message
            .get(start..name_start)
            .ok_or(ParseError::UnexpectedEof)?,
    );
    name.encode_wire(&mut out)?;
    out.extend(message.get(next..end).ok_or(ParseError::UnexpectedEof)?);
    Ok(out)
}

fn validate_svc_param_value(key: u16, value: &[u8]) -> Result<(), ParseError> {
    match key {
        SVCB_PARAM_MANDATORY => {
            if value.is_empty() || !value.len().is_multiple_of(2) {
                return Err(ParseError::InvalidSvcb);
            }
            let mut previous_key = None;
            for chunk in value.chunks_exact(2) {
                let mandatory_key = u16::from_be_bytes([chunk[0], chunk[1]]);
                if mandatory_key == SVCB_PARAM_MANDATORY
                    || previous_key.is_some_and(|previous| mandatory_key <= previous)
                {
                    return Err(ParseError::InvalidSvcb);
                }
                previous_key = Some(mandatory_key);
            }
            Ok(())
        }
        SVCB_PARAM_ALPN => parse_alpn_ids(value).map(|_| ()),
        SVCB_PARAM_NO_DEFAULT_ALPN => {
            if value.is_empty() {
                Ok(())
            } else {
                Err(ParseError::InvalidSvcb)
            }
        }
        SVCB_PARAM_PORT => {
            if value.len() == 2 {
                Ok(())
            } else {
                Err(ParseError::InvalidSvcb)
            }
        }
        SVCB_PARAM_IPV4HINT => {
            if !value.is_empty() && value.len().is_multiple_of(4) {
                Ok(())
            } else {
                Err(ParseError::InvalidSvcb)
            }
        }
        SVCB_PARAM_IPV6HINT => {
            if !value.is_empty() && value.len().is_multiple_of(16) {
                Ok(())
            } else {
                Err(ParseError::InvalidSvcb)
            }
        }
        SVCB_PARAM_ECH => Ok(()),
        _ => Ok(()),
    }
}

fn parse_uncompressed_dns_name(
    message: &[u8],
    offset: usize,
) -> Result<(DnsName, usize), ParseError> {
    let mut labels = Vec::new();
    let mut cursor = offset;

    loop {
        let length = *message.get(cursor).ok_or(ParseError::InvalidSvcb)?;
        cursor += 1;
        if length & 0xc0 != 0 {
            return Err(ParseError::InvalidSvcb);
        }
        if length == 0 {
            let name = DnsName(labels);
            if name.wire_len() > MAX_DNS_NAME_LEN + 2 {
                return Err(ParseError::LengthLimit);
            }
            return Ok((name, cursor));
        }
        if length as usize > MAX_DNS_LABEL_LEN {
            return Err(ParseError::InvalidSvcb);
        }

        let end = cursor
            .checked_add(length as usize)
            .ok_or(ParseError::LengthLimit)?;
        let label_bytes = message.get(cursor..end).ok_or(ParseError::InvalidSvcb)?;
        if !is_valid_dns_label(label_bytes) {
            return Err(ParseError::InvalidSvcb);
        }
        let label = std::str::from_utf8(label_bytes)
            .map_err(|_| ParseError::InvalidSvcb)?
            .to_ascii_lowercase();
        labels.push(label);
        cursor = end;
    }
}

fn parse_alpn_ids(value: &[u8]) -> Result<Vec<Vec<u8>>, ParseError> {
    if value.is_empty() {
        return Err(ParseError::InvalidSvcb);
    }

    let mut cursor = 0usize;
    let mut ids = Vec::new();
    while cursor < value.len() {
        let length = value[cursor] as usize;
        cursor += 1;
        if length == 0 {
            return Err(ParseError::InvalidSvcb);
        }
        let end = cursor.checked_add(length).ok_or(ParseError::LengthLimit)?;
        let id = value.get(cursor..end).ok_or(ParseError::InvalidSvcb)?;
        ids.push(id.to_vec());
        cursor = end;
    }

    Ok(ids)
}

fn is_valid_dns_label(label: &[u8]) -> bool {
    label == b"*"
        || label
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-' || *byte == b'_')
}

fn write_u16_be(out: &mut Vec<u8>, value: u16) {
    out.extend(value.to_be_bytes());
}

fn write_u32_be(out: &mut Vec<u8>, value: u32) {
    out.extend(value.to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_compressed_name() {
        let message = b"\x07example\x03com\x00\xc0\x00";
        let (name, next) = DnsName::parse_wire(message, 13).unwrap();

        assert_eq!(name.to_string(), "example.com");
        assert_eq!(next, 15);
    }

    #[test]
    fn parses_dns_wildcard_owner_name() {
        let name = DnsName::from_ascii("*.example").unwrap();
        let mut wire = Vec::new();
        name.encode_wire(&mut wire).unwrap();

        assert_eq!(name.to_string(), "*.example");
        assert_eq!(wire, b"\x01*\x07example\x00");
    }

    #[test]
    fn accepts_maximum_255_octet_wire_name() {
        let ascii = [
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61),
        ]
        .join(".");
        assert_eq!(ascii.len(), MAX_DNS_NAME_LEN);

        let name = DnsName::from_ascii(&ascii).unwrap();
        let mut wire = Vec::new();
        name.encode_wire(&mut wire).unwrap();

        assert_eq!(wire.len(), 255);
        assert_eq!(DnsName::parse_wire(&wire, 0).unwrap().0, name);
    }

    #[test]
    fn rejects_pointer_loop() {
        let message = b"\xc0\x00";

        assert_eq!(
            DnsName::parse_wire(message, 0).unwrap_err(),
            ParseError::InvalidDnsPointer,
        );
    }

    #[test]
    fn parses_query_message() {
        let message = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01";
        let parsed = DnsMessage::parse(message).unwrap();

        assert_eq!(parsed.header.id, 0x1234);
        assert!(parsed.header.flags.recursion_desired());
        assert_eq!(parsed.questions.len(), 1);
        assert_eq!(parsed.questions[0].name.to_string(), "example.com");
        assert_eq!(parsed.questions[0].record_type, RecordType::A);
    }

    #[test]
    fn parses_response_with_compressed_answer() {
        let message = b"\x12\x34\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x7f\x00\x00\x01";
        let parsed = DnsMessage::parse(message).unwrap();

        assert!(parsed.header.flags.is_response());
        assert_eq!(parsed.answers.len(), 1);
        assert_eq!(parsed.answers[0].name.to_string(), "example.com");
        assert_eq!(parsed.answers[0].ttl, 60);
        assert_eq!(parsed.answers[0].rdata, vec![127, 0, 0, 1]);
    }

    #[test]
    fn expands_compressed_cname_target_in_rdata() {
        let message = b"\x12\x34\x81\x80\x00\x01\x00\x02\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01\xc0\x0c\x00\x05\x00\x01\x00\x00\x00\x3c\x00\x07\x04edge\xc0\x0c\xc0\x29\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x01\x01\x01\x01";
        let parsed = DnsMessage::parse(message).unwrap();

        assert_eq!(parsed.answers.len(), 2);
        assert_eq!(parsed.answers[0].record_type, RecordType::Cname);
        assert_eq!(
            parsed.answers[0].rdata,
            b"\x04edge\x07example\x03com\x00".to_vec(),
        );
        assert_eq!(parsed.answers[1].name.to_string(), "edge.example.com");
    }

    #[test]
    fn rejects_trailing_bytes_after_cname_target() {
        let message = b"\x12\x34\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01\xc0\x0c\x00\x05\x00\x01\x00\x00\x00\x3c\x00\x08\x04edge\xc0\x0c\x00";

        assert_eq!(DnsMessage::parse(message), Err(ParseError::TrailingBytes));
    }

    #[test]
    fn expands_compressed_ns_target_in_rdata() {
        let message = b"\x12\x34\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x07example\x03com\x00\x00\x02\x00\x01\xc0\x0c\x00\x02\x00\x01\x00\x00\x00\x3c\x00\x06\x03ns1\xc0\x0c";
        let parsed = DnsMessage::parse(message).unwrap();

        assert_eq!(parsed.answers.len(), 1);
        assert_eq!(parsed.answers[0].record_type, RecordType::Ns);
        assert_eq!(
            parsed.answers[0].rdata,
            b"\x03ns1\x07example\x03com\x00".to_vec(),
        );
    }

    #[test]
    fn expands_compressed_soa_names_in_rdata() {
        let mut message = Vec::new();
        message.extend(b"\x12\x34\x81\xa0\x00\x01\x00\x00\x00\x01\x00\x00");
        DnsName::from_ascii("denuoweb.com")
            .unwrap()
            .encode_wire(&mut message)
            .unwrap();
        write_u16_be(&mut message, RecordType::Aaaa.code());
        write_u16_be(&mut message, 1);
        message.extend(b"\xc0\x0c");
        write_u16_be(&mut message, RecordType::Soa.code());
        write_u16_be(&mut message, 1);
        write_u32_be(&mut message, 900);
        let rdlength_offset = message.len();
        write_u16_be(&mut message, 0);
        let rdata_start = message.len();
        message.extend(b"\x02ns\xc0\x0c");
        message.extend(b"\x0ahostmaster\xc0\x0c");
        for value in [1_u32, 60, 120, 300, 45] {
            write_u32_be(&mut message, value);
        }
        let rdlength = u16::try_from(message.len() - rdata_start).unwrap();
        message[rdlength_offset..rdlength_offset + 2].copy_from_slice(&rdlength.to_be_bytes());

        let parsed = DnsMessage::parse(&message).unwrap();
        let soa = &parsed.authorities[0];
        let (mname, cursor) = DnsName::parse_wire(&soa.rdata, 0).unwrap();
        let (rname, cursor) = DnsName::parse_wire(&soa.rdata, cursor).unwrap();

        assert_eq!(soa.record_type, RecordType::Soa);
        assert_eq!(mname.to_string(), "ns.denuoweb.com");
        assert_eq!(rname.to_string(), "hostmaster.denuoweb.com");
        assert_eq!(soa.rdata.len() - cursor, 20);
        assert_eq!(
            &soa.rdata[soa.rdata.len() - 4..],
            45_u32.to_be_bytes().as_slice(),
        );

        let encoded = parsed.encode(&DnsEncodeConfig::default()).unwrap();
        let reparsed = DnsMessage::parse(&encoded).unwrap();
        assert_eq!(reparsed.authorities[0].rdata, soa.rdata);
    }

    #[test]
    fn rejects_malformed_compressed_soa_tail_lengths() {
        fn message_with_soa_tail(tail: &[u8]) -> Vec<u8> {
            let mut message = Vec::new();
            message.extend(b"\x12\x34\x81\xa0\x00\x01\x00\x00\x00\x01\x00\x00");
            DnsName::from_ascii("example.com")
                .unwrap()
                .encode_wire(&mut message)
                .unwrap();
            write_u16_be(&mut message, RecordType::Aaaa.code());
            write_u16_be(&mut message, 1);
            message.extend(b"\xc0\x0c");
            write_u16_be(&mut message, RecordType::Soa.code());
            write_u16_be(&mut message, 1);
            write_u32_be(&mut message, 900);
            let rdlength_offset = message.len();
            write_u16_be(&mut message, 0);
            let rdata_start = message.len();
            message.extend(b"\x02ns\xc0\x0c");
            message.extend(b"\x0ahostmaster\xc0\x0c");
            message.extend(tail);
            let rdlength = u16::try_from(message.len() - rdata_start).unwrap();
            message[rdlength_offset..rdlength_offset + 2].copy_from_slice(&rdlength.to_be_bytes());
            message
        }

        assert_eq!(
            DnsMessage::parse(&message_with_soa_tail(&[0; 19])),
            Err(ParseError::UnexpectedEof),
        );
        assert_eq!(
            DnsMessage::parse(&message_with_soa_tail(&[0; 21])),
            Err(ParseError::TrailingBytes),
        );
    }

    #[test]
    fn expands_compressed_rrsig_signer_name_in_rdata() {
        let message = b"\x12\x34\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x04alee\x01g\x00\x00\x01\x00\x01\xc0\x0c\x00\x2e\x00\x01\x00\x00\x00\x14\x00\x17\x00\x01\x0d\x02\x00\x00\x00\x14\x6a\x58\x1f\x00\x6a\x3c\x6f\x80\xa6\x75\xc0\x0c\x01\x02\x03";
        let parsed = DnsMessage::parse(message).unwrap();

        assert_eq!(parsed.answers.len(), 1);
        assert_eq!(parsed.answers[0].record_type, RecordType::Rrsig);
        assert_eq!(
            parsed.answers[0].rdata,
            b"\x00\x01\x0d\x02\x00\x00\x00\x14\x6a\x58\x1f\x00\x6a\x3c\x6f\x80\xa6\x75\x04alee\x01g\x00\x01\x02\x03".to_vec(),
        );
    }

    #[test]
    fn encodes_response_message() {
        let query = DnsMessage::parse(
            b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01",
        )
        .unwrap();
        let answer = ResourceRecord {
            name: DnsName::from_ascii("example.com").unwrap(),
            record_type: RecordType::A,
            class: 1,
            ttl: 60,
            rdata: vec![127, 0, 0, 1],
        };
        let response = DnsMessage::response_for_query(&query, vec![answer]).unwrap();
        let encoded = response.encode(&DnsEncodeConfig::default()).unwrap();
        let decoded = DnsMessage::parse(&encoded).unwrap();

        assert!(decoded.header.flags.is_response());
        assert!(decoded.header.flags.authoritative_answer());
        assert_eq!(decoded.answers.len(), 1);
        assert_eq!(decoded.answers[0].rdata, vec![127, 0, 0, 1]);
    }

    #[test]
    fn parses_https_svcb_rdata() {
        let mut rdata = Vec::new();
        write_u16_be(&mut rdata, 1);
        DnsName::from_ascii("svc.example")
            .unwrap()
            .encode_wire(&mut rdata)
            .unwrap();
        write_u16_be(&mut rdata, SVCB_PARAM_ALPN);
        write_u16_be(&mut rdata, 6);
        rdata.extend([2, b'h', b'2', 2, b'h', b'3']);
        write_u16_be(&mut rdata, SVCB_PARAM_PORT);
        write_u16_be(&mut rdata, 2);
        write_u16_be(&mut rdata, 8443);

        let record = ResourceRecord {
            name: DnsName::from_ascii("example").unwrap(),
            record_type: RecordType::Https,
            class: 1,
            ttl: 60,
            rdata,
        };
        let parsed = SvcbRecord::from_record(&record).unwrap();

        assert!(!parsed.is_alias_mode());
        assert_eq!(parsed.target_name.to_string(), "svc.example");
        assert_eq!(
            parsed.alpn_ids().unwrap(),
            vec![b"h2".to_vec(), b"h3".to_vec()]
        );
        assert_eq!(parsed.port().unwrap(), Some(8443));
    }

    #[test]
    fn rejects_malformed_svcb_params() {
        let base = {
            let mut rdata = Vec::new();
            write_u16_be(&mut rdata, 1);
            DnsName::from_ascii("svc.example")
                .unwrap()
                .encode_wire(&mut rdata)
                .unwrap();
            rdata
        };

        let mut duplicate = base.clone();
        for _ in 0..2 {
            write_u16_be(&mut duplicate, SVCB_PARAM_PORT);
            write_u16_be(&mut duplicate, 2);
            write_u16_be(&mut duplicate, 443);
        }
        assert_eq!(
            SvcbRecord::parse_rdata(&duplicate).unwrap_err(),
            ParseError::InvalidSvcb,
        );

        let mut bad_alpn = base.clone();
        write_u16_be(&mut bad_alpn, SVCB_PARAM_ALPN);
        write_u16_be(&mut bad_alpn, 1);
        bad_alpn.push(0);
        assert_eq!(
            SvcbRecord::parse_rdata(&bad_alpn).unwrap_err(),
            ParseError::InvalidSvcb,
        );

        let compressed_target = [0, 1, 0xc0, 0x00];
        assert_eq!(
            SvcbRecord::parse_rdata(&compressed_target).unwrap_err(),
            ParseError::InvalidSvcb,
        );
    }
}
