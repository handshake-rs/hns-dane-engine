//! Strict, runtime-independent DNS wire parsing for HNS DNSSEC and DANE.
//!
//! The parser bounds the packet, section counts, RDATA, labels, and compression
//! jumps before allocation. It rejects forward, out-of-message, and cyclic
//! compression pointers. DNS AD is exposed only as an untrusted wire claim.

#![forbid(unsafe_code)]
#![allow(
    clippy::doc_markdown,
    clippy::missing_errors_doc,
    clippy::module_name_repetitions,
    clippy::similar_names,
    reason = "DNS acronyms and the crate-wide Error enum make repeated per-method prose less clear"
)]

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

/// DNS class IN.
pub const CLASS_IN: u16 = 1;
/// Maximum RFC 1035 label length.
pub const MAX_LABEL_LEN: usize = 63;
/// Maximum complete DNS wire name length, including length octets and root.
pub const MAX_WIRE_NAME_LEN: usize = 255;
/// Traditional safe DNS-over-UDP payload.
pub const DEFAULT_UDP_PAYLOAD: u16 = 1_232;
/// DNSSEC OK bit in the EDNS OPT TTL field.
pub const EDNS_DO: u16 = 0x8000;

/// Parser and allocation limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParseLimits {
    /// Maximum complete DNS message length.
    pub max_message_len: usize,
    /// Maximum number of questions.
    pub max_questions: usize,
    /// Maximum total records across all response sections.
    pub max_records: usize,
    /// Maximum RDATA length accepted for one record.
    pub max_rdata_len: usize,
    /// Maximum labels in one expanded name.
    pub max_labels_per_name: usize,
    /// Maximum followed compression pointers in one name.
    pub max_compression_jumps: usize,
}

impl ParseLimits {
    /// Browser production limits for UDP or length-delimited TCP input.
    #[must_use]
    pub const fn browser() -> Self {
        Self {
            max_message_len: u16::MAX as usize,
            max_questions: 4,
            max_records: 2_048,
            max_rdata_len: u16::MAX as usize,
            max_labels_per_name: 127,
            max_compression_jumps: 32,
        }
    }

    /// Stricter limits for a single-question requester.
    #[must_use]
    pub const fn requester() -> Self {
        Self {
            max_message_len: u16::MAX as usize,
            max_questions: 1,
            max_records: 1_024,
            max_rdata_len: 16_384,
            max_labels_per_name: 127,
            max_compression_jumps: 16,
        }
    }
}

impl Default for ParseLimits {
    fn default() -> Self {
        Self::browser()
    }
}

/// DNS wire parse or validation failure.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Error {
    /// A read extended beyond the supplied message or RDATA.
    UnexpectedEof,
    /// The complete message exceeds its configured bound.
    MessageTooLong,
    /// A declared section count exceeds its configured bound.
    CountLimit,
    /// A label exceeds 63 octets or uses reserved length bits.
    InvalidLabel,
    /// An expanded name exceeds configured label or RFC wire limits.
    NameLimit,
    /// A compression pointer points outside the packet.
    PointerOutOfBounds,
    /// A compression pointer points to itself or forward.
    ForwardPointer,
    /// A compression pointer cycle was detected.
    CompressionLoop,
    /// A name followed too many compression pointers.
    CompressionJumpLimit,
    /// A record RDATA length exceeds the configured bound.
    RdataLimit,
    /// A known resource record has malformed RDATA.
    InvalidRdata,
    /// EDNS options are malformed.
    InvalidEdns,
    /// Bytes remain after all declared sections.
    TrailingBytes,
    /// An arithmetic operation overflowed.
    LengthOverflow,
    /// A strict query has invalid flags or section structure.
    InvalidQuery,
    /// Reserved DNS header bits are nonzero.
    ReservedHeaderBits,
    /// A packet expected to be a response is not one.
    NotResponse,
    /// Response ID does not match the query.
    IdMismatch,
    /// Response opcode is unsupported or does not match.
    OpcodeMismatch,
    /// Response question does not exactly match the query.
    QuestionMismatch,
    /// Response is truncated and requires a bounded TCP retry.
    Truncated,
    /// Encoding would exceed a caller-provided bound.
    EncodeLimit,
    /// A typed RDATA variant does not match its RR type.
    TypeMismatch,
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::UnexpectedEof => "unexpected end of DNS message",
            Self::MessageTooLong => "DNS message exceeds configured limit",
            Self::CountLimit => "DNS section count exceeds configured limit",
            Self::InvalidLabel => "invalid DNS label",
            Self::NameLimit => "expanded DNS name exceeds configured limit",
            Self::PointerOutOfBounds => "DNS compression pointer is out of bounds",
            Self::ForwardPointer => "DNS compression pointer is self-referential or forward",
            Self::CompressionLoop => "DNS compression pointer loop",
            Self::CompressionJumpLimit => "DNS compression jump limit exceeded",
            Self::RdataLimit => "DNS RDATA exceeds configured limit",
            Self::InvalidRdata => "malformed known DNS RDATA",
            Self::InvalidEdns => "malformed EDNS option list",
            Self::TrailingBytes => "trailing bytes after declared DNS sections",
            Self::LengthOverflow => "DNS length arithmetic overflow",
            Self::InvalidQuery => "invalid strict DNS query",
            Self::ReservedHeaderBits => "reserved DNS header bits are nonzero",
            Self::NotResponse => "DNS packet is not a response",
            Self::IdMismatch => "DNS response ID mismatch",
            Self::OpcodeMismatch => "DNS response opcode mismatch",
            Self::QuestionMismatch => "DNS response question mismatch",
            Self::Truncated => "DNS response is truncated",
            Self::EncodeLimit => "encoded DNS message exceeds configured limit",
            Self::TypeMismatch => "resource record type and typed RDATA do not match",
        })
    }
}

impl std::error::Error for Error {}

/// A canonical, absolute DNS name.
///
/// ASCII letters are normalized to lowercase when parsed. Other label octets
/// remain opaque and are escaped by [`Display`](fmt::Display).
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Name {
    labels: Vec<Vec<u8>>,
}

impl Name {
    /// The DNS root name.
    #[must_use]
    pub const fn root() -> Self {
        Self { labels: Vec::new() }
    }

    /// Construct from opaque labels, validating and canonicalizing ASCII case.
    pub fn from_labels(labels: Vec<Vec<u8>>) -> Result<Self, Error> {
        let mut canonical = Vec::with_capacity(labels.len());
        let mut wire_len = 1usize;
        for label in labels {
            if label.is_empty() || label.len() > MAX_LABEL_LEN {
                return Err(Error::InvalidLabel);
            }
            wire_len = wire_len
                .checked_add(label.len() + 1)
                .ok_or(Error::LengthOverflow)?;
            if wire_len > MAX_WIRE_NAME_LEN {
                return Err(Error::NameLimit);
            }
            canonical.push(canonical_label(&label));
        }
        Ok(Self { labels: canonical })
    }

    /// Parse an ASCII presentation name. A final dot is optional.
    pub fn from_ascii(input: &str) -> Result<Self, Error> {
        let input = input.strip_suffix('.').unwrap_or(input);
        if input.is_empty() {
            return Ok(Self::root());
        }

        Self::from_labels(
            input
                .as_bytes()
                .split(|byte| *byte == b'.')
                .map(<[u8]>::to_vec)
                .collect(),
        )
    }

    /// Return the opaque labels in canonical lowercase form.
    #[must_use]
    pub fn labels(&self) -> &[Vec<u8>] {
        &self.labels
    }

    /// Whether this is the root name.
    #[must_use]
    pub fn is_root(&self) -> bool {
        self.labels.is_empty()
    }

    /// Expanded wire length, including the terminating root.
    #[must_use]
    pub fn wire_len(&self) -> usize {
        self.labels
            .iter()
            .fold(1usize, |length, label| length + label.len() + 1)
    }

    /// Encode without compression.
    pub fn encode(&self, output: &mut Vec<u8>) -> Result<(), Error> {
        if self.wire_len() > MAX_WIRE_NAME_LEN {
            return Err(Error::NameLimit);
        }
        for label in &self.labels {
            let length = u8::try_from(label.len()).map_err(|_| Error::InvalidLabel)?;
            if usize::from(length) > MAX_LABEL_LEN {
                return Err(Error::InvalidLabel);
            }
            output.push(length);
            output.extend_from_slice(label);
        }
        output.push(0);
        Ok(())
    }
}

impl fmt::Display for Name {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.labels.is_empty() {
            return formatter.write_str(".");
        }
        for (label_index, label) in self.labels.iter().enumerate() {
            if label_index != 0 {
                formatter.write_str(".")?;
            }
            for byte in label {
                if byte.is_ascii_alphanumeric() || matches!(*byte, b'-' | b'_') {
                    formatter.write_str(&char::from(*byte).to_string())?;
                } else {
                    write!(formatter, "\\{byte:03}")?;
                }
            }
        }
        formatter.write_str(".")
    }
}

/// DNS header flags.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Flags(u16);

impl Flags {
    /// Construct flags from raw network bits.
    #[must_use]
    pub const fn from_bits(bits: u16) -> Self {
        Self(bits)
    }

    /// Return raw network bits.
    #[must_use]
    pub const fn bits(self) -> u16 {
        self.0
    }

    /// Query/response flag.
    #[must_use]
    pub const fn is_response(self) -> bool {
        self.0 & 0x8000 != 0
    }

    /// Four-bit opcode.
    #[must_use]
    pub const fn opcode(self) -> u8 {
        ((self.0 >> 11) & 0x0f) as u8
    }

    /// Authoritative answer flag.
    #[must_use]
    pub const fn authoritative(self) -> bool {
        self.0 & 0x0400 != 0
    }

    /// Truncation flag.
    #[must_use]
    pub const fn truncated(self) -> bool {
        self.0 & 0x0200 != 0
    }

    /// Recursion-desired flag.
    #[must_use]
    pub const fn recursion_desired(self) -> bool {
        self.0 & 0x0100 != 0
    }

    /// Recursion-available flag.
    #[must_use]
    pub const fn recursion_available(self) -> bool {
        self.0 & 0x0080 != 0
    }

    /// Authenticated-data flag. This is an untrusted peer claim.
    #[must_use]
    pub const fn authenticated_data_claim(self) -> bool {
        self.0 & 0x0020 != 0
    }

    /// Four-bit response code.
    #[must_use]
    pub const fn rcode(self) -> u8 {
        (self.0 & 0x000f) as u8
    }
}

/// Parsed DNS header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Header {
    /// Transaction identifier.
    pub id: u16,
    /// Header flags.
    pub flags: Flags,
    /// Declared question count.
    pub question_count: u16,
    /// Declared answer count.
    pub answer_count: u16,
    /// Declared authority count.
    pub authority_count: u16,
    /// Declared additional count.
    pub additional_count: u16,
}

impl Header {
    fn parse(message: &[u8]) -> Result<Self, Error> {
        let bytes = message.get(..12).ok_or(Error::UnexpectedEof)?;
        Ok(Self {
            id: be_u16(bytes, 0)?,
            flags: Flags::from_bits(be_u16(bytes, 2)?),
            question_count: be_u16(bytes, 4)?,
            answer_count: be_u16(bytes, 6)?,
            authority_count: be_u16(bytes, 8)?,
            additional_count: be_u16(bytes, 10)?,
        })
    }
}

/// DNS resource-record type.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum RecordType {
    /// IPv4 address.
    A,
    /// Authoritative name server.
    Ns,
    /// Canonical name.
    Cname,
    /// Start of authority.
    Soa,
    /// Mail exchange.
    Mx,
    /// Text strings.
    Txt,
    /// IPv6 address.
    Aaaa,
    /// Service location.
    Srv,
    /// Delegation signer.
    Ds,
    /// EDNS pseudo-record.
    Opt,
    /// DNSSEC signature.
    Rrsig,
    /// Authenticated denial.
    Nsec,
    /// DNSSEC public key.
    Dnskey,
    /// Hashed authenticated denial.
    Nsec3,
    /// DANE TLS association.
    Tlsa,
    /// Service binding.
    Svcb,
    /// HTTPS service binding.
    Https,
    /// Unrecognized numeric type.
    Unknown(u16),
}

impl RecordType {
    /// Convert a wire code.
    #[must_use]
    pub const fn from_code(code: u16) -> Self {
        match code {
            1 => Self::A,
            2 => Self::Ns,
            5 => Self::Cname,
            6 => Self::Soa,
            15 => Self::Mx,
            16 => Self::Txt,
            28 => Self::Aaaa,
            33 => Self::Srv,
            41 => Self::Opt,
            43 => Self::Ds,
            46 => Self::Rrsig,
            47 => Self::Nsec,
            48 => Self::Dnskey,
            50 => Self::Nsec3,
            52 => Self::Tlsa,
            64 => Self::Svcb,
            65 => Self::Https,
            value => Self::Unknown(value),
        }
    }

    /// Convert to a wire code.
    #[must_use]
    pub const fn code(self) -> u16 {
        match self {
            Self::A => 1,
            Self::Ns => 2,
            Self::Cname => 5,
            Self::Soa => 6,
            Self::Mx => 15,
            Self::Txt => 16,
            Self::Aaaa => 28,
            Self::Srv => 33,
            Self::Opt => 41,
            Self::Ds => 43,
            Self::Rrsig => 46,
            Self::Nsec => 47,
            Self::Dnskey => 48,
            Self::Nsec3 => 50,
            Self::Tlsa => 52,
            Self::Svcb => 64,
            Self::Https => 65,
            Self::Unknown(value) => value,
        }
    }
}

/// One DNS question.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Question {
    /// Canonical question name.
    pub name: Name,
    /// Requested RR type.
    pub record_type: RecordType,
    /// Requested class.
    pub class: u16,
}

/// SOA RDATA.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Soa {
    /// Primary name server.
    pub mname: Name,
    /// Responsible mailbox name.
    pub rname: Name,
    /// Zone serial.
    pub serial: u32,
    /// Refresh interval.
    pub refresh: u32,
    /// Retry interval.
    pub retry: u32,
    /// Expire interval.
    pub expire: u32,
    /// Negative-cache minimum TTL.
    pub minimum: u32,
}

/// MX RDATA.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Mx {
    /// Preference value.
    pub preference: u16,
    /// Mail-exchanger name.
    pub exchange: Name,
}

/// SRV RDATA.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Srv {
    /// Selection priority.
    pub priority: u16,
    /// Relative weight.
    pub weight: u16,
    /// Service port.
    pub port: u16,
    /// Target host.
    pub target: Name,
}

/// DS RDATA.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ds {
    /// DNSKEY key tag.
    pub key_tag: u16,
    /// DNSSEC algorithm.
    pub algorithm: u8,
    /// Digest algorithm.
    pub digest_type: u8,
    /// Key digest.
    pub digest: Vec<u8>,
}

/// DNSKEY RDATA.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Dnskey {
    /// DNSKEY flags.
    pub flags: u16,
    /// Must be 3 for DNSSEC.
    pub protocol: u8,
    /// DNSSEC algorithm.
    pub algorithm: u8,
    /// Encoded public key.
    pub public_key: Vec<u8>,
}

/// RRSIG RDATA.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Rrsig {
    /// Covered RR type.
    pub type_covered: RecordType,
    /// DNSSEC algorithm.
    pub algorithm: u8,
    /// Original owner label count.
    pub labels: u8,
    /// Original RRset TTL.
    pub original_ttl: u32,
    /// Signature expiration time.
    pub expiration: u32,
    /// Signature inception time.
    pub inception: u32,
    /// Signing key tag.
    pub key_tag: u16,
    /// Signer name.
    pub signer: Name,
    /// Signature bytes.
    pub signature: Vec<u8>,
}

/// NSEC RDATA.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Nsec {
    /// Next canonical owner.
    pub next_domain: Name,
    /// Validated RFC 4034 type bitmap bytes.
    pub type_bitmaps: Vec<u8>,
}

/// NSEC3 RDATA.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Nsec3 {
    /// Hash algorithm.
    pub hash_algorithm: u8,
    /// NSEC3 flags.
    pub flags: u8,
    /// Additional hash iterations.
    pub iterations: u16,
    /// Salt.
    pub salt: Vec<u8>,
    /// Next hashed owner.
    pub next_hashed_owner: Vec<u8>,
    /// Validated RFC 4034 type bitmap bytes.
    pub type_bitmaps: Vec<u8>,
}

/// TLSA RDATA.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Tlsa {
    /// Certificate usage.
    pub usage: u8,
    /// Selector.
    pub selector: u8,
    /// Matching type.
    pub matching_type: u8,
    /// Certificate association data.
    pub association_data: Vec<u8>,
}

/// One EDNS option.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EdnsOption {
    /// EDNS option code.
    pub code: u16,
    /// Opaque option value.
    pub data: Vec<u8>,
}

/// Parsed or preserved resource-record data.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Rdata {
    /// A address.
    A(Ipv4Addr),
    /// AAAA address.
    Aaaa(Ipv6Addr),
    /// NS name.
    Ns(Name),
    /// CNAME name.
    Cname(Name),
    /// SOA fields.
    Soa(Soa),
    /// MX fields.
    Mx(Mx),
    /// TXT character strings.
    Txt(Vec<Vec<u8>>),
    /// SRV fields.
    Srv(Srv),
    /// DS fields.
    Ds(Ds),
    /// DNSKEY fields.
    Dnskey(Dnskey),
    /// RRSIG fields.
    Rrsig(Rrsig),
    /// NSEC fields.
    Nsec(Nsec),
    /// NSEC3 fields.
    Nsec3(Nsec3),
    /// TLSA fields.
    Tlsa(Tlsa),
    /// Validated EDNS options.
    Opt(Vec<EdnsOption>),
    /// Opaque data for an unrecognized or intentionally uninterpreted type.
    Opaque(Vec<u8>),
}

/// One DNS resource record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResourceRecord {
    /// Canonical owner name.
    pub name: Name,
    /// RR type.
    pub record_type: RecordType,
    /// RR class, or advertised UDP payload for OPT.
    pub class: u16,
    /// TTL, or EDNS extended fields for OPT.
    pub ttl: u32,
    /// Parsed RDATA.
    pub rdata: Rdata,
}

/// Complete parsed DNS message.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Message {
    /// Header.
    pub header: Header,
    /// Questions.
    pub questions: Vec<Question>,
    /// Answer records.
    pub answers: Vec<ResourceRecord>,
    /// Authority records.
    pub authorities: Vec<ResourceRecord>,
    /// Additional records.
    pub additionals: Vec<ResourceRecord>,
}

impl Message {
    /// Parse with browser production limits.
    pub fn parse(message: &[u8]) -> Result<Self, Error> {
        Self::parse_with_limits(message, ParseLimits::browser())
    }

    /// Parse with explicit limits.
    pub fn parse_with_limits(message: &[u8], limits: ParseLimits) -> Result<Self, Error> {
        if message.len() > limits.max_message_len || message.len() > usize::from(u16::MAX) {
            return Err(Error::MessageTooLong);
        }
        let header = Header::parse(message)?;
        if header.flags.bits() & 0x0040 != 0 {
            return Err(Error::ReservedHeaderBits);
        }
        if usize::from(header.question_count) > limits.max_questions {
            return Err(Error::CountLimit);
        }
        let total_records = usize::from(header.answer_count)
            .checked_add(usize::from(header.authority_count))
            .and_then(|count| count.checked_add(usize::from(header.additional_count)))
            .ok_or(Error::LengthOverflow)?;
        if total_records > limits.max_records {
            return Err(Error::CountLimit);
        }

        let mut cursor = 12usize;
        let mut questions = Vec::with_capacity(usize::from(header.question_count));
        for _ in 0..header.question_count {
            let (question, next) = parse_question(message, cursor, limits)?;
            questions.push(question);
            cursor = next;
        }
        let (answers, next) = parse_records(message, cursor, header.answer_count, limits)?;
        let (authorities, next) = parse_records(message, next, header.authority_count, limits)?;
        let (additionals, next) = parse_records(message, next, header.additional_count, limits)?;
        if next != message.len() {
            return Err(Error::TrailingBytes);
        }
        let parsed = Self {
            header,
            questions,
            answers,
            authorities,
            additionals,
        };
        validate_pseudo_records(&parsed)?;
        Ok(parsed)
    }

    /// Encode all names without compression, enforcing a complete-message bound.
    pub fn encode(&self, max_message_len: usize) -> Result<Vec<u8>, Error> {
        let mut output = Vec::new();
        write_u16(&mut output, self.header.id);
        write_u16(&mut output, self.header.flags.bits());
        write_count(&mut output, self.questions.len())?;
        write_count(&mut output, self.answers.len())?;
        write_count(&mut output, self.authorities.len())?;
        write_count(&mut output, self.additionals.len())?;
        for question in &self.questions {
            encode_question(question, &mut output)?;
        }
        for record in self
            .answers
            .iter()
            .chain(&self.authorities)
            .chain(&self.additionals)
        {
            encode_record(record, &mut output)?;
        }
        if output.len() > max_message_len {
            return Err(Error::EncodeLimit);
        }
        Ok(output)
    }
}

/// A validated single-question standard query.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Query {
    /// Transaction identifier.
    pub id: u16,
    /// Exact question.
    pub question: Question,
}

impl Query {
    /// Construct a class-IN query.
    pub fn new(id: u16, name: Name, record_type: RecordType) -> Result<Self, Error> {
        if name.is_root() || matches!(record_type, RecordType::Opt) {
            return Err(Error::InvalidQuery);
        }
        Ok(Self {
            id,
            question: Question {
                name,
                record_type,
                class: CLASS_IN,
            },
        })
    }

    /// Parse and validate a single-question standard query.
    pub fn parse(message: &[u8], limits: ParseLimits) -> Result<Self, Error> {
        let parsed = Message::parse_with_limits(message, limits)?;
        if parsed.header.flags.is_response()
            || parsed.header.flags.opcode() != 0
            || parsed.header.flags.truncated()
            || parsed.header.flags.bits() & !0x0130 != 0
            || parsed.questions.len() != 1
            || !parsed.answers.is_empty()
            || !parsed.authorities.is_empty()
            || parsed.additionals.len() > 1
        {
            return Err(Error::InvalidQuery);
        }
        let question = parsed.questions.first().ok_or(Error::InvalidQuery)?.clone();
        if question.class != CLASS_IN
            || question.name.is_root()
            || matches!(question.record_type, RecordType::Opt)
        {
            return Err(Error::InvalidQuery);
        }
        if let Some(opt) = parsed.additionals.first()
            && (!opt.name.is_root() || opt.record_type != RecordType::Opt)
        {
            return Err(Error::InvalidQuery);
        }
        if parsed.additionals.iter().any(|record| {
            matches!(
                &record.rdata,
                Rdata::Opt(options) if options.iter().any(|option| option.code == 8)
            )
        }) {
            return Err(Error::InvalidQuery);
        }
        Ok(Self {
            id: parsed.header.id,
            question,
        })
    }

    /// Encode an authoritative-oriented query with DNSSEC OK and no RD bit.
    pub fn encode(&self, max_message_len: usize) -> Result<Vec<u8>, Error> {
        let message = Message {
            header: Header {
                id: self.id,
                flags: Flags::from_bits(0),
                question_count: 1,
                answer_count: 0,
                authority_count: 0,
                additional_count: 1,
            },
            questions: vec![self.question.clone()],
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals: vec![ResourceRecord {
                name: Name::root(),
                record_type: RecordType::Opt,
                class: DEFAULT_UDP_PAYLOAD,
                ttl: u32::from(EDNS_DO),
                rdata: Rdata::Opt(Vec::new()),
            }],
        };
        message.encode(max_message_len)
    }

    /// Correlate a parsed response to this exact query.
    ///
    /// The returned AD value is an untrusted transport claim only.
    pub fn correlate<'a>(&self, response: &'a Message) -> Result<CorrelatedResponse<'a>, Error> {
        if !response.header.flags.is_response() {
            return Err(Error::NotResponse);
        }
        if response.header.id != self.id {
            return Err(Error::IdMismatch);
        }
        if response.header.flags.opcode() != 0 {
            return Err(Error::OpcodeMismatch);
        }
        if response.header.flags.truncated() {
            return Err(Error::Truncated);
        }
        if response.questions.as_slice() != [self.question.clone()] {
            return Err(Error::QuestionMismatch);
        }
        Ok(CorrelatedResponse {
            message: response,
            untrusted_ad_claim: response.header.flags.authenticated_data_claim(),
        })
    }
}

/// A structurally correlated response.
#[derive(Clone, Copy, Debug)]
pub struct CorrelatedResponse<'a> {
    message: &'a Message,
    untrusted_ad_claim: bool,
}

impl<'a> CorrelatedResponse<'a> {
    /// The correlated response.
    #[must_use]
    pub const fn response(&self) -> &'a Message {
        self.message
    }

    /// Whether the sender asserted AD. Never treat this as local validation.
    #[must_use]
    pub const fn untrusted_ad_claim(&self) -> bool {
        self.untrusted_ad_claim
    }
}

fn parse_question(
    message: &[u8],
    offset: usize,
    limits: ParseLimits,
) -> Result<(Question, usize), Error> {
    let (name, cursor) = decode_name(message, offset, message.len(), limits)?;
    let end = cursor.checked_add(4).ok_or(Error::LengthOverflow)?;
    let fixed = message.get(cursor..end).ok_or(Error::UnexpectedEof)?;
    Ok((
        Question {
            name,
            record_type: RecordType::from_code(be_u16(fixed, 0)?),
            class: be_u16(fixed, 2)?,
        },
        end,
    ))
}

fn validate_pseudo_records(message: &Message) -> Result<(), Error> {
    if message
        .answers
        .iter()
        .chain(&message.authorities)
        .any(|record| record.record_type == RecordType::Opt)
    {
        return Err(Error::InvalidEdns);
    }
    let mut opt_count = 0usize;
    for record in &message.additionals {
        if record.record_type == RecordType::Opt {
            opt_count = opt_count.checked_add(1).ok_or(Error::LengthOverflow)?;
            if opt_count > 1 || !record.name.is_root() {
                return Err(Error::InvalidEdns);
            }
        }
    }
    Ok(())
}

fn parse_records(
    message: &[u8],
    mut cursor: usize,
    count: u16,
    limits: ParseLimits,
) -> Result<(Vec<ResourceRecord>, usize), Error> {
    let mut records = Vec::with_capacity(usize::from(count));
    for _ in 0..count {
        let (record, next) = parse_record(message, cursor, limits)?;
        records.push(record);
        cursor = next;
    }
    Ok((records, cursor))
}

fn parse_record(
    message: &[u8],
    offset: usize,
    limits: ParseLimits,
) -> Result<(ResourceRecord, usize), Error> {
    let (name, cursor) = decode_name(message, offset, message.len(), limits)?;
    let fixed_end = cursor.checked_add(10).ok_or(Error::LengthOverflow)?;
    let fixed = message.get(cursor..fixed_end).ok_or(Error::UnexpectedEof)?;
    let record_type = RecordType::from_code(be_u16(fixed, 0)?);
    let class = be_u16(fixed, 2)?;
    let ttl = be_u32(fixed, 4)?;
    let rdata_len = usize::from(be_u16(fixed, 8)?);
    if rdata_len > limits.max_rdata_len {
        return Err(Error::RdataLimit);
    }
    let rdata_start = fixed_end;
    let rdata_end = rdata_start
        .checked_add(rdata_len)
        .ok_or(Error::LengthOverflow)?;
    message
        .get(rdata_start..rdata_end)
        .ok_or(Error::UnexpectedEof)?;
    let rdata = parse_rdata(message, rdata_start, rdata_end, record_type, limits)?;
    Ok((
        ResourceRecord {
            name,
            record_type,
            class,
            ttl,
            rdata,
        },
        rdata_end,
    ))
}

fn parse_rdata(
    message: &[u8],
    start: usize,
    end: usize,
    record_type: RecordType,
    limits: ParseLimits,
) -> Result<Rdata, Error> {
    let raw = message.get(start..end).ok_or(Error::UnexpectedEof)?;
    match record_type {
        RecordType::A => {
            let bytes: [u8; 4] = raw.try_into().map_err(|_| Error::InvalidRdata)?;
            Ok(Rdata::A(Ipv4Addr::from(bytes)))
        }
        RecordType::Aaaa => {
            let bytes: [u8; 16] = raw.try_into().map_err(|_| Error::InvalidRdata)?;
            Ok(Rdata::Aaaa(Ipv6Addr::from(bytes)))
        }
        RecordType::Ns | RecordType::Cname => {
            let (name, next) = decode_name(message, start, end, limits)?;
            if next != end {
                return Err(Error::InvalidRdata);
            }
            Ok(if record_type == RecordType::Ns {
                Rdata::Ns(name)
            } else {
                Rdata::Cname(name)
            })
        }
        RecordType::Soa => parse_soa(message, start, end, limits).map(Rdata::Soa),
        RecordType::Mx => parse_mx(message, start, end, limits).map(Rdata::Mx),
        RecordType::Txt => parse_txt(raw).map(Rdata::Txt),
        RecordType::Srv => parse_srv(message, start, end, limits).map(Rdata::Srv),
        RecordType::Ds => parse_ds(raw).map(Rdata::Ds),
        RecordType::Dnskey => parse_dnskey(raw).map(Rdata::Dnskey),
        RecordType::Rrsig => parse_rrsig(message, start, end, limits).map(Rdata::Rrsig),
        RecordType::Nsec => parse_nsec(message, start, end, limits).map(Rdata::Nsec),
        RecordType::Nsec3 => parse_nsec3(raw).map(Rdata::Nsec3),
        RecordType::Tlsa => parse_tlsa(raw).map(Rdata::Tlsa),
        RecordType::Opt => parse_edns(raw).map(Rdata::Opt),
        RecordType::Svcb | RecordType::Https | RecordType::Unknown(_) => {
            Ok(Rdata::Opaque(raw.to_vec()))
        }
    }
}

fn parse_soa(message: &[u8], start: usize, end: usize, limits: ParseLimits) -> Result<Soa, Error> {
    let (mname, next) = decode_name(message, start, end, limits)?;
    let (rname, next) = decode_name(message, next, end, limits)?;
    let fixed_end = next.checked_add(20).ok_or(Error::LengthOverflow)?;
    let fixed = message.get(next..fixed_end).ok_or(Error::InvalidRdata)?;
    if fixed_end != end {
        return Err(Error::InvalidRdata);
    }
    Ok(Soa {
        mname,
        rname,
        serial: be_u32(fixed, 0)?,
        refresh: be_u32(fixed, 4)?,
        retry: be_u32(fixed, 8)?,
        expire: be_u32(fixed, 12)?,
        minimum: be_u32(fixed, 16)?,
    })
}

fn parse_mx(message: &[u8], start: usize, end: usize, limits: ParseLimits) -> Result<Mx, Error> {
    let preference = be_u16(message.get(start..end).ok_or(Error::InvalidRdata)?, 0)?;
    let name_start = start.checked_add(2).ok_or(Error::LengthOverflow)?;
    let (exchange, next) = decode_name(message, name_start, end, limits)?;
    if next != end {
        return Err(Error::InvalidRdata);
    }
    Ok(Mx {
        preference,
        exchange,
    })
}

fn parse_txt(raw: &[u8]) -> Result<Vec<Vec<u8>>, Error> {
    let mut cursor = 0usize;
    let mut strings = Vec::new();
    while cursor < raw.len() {
        let length = usize::from(*raw.get(cursor).ok_or(Error::InvalidRdata)?);
        cursor = cursor.checked_add(1).ok_or(Error::LengthOverflow)?;
        let end = cursor.checked_add(length).ok_or(Error::LengthOverflow)?;
        strings.push(raw.get(cursor..end).ok_or(Error::InvalidRdata)?.to_vec());
        cursor = end;
    }
    if strings.is_empty() {
        return Err(Error::InvalidRdata);
    }
    Ok(strings)
}

fn parse_srv(message: &[u8], start: usize, end: usize, limits: ParseLimits) -> Result<Srv, Error> {
    let raw = message.get(start..end).ok_or(Error::InvalidRdata)?;
    let target_start = start.checked_add(6).ok_or(Error::LengthOverflow)?;
    let (target, next) = decode_name(message, target_start, end, limits)?;
    if next != end {
        return Err(Error::InvalidRdata);
    }
    Ok(Srv {
        priority: be_u16(raw, 0)?,
        weight: be_u16(raw, 2)?,
        port: be_u16(raw, 4)?,
        target,
    })
}

fn parse_ds(raw: &[u8]) -> Result<Ds, Error> {
    if raw.len() < 5 {
        return Err(Error::InvalidRdata);
    }
    Ok(Ds {
        key_tag: be_u16(raw, 0)?,
        algorithm: *raw.get(2).ok_or(Error::InvalidRdata)?,
        digest_type: *raw.get(3).ok_or(Error::InvalidRdata)?,
        digest: raw.get(4..).ok_or(Error::InvalidRdata)?.to_vec(),
    })
}

fn parse_dnskey(raw: &[u8]) -> Result<Dnskey, Error> {
    if raw.len() < 5 {
        return Err(Error::InvalidRdata);
    }
    Ok(Dnskey {
        flags: be_u16(raw, 0)?,
        protocol: *raw.get(2).ok_or(Error::InvalidRdata)?,
        algorithm: *raw.get(3).ok_or(Error::InvalidRdata)?,
        public_key: raw.get(4..).ok_or(Error::InvalidRdata)?.to_vec(),
    })
}

fn parse_rrsig(
    message: &[u8],
    start: usize,
    end: usize,
    limits: ParseLimits,
) -> Result<Rrsig, Error> {
    let fixed_end = start.checked_add(18).ok_or(Error::LengthOverflow)?;
    let fixed = message.get(start..fixed_end).ok_or(Error::InvalidRdata)?;
    let (signer, next) = decode_name(message, fixed_end, end, limits)?;
    let signature = message.get(next..end).ok_or(Error::InvalidRdata)?;
    if signature.is_empty() {
        return Err(Error::InvalidRdata);
    }
    Ok(Rrsig {
        type_covered: RecordType::from_code(be_u16(fixed, 0)?),
        algorithm: *fixed.get(2).ok_or(Error::InvalidRdata)?,
        labels: *fixed.get(3).ok_or(Error::InvalidRdata)?,
        original_ttl: be_u32(fixed, 4)?,
        expiration: be_u32(fixed, 8)?,
        inception: be_u32(fixed, 12)?,
        key_tag: be_u16(fixed, 16)?,
        signer,
        signature: signature.to_vec(),
    })
}

fn parse_nsec(
    message: &[u8],
    start: usize,
    end: usize,
    limits: ParseLimits,
) -> Result<Nsec, Error> {
    let (next_domain, next) = decode_name(message, start, end, limits)?;
    let bitmap = message.get(next..end).ok_or(Error::InvalidRdata)?;
    validate_type_bitmaps(bitmap)?;
    Ok(Nsec {
        next_domain,
        type_bitmaps: bitmap.to_vec(),
    })
}

fn parse_nsec3(raw: &[u8]) -> Result<Nsec3, Error> {
    if raw.len() < 6 {
        return Err(Error::InvalidRdata);
    }
    let salt_len = usize::from(*raw.get(4).ok_or(Error::InvalidRdata)?);
    let salt_start = 5usize;
    let salt_end = salt_start
        .checked_add(salt_len)
        .ok_or(Error::LengthOverflow)?;
    let hash_len = usize::from(*raw.get(salt_end).ok_or(Error::InvalidRdata)?);
    if hash_len == 0 {
        return Err(Error::InvalidRdata);
    }
    let hash_start = salt_end.checked_add(1).ok_or(Error::LengthOverflow)?;
    let hash_end = hash_start
        .checked_add(hash_len)
        .ok_or(Error::LengthOverflow)?;
    let bitmap = raw.get(hash_end..).ok_or(Error::InvalidRdata)?;
    validate_type_bitmaps(bitmap)?;
    Ok(Nsec3 {
        hash_algorithm: *raw.first().ok_or(Error::InvalidRdata)?,
        flags: *raw.get(1).ok_or(Error::InvalidRdata)?,
        iterations: be_u16(raw, 2)?,
        salt: raw
            .get(salt_start..salt_end)
            .ok_or(Error::InvalidRdata)?
            .to_vec(),
        next_hashed_owner: raw
            .get(hash_start..hash_end)
            .ok_or(Error::InvalidRdata)?
            .to_vec(),
        type_bitmaps: bitmap.to_vec(),
    })
}

fn parse_tlsa(raw: &[u8]) -> Result<Tlsa, Error> {
    if raw.len() < 4 {
        return Err(Error::InvalidRdata);
    }
    Ok(Tlsa {
        usage: *raw.first().ok_or(Error::InvalidRdata)?,
        selector: *raw.get(1).ok_or(Error::InvalidRdata)?,
        matching_type: *raw.get(2).ok_or(Error::InvalidRdata)?,
        association_data: raw.get(3..).ok_or(Error::InvalidRdata)?.to_vec(),
    })
}

fn parse_edns(raw: &[u8]) -> Result<Vec<EdnsOption>, Error> {
    let mut cursor = 0usize;
    let mut options = Vec::new();
    while cursor < raw.len() {
        let header_end = cursor.checked_add(4).ok_or(Error::LengthOverflow)?;
        let header = raw.get(cursor..header_end).ok_or(Error::InvalidEdns)?;
        let code = be_u16(header, 0).map_err(|_| Error::InvalidEdns)?;
        let length = usize::from(be_u16(header, 2).map_err(|_| Error::InvalidEdns)?);
        let data_end = header_end
            .checked_add(length)
            .ok_or(Error::LengthOverflow)?;
        options.push(EdnsOption {
            code,
            data: raw
                .get(header_end..data_end)
                .ok_or(Error::InvalidEdns)?
                .to_vec(),
        });
        cursor = data_end;
    }
    Ok(options)
}

fn validate_type_bitmaps(raw: &[u8]) -> Result<(), Error> {
    let mut cursor = 0usize;
    let mut previous_window = None;
    let mut block_count = 0usize;
    while cursor < raw.len() {
        let window = *raw.get(cursor).ok_or(Error::InvalidRdata)?;
        let bitmap_len = usize::from(*raw.get(cursor + 1).ok_or(Error::InvalidRdata)?);
        if !(1..=32).contains(&bitmap_len)
            || previous_window.is_some_and(|previous| window <= previous)
        {
            return Err(Error::InvalidRdata);
        }
        previous_window = Some(window);
        cursor = cursor
            .checked_add(2)
            .and_then(|value| value.checked_add(bitmap_len))
            .ok_or(Error::LengthOverflow)?;
        if cursor > raw.len() {
            return Err(Error::InvalidRdata);
        }
        block_count = block_count.checked_add(1).ok_or(Error::LengthOverflow)?;
        if block_count > 256 {
            return Err(Error::InvalidRdata);
        }
    }
    if block_count == 0 {
        return Err(Error::InvalidRdata);
    }
    Ok(())
}

fn decode_name(
    message: &[u8],
    offset: usize,
    contiguous_end: usize,
    limits: ParseLimits,
) -> Result<(Name, usize), Error> {
    if contiguous_end > message.len() || offset >= contiguous_end {
        return Err(Error::UnexpectedEof);
    }
    let mut labels = Vec::new();
    let mut cursor = offset;
    let mut consumed_end = None;
    let mut jumps = 0usize;
    let mut expanded_len = 1usize;
    let mut visited = vec![false; message.len()];

    loop {
        let was_visited = *visited.get(cursor).ok_or(Error::PointerOutOfBounds)?;
        if was_visited {
            return Err(Error::CompressionLoop);
        }
        let slot = visited.get_mut(cursor).ok_or(Error::PointerOutOfBounds)?;
        *slot = true;

        let length = *message.get(cursor).ok_or(Error::UnexpectedEof)?;
        match length & 0xc0 {
            0xc0 => {
                let pointer_end = cursor.checked_add(2).ok_or(Error::LengthOverflow)?;
                if consumed_end.is_none() && pointer_end > contiguous_end {
                    return Err(Error::UnexpectedEof);
                }
                let second = *message.get(cursor + 1).ok_or(Error::UnexpectedEof)?;
                let pointer = (usize::from(length & 0x3f) << 8) | usize::from(second);
                if pointer >= message.len() {
                    return Err(Error::PointerOutOfBounds);
                }
                if pointer >= cursor {
                    return Err(Error::ForwardPointer);
                }
                if consumed_end.is_none() {
                    consumed_end = Some(pointer_end);
                }
                jumps = jumps.checked_add(1).ok_or(Error::LengthOverflow)?;
                if jumps > limits.max_compression_jumps {
                    return Err(Error::CompressionJumpLimit);
                }
                cursor = pointer;
            }
            0x00 => {
                cursor = cursor.checked_add(1).ok_or(Error::LengthOverflow)?;
                if length == 0 {
                    let next = consumed_end.unwrap_or(cursor);
                    return Ok((Name { labels }, next));
                }
                let label_len = usize::from(length);
                if label_len > MAX_LABEL_LEN {
                    return Err(Error::InvalidLabel);
                }
                let label_end = cursor.checked_add(label_len).ok_or(Error::LengthOverflow)?;
                if consumed_end.is_none() && label_end > contiguous_end {
                    return Err(Error::UnexpectedEof);
                }
                let label = message.get(cursor..label_end).ok_or(Error::UnexpectedEof)?;
                expanded_len = expanded_len
                    .checked_add(label_len + 1)
                    .ok_or(Error::LengthOverflow)?;
                if expanded_len > MAX_WIRE_NAME_LEN || labels.len() >= limits.max_labels_per_name {
                    return Err(Error::NameLimit);
                }
                labels.push(canonical_label(label));
                cursor = label_end;
            }
            _ => return Err(Error::InvalidLabel),
        }
    }
}

fn canonical_label(label: &[u8]) -> Vec<u8> {
    label.iter().map(u8::to_ascii_lowercase).collect()
}

fn encode_question(question: &Question, output: &mut Vec<u8>) -> Result<(), Error> {
    question.name.encode(output)?;
    write_u16(output, question.record_type.code());
    write_u16(output, question.class);
    Ok(())
}

fn encode_record(record: &ResourceRecord, output: &mut Vec<u8>) -> Result<(), Error> {
    record.name.encode(output)?;
    write_u16(output, record.record_type.code());
    write_u16(output, record.class);
    output.extend_from_slice(&record.ttl.to_be_bytes());
    let mut rdata = Vec::new();
    encode_rdata(record.record_type, &record.rdata, &mut rdata)?;
    let length = u16::try_from(rdata.len()).map_err(|_| Error::EncodeLimit)?;
    write_u16(output, length);
    output.extend_from_slice(&rdata);
    Ok(())
}

#[allow(
    clippy::too_many_lines,
    reason = "keeping the RR-type mapping in one exhaustive function makes type checks auditable"
)]
fn encode_rdata(record_type: RecordType, rdata: &Rdata, output: &mut Vec<u8>) -> Result<(), Error> {
    match (record_type, rdata) {
        (RecordType::A, Rdata::A(address)) => output.extend_from_slice(&address.octets()),
        (RecordType::Aaaa, Rdata::Aaaa(address)) => {
            output.extend_from_slice(&address.octets());
        }
        (RecordType::Ns, Rdata::Ns(name)) | (RecordType::Cname, Rdata::Cname(name)) => {
            name.encode(output)?;
        }
        (RecordType::Soa, Rdata::Soa(soa)) => {
            soa.mname.encode(output)?;
            soa.rname.encode(output)?;
            for value in [soa.serial, soa.refresh, soa.retry, soa.expire, soa.minimum] {
                output.extend_from_slice(&value.to_be_bytes());
            }
        }
        (RecordType::Mx, Rdata::Mx(mx)) => {
            write_u16(output, mx.preference);
            mx.exchange.encode(output)?;
        }
        (RecordType::Txt, Rdata::Txt(strings)) => {
            if strings.is_empty() {
                return Err(Error::InvalidRdata);
            }
            for string in strings {
                let length = u8::try_from(string.len()).map_err(|_| Error::InvalidRdata)?;
                output.push(length);
                output.extend_from_slice(string);
            }
        }
        (RecordType::Srv, Rdata::Srv(srv)) => {
            write_u16(output, srv.priority);
            write_u16(output, srv.weight);
            write_u16(output, srv.port);
            srv.target.encode(output)?;
        }
        (RecordType::Ds, Rdata::Ds(ds)) => {
            write_u16(output, ds.key_tag);
            output.extend_from_slice(&[ds.algorithm, ds.digest_type]);
            output.extend_from_slice(&ds.digest);
        }
        (RecordType::Dnskey, Rdata::Dnskey(key)) => {
            write_u16(output, key.flags);
            output.extend_from_slice(&[key.protocol, key.algorithm]);
            output.extend_from_slice(&key.public_key);
        }
        (RecordType::Rrsig, Rdata::Rrsig(signature)) => {
            write_u16(output, signature.type_covered.code());
            output.extend_from_slice(&[signature.algorithm, signature.labels]);
            for value in [
                signature.original_ttl,
                signature.expiration,
                signature.inception,
            ] {
                output.extend_from_slice(&value.to_be_bytes());
            }
            write_u16(output, signature.key_tag);
            signature.signer.encode(output)?;
            output.extend_from_slice(&signature.signature);
        }
        (RecordType::Nsec, Rdata::Nsec(nsec)) => {
            nsec.next_domain.encode(output)?;
            validate_type_bitmaps(&nsec.type_bitmaps)?;
            output.extend_from_slice(&nsec.type_bitmaps);
        }
        (RecordType::Nsec3, Rdata::Nsec3(nsec3)) => {
            let salt_len = u8::try_from(nsec3.salt.len()).map_err(|_| Error::InvalidRdata)?;
            let hash_len =
                u8::try_from(nsec3.next_hashed_owner.len()).map_err(|_| Error::InvalidRdata)?;
            if hash_len == 0 {
                return Err(Error::InvalidRdata);
            }
            output.extend_from_slice(&[nsec3.hash_algorithm, nsec3.flags]);
            write_u16(output, nsec3.iterations);
            output.push(salt_len);
            output.extend_from_slice(&nsec3.salt);
            output.push(hash_len);
            output.extend_from_slice(&nsec3.next_hashed_owner);
            validate_type_bitmaps(&nsec3.type_bitmaps)?;
            output.extend_from_slice(&nsec3.type_bitmaps);
        }
        (RecordType::Tlsa, Rdata::Tlsa(tlsa)) => {
            if tlsa.association_data.is_empty() {
                return Err(Error::InvalidRdata);
            }
            output.extend_from_slice(&[tlsa.usage, tlsa.selector, tlsa.matching_type]);
            output.extend_from_slice(&tlsa.association_data);
        }
        (RecordType::Opt, Rdata::Opt(options)) => {
            for option in options {
                write_u16(output, option.code);
                let length = u16::try_from(option.data.len()).map_err(|_| Error::InvalidEdns)?;
                write_u16(output, length);
                output.extend_from_slice(&option.data);
            }
        }
        (RecordType::Svcb | RecordType::Https | RecordType::Unknown(_), Rdata::Opaque(bytes)) => {
            output.extend_from_slice(bytes);
        }
        _ => return Err(Error::TypeMismatch),
    }
    Ok(())
}

fn write_count(output: &mut Vec<u8>, count: usize) -> Result<(), Error> {
    write_u16(output, u16::try_from(count).map_err(|_| Error::CountLimit)?);
    Ok(())
}

fn write_u16(output: &mut Vec<u8>, value: u16) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn be_u16(bytes: &[u8], offset: usize) -> Result<u16, Error> {
    let end = offset.checked_add(2).ok_or(Error::LengthOverflow)?;
    let value: [u8; 2] = bytes
        .get(offset..end)
        .ok_or(Error::UnexpectedEof)?
        .try_into()
        .map_err(|_| Error::UnexpectedEof)?;
    Ok(u16::from_be_bytes(value))
}

fn be_u32(bytes: &[u8], offset: usize) -> Result<u32, Error> {
    let end = offset.checked_add(4).ok_or(Error::LengthOverflow)?;
    let value: [u8; 4] = bytes
        .get(offset..end)
        .ok_or(Error::UnexpectedEof)?
        .try_into()
        .map_err(|_| Error::UnexpectedEof)?;
    Ok(u32::from_be_bytes(value))
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "tests intentionally fail immediately on malformed fixtures"
)]
mod tests {
    use super::*;

    const BASIC_QUERY: &[u8] =
        b"\x12\x34\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01";
    const COMPRESSED_RESPONSE: &[u8] =
        b"\x12\x34\x84\x20\x00\x01\x00\x01\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x7f\x00\x00\x01";

    fn decode_hex(input: &str) -> Vec<u8> {
        let compact: Vec<u8> = input
            .bytes()
            .filter(|byte| !byte.is_ascii_whitespace())
            .collect();
        assert!(compact.len().is_multiple_of(2));
        compact
            .chunks_exact(2)
            .map(|pair| {
                let high = (pair[0] as char).to_digit(16).unwrap();
                let low = (pair[1] as char).to_digit(16).unwrap();
                u8::try_from((high << 4) | low).unwrap()
            })
            .collect()
    }

    #[test]
    fn pinned_fixture_corpus_matches_parser_contract() {
        let query_wire = decode_hex(include_str!("../fixtures/dns/basic-query.hex"));
        let response_wire = decode_hex(include_str!(
            "../fixtures/dns/compressed-a-response-ad.hex"
        ));
        let tlsa_wire = decode_hex(include_str!("../fixtures/dns/tlsa-response.hex"));
        let query = Query::parse(&query_wire, ParseLimits::requester()).unwrap();
        let response = Message::parse(&response_wire).unwrap();
        assert!(query.correlate(&response).unwrap().untrusted_ad_claim());

        let tlsa = Message::parse(&tlsa_wire).unwrap();
        assert!(matches!(tlsa.answers[0].rdata, Rdata::Tlsa(_)));

        let self_loop = decode_hex(include_str!(
            "../fixtures/dns/mutation-compression-self-loop.hex"
        ));
        assert_eq!(Message::parse(&self_loop), Err(Error::ForwardPointer));

        let out_of_bounds = decode_hex(include_str!(
            "../fixtures/dns/mutation-pointer-out-of-bounds.hex"
        ));
        assert_eq!(
            Message::parse(&out_of_bounds),
            Err(Error::PointerOutOfBounds)
        );

        let count_bomb = decode_hex(include_str!(
            "../fixtures/dns/mutation-count-bomb.hex"
        ));
        assert_eq!(
            Message::parse_with_limits(&count_bomb, ParseLimits::requester()),
            Err(Error::CountLimit)
        );
    }

    #[test]
    fn parses_and_correlates_compressed_response_without_trusting_ad() {
        let query = Query::parse(BASIC_QUERY, ParseLimits::requester()).unwrap();
        let response = Message::parse(COMPRESSED_RESPONSE).unwrap();
        let correlated = query.correlate(&response).unwrap();

        assert!(correlated.untrusted_ad_claim());
        assert_eq!(correlated.response().answers.len(), 1);
        assert_eq!(
            correlated.response().answers[0].rdata,
            Rdata::A(Ipv4Addr::LOCALHOST)
        );
    }

    #[test]
    fn outgoing_query_sets_do_but_not_rd() {
        let query = Query::new(
            7,
            Name::from_ascii("_443._tcp.example").unwrap(),
            RecordType::Tlsa,
        )
        .unwrap();
        let encoded = query.encode(1_232).unwrap();
        let parsed = Message::parse(&encoded).unwrap();

        assert!(!parsed.header.flags.recursion_desired());
        assert_eq!(parsed.additionals.len(), 1);
        assert_eq!(parsed.additionals[0].record_type, RecordType::Opt);
        assert_eq!(
            u16::try_from(parsed.additionals[0].ttl).unwrap() & EDNS_DO,
            EDNS_DO
        );
    }

    #[test]
    fn parses_tlsa_dnskey_ds_rrsig_nsec_and_nsec3() {
        let name = Name::from_ascii("example").unwrap();
        let records = vec![
            ResourceRecord {
                name: name.clone(),
                record_type: RecordType::Tlsa,
                class: CLASS_IN,
                ttl: 60,
                rdata: Rdata::Tlsa(Tlsa {
                    usage: 3,
                    selector: 1,
                    matching_type: 1,
                    association_data: vec![0x42; 32],
                }),
            },
            ResourceRecord {
                name: name.clone(),
                record_type: RecordType::Dnskey,
                class: CLASS_IN,
                ttl: 60,
                rdata: Rdata::Dnskey(Dnskey {
                    flags: 257,
                    protocol: 3,
                    algorithm: 13,
                    public_key: vec![0x11; 64],
                }),
            },
            ResourceRecord {
                name: name.clone(),
                record_type: RecordType::Ds,
                class: CLASS_IN,
                ttl: 60,
                rdata: Rdata::Ds(Ds {
                    key_tag: 42,
                    algorithm: 13,
                    digest_type: 2,
                    digest: vec![0x22; 32],
                }),
            },
            ResourceRecord {
                name: name.clone(),
                record_type: RecordType::Rrsig,
                class: CLASS_IN,
                ttl: 60,
                rdata: Rdata::Rrsig(Rrsig {
                    type_covered: RecordType::Tlsa,
                    algorithm: 13,
                    labels: 1,
                    original_ttl: 60,
                    expiration: 2_000_000_000,
                    inception: 1_900_000_000,
                    key_tag: 42,
                    signer: name.clone(),
                    signature: vec![0x33; 64],
                }),
            },
            ResourceRecord {
                name: name.clone(),
                record_type: RecordType::Nsec,
                class: CLASS_IN,
                ttl: 60,
                rdata: Rdata::Nsec(Nsec {
                    next_domain: Name::from_ascii("next").unwrap(),
                    type_bitmaps: vec![0, 1, 0x40],
                }),
            },
            ResourceRecord {
                name,
                record_type: RecordType::Nsec3,
                class: CLASS_IN,
                ttl: 60,
                rdata: Rdata::Nsec3(Nsec3 {
                    hash_algorithm: 1,
                    flags: 0,
                    iterations: 10,
                    salt: vec![1, 2],
                    next_hashed_owner: vec![0x44; 20],
                    type_bitmaps: vec![0, 1, 0x40],
                }),
            },
        ];
        let message = Message {
            header: Header {
                id: 3,
                flags: Flags::from_bits(0x8400),
                question_count: 0,
                answer_count: u16::try_from(records.len()).unwrap(),
                authority_count: 0,
                additional_count: 0,
            },
            questions: Vec::new(),
            answers: records.clone(),
            authorities: Vec::new(),
            additionals: Vec::new(),
        };
        let encoded = message.encode(u16::MAX as usize).unwrap();
        let parsed = Message::parse(&encoded).unwrap();

        assert_eq!(parsed.answers, records);
    }

    #[test]
    fn canonicalizes_ascii_case_and_escapes_opaque_octets() {
        let wire = b"\x03WwW\x02\xffx\x00";
        let (name, next) = decode_name(wire, 0, wire.len(), ParseLimits::browser()).unwrap();

        assert_eq!(next, wire.len());
        assert_eq!(name.labels()[0], b"www");
        assert_eq!(name.to_string(), "www.\\255x.");
    }

    #[test]
    fn accepts_maximum_wire_name_and_rejects_one_octet_more() {
        let valid = format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61)
        );
        assert_eq!(Name::from_ascii(&valid).unwrap().wire_len(), 255);

        let invalid = format!("{valid}e");
        assert_eq!(Name::from_ascii(&invalid), Err(Error::NameLimit));
    }

    #[test]
    fn rejects_self_pointer_loop() {
        assert_eq!(
            decode_name(b"\xc0\x00", 0, 2, ParseLimits::browser()),
            Err(Error::ForwardPointer)
        );
    }

    #[test]
    fn rejects_two_pointer_cycle() {
        let message = b"\x00\x00\xc0\x04\xc0\x02";
        assert_eq!(
            decode_name(message, 4, message.len(), ParseLimits::browser()),
            Err(Error::ForwardPointer)
        );
    }

    #[test]
    fn rejects_out_of_bounds_pointer() {
        assert_eq!(
            decode_name(b"\x00\xc0\xff", 1, 3, ParseLimits::browser()),
            Err(Error::PointerOutOfBounds)
        );
    }

    #[test]
    fn rejects_reserved_label_bits() {
        assert_eq!(
            decode_name(b"\x40\x00", 0, 2, ParseLimits::browser()),
            Err(Error::InvalidLabel)
        );
    }

    #[test]
    fn rejects_count_bomb_before_section_allocation() {
        let message = b"\x00\x01\x80\x00\xff\xff\xff\xff\xff\xff\xff\xff";
        assert_eq!(
            Message::parse_with_limits(message, ParseLimits::requester()),
            Err(Error::CountLimit)
        );
    }

    #[test]
    fn rejects_reserved_header_bits_and_oversized_tcp_message() {
        let mut reserved = BASIC_QUERY.to_vec();
        reserved[3] |= 0x40;
        assert_eq!(Message::parse(&reserved), Err(Error::ReservedHeaderBits));

        assert_eq!(
            Message::parse(&vec![0; usize::from(u16::MAX) + 1]),
            Err(Error::MessageTooLong)
        );
    }

    #[test]
    fn strict_query_rejects_ecs_and_misplaced_opt() {
        let query = Query::new(9, Name::from_ascii("example").unwrap(), RecordType::A).unwrap();
        let mut encoded = query.encode(1_232).unwrap();
        // Replace empty OPT RDATA with one empty ECS option.
        encoded.truncate(encoded.len() - 2);
        encoded.extend_from_slice(&[0, 4, 0, 8, 0, 0]);
        assert_eq!(
            Query::parse(&encoded, ParseLimits::requester()),
            Err(Error::InvalidQuery)
        );

        let misplaced = Message {
            header: Header {
                id: 1,
                flags: Flags::from_bits(0x8000),
                question_count: 0,
                answer_count: 1,
                authority_count: 0,
                additional_count: 0,
            },
            questions: Vec::new(),
            answers: vec![ResourceRecord {
                name: Name::root(),
                record_type: RecordType::Opt,
                class: DEFAULT_UDP_PAYLOAD,
                ttl: 0,
                rdata: Rdata::Opt(Vec::new()),
            }],
            authorities: Vec::new(),
            additionals: Vec::new(),
        }
        .encode(1_232)
        .unwrap();
        assert_eq!(Message::parse(&misplaced), Err(Error::InvalidEdns));
    }

    #[test]
    fn rejects_truncated_and_oversized_rdata() {
        let truncated =
            b"\x00\x01\x80\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x01\x00\x01\x00\x00\x00\x00\x00\x04\x7f";
        assert_eq!(
            Message::parse_with_limits(truncated, ParseLimits::browser()),
            Err(Error::UnexpectedEof)
        );

        let mut limits = ParseLimits::browser();
        limits.max_rdata_len = 2;
        assert_eq!(
            Message::parse_with_limits(COMPRESSED_RESPONSE, limits),
            Err(Error::RdataLimit)
        );
    }

    #[test]
    fn mutation_negatives_reject_response_mismatches() {
        let query = Query::parse(BASIC_QUERY, ParseLimits::requester()).unwrap();

        let mut bad_id = COMPRESSED_RESPONSE.to_vec();
        bad_id[1] ^= 1;
        assert_eq!(
            query
                .correlate(&Message::parse(&bad_id).unwrap())
                .unwrap_err(),
            Error::IdMismatch
        );

        let mut bad_name = COMPRESSED_RESPONSE.to_vec();
        bad_name[13] = b'f';
        assert_eq!(
            query
                .correlate(&Message::parse(&bad_name).unwrap())
                .unwrap_err(),
            Error::QuestionMismatch
        );

        let mut truncated = COMPRESSED_RESPONSE.to_vec();
        truncated[2] |= 0x02;
        assert_eq!(
            query
                .correlate(&Message::parse(&truncated).unwrap())
                .unwrap_err(),
            Error::Truncated
        );
    }

    #[test]
    fn rejects_malformed_dnssec_rdata() {
        let message =
            b"\x00\x01\x80\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x2b\x00\x01\x00\x00\x00\x00\x00\x04\x00\x01\x08\x02";
        assert_eq!(Message::parse(message), Err(Error::InvalidRdata));
    }

    #[test]
    fn rejects_invalid_nsec_bitmap_window_order() {
        let nsec = ResourceRecord {
            name: Name::from_ascii("example").unwrap(),
            record_type: RecordType::Nsec,
            class: CLASS_IN,
            ttl: 60,
            rdata: Rdata::Nsec(Nsec {
                next_domain: Name::from_ascii("next").unwrap(),
                type_bitmaps: vec![1, 1, 1, 0, 1, 1],
            }),
        };
        let message = Message {
            header: Header {
                id: 1,
                flags: Flags::from_bits(0x8000),
                question_count: 0,
                answer_count: 1,
                authority_count: 0,
                additional_count: 0,
            },
            questions: Vec::new(),
            answers: vec![nsec],
            authorities: Vec::new(),
            additionals: Vec::new(),
        };
        assert_eq!(message.encode(1_232), Err(Error::InvalidRdata));
    }
}
