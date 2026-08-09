use crate::dns::{DnsName, RecordType, ResourceRecord};
use thiserror::Error;

pub const DEFAULT_HANDSHAKE_RESOURCE_TTL: u32 = 21_600;
pub const MAX_HANDSHAKE_RESOURCE_RECORDS: usize = 128;
pub const MAX_HANDSHAKE_TXT_STRINGS: usize = 64;

const RESOURCE_VERSION: u8 = 0;
const HS_TYPE_DS: u8 = 0;
const HS_TYPE_NS: u8 = 1;
const HS_TYPE_GLUE4: u8 = 2;
const HS_TYPE_GLUE6: u8 = 3;
const HS_TYPE_SYNTH4: u8 = 4;
const HS_TYPE_SYNTH6: u8 = 5;
const HS_TYPE_TXT: u8 = 6;

#[derive(Debug, Error, Eq, PartialEq)]
pub enum ResourceError {
    #[error("Handshake resource is malformed")]
    Malformed,
    #[error("Handshake resource serialization version is unsupported")]
    UnsupportedVersion,
    #[error("Handshake resource record type is unsupported")]
    UnsupportedRecordType,
    #[error("Handshake resource exceeds record limits")]
    TooManyRecords,
}

pub fn decode_handshake_resource_records(
    owner: &DnsName,
    data: &[u8],
) -> Result<Vec<ResourceRecord>, ResourceError> {
    decode_handshake_resource_records_with_ttl(owner, data, DEFAULT_HANDSHAKE_RESOURCE_TTL)
}

pub fn decode_handshake_resource_records_with_ttl(
    owner: &DnsName,
    data: &[u8],
    ttl: u32,
) -> Result<Vec<ResourceRecord>, ResourceError> {
    let mut cursor = Cursor::new(data);
    let version = cursor.read_u8()?;
    if version != RESOURCE_VERSION {
        return Err(ResourceError::UnsupportedVersion);
    }

    let mut records = Vec::new();
    while cursor.remaining() > 0 {
        match cursor.read_u8()? {
            HS_TYPE_DS => {
                let key_tag = cursor.read_u16_be()?;
                let algorithm = cursor.read_u8()?;
                let digest_type = cursor.read_u8()?;
                let digest = cursor.read_len_u8_bytes()?;
                let mut rdata = Vec::with_capacity(4 + digest.len());
                rdata.extend(key_tag.to_be_bytes());
                rdata.push(algorithm);
                rdata.push(digest_type);
                rdata.extend(digest);
                push_record(
                    &mut records,
                    record(owner.clone(), RecordType::Ds, ttl, rdata),
                )?;
            }
            HS_TYPE_NS => {
                let ns = cursor.read_name()?;
                push_record(
                    &mut records,
                    record(owner.clone(), RecordType::Ns, ttl, name_rdata(&ns)?),
                )?;
            }
            HS_TYPE_GLUE4 => {
                let ns = cursor.read_name()?;
                let address = cursor.read_array::<4>()?;
                push_record(
                    &mut records,
                    record(owner.clone(), RecordType::Ns, ttl, name_rdata(&ns)?),
                )?;
                if is_subdomain_or_equal(&ns, owner) {
                    push_record(
                        &mut records,
                        record(ns, RecordType::A, ttl, address.to_vec()),
                    )?;
                }
            }
            HS_TYPE_GLUE6 => {
                let ns = cursor.read_name()?;
                let address = cursor.read_array::<16>()?;
                push_record(
                    &mut records,
                    record(owner.clone(), RecordType::Ns, ttl, name_rdata(&ns)?),
                )?;
                if is_subdomain_or_equal(&ns, owner) {
                    push_record(
                        &mut records,
                        record(ns, RecordType::Aaaa, ttl, address.to_vec()),
                    )?;
                }
            }
            HS_TYPE_SYNTH4 => {
                let address = cursor.read_array::<4>()?;
                let ns = synth_name(&address)?;
                push_record(
                    &mut records,
                    record(owner.clone(), RecordType::Ns, ttl, name_rdata(&ns)?),
                )?;
                push_record(
                    &mut records,
                    record(ns, RecordType::A, ttl, address.to_vec()),
                )?;
            }
            HS_TYPE_SYNTH6 => {
                let address = cursor.read_array::<16>()?;
                let ns = synth_name(&address)?;
                push_record(
                    &mut records,
                    record(owner.clone(), RecordType::Ns, ttl, name_rdata(&ns)?),
                )?;
                push_record(
                    &mut records,
                    record(ns, RecordType::Aaaa, ttl, address.to_vec()),
                )?;
            }
            HS_TYPE_TXT => {
                let count = cursor.read_u8()? as usize;
                if count > MAX_HANDSHAKE_TXT_STRINGS {
                    return Err(ResourceError::TooManyRecords);
                }
                let mut rdata = Vec::new();
                for _ in 0..count {
                    let text = cursor.read_len_u8_bytes()?;
                    rdata.push(text.len() as u8);
                    rdata.extend(text);
                }
                push_record(
                    &mut records,
                    record(owner.clone(), RecordType::Txt, ttl, rdata),
                )?;
            }
            _ => return Err(ResourceError::UnsupportedRecordType),
        }
    }

    Ok(records)
}

fn push_record(
    records: &mut Vec<ResourceRecord>,
    record: ResourceRecord,
) -> Result<(), ResourceError> {
    if records.len() >= MAX_HANDSHAKE_RESOURCE_RECORDS {
        return Err(ResourceError::TooManyRecords);
    }
    records.push(record);
    Ok(())
}

fn record(name: DnsName, record_type: RecordType, ttl: u32, rdata: Vec<u8>) -> ResourceRecord {
    ResourceRecord {
        name,
        record_type,
        class: 1,
        ttl,
        rdata,
    }
}

fn name_rdata(name: &DnsName) -> Result<Vec<u8>, ResourceError> {
    let mut rdata = Vec::new();
    name.encode_wire(&mut rdata)
        .map_err(|_| ResourceError::Malformed)?;
    Ok(rdata)
}

fn is_subdomain_or_equal(name: &DnsName, parent: &DnsName) -> bool {
    name.labels().ends_with(parent.labels())
}

fn synth_name(address: &[u8]) -> Result<DnsName, ResourceError> {
    DnsName::from_ascii(&format!("_{}._synth", base32hex_nopad(address)))
        .map_err(|_| ResourceError::Malformed)
}

fn base32hex_nopad(input: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"0123456789abcdefghijklmnopqrstuv";
    let mut out = String::new();
    let mut buffer = 0u32;
    let mut bits = 0u8;
    for byte in input {
        buffer = (buffer << 8) | (*byte as u32);
        bits += 8;
        while bits >= 5 {
            let index = ((buffer >> (bits - 5)) & 0x1f) as usize;
            out.push(ALPHABET[index] as char);
            bits -= 5;
        }
    }
    if bits > 0 {
        let index = ((buffer << (5 - bits)) & 0x1f) as usize;
        out.push(ALPHABET[index] as char);
    }
    out
}

struct Cursor<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, offset: 0 }
    }

    fn read_u8(&mut self) -> Result<u8, ResourceError> {
        let byte = *self.data.get(self.offset).ok_or(ResourceError::Malformed)?;
        self.offset += 1;
        Ok(byte)
    }

    fn read_u16_be(&mut self) -> Result<u16, ResourceError> {
        let bytes = self.read_array::<2>()?;
        Ok(u16::from_be_bytes(bytes))
    }

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N], ResourceError> {
        let bytes = self.read_bytes(N)?;
        let mut out = [0u8; N];
        out.copy_from_slice(bytes);
        Ok(out)
    }

    fn read_len_u8_bytes(&mut self) -> Result<&'a [u8], ResourceError> {
        let len = self.read_u8()? as usize;
        self.read_bytes(len)
    }

    fn read_name(&mut self) -> Result<DnsName, ResourceError> {
        let (name, next) =
            DnsName::parse_wire(self.data, self.offset).map_err(|_| ResourceError::Malformed)?;
        if next <= self.offset || next > self.data.len() {
            return Err(ResourceError::Malformed);
        }
        self.offset = next;
        Ok(name)
    }

    fn read_bytes(&mut self, len: usize) -> Result<&'a [u8], ResourceError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(ResourceError::Malformed)?;
        let bytes = self
            .data
            .get(self.offset..end)
            .ok_or(ResourceError::Malformed)?;
        self.offset = end;
        Ok(bytes)
    }

    fn remaining(&self) -> usize {
        self.data.len() - self.offset
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_ds_ns_and_txt_records() {
        let owner = DnsName::from_ascii("welcome").unwrap();
        let mut resource = vec![0, HS_TYPE_DS, 0x12, 0x34, 13, 2, 3, 0xaa, 0xbb, 0xcc];
        resource.push(HS_TYPE_NS);
        encode_name(&mut resource, "ns1.welcome");
        resource.push(HS_TYPE_TXT);
        resource.push(2);
        resource.push(5);
        resource.extend(b"proof");
        resource.push(4);
        resource.extend(b"hns!");

        let records = decode_handshake_resource_records(&owner, &resource).unwrap();

        assert_eq!(records.len(), 3);
        assert_eq!(records[0].record_type, RecordType::Ds);
        assert_eq!(records[0].rdata, vec![0x12, 0x34, 13, 2, 0xaa, 0xbb, 0xcc]);
        assert_eq!(records[1].record_type, RecordType::Ns);
        assert_eq!(records[1].rdata, name_bytes("ns1.welcome"));
        assert_eq!(records[2].record_type, RecordType::Txt);
        assert_eq!(records[2].rdata, b"\x05proof\x04hns!".to_vec());
    }

    #[test]
    fn decodes_glue_and_synth_records() {
        let owner = DnsName::from_ascii("welcome").unwrap();
        let mut resource = vec![0, HS_TYPE_GLUE4];
        encode_name(&mut resource, "ns1.welcome");
        resource.extend([127, 0, 0, 1]);
        resource.push(HS_TYPE_SYNTH4);
        resource.extend([45, 77, 219, 32]);

        let records = decode_handshake_resource_records(&owner, &resource).unwrap();

        assert_eq!(records.len(), 4);
        assert_eq!(records[0].record_type, RecordType::Ns);
        assert_eq!(records[1].name, DnsName::from_ascii("ns1.welcome").unwrap());
        assert_eq!(records[1].record_type, RecordType::A);
        assert_eq!(records[1].rdata, vec![127, 0, 0, 1]);
        assert_eq!(records[2].rdata, name_bytes("_5l6tm80._synth"));
        assert_eq!(
            records[3].name,
            DnsName::from_ascii("_5l6tm80._synth").unwrap()
        );
        assert_eq!(records[3].rdata, vec![45, 77, 219, 32]);
    }

    #[test]
    fn decodes_compressed_resource_names() {
        let owner = DnsName::from_ascii("welcome").unwrap();
        let mut resource = vec![0, HS_TYPE_NS];
        encode_name(&mut resource, "ns1.welcome");
        resource.push(HS_TYPE_NS);
        resource.extend([3, b'n', b's', b'2', 0xc0, 6]);

        let records = decode_handshake_resource_records(&owner, &resource).unwrap();

        assert_eq!(records[0].rdata, name_bytes("ns1.welcome"));
        assert_eq!(records[1].rdata, name_bytes("ns2.welcome"));
    }

    #[test]
    fn rejects_malformed_or_unsupported_resources() {
        let owner = DnsName::from_ascii("welcome").unwrap();

        assert_eq!(
            decode_handshake_resource_records(&owner, &[1]).unwrap_err(),
            ResourceError::UnsupportedVersion,
        );
        assert_eq!(
            decode_handshake_resource_records(&owner, &[0, 255]).unwrap_err(),
            ResourceError::UnsupportedRecordType,
        );
        assert_eq!(
            decode_handshake_resource_records(&owner, &[0, HS_TYPE_DS, 0]).unwrap_err(),
            ResourceError::Malformed,
        );
    }

    #[test]
    fn rejects_resources_that_expand_past_record_limit() {
        let owner = DnsName::from_ascii("welcome").unwrap();
        let mut resource = vec![0];
        for _ in 0..MAX_HANDSHAKE_RESOURCE_RECORDS {
            resource.push(HS_TYPE_NS);
            encode_name(&mut resource, "ns1.welcome");
        }
        resource.push(HS_TYPE_SYNTH4);
        resource.extend([127, 0, 0, 1]);

        assert_eq!(
            decode_handshake_resource_records(&owner, &resource).unwrap_err(),
            ResourceError::TooManyRecords,
        );
    }

    fn encode_name(out: &mut Vec<u8>, name: &str) {
        DnsName::from_ascii(name).unwrap().encode_wire(out).unwrap();
    }

    fn name_bytes(name: &str) -> Vec<u8> {
        let mut out = Vec::new();
        encode_name(&mut out, name);
        out
    }
}
