pub mod bytes;
pub mod dns;
pub mod hash;
pub mod header;
pub mod network;
pub mod network_policy;
pub mod pow;
pub mod resource;

pub use hash::{Hash, MAX_HANDSHAKE_NAME_LEN, NameHash, NameHashError, validate_handshake_name};
pub use header::{BlockHeader, HEADER_SIZE};
pub use pow::{Chainwork, Target};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Height(pub u32);

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Timestamp(pub u64);
