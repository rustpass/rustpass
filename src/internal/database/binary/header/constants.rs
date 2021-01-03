/// DH_BLOCKID VALUES

/// END - end of the dynamic header entries, there are no more entries after end
pub(crate) const DH_BLOCKID_END: u8 = 0x00;
/// COMMENT - comment specifies some arbitrary data not to be parsed any further
pub(crate) const DH_BLOCKID_COMMENT: u8 = 0x01;
/// CIPHERID - a UUID specifying which cipher suite should be used to encrypt the payload
pub(crate) const DH_BLOCKID_CIPHERID: u8 = 0x02;
/// COMPRESSIONFLAGS - first byte determines compression of payload
pub(crate) const DH_BLOCKID_COMPRESSIONFLAGS: u8 = 0x03;
/// MASTERSEED - Master seed for deriving the master key
pub(crate) const DH_BLOCKID_MASTERSEED: u8 = 0x04;
/// TRANSFORMSEED - Seed used in deriving the transformed key
pub(crate) const DH_BLOCKID_TRANSFORMSEED: u8 = 0x05;
/// TRANSFORMROUNDS - Number of rounds used in derivation of transformed key
pub(crate) const DH_BLOCKID_TRANSFORMROUNDS: u8 = 0x06;
/// ENCRYPTIONIV - Initialization Vector for decrypting the payload
pub(crate) const DH_BLOCKID_ENCRYPTIONIV: u8 = 0x07;
/// PROTECTEDSTREAMKEY - Key for decrypting the inner protected valuesWSq
pub(crate) const DH_BLOCKID_PROTECTEDSTREAMKEY: u8 = 0x08;
/// STREAMSTARTBYTES - First bytes of decrypted payload (to check correct decryption)
pub(crate) const DH_BLOCKID_STREAMSTARTBYTES: u8 = 0x09;
/// INNERRANDOMSTREAMID - specifies which cipher suite to use for decrypting the inner protected values
pub(crate) const DH_BLOCKID_INNERRANDOMSTREAMID: u8 = 0x0a;
/// KDFPARAMETERS - parameters for the key derivation function
pub(crate) const DH_BLOCKID_KDFPARAMETERS: u8 = 0x0b;

pub(crate) const DH_INNER_BLOCKID_END: u8 = 0x00;
pub(crate) const DH_INNER_BLOCKID_RANDOM_STREAM_ID: u8 = 0x01;
pub(crate) const DH_INNER_BLOCKID_RANDOM_STREAM_KEY: u8 = 0x02;
pub(crate) const DH_INNER_BLOCKID_BINARY_ATTACHMENT: u8 = 0x03;

/// OUTER AES256 encryption, only supported mechanism
#[allow(dead_code)]
const DH_BLOCKDATA_CIPHERID: &str = "31c1f2e6bf714350be5805216afc5aff";

// COMPRESSIONFLAGS
#[allow(dead_code)]
const DH_BLOCKDATA_COMPRESSIONFLAGS_UNCOMPRESSED: u32 = 0u32;
#[allow(dead_code)]
const DH_BLOCKDATA_COMPRESSIONFLAGS_COMPRESSED: u32 = 1u32;

#[allow(dead_code)]
const DH_BLOCKID_PROTECTEDSTREAMKEY_SALSA20: [u8;8] = [0xE8, 0x30, 0x09, 0x4B, 0x97, 0x20, 0x5D, 0x2A];
