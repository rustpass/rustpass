#[derive(Debug)]
pub struct KDBHeader {
    pub version: u32,
    pub flags: u32,
    pub subversion: u32,
    pub master_seed: Vec<u8>,
    pub encryption_iv: Vec<u8>,
    pub num_groups: u32,
    pub num_entries: u32,
    pub contents_hash: Vec<u8>,
    pub transform_seed: Vec<u8>,
    pub transform_rounds: u32,
}
