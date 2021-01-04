#[derive(Debug)]
pub enum KdfSettings {
    Aes {
        seed: Vec<u8>,
        rounds: u64,
    },
    Argon2 {
        memory: u64,
        salt: Vec<u8>,
        iterations: u64,
        parallelism: u32,
        version: argon2::Version, // todo: this should be supplied via our own api
    },
}
