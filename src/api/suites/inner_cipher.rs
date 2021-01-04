#[derive(Debug, Clone)]
pub enum InnerCipherSuite {
    Plain,
    Salsa20,
    ChaCha20,
}
