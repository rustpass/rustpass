pub(crate) trait AsBytes {
    fn as_bytes(&self) -> Vec<u8>;
}

pub(crate) trait TryFromBytes {
    type Error;

    fn from_bytes(value: &[u8]) -> Result<Self, Self::Error> where Self: Sized;
}
