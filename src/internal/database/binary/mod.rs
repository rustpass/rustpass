pub(crate) mod constants;

pub(crate) mod header;
pub(crate) mod payload;

pub(crate) mod structure;
pub(crate) mod version;

pub(crate) trait AsBytes {
    fn as_bytes(&self) -> Vec<u8>;
}

pub(crate) trait TryFromBytes {
    type Error;

    fn from_bytes(value: &[u8]) -> Result<Self, ()> where Self: Sized;
}

/// `Block<'a>` trait
pub(crate) trait Block<'a> {}

/// `BlockId<'a, T>` trait
pub(crate) trait BlockId<'a, T>: Block<'a>
    where T: Sized + PartialEq + Ord + Clone
{
    fn block_id(&self) -> T;
}

/// `BlockSize<'a, T>` trait
pub(crate) trait BlockSize<'a, T>: Block<'a>
    where T: Sized + PartialEq + Ord + Clone
{
    fn block_size(&self) -> T;
}

/// `BlockHash<'a, T>` trait
pub(crate) trait BlockHash<'a, T>: Block<'a>
    where T: Sized + PartialEq + Ord + Clone
{
    fn block_hash(&self) -> Vec<T>;
}

/// `BlockHashLength<'a, T>` trait
pub(crate) trait BlockHashLength<'a, T>: Block<'a> + BlockHash<'a, T>
    where T: Sized + PartialEq + Ord + Clone
{
    fn block_hash_len(&self) -> usize {
        self.block_hash().len()
    }
}

/// `BlockData<'a, T>` trait
pub(crate) trait BlockData<'a, T>: Block<'a>
    where T: Sized + PartialEq + Ord + Clone
{
    fn block_data(&self) -> Vec<T>;
}

/// `BlockDataLength<'a, T>` trait
pub(crate) trait BlockDataLength<'a, T>: Block<'a> + BlockData<'a, T>
    where T: Sized + PartialEq + Ord + Clone
{
    fn block_data_len(&self) -> usize {
        self.block_data().len()
    }
}

/// `BlockDataSlice<'a, T>` trait
pub(crate) trait BlockDataSlice<'a, T>: BlockData<'a, T>
    where T: Sized + PartialEq + Ord + Clone
{
    fn slice_of(&self, n: usize) -> Vec<T> {
        if self.block_data().len() >= n {
            self.block_data()[0..n].to_vec()
        } else {
            Vec::new()
        }
    }
}

pub(crate) fn write<'a, T>(header: &'a T) -> Vec<u8>
    where
        T: Block<'a> + AsBytes
{
    header.as_bytes()
}

pub(crate) fn read<'a, T>(buf: &'a [u8]) -> Result<T, ()>
    where T: Block<'a> + TryFromBytes
{
    T::from_bytes(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use spectral::prelude::*;

    #[test]
    fn test_write_read_header_kdbx3() {

        let data = vec![0x00, 0x01, 0x02];
        let block_data = header::block::HeaderBlock3::new(1, data);

        let serialized = write::<header::block::HeaderBlock3>(&block_data);

        let deserialized = read::<header::block::HeaderBlock3>(serialized.as_ref());

        assert_that(&deserialized).is_ok();

        let header = deserialized.unwrap();

        assert_that(&header.block_id()).is_equal_to(1);
        assert_that(&header.block_size()).is_equal_to(3);
        assert_that(&header.block_data()).is_equal_to(vec![0x00, 0x01, 0x02]);
        assert_that(&header.slice_of(2)).is_equal_to(vec![0x00, 0x01])
    }

    #[test]
    fn test_write_read_header_kdbx4() {
        let data = vec![0x00, 0x01, 0x02];
        let block_data = header::block::HeaderBlock4::new(1, data);

        let serialized = write::<header::block::HeaderBlock4>(&block_data);

        let deserialized = read::<header::block::HeaderBlock4>(serialized.as_ref());

        assert_that(&deserialized).is_ok();

        let header = deserialized.unwrap();

        assert_that(&header.block_id()).is_equal_to(1);
        assert_that(&header.block_size()).is_equal_to(3);
        assert_that(&header.block_data()).is_equal_to(vec![0x00, 0x01, 0x02]);
        assert_that(&header.slice_of(2)).is_equal_to(vec![0x00, 0x01])
    }

    #[test]
    fn test_write_read_payload() {
        let data = vec![0x00, 0x01, 0x02];
        let hash = [42u8;32].to_vec();
        let block_data = payload::block::PayloadBlock::new(1, hash, data);

        let serialized = write::<payload::block::PayloadBlock>(&block_data);

        let deserialized = read::<payload::block::PayloadBlock>(serialized.as_ref());

        assert_that(&deserialized).is_ok();

        let header = deserialized.unwrap();

        assert_that(&header.block_id()).is_equal_to(1);
        assert_that(&header.block_hash()).is_equal_to([42u8;32].to_vec());
        assert_that(&header.block_size()).is_equal_to(3);
        assert_that(&header.block_data()).is_equal_to(vec![0x00, 0x01, 0x02]);
        assert_that(&header.slice_of(2)).is_equal_to(vec![0x00, 0x01])
    }
}
