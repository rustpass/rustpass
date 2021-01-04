use crate::{
    api::traits::Sizable,
    internal::{
        database::binary::{
            Block,
            BlockId,
            BlockHash,
            BlockSize,
            BlockData,
            BlockDataSlice
        },
        traits::{
            AsBytes,
            TryFromBytes,
        }
    }
};

use bytes::{
    self,
    BufMut
};

use byteorder::{
    ByteOrder,
    LittleEndian
};

use std::{
    io::Read,
    mem
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PayloadBlock {
    block_id: u32,
    block_hash: Vec<u8>,
    block_size: u32,
    block_data: Vec<u8>,
}

impl PayloadBlock {
    const OFFSET: usize = mem::size_of::<u32>() + mem::size_of::<u32>() + 32usize;

    pub fn new(
        _block_id: u32,
        _block_hash: Vec<u8>,
        _block_data: Vec<u8>,
    ) -> Self {
        Self {
            block_id: _block_id,
            block_hash: _block_hash.clone(),
            block_size: _block_data.len() as u32,
            block_data: _block_data.clone(),
        }
    }
}

impl Sizable for PayloadBlock {
    fn size_in_bytes(&self) -> usize {
        Self::OFFSET + self.block_size() as usize
    }
}

impl AsBytes for PayloadBlock {
    fn as_bytes(&self) -> Vec<u8> {
        let mut buf = bytes::BytesMut::with_capacity(self.block_size as usize);
        buf.put_u32_le(self.block_id());
        buf.put_slice(self.block_hash().as_ref());
        buf.put_u32_le(self.block_size());
        buf.put_slice(self.block_data().as_ref());
        buf.to_vec()
    }
}

impl TryFromBytes for PayloadBlock {
    type Error = ();

    fn from_bytes(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() < 3 {
            return Err(());
        }

        let block_id = LittleEndian::read_u32(&value[0..4]);
        let block_hash = value[4..36].to_vec();
        let block_size = LittleEndian::read_u32(&value[36..40]);
        let mut block_data = vec![];

        if block_size > 0 {
            let mut _tmp: &mut &[u8] = &mut value[Self::OFFSET..(block_size as usize + Self::OFFSET)].as_ref();
            _tmp.read_to_end(&mut block_data).map_err(|_| ())?;
        }

        Ok(
            PayloadBlock::new(
                block_id,
                block_hash,
                block_data,
            )
        )
    }
}
impl<'a> Block<'a> for PayloadBlock {}

impl<'a> BlockId<'a, u32> for PayloadBlock {
    fn block_id(&self) -> u32 {
        self.block_id
    }
}
impl<'a> BlockHash<'a, u8> for PayloadBlock {
    fn block_hash(&self) -> Vec<u8> {
        self.block_hash.clone()
    }
}
impl<'a> BlockSize<'a, u32> for PayloadBlock {
    fn block_size(&self) -> u32 {
        self.block_size
    }

}
impl<'a> BlockData<'a, u8> for PayloadBlock {
    fn block_data(&self) -> Vec<u8> {
        Vec::from(self.block_data.clone())
    }
}

impl<'a> BlockDataSlice<'a, u8> for PayloadBlock {}

#[cfg(test)]
mod tests {
    const TEST_BLOCK_ID: u32 = 1u32;
    const TEST_BLOCK_HASH: [u8; 32] = [0u8; 32];

    const TEST_BLOCK_DATA_0: [u8; 0] = [1u8; 0];
    const TEST_BLOCK_SIZE_0: u32 = 0u32;

    const TEST_BLOCK_DATA_32: [u8; 32] = [1u8; 32];
    const TEST_BLOCK_SIZE_32: u32 = 32u32;

    use super::PayloadBlock;

    #[test]
    fn test_create_0() {
        let block = PayloadBlock::new(
            TEST_BLOCK_ID,
            Vec::from(TEST_BLOCK_HASH),
            Vec::from(TEST_BLOCK_DATA_0),
        );

        assert_eq!(block.block_id, 1u32);
        assert_eq!(block.block_hash, TEST_BLOCK_HASH);
        assert_eq!(block.block_size, TEST_BLOCK_SIZE_0);
        assert_eq!(block.block_data.len(), TEST_BLOCK_DATA_0.len());
    }

    #[test]
    fn test_create_32() {
        let block = PayloadBlock::new(
            TEST_BLOCK_ID,
            Vec::from(TEST_BLOCK_HASH),
            Vec::from(TEST_BLOCK_DATA_32),
        );

        assert_eq!(block.block_id, 1u32);
        assert_eq!(block.block_hash, TEST_BLOCK_HASH);
        assert_eq!(block.block_size, TEST_BLOCK_SIZE_32);
        assert_eq!(block.block_data.len(), TEST_BLOCK_DATA_32.len());
    }
}
