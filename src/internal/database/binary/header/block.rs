use crate::{
    api::traits::Sizable,
    internal::{
        database::binary::{
            Block,
            BlockId,
            BlockSize,
            BlockData,
            BlockDataSlice,
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
    LittleEndian,
};

use std::{
    io::Read,
    mem,
};

///
/// `HeaderBlock3` implementation
///
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct HeaderBlock3 {
    block_id: u8,
    block_size: u16,
    block_data: Vec<u8>,
}

impl HeaderBlock3 {
    const OFFSET: usize = mem::size_of::<u8>() + mem::size_of::<u16>();

    pub fn new(_block_id: u8, _block_data: Vec<u8>) -> Self {
        Self {
            block_id: _block_id,
            block_size: _block_data.len() as u16,
            block_data: Vec::from(_block_data.as_slice()),
        }
    }
}

impl Sizable for HeaderBlock3 {
    fn size_in_bytes(&self) -> usize {
        Self::OFFSET + self.block_size as usize
    }
}

impl AsBytes for HeaderBlock3 {
    fn as_bytes(&self) -> Vec<u8> {
        let mut buf = bytes::BytesMut::with_capacity(
            self.block_size as usize
        );
        buf.put_u8(self.block_id);
        buf.put_u16_le(self.block_size);
        buf.put_slice(self.block_data.as_ref());
        buf.to_vec()
    }
}

impl TryFromBytes for HeaderBlock3 {
    type Error = ();

    fn from_bytes(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() < 3 {
            return Err(());
        }

        let block_id = value[0];
        let block_size = LittleEndian::read_u16(&value[1..3]);

        if block_size as usize > value.len() {
            return Err(())
        }

        let mut block_data = vec![];

        if block_size > 0 {
            let mut _tmp = value[Self::OFFSET..(block_size as usize + Self::OFFSET)].as_ref();
            _tmp.read_to_end(&mut block_data).map_err(|_| ())?;
        }

        Ok(
            HeaderBlock3::new(
                block_id,
                block_data,
            )
        )
    }

}

impl<'a> Block<'a> for HeaderBlock3 {}

impl<'a> BlockId<'a, u8> for HeaderBlock3 {
    fn block_id(&self) -> u8 {
        self.block_id
    }
}

impl<'a> BlockSize<'a, u16> for HeaderBlock3 {
    fn block_size(&self) -> u16 {
        self.block_size
    }
}

impl<'a> BlockData<'a, u8> for HeaderBlock3 {
    fn block_data(&self) -> Vec<u8> {
        Vec::from(self.block_data.clone())
    }
}

impl<'a> BlockDataSlice<'a, u8> for HeaderBlock3 {}

///
/// `HeaderBlock4` implementation
///
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct HeaderBlock4 {
    block_id: u8,
    block_size: u32,
    block_data: Vec<u8>,
}

impl HeaderBlock4 {
    const OFFSET: usize = mem::size_of::<u32>() + mem::size_of::<u8>();

    pub fn new(_block_id: u8, _block_data: Vec<u8>) -> Self {
        Self {
            block_id: _block_id,
            block_size: _block_data.len() as u32,
            block_data: Vec::from(_block_data),
        }
    }
}

impl Sizable for HeaderBlock4 {
    fn size_in_bytes(&self) -> usize {
        Self::OFFSET + self.block_size as usize
    }
}

impl AsBytes for HeaderBlock4 {
    fn as_bytes(&self) -> Vec<u8> {
        let mut buf = bytes::BytesMut::with_capacity(self.block_size as usize);
        buf.put_u8(self.block_id);
        buf.put_u32_le(self.block_size);
        buf.put_slice(self.block_data.as_ref());
        buf.to_vec()
    }
}

impl TryFromBytes for HeaderBlock4 {
    type Error = ();

    fn from_bytes(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() < 5 {
            return Err(());
        }

        let block_id = value[0];
        let block_size = LittleEndian::read_u32(&value[1..5]);
        let mut block_data = vec![];

        if block_size > 0 {
            let mut _tmp: &mut &[u8] = &mut value[Self::OFFSET..(block_size as usize + Self::OFFSET)].as_ref();
            _tmp.read_to_end(&mut block_data).map_err(|_| ())?;
        }

        Ok(
            HeaderBlock4::new(
                block_id,
                block_data,
            )
        )
    }
}

impl<'a> Block<'a> for HeaderBlock4 {}

impl<'a> BlockId<'a, u8> for HeaderBlock4 {
    fn block_id(&self) -> u8 {
        self.block_id
    }
}

impl<'a> BlockSize<'a, u32> for HeaderBlock4 {
    fn block_size(&self) -> u32 {
        self.block_size
    }
}

impl<'a> BlockData<'a, u8> for HeaderBlock4 {
    fn block_data(&self) -> Vec<u8> {
        Vec::from(self.block_data.clone())
    }
}

impl<'a> BlockDataSlice<'a, u8> for HeaderBlock4 {}

#[cfg(test)]
mod tests {
    const TEST_BLOCK_ID: u8 = 1u8;

    const TEST_BLOCK_DATA_0: [u8; 0] = [1u8; 0];
    const TEST_BLOCK_SIZE_0: usize = 0usize;

    const TEST_BLOCK_DATA_32: [u8; 32] = [1u8; 32];
    const TEST_BLOCK_SIZE_32: usize = 32usize;

    use super::{
        HeaderBlock3,
        HeaderBlock4,
    };

    #[test]
    fn test_create_kdbx3_0() {
        let block = HeaderBlock3::new(
            TEST_BLOCK_ID,
            Vec::from(TEST_BLOCK_DATA_0),
        );

        assert_eq!(block.block_id, 1u8);
        assert_eq!(block.block_size, TEST_BLOCK_SIZE_0 as u16);
        assert_eq!(block.block_data.len(), TEST_BLOCK_DATA_0.len());
    }

    #[test]
    fn test_create_kdbx3_32() {
        let block = HeaderBlock3::new(
            TEST_BLOCK_ID,
            Vec::from(TEST_BLOCK_DATA_32),
        );

        assert_eq!(block.block_id, 1u8);
        assert_eq!(block.block_size, TEST_BLOCK_SIZE_32 as u16);
        assert_eq!(block.block_data.len(), TEST_BLOCK_DATA_32.len());
    }

    #[test]
    fn test_create_kdbx4_0() {
        let block = HeaderBlock4::new(
            TEST_BLOCK_ID,
            Vec::from(TEST_BLOCK_DATA_0),
        );

        assert_eq!(block.block_id, 1u8);
        assert_eq!(block.block_size, TEST_BLOCK_SIZE_0 as u32);
        assert_eq!(block.block_data.len(), TEST_BLOCK_DATA_0.len());
    }

    #[test]
    fn test_create_kdbx4_32() {
        let block = HeaderBlock4::new(
            TEST_BLOCK_ID,
            Vec::from(TEST_BLOCK_DATA_32),
        );

        assert_eq!(block.block_id, 1u8);
        assert_eq!(block.block_size, TEST_BLOCK_SIZE_32 as u32);
        assert_eq!(block.block_data.len(), TEST_BLOCK_DATA_32.len());
    }
}


