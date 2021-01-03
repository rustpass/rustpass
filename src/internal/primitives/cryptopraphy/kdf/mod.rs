mod aeskdf;
pub use self::aeskdf::*;

mod argon2;
pub use self::argon2::*;

use crate::results::Result;

pub(super) use aes::cipher::generic_array::{
    typenum,
    GenericArray,
};

pub trait Kdf {
    fn transform_key(
        &self,
        composite_key: &GenericArray<u8, typenum::U32>
    ) -> Result<GenericArray<u8, typenum::U32>>;
}
