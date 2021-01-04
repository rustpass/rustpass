mod aeskdf;
pub(crate) use self::aeskdf::*;

mod argon2;
pub(crate) use self::argon2::*;

use crate::results::Result;

pub(in crate::internal) use generic_array::{
    typenum,
    GenericArray,
};

pub trait Kdf {
    fn transform_key(
        &self,
        composite_key: &GenericArray<u8, typenum::U32>
    ) -> Result<GenericArray<u8, typenum::U32>>;
}
