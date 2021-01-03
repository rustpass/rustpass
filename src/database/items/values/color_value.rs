use extfmt::Hexlify;

use std::convert::TryFrom;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ColorValue(u8, u8, u8);

impl ColorValue {
    const BLACK: Self = Self(0,0,0);
    const WHITE: Self = Self(255, 255, 255);

    pub fn new(r:u8, g:u8, b:u8) -> Self {
        Self(r,g,b)
    }

    pub fn black() -> Self {
        Self::BLACK
    }

    pub fn white() -> Self {
        Self::WHITE
    }

    pub fn red(&self) -> u8 {
        self.0
    }
    pub fn green(&self) -> u8 {
        self.1
    }
    pub fn blue(&self) -> u8 {
        self.2
    }

    pub fn to_hex(&self) -> String {
        format!("#{}", Hexlify(&[self.0, self.1, self.2])).to_uppercase()
    }
}

impl Default for ColorValue {
    fn default() -> Self {
        Self::black()
    }
}

impl TryFrom<&[u8]> for ColorValue {
    type Error = ();

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let l = value.len();

        if l == 0 {
            return Ok(ColorValue::black())
        }

        if l != 3 {
            return Err(());
        }

        Ok(ColorValue::new(value[0], value[1], value[2]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use spectral::prelude::*;

    #[test]
    fn test_default() {
        assert_that(&ColorValue::default().to_hex())
            .is_equal_to("#000000".to_owned());
    }

    #[test]
    fn test_black() {
        assert_that(&ColorValue::black().to_hex())
            .is_equal_to("#000000".to_owned());
    }

    #[test]
    fn test_white() {
        assert_that(&ColorValue::white().to_hex())
            .is_equal_to("#FFFFFF".to_owned());
    }

    #[test]
    fn test_custom() {
        assert_that(&ColorValue::new(240, 240, 240).to_hex())
            .is_equal_to("#F0F0F0".to_owned());
    }
}
