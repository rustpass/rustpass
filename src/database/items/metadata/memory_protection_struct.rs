use super::Identifier;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemoryProtection {
    pub protect_title: bool,
    pub protect_user_name: bool,
    pub protect_password: bool,
    pub protect_url: bool,
    pub protect_notes: bool,
}

impl Default for MemoryProtection {
    fn default() -> Self {
        MemoryProtection {
            protect_title: false,
            protect_user_name: false,
            protect_password: true,
            protect_url: true,
            protect_notes: true,
        }
    }
}

impl Identifier for MemoryProtection {
    const IDENTIFIER: &'static [u8] = b"MemoryProtection";
}

#[cfg(test)]
mod tests {
    use super::*;
    use spectral::prelude::*;

    #[test]
    fn test_default() {
        let memory_protection = MemoryProtection::default();

        assert_that(&memory_protection)
            .is_equal_to(MemoryProtection {
                protect_title: false,
                protect_user_name: false,
                protect_password: true,
                protect_url: true,
                protect_notes: true
            });
    }
}
