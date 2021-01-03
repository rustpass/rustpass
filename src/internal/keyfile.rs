use crate::{
    internal::primitives::{
        cryptopraphy,
    },
    errors::Error,
    results::Result

};
use xml::{
    name::OwnedName,
    reader::{
        EventReader,
        XmlEvent
    }
};

use std::io::Read;

pub fn parse(source: &mut dyn Read) -> Result<Vec<u8>> {
    let mut buffer = Vec::new();
    source.read_to_end(&mut buffer)?;

    if let Ok(v) = parse_xml_keyfile(&buffer) {
        // items formatted keyfile
        Ok(v)
    } else if buffer.len() == 32 {
        // legacy binary key format
        Ok(buffer.to_vec())
    } else if buffer.len() == 64 {
        let v = ::hex::decode(&buffer).map_err(|_e| Error::InvalidKeyFile)?;
        Ok(v)
    } else {
        // hashed key format
        Ok(cryptopraphy::sha256(&[&buffer])?.as_slice().to_vec())
    }
}

fn parse_xml_keyfile(xml: &[u8]) -> Result<Vec<u8>> {
    let parser = EventReader::new(xml);

    let mut tag_stack = Vec::new();

    for ev in parser {
        match ev.map_err(|_e| Error::InvalidKeyFile)? {
            XmlEvent::StartElement {
                name: OwnedName { ref local_name, .. },
                ..
            } => {
                tag_stack.push(local_name.clone());
            }
            XmlEvent::EndElement { .. } => {
                tag_stack.pop();
            }
            XmlEvent::Characters(s) => {
                // Check if we are at KeyFile/Key/Data
                if tag_stack == ["KeyFile", "Key", "Data"] {
                    let key_base64 = s.as_bytes().to_vec();

                    // Check if the key is base64-encoded. If yes, return decoded bytes
                    return if let Ok(key) = ::base64::decode(&key_base64) {
                        Ok(key)
                    } else {
                        Ok(key_base64)
                    };
                }
            }
            _ => {}
        }
    }

    Err(Error::InvalidKeyFile)
}

#[cfg(test)]
mod tests {
    use super::*;
    use extfmt::Hexlify;
    use spectral::prelude::*;

    #[test]
    fn test_parse_keyfile_xml() {
        let data = "7tWfHhOfIVAi0ywgzH99Fwav6fjl1LcBv67WVo9fQOiSpG8M1jravWyFDkmlQDUoZa49BVTvCdD4K7rUFQi4gJZ3OamX31+RkDLyc4gVcYi9FxlTAmAf5j+rUTMYc+4ggq01/y3pCaa1XsCML8xqE9AZkjhKQQA2slf+2ptpRk8=";
        let xml = format!("<?items version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><KeyFile><Key><Data>{}</Data></Key></KeyFile>", data);

        let result = parse(&mut xml.as_bytes());

        assert_that(&result)
            .is_ok()
            .is_equal_to(::base64::decode(data).unwrap());
    }

    #[test]
    fn test_parse_keyfile_hex_32byte() {
        let data = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let expected = data.clone();


        let base64_encoded = ::hex::encode(data);

        let result = parse(&mut base64_encoded.as_bytes());

        assert_that(&result)
            .is_ok()
            .is_equal_to(expected.to_vec());
    }

    #[test]
    fn test_parse_keyfile_bin_128byte() {
        let data = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        let result = parse(&mut data.as_ref());

        let expected = cryptopraphy::sha256(
            &[&data]
        ).unwrap().to_vec();

        assert_that(&result)
            .is_ok()
            .is_equal_to(expected);
    }

    #[test]
    fn test_parse_keyfile_bin_32byte() {
        let data = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let expected = data.clone();

        let result = parse(&mut data.as_ref());

        assert_that(&result)
            .is_ok()
            .is_equal_to(expected.to_vec());
    }

    #[test]
    fn test_parse_xml_keyfile_base64() {
        let data = "7tWfHhOfIVAi0ywgzH99Fwav6fjl1LcBv67WVo9fQOiSpG8M1jravWyFDkmlQDUoZa49BVTvCdD4K7rUFQi4gJZ3OamX31+RkDLyc4gVcYi9FxlTAmAf5j+rUTMYc+4ggq01/y3pCaa1XsCML8xqE9AZkjhKQQA2slf+2ptpRk8=";
        let xml = format!("<?items version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><KeyFile><Key><Data>{}</Data></Key></KeyFile>", data);

        let result = parse_xml_keyfile(xml.as_ref());

        assert_that(&result)
            .is_ok()
            .is_equal_to(::base64::decode(&data).unwrap());
    }

    #[test]
    fn test_parse_xml_keyfile_plain() {
        let data = "some other data just random bytes no encoding required";
        let xml = format!("<?items version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><KeyFile><Key><Data>{}</Data></Key></KeyFile>", data);

        let result = parse_xml_keyfile(xml.as_ref());

        assert_that(&result)
            .is_ok()
            .is_equal_to(data.as_bytes().to_vec());
    }

    #[test]
    fn test_parse_xml_keyfile_empty() {
        let xml = format!("<?items version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><KeyFile><Key><Data></Data></Key></KeyFile>");

        let result = parse_xml_keyfile(xml.as_ref());

        assert_that(&result)
            .is_err();
    }

    #[test]
    fn test_parse_xml_keyfile_nokeydata() {
        let xml = format!("<?items version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><KeyFile></KeyFile>");

        let result = parse_xml_keyfile(xml.as_ref());

        assert_that(&result)
            .is_err();
    }
}
