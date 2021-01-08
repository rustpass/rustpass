use super::*;
use crate::{
    errors::{
        DatabaseIntegrityError,
        Error,
    },
    results::Result,
    internal::cryptopraphy::cipher::Cipher,
};

use base64;
use secstr::SecStr;

use quick_xml::{
    Reader,
    events::{
        Event,
        attributes::Attribute,
    },
};
use std::io::Read;

pub(crate) fn parse(
    xml: &[u8],
    inner_cipher: &mut dyn Cipher,
) -> Result<Group>
{
    let mut parser = Reader::from_reader(xml);

    let mut buf = Vec::new();
    let mut stack: Vec<Vec<u8>> = vec![];
    let mut parsed_stack: Vec<Node> = vec![];
    let mut root_group: Group = Default::default();

    loop {
        match parser.read_event(&mut buf) {
            Ok(Event::Start(ref e)) => {
                stack.push(e.local_name().to_vec());

                match e.local_name() {
                    b"Group" => parsed_stack.push(
                        Node::Group(Default::default())
                    ),
                    b"Entry" => parsed_stack.push(
                        Node::Entry(Default::default())
                    ),
                    b"String" => parsed_stack.push(
                        Node::KeyValue(
                            String::new(),
                            StringValue::UnprotectedString(String::new()),
                        )
                    ),
                    b"Value" => {
                        // Are we encountering a protected value?
                        if e.attributes()
                            .map(|res|
                                res.unwrap_or(
                                    Attribute {
                                        key: b"",
                                        value: std::borrow::Cow::from(
                                            "".as_bytes().to_vec()
                                        ),
                                    }
                                )
                            )
                            .find(|attr| attr.key == b"Protected")
                            .map(|attr| attr.value)
                            .map_or(false, |v| {
                                std::str::from_utf8(&v).expect("").parse::<bool>().unwrap_or_default()
                            })
                        {
                            // Transform value to a Value::Protected
                            if let Some(&mut Node::KeyValue(_, ref mut ev)) =
                            parsed_stack.last_mut()
                            {
                                *ev = StringValue::ProtectedString(SecStr::new(vec![]));
                            }
                        }
                    }
                    b"AutoType" => parsed_stack.push(Node::AutoType(Default::default())),
                    b"Association" => {
                        parsed_stack.push(Node::AutoTypeAssociation(Default::default()))
                    }
                    _ => {}
                }
            }

            Ok(Event::End(ref e)) => {
                stack.pop();
                let local_name = e.local_name();
                let local_name_matches = match local_name {
                    b"Group"
                    | b"Entry"
                    | b"String"
                    | b"AutoType"
                    | b"Association" => true,
                    _ => false
                };
                if local_name_matches {
                    let finished_node = parsed_stack.pop().unwrap();
                    let parsed_stack_head = parsed_stack.last_mut();

                    match finished_node {
                        Node::KeyValue(k, v) => {
                            if let Some(
                                &mut Node::Entry(ref mut entry)
                            ) = parsed_stack_head
                            {
                                // A KeyValue was finished inside of an Entry -> add a field
                                entry.add(&k, &v);
                            }
                        }

                        Node::Group(finished_group) => {
                            match parsed_stack_head {
                                Some(&mut Node::Group(Group {
                                                          ref mut child_groups,
                                                          ..
                                                      })) => {
                                    // A Group was finished - add Group to parent Group's child groups
                                    child_groups
                                        .insert(
                                            finished_group.name.clone(),
                                            finished_group,
                                        );
                                }
                                None => {
                                    // There is no more parent nodes left -> we are at the root
                                    root_group = finished_group;
                                }
                                _ => {}
                            }
                        }

                        Node::Entry(finished_entry) => {
                            if let Some(&mut Node::Group(Group {
                                                             ref mut entries, ..
                                                         })) = parsed_stack_head
                            {
                                // A Entry was finished - add Node to parent Group's entries
                                entries.insert(
                                    finished_entry.get_title().unwrap().to_owned(),
                                    finished_entry,
                                );
                            }
                        }

                        Node::AutoType(at) => {
                            if let Some(
                                &mut Node::Entry(
                                    ref mut entry)
                            ) = parsed_stack_head
                            {
                                entry.set_autotype(&at);
                            }
                        }

                        Node::AutoTypeAssociation(ata) => {
                            if let Some(
                                &mut Node::AutoType(
                                    ref mut autotype
                                )
                            ) = parsed_stack_head
                            {
                                autotype.associations.push(ata);
                            }
                        }
                    }
                }
            }
            Ok(Event::Text(ref e)) => {
                // Got some character data that need to be matched to a Node on the parsed_stack.

                let c = e.unescape_and_decode(&parser).expect("character value should be decodable");

                match (
                    stack.last().map(|s| &s[..]),
                    parsed_stack.last_mut()
                ) {
                    (
                        Some(b"Name"),
                        Some(&mut Node::Group(Group { ref mut name, .. }))
                    ) => {
                        // Got a "Name" element with a Node::Group on the parsed_stack
                        // Update the Group's name
                        *name = c;
                    }
                    (
                        Some(b"Key"),
                        Some(&mut Node::KeyValue(ref mut k, _))
                    ) => {
                        // Got a "Key" element with a Node::KeyValue on the parsed_stack
                        // Update the KeyValue's key
                        *k = c;
                    }
                    (
                        Some(b"Value"),
                        Some(&mut Node::KeyValue(_, ref mut ev))
                    ) => {
                        // Got a "Value" element with a Node::KeyValue on the parsed_stack
                        // Update the KeyValue's value

                        match *ev {
                            StringValue::Bytes(_) => {} // not possible
                            StringValue::UnprotectedString(ref mut v) => {
                                *v = c;
                            }
                            StringValue::ProtectedString(ref mut v) => {
                                let buf = base64::decode(&c)
                                    .map_err(|e| Error::from(DatabaseIntegrityError::from(e)))?;

                                let buf_decode = inner_cipher.decrypt(&buf)?;

                                let c_decode = std::str::from_utf8(&buf_decode)
                                    .map_err(|e| Error::from(DatabaseIntegrityError::from(e)))?;

                                *v = SecStr::from(c_decode);
                            }
                        }
                    }
                    (
                        Some(b"Enabled"),
                        Some(&mut Node::AutoType(ref mut at))
                    ) => {
                        at.enabled = c.parse().unwrap_or(false);
                    }
                    (
                        Some(b"DefaultSequence"),
                        Some(&mut Node::AutoType(ref mut at))
                    ) => {
                        at.sequence = Some(c.to_owned());
                    }
                    (
                        Some(b"Window"),
                        Some(&mut Node::AutoTypeAssociation(ref mut ata))
                    ) => {
                        ata.window = Some(c.to_owned());
                    }
                    (
                        Some(b"KeystrokeSequence"),
                        Some(&mut Node::AutoTypeAssociation(ref mut ata)),
                    ) => {
                        ata.sequence = Some(c.to_owned());
                    }
                    _ => {}
                }
            }
            Ok(Event::Eof) => break,
            Err(ref err) => {}
            _ => ()
        }

        buf.clear();
    }

    Ok(root_group)
}
