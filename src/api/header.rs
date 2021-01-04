use super::{
    kdb::KDBHeader,
    kdbx3::KDBX3Header,
    kdbx4::{
        KDBX4Header,
        KDBX4InnerHeader,
    }
};

#[derive(Debug)]
pub enum Header {
    KDB(KDBHeader),
    KDBX3(KDBX3Header),
    KDBX4(KDBX4Header),
}

#[derive(Debug)]
pub enum InnerHeader {
    None,
    KDBX4(KDBX4InnerHeader),
}
