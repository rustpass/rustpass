use spectral::prelude::*;

use rustpass::{
    Database,
    Result
};

use std::{
    fs::File,
    io::Read
};

#[test]
fn it_open_aes256_aeskdf_v31() {
    let result = _open_database(
        "empty-aes256-aeskdf-v31.kdbx",
        "empty-aes256-aeskdf-v31.key",
        None
    );

    let database = assert_that(&result)
        .is_ok()
        .subject;

    database.close();
}

fn _open_database(
    dbfile: &str,
    keyfile: &str,
    password: Option<&str>
) -> Result<Database> {
    let mut key_file: File = File::open(format!("tests/fixture/{}", keyfile))
        .expect(".key is present");

    let mut kdbx_file: File = File::open(format!("tests/fixture/{}", dbfile))
        .expect(".kdbx is present");

    let mut data: Vec<u8> = vec![];

    let kdbx_result = kdbx_file.read_to_end(&mut data);

    assert_that(&kdbx_result)
        .is_ok()
        .is_greater_than(0);

    Database::open(
        &mut data.as_ref() as &mut &[u8],
        password,
        Some(&mut key_file)
    )
}
