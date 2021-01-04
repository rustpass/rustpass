#![feature(test)]
extern crate test;

use test::Bencher;

use rustpass::Database;

use std::{
    fs::File,
    io::Read,
};

#[bench]
#[cfg(not(debug_assertions))]
fn bench_open_aes256_aeskdf_v31(b: &mut Bencher) {
    _open_datatabase(
        b,
        "empty-aes256-aeskdf-v31.kdbx",
        "empty-aes256-aeskdf-v31.key",
        None,
    )
}

fn _open_datatabase(
    b: &mut Bencher,
    dbfile: &str,
    keyfile: &str,
    password: Option<&str>,
) {
    let mut key_file: File = File::open(format!("tests/fixture/{}", keyfile))
        .expect(".key is present");

    let mut kdbx_file: File = File::open(format!("tests/fixture/{}", dbfile))
        .expect(".kdbx is present");

    let mut data: Vec<u8> = vec![];

    let _ = kdbx_file.read_to_end(&mut data);

    b.iter(|| {
        let _ = Database::open(
            &mut data.as_ref() as &mut &[u8],
            password,
            Some(&mut key_file),
        );
    })
}
