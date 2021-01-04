#![feature(test)]
extern crate test;

use test::Bencher;

use rustpass::Database;

use std::{
    fs::File,
    io::Read
};

#[bench]
fn bench_open_aes256_aeskdf_v4(b: &mut Bencher) {
    _open_datatabase(
        b,
        "empty-aes256-aeskdf-v4.kdbx",
        "empty-aes256-aeskdf-v4.key",
        None
    )
}

#[bench]
fn bench_open_aes256_argon2_v4(b: &mut Bencher) {
    _open_datatabase(
        b,
        "empty-aes256-argon2-v4.kdbx",
        "empty-aes256-argon2-v4.key",
        None
    )
}

#[bench]
fn bench_open_chacha20_aeskdf_v4(b: &mut Bencher) {
    _open_datatabase(
        b,
        "empty-chacha20-aeskdf-v4.kdbx",
        "empty-chacha20-aeskdf-v4.key",
        None
    )
}

#[bench]
fn bench_open_chacha20_argon2_v4(b: &mut Bencher) {
    _open_datatabase(
        b,
        "empty-chacha20-argon2-v4.kdbx",
        "empty-chacha20-argon2-v4.key",
        None
    )
}

#[bench]
fn bench_open_twofish_aeskdf_v4(b: &mut Bencher) {
    _open_datatabase(
        b,
        "empty-twofish-aeskdf-v4.kdbx",
        "empty-twofish-aeskdf-v4.key",
        None
    )
}

#[bench]
fn bench_open_twofish_argon2_v4(b: &mut Bencher) {
    _open_datatabase(
        b,
        "empty-twofish-argon2-v4.kdbx",
        "empty-twofish-argon2-v4.key",
        None
    )
}

fn _open_datatabase(
    b: &mut Bencher,
    dbfile: &str,
    keyfile: &str,
    password: Option<&str>
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
            Some(&mut key_file)
        );
    })
}
