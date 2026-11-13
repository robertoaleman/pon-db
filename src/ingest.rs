// SPDX-License-Identifier: AGPL-3.0-only
// PON-DB Engine: a database engine encapsulated in a single, portable, encrypted binary format
// Copyright (C) 2026 Roberto C. Aleman F.
// https://github.com/robertoaleman/pon-db
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

/// Resultado de una ingesta.
#[derive(Debug)]
pub struct IngestStats {
    pub rows: u32,
    pub unindexed: u64,
    pub index_entries: usize,
    /// SHA-256 real del archivo de entrada completo.
    pub original_sha256: [u8; 32],
}

/// Lector que calcula el SHA-256 de todo lo que pasa por él.
pub(crate) struct HashingReader<R: Read> {
    inner: R,
    hasher: Sha256,
}

impl<R: Read> HashingReader<R> {
    pub(crate) fn new(inner: R) -> Self {
        Self { inner, hasher: Sha256::new() }
    }

    pub(crate) fn finish(self) -> [u8; 32] {
        self.hasher.finalize().into()
    }
}

impl<R: Read> Read for HashingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.hasher.update(&buf[..n]);
        Ok(n)
    }
}

/// SHA-256 de un archivo completo.
pub fn sha256_file(path: &Path) -> io::Result<[u8; 32]> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1 << 16];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TempDir;

    #[test]
    fn hashing_reader_matches_a_direct_hash_for_any_read_size() {
        let data: Vec<u8> = (0..10_000u32).map(|i| (i % 251) as u8).collect();
        let expected: [u8; 32] = Sha256::digest(&data).into();

        let mut r = HashingReader::new(io::Cursor::new(data.clone()));
        let mut sink = Vec::new();
        r.read_to_end(&mut sink).unwrap();
        assert_eq!(sink, data);
        assert_eq!(r.finish(), expected);
    }

    #[test]
    fn sha256_file_matches_a_direct_hash() {
        let dir = TempDir::new("sha_file");
        let p = dir.join("f.bin");
        let data = vec![7u8; 200_000];
        std::fs::write(&p, &data).unwrap();
        let expected: [u8; 32] = Sha256::digest(&data).into();
        assert_eq!(sha256_file(&p).unwrap(), expected);
    }
}
