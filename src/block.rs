// SPDX-License-Identifier: AGPL-3.0-only
// PON-DB Engine: a database engine encapsulated in a single, portable, encrypted binary format
// Copyright (C) 2026 Roberto C. Aleman F.
// https://github.com/robertoaleman/pon-db
//
// Formato de un bloque de datos (revisión 3):
//   LEN u32 LE (4) | CIPHERTEXT (LEN) | TAG (16)
//
// El nonce de AES-GCM no se guarda: se deriva de la posición del bloque (ver `v9::keys`).
use std::io::{self, Read, Write};

pub const TAG_LEN: usize = 16;
/// Bytes de la cabecera de un bloque: la longitud del ciphertext.
pub const BLOCK_HEADER: usize = 4;
/// Bytes que ocupa un bloque además del ciphertext: longitud + tag.
pub const BLOCK_OVERHEAD: u64 = (BLOCK_HEADER + TAG_LEN) as u64;

pub struct RawBlock {
    pub ciphertext: Vec<u8>,
    pub tag: [u8; TAG_LEN],
}

impl RawBlock {
    /// Tamaño total del bloque en disco.
    pub fn encoded_len(&self) -> u64 {
        BLOCK_OVERHEAD + self.ciphertext.len() as u64
    }
}

pub fn corrupt(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

/// Lee un bloque. `remaining` son los bytes que quedan hasta el final de la región de datos:
/// la longitud declarada se valida contra ese límite ANTES de reservar memoria, así un
/// archivo manipulado no puede forzar una reserva de hasta 4 GiB.
pub fn read_block<R: Read>(r: &mut R, remaining: u64) -> io::Result<RawBlock> {
    if remaining < BLOCK_OVERHEAD {
        return Err(corrupt("truncated data block"));
    }

    let mut len_bytes = [0u8; BLOCK_HEADER];
    r.read_exact(&mut len_bytes)?;
    let len = u32::from_le_bytes(len_bytes) as u64;
    if len + BLOCK_OVERHEAD > remaining {
        return Err(corrupt("block length exceeds the available data"));
    }

    let mut ciphertext = vec![0u8; len as usize];
    r.read_exact(&mut ciphertext)?;

    let mut tag = [0u8; TAG_LEN];
    r.read_exact(&mut tag)?;

    Ok(RawBlock { ciphertext, tag })
}

/// Escribe un bloque y devuelve cuántos bytes ocupó.
pub fn write_block<W: Write>(w: &mut W, ciphertext: &[u8], tag: &[u8; TAG_LEN]) -> io::Result<u64> {
    let len = u32::try_from(ciphertext.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "record larger than 4 GiB"))?;
    w.write_all(&len.to_le_bytes())?;
    w.write_all(ciphertext)?;
    w.write_all(tag)?;
    Ok(BLOCK_OVERHEAD + ciphertext.len() as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn write_then_read_roundtrip() {
        let mut buf: Vec<u8> = Vec::new();
        let written = write_block(&mut buf, b"hello", &[2u8; 16]).unwrap();
        assert_eq!(written as usize, buf.len());
        assert_eq!(written, 4 + 5 + 16);

        let mut c = Cursor::new(buf);
        let b = read_block(&mut c, written).unwrap();
        assert_eq!(b.ciphertext, b"hello".to_vec());
        assert_eq!(b.tag, [2u8; 16]);
        assert_eq!(b.encoded_len(), written);
    }

    #[test]
    fn an_empty_ciphertext_is_a_valid_block() {
        let mut buf: Vec<u8> = Vec::new();
        let written = write_block(&mut buf, b"", &[1u8; 16]).unwrap();
        assert_eq!(written, BLOCK_OVERHEAD);
        let b = read_block(&mut Cursor::new(buf), written).unwrap();
        assert!(b.ciphertext.is_empty());
    }

    #[test]
    fn declared_length_beyond_region_is_rejected_without_allocating() {
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(&u32::MAX.to_le_bytes());
        buf.extend_from_slice(&[0u8; 64]);
        let remaining = buf.len() as u64;
        assert!(read_block(&mut Cursor::new(buf), remaining).is_err());
    }

    #[test]
    fn region_shorter_than_overhead_is_rejected() {
        assert!(read_block(&mut Cursor::new(vec![0u8; 100]), 10).is_err());
    }
}
