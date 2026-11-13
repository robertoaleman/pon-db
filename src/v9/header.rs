// SPDX-License-Identifier: AGPL-3.0-only
// PON-DB Engine: a database engine encapsulated in a single, portable, encrypted binary format
// Copyright (C) 2026 Roberto C. Aleman F.
// https://github.com/robertoaleman/pon-db
//
// Layout de un archivo PON V9 (revisión 4):
//
//   [cabecera 128][metadatos cifrados][bloques cifrados][tablas de coincidencias]
//   [páginas del índice (tabla hash)][pie 32]
//
use crate::block::{corrupt, BLOCK_OVERHEAD};
use crate::v9::keys::FILE_ID_LEN;
use std::io;

pub const MAGIC9: [u8; 4] = *b"PON9";
pub const FORMAT_REV: u8 = 4;
pub const HEADER9_SIZE: usize = 128;
/// El pie es el HMAC-SHA256 de la cabecera.
pub const FOOTER_LEN: u64 = 32;
/// Página del índice: 255 entradas de 16 bytes (hash, puntero) + 16 bytes de etiqueta = 4 KiB.
pub const PAGE_SIZE: usize = 4096;
pub const PAGE_ENTRIES: usize = 255;
pub const PAGE_DATA_LEN: usize = PAGE_ENTRIES * 16;
/// Longitud de la etiqueta de una página o de una tabla de coincidencias.
pub const TAG_LEN: u64 = 16;
/// Tamaño máximo del bloque de metadatos cifrado (1 MiB).
pub const MAX_META_LEN: u32 = 1 << 20;

const DATA_MODEL: u8 = 0x02;

/// Algoritmo AEAD de los registros y del bloque de metadatos. Solo se implementa el 1; los demás
/// valores están reservados (p. ej. AES-256-GCM-SIV o ChaCha20-Poly1305) y se rechazan.
pub const AEAD_AES_256_GCM: u8 = 1;
/// Modo de acceso: 1 = solo clave. Los modos con prueba de hardware están reservados.
pub const ACCESS_KEY_ONLY: u8 = 1;

/// Capacidades del formato que el archivo declara (mapa de bits). Un lector rechaza un archivo con
/// capacidades que no conoce: cada bit puede cambiar cómo se interpreta el resto.
pub const CAP_KEYED_INDEX: u32 = 1 << 0; // las entradas del índice son HMAC con clave
pub const CAP_ENCRYPTED_METADATA: u32 = 1 << 1; // los metadatos van en un bloque cifrado
pub const CAP_DETERMINISTIC_NONCE: u32 = 1 << 2; // el nonce se deriva de la posición del bloque
pub const CAP_PAGED_HASH_INDEX: u32 = 1 << 3; // el índice es una tabla hash por páginas autenticadas
/// Conjunto que declara y exige esta revisión.
pub const CAPS_REV4: u32 = CAP_KEYED_INDEX | CAP_ENCRYPTED_METADATA | CAP_DETERMINISTIC_NONCE | CAP_PAGED_HASH_INDEX;

/// Cabecera V9 (128 bytes, little-endian):
///
/// ```text
///  0..4   magic "PON9"            4      revisión del formato (4)
///  5      data_model (0x02)       6      aead_algo (1)           7  access_mode (1)
///  8..24  file_id                24..32  created_at
/// 32..36  total_rows             36..40  bucket_count (páginas de direccionamiento)
/// 40..48  body_offset            48..56  coincidence_table_offset
/// 56..64  index_table_offset     64..72  index_entry_count
/// 72..76  meta_len               76..80  capabilities
/// 80..84  page_count             84..88  max_probe
/// 88..128 reservado (ceros)
/// ```
///
/// El bloque de metadatos ocupa `meta_len` bytes a partir del offset 128; los registros empiezan en
/// `body_offset`. Las páginas del índice ocupan `page_count × 4096` bytes desde `index_table_offset`
/// hasta el pie. `page_count ≥ bucket_count`: el desborde del final puede añadir páginas.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeaderV9 {
    pub file_id: [u8; FILE_ID_LEN],
    pub created_at: u64,
    pub total_rows: u32,
    /// Páginas del espacio de direccionamiento: la página natural de un hash es `⌊hash·bucket_count/2^64⌋`.
    pub bucket_count: u32,
    pub body_offset: u64,
    pub coincidence_table_offset: u64,
    pub index_table_offset: u64,
    /// Número de entradas del índice (hashes distintos, de todos los campos indexados).
    pub index_entry_count: u64,
    /// Longitud en bytes del bloque de metadatos cifrado.
    pub meta_len: u32,
    /// Capacidades declaradas (`CAP_*`).
    pub capabilities: u32,
    /// Páginas del índice escritas.
    pub page_count: u32,
    /// Páginas que hay que leer, como máximo, para decidir si una clave está (medido al construir).
    pub max_probe: u32,
}

fn le_u32(b: &[u8; HEADER9_SIZE], at: usize) -> u32 {
    let mut a = [0u8; 4];
    a.copy_from_slice(&b[at..at + 4]);
    u32::from_le_bytes(a)
}

fn le_u64(b: &[u8; HEADER9_SIZE], at: usize) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[at..at + 8]);
    u64::from_le_bytes(a)
}

impl HeaderV9 {
    pub fn as_bytes(&self) -> [u8; HEADER9_SIZE] {
        let mut b = [0u8; HEADER9_SIZE];
        b[0..4].copy_from_slice(&MAGIC9);
        b[4] = FORMAT_REV;
        b[5] = DATA_MODEL;
        b[6] = AEAD_AES_256_GCM;
        b[7] = ACCESS_KEY_ONLY;
        b[8..24].copy_from_slice(&self.file_id);
        b[24..32].copy_from_slice(&self.created_at.to_le_bytes());
        b[32..36].copy_from_slice(&self.total_rows.to_le_bytes());
        b[36..40].copy_from_slice(&self.bucket_count.to_le_bytes());
        b[40..48].copy_from_slice(&self.body_offset.to_le_bytes());
        b[48..56].copy_from_slice(&self.coincidence_table_offset.to_le_bytes());
        b[56..64].copy_from_slice(&self.index_table_offset.to_le_bytes());
        b[64..72].copy_from_slice(&self.index_entry_count.to_le_bytes());
        b[72..76].copy_from_slice(&self.meta_len.to_le_bytes());
        b[76..80].copy_from_slice(&self.capabilities.to_le_bytes());
        b[80..84].copy_from_slice(&self.page_count.to_le_bytes());
        b[84..88].copy_from_slice(&self.max_probe.to_le_bytes());
        b
    }

    /// Interpreta los 128 bytes. Aún no está autenticada: el pie (HMAC) lo verifica el lector.
    pub fn from_bytes(b: &[u8; HEADER9_SIZE]) -> io::Result<Self> {
        if b[0..4] == b"PON8"[..] {
            return Err(corrupt(
                "this is a PON V8 file: formats before V9 are no longer supported (re-create it from the original JSON)",
            ));
        }
        if b[0..4] != MAGIC9[..] {
            return Err(corrupt("not a PON V9 file (bad magic bytes)"));
        }
        if b[4] != FORMAT_REV {
            return Err(corrupt(format!(
                "unsupported PON V9 format revision {} (this build reads revision {}); re-create the file from the original JSON",
                b[4], FORMAT_REV
            )));
        }
        if b[5] != DATA_MODEL {
            return Err(corrupt("unsupported data model"));
        }
        if b[6] != AEAD_AES_256_GCM {
            return Err(corrupt(format!("unsupported AEAD algorithm {} (only AES-256-GCM is implemented)", b[6])));
        }
        if b[7] != ACCESS_KEY_ONLY {
            return Err(corrupt(format!("unsupported access mode {} (only key-only access is implemented)", b[7])));
        }
        let capabilities = le_u32(b, 76);
        if capabilities & !CAPS_REV4 != 0 {
            return Err(corrupt(format!(
                "the file declares capabilities this build does not know (0x{:08x}); use a newer version",
                capabilities & !CAPS_REV4
            )));
        }
        if capabilities != CAPS_REV4 {
            return Err(corrupt(format!(
                "the file lacks capabilities required by revision {} (0x{:08x})",
                FORMAT_REV,
                CAPS_REV4 & !capabilities
            )));
        }
        if b[88..HEADER9_SIZE].iter().any(|&x| x != 0) {
            return Err(corrupt("reserved header bytes are not zero"));
        }
        let mut file_id = [0u8; FILE_ID_LEN];
        file_id.copy_from_slice(&b[8..24]);
        Ok(Self {
            file_id,
            created_at: le_u64(b, 24),
            total_rows: le_u32(b, 32),
            bucket_count: le_u32(b, 36),
            body_offset: le_u64(b, 40),
            coincidence_table_offset: le_u64(b, 48),
            index_table_offset: le_u64(b, 56),
            index_entry_count: le_u64(b, 64),
            meta_len: le_u32(b, 72),
            capabilities,
            page_count: le_u32(b, 80),
            max_probe: le_u32(b, 84),
        })
    }

    /// Coherencia de los offsets y de la geometría del índice con el tamaño real del archivo.
    pub fn check_layout(&self, file_len: u64) -> io::Result<()> {
        let bad = || corrupt("inconsistent V9 header offsets (corrupted or truncated file)");

        let footer_start = file_len.checked_sub(FOOTER_LEN).ok_or_else(bad)?;

        // El bloque de metadatos va justo tras la cabecera y los registros justo después.
        if self.meta_len < BLOCK_OVERHEAD as u32 || self.meta_len > MAX_META_LEN {
            return Err(bad());
        }
        if self.body_offset != HEADER9_SIZE as u64 + self.meta_len as u64 {
            return Err(bad());
        }
        let ordered = self.body_offset <= self.coincidence_table_offset
            && self.coincidence_table_offset <= self.index_table_offset
            && self.index_table_offset <= footer_start;
        if !ordered {
            return Err(bad());
        }

        // Las páginas ocupan exactamente el espacio que va hasta el pie.
        let table_bytes = (self.page_count as u64).checked_mul(PAGE_SIZE as u64).ok_or_else(bad)?;
        if footer_start - self.index_table_offset != table_bytes {
            return Err(bad());
        }

        // Geometría de la tabla hash.
        if self.page_count == 0 {
            if self.index_entry_count != 0 || self.bucket_count != 0 || self.max_probe != 0 {
                return Err(bad());
            }
        } else {
            let capacity = (self.page_count as u64) * PAGE_ENTRIES as u64;
            let geometry_ok = self.bucket_count >= 1
                && self.bucket_count <= self.page_count
                && self.max_probe >= 1
                && self.max_probe <= self.page_count
                && self.index_entry_count >= 1
                && self.index_entry_count <= capacity;
            if !geometry_ok {
                return Err(bad());
            }
        }

        // Cada registro ocupa como mínimo BLOCK_OVERHEAD bytes.
        let body_len = self.coincidence_table_offset - self.body_offset;
        let min_body = (self.total_rows as u64).checked_mul(BLOCK_OVERHEAD).ok_or_else(bad)?;
        if min_body > body_len {
            return Err(bad());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const META: u32 = 40;
    const BODY: u64 = HEADER9_SIZE as u64 + META as u64;

    /// Archivo mínimo coherente: cabecera + metadatos + (sin registros) + pie, sin índice.
    fn minimal() -> HeaderV9 {
        HeaderV9 {
            file_id: [9u8; 16],
            created_at: 1,
            total_rows: 0,
            bucket_count: 0,
            body_offset: BODY,
            coincidence_table_offset: BODY,
            index_table_offset: BODY,
            index_entry_count: 0,
            meta_len: META,
            capabilities: CAPS_REV4,
            page_count: 0,
            max_probe: 0,
        }
    }

    /// Con `pages` páginas de índice (y `entries` entradas) y un registro de 40 bytes.
    fn with_index(pages: u32, entries: u64) -> (HeaderV9, u64) {
        let mut h = minimal();
        h.total_rows = 1;
        h.coincidence_table_offset = BODY + 40;
        h.index_table_offset = h.coincidence_table_offset;
        h.bucket_count = pages;
        h.page_count = pages;
        h.max_probe = 1;
        h.index_entry_count = entries;
        let len = h.index_table_offset + pages as u64 * PAGE_SIZE as u64 + FOOTER_LEN;
        (h, len)
    }

    #[test]
    fn page_geometry_constants_are_consistent() {
        assert_eq!(PAGE_ENTRIES * 16 + TAG_LEN as usize, PAGE_SIZE);
        assert_eq!(PAGE_DATA_LEN, 4080);
    }

    #[test]
    fn bytes_roundtrip() {
        let (mut h, _) = with_index(3, 500);
        h.max_probe = 2;
        assert_eq!(HeaderV9::from_bytes(&h.as_bytes()).unwrap(), h);
    }

    #[test]
    fn rejects_bad_magic_scheme_and_reserved_bytes() {
        let good = minimal().as_bytes();

        let mut b = good;
        b[0] = b'X';
        assert!(HeaderV9::from_bytes(&b).is_err());

        let mut b = good;
        b[5] = 0x07;
        assert!(HeaderV9::from_bytes(&b).is_err());

        let mut b = good;
        b[100] = 1;
        assert!(HeaderV9::from_bytes(&b).is_err());
    }

    #[test]
    fn reserved_algorithms_and_access_modes_are_rejected() {
        let good = minimal().as_bytes();

        let mut b = good;
        b[6] = 2; // AES-256-GCM-SIV: reservado
        let err = HeaderV9::from_bytes(&b).unwrap_err();
        assert!(err.to_string().contains("AEAD"), "{}", err);

        let mut b = good;
        b[7] = 3; // clave + hardware: reservado
        let err = HeaderV9::from_bytes(&b).unwrap_err();
        assert!(err.to_string().contains("access mode"), "{}", err);
    }

    #[test]
    fn unknown_or_missing_capabilities_are_rejected() {
        let h = minimal();
        assert_eq!(HeaderV9::from_bytes(&h.as_bytes()).unwrap().capabilities, CAPS_REV4);

        let mut unknown = h;
        unknown.capabilities = CAPS_REV4 | (1 << 9);
        let err = HeaderV9::from_bytes(&unknown.as_bytes()).unwrap_err();
        assert!(err.to_string().contains("does not know"), "{}", err);

        let mut missing = h;
        missing.capabilities = CAPS_REV4 & !CAP_PAGED_HASH_INDEX;
        let err = HeaderV9::from_bytes(&missing.as_bytes()).unwrap_err();
        assert!(err.to_string().contains("lacks"), "{}", err);
    }

    #[test]
    fn other_revisions_and_v8_files_get_a_clear_message() {
        let good = minimal().as_bytes();

        for old in [1u8, 2, 3] {
            let mut b = good;
            b[4] = old;
            let err = HeaderV9::from_bytes(&b).unwrap_err();
            assert!(err.to_string().contains("unsupported PON V9 format revision"), "{}", err);
        }

        let mut b = good;
        b[3] = b'8'; // "PON8"
        let err = HeaderV9::from_bytes(&b).unwrap_err();
        assert!(err.to_string().contains("no longer supported"), "{}", err);
    }

    #[test]
    fn layout_accepts_consistent_files() {
        assert!(minimal().check_layout(BODY + FOOTER_LEN).is_ok(), "no index at all");

        let (h, len) = with_index(3, 500);
        assert!(h.check_layout(len).is_ok());

        let (mut h, len) = with_index(3, 500);
        h.bucket_count = 2; // una página de desborde tras las de direccionamiento
        h.max_probe = 3;
        assert!(h.check_layout(len).is_ok());
    }

    #[test]
    fn layout_rejects_inconsistencies() {
        let h = minimal();
        let ok_len = BODY + FOOTER_LEN;
        assert!(h.check_layout(ok_len - 1).is_err(), "file shorter than header + metadata + footer");
        assert!(h.check_layout(ok_len + 1).is_err(), "trailing bytes before the footer");

        let mut bad = minimal();
        bad.body_offset = 128; // no deja sitio al bloque de metadatos
        assert!(bad.check_layout(ok_len).is_err());

        let mut bad = minimal();
        bad.meta_len = 8; // menor que el mínimo de un bloque
        bad.body_offset = HEADER9_SIZE as u64 + 8;
        assert!(bad.check_layout(ok_len).is_err());

        let mut bad = minimal();
        bad.meta_len = MAX_META_LEN + 1;
        bad.body_offset = HEADER9_SIZE as u64 + MAX_META_LEN as u64 + 1;
        assert!(bad.check_layout(bad.body_offset + FOOTER_LEN).is_err());

        let mut bad = minimal();
        bad.total_rows = 1; // un registro no cabe en un cuerpo vacío
        assert!(bad.check_layout(ok_len).is_err());

        // páginas que no ocupan exactamente hasta el pie
        let (h, len) = with_index(3, 500);
        assert!(h.check_layout(len + 1).is_err());
        assert!(h.check_layout(len - 1).is_err());
        let mut bad = h;
        bad.page_count = 2;
        assert!(bad.check_layout(len).is_err());
    }

    #[test]
    fn layout_rejects_an_impossible_hash_table_geometry() {
        let (h, len) = with_index(3, 500);

        let mut bad = h;
        bad.index_entry_count = 3 * PAGE_ENTRIES as u64 + 1; // no caben
        assert!(bad.check_layout(len).is_err());

        let mut bad = h;
        bad.index_entry_count = 0; // con páginas, hay entradas
        assert!(bad.check_layout(len).is_err());

        let mut bad = h;
        bad.max_probe = 0; // o es mayor que el número de páginas
        assert!(bad.check_layout(len).is_err());
        bad.max_probe = 4;
        assert!(bad.check_layout(len).is_err());

        let mut bad = h;
        bad.bucket_count = 0; // o más que las páginas
        assert!(bad.check_layout(len).is_err());
        bad.bucket_count = 4;
        assert!(bad.check_layout(len).is_err());

        // sin páginas no puede haber entradas ni cota de sondeo
        let mut bad = minimal();
        bad.index_entry_count = 1;
        assert!(bad.check_layout(BODY + FOOTER_LEN).is_err());
        let mut bad = minimal();
        bad.max_probe = 1;
        assert!(bad.check_layout(BODY + FOOTER_LEN).is_err());
        let mut bad = minimal();
        bad.page_count = u32::MAX; // el producto con PAGE_SIZE no debe desbordar ni aceptarse
        assert!(bad.check_layout(BODY + FOOTER_LEN).is_err());
    }
}
