// SPDX-License-Identifier: AGPL-3.0-only
// PON-DB Engine: a database engine encapsulated in a single, portable, encrypted binary format
// Copyright (C) 2026 Roberto C. Aleman F.
// https://github.com/robertoaleman/pon-db
//
// Jerarquía de claves de V9:
//
//   clave maestra (archivo de 32 bytes)
//        |  HKDF-SHA256, sal = file_id (16 bytes aleatorios por archivo)
//        +--> clave de registros   ("pon-db/v9/block-encryption")     -> AES-256-GCM
//        +--> clave de metadatos   ("pon-db/v9/metadata-encryption")  -> AES-256-GCM
//        +--> clave del índice     ("pon-db/v9/index-key")            -> HMAC-SHA256
//        +--> clave de páginas     ("pon-db/v9/index-page-mac")       -> GMAC (AES-256-GCM)
//        +--> clave de estructura  ("pon-db/v9/structure-mac")        -> HMAC-SHA256
//
// Cada archivo tiene claves distintas aunque comparta la clave maestra, así que los
// nonces aleatorios de 96 bits nunca se acumulan entre archivos.
use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::{Aead, AeadInPlace, Payload};
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::io;
use zeroize::Zeroizing;

use crate::block::{corrupt, RawBlock};

type HmacSha256 = Hmac<Sha256>;

pub const FILE_ID_LEN: usize = 16;

const DOM_FOOTER: &[u8] = b"pon-db/v9/footer\0";
const DOM_COINCIDENCE: &[u8] = b"pon-db/v9/coincidence\0";
const DOM_INDEX: &[u8] = b"pon-db/v9/index-entry\0";

/// Versión de bloque dentro del nonce. Un archivo WORM no reescribe nunca un bloque: siempre 0.
/// El hueco existe para que una variante con escritura in situ pueda numerar las versiones de un
/// bloque sin cambiar el formato del nonce.
const NONCE_VERSION: u32 = 0;

/// Nonce de AES-GCM de un bloque: `offset (u64 LE) || versión (u32 LE)`. Es único por construcción:
/// cada archivo tiene claves propias (HKDF con un `file_id` aleatorio) y cada offset se escribe una
/// sola vez. No hay nonces aleatorios, así que no existe la cota de cumpleaños de 2^32 bloques.
fn nonce_for(offset: u64) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[..8].copy_from_slice(&offset.to_le_bytes());
    n[8..].copy_from_slice(&NONCE_VERSION.to_le_bytes());
    n
}

fn other(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::Other, msg.to_string())
}

/// HKDF-SHA256 (RFC 5869).
pub fn hkdf_sha256(salt: &[u8], ikm: &[u8], info: &[u8], out: &mut [u8]) -> io::Result<()> {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    hk.expand(info, out).map_err(|_| other("invalid HKDF output length"))
}

/// HMAC-SHA256 (RFC 2104) sobre la concatenación de `parts`.
pub fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> io::Result<[u8; 32]> {
    // Rutas completas: `KeyInit` (de aes_gcm) y `Mac` (de hmac) definen ambos `new_from_slice`
    // para `Hmac`, y con los dos traits en ámbito la llamada abreviada sería ambigua (E0034).
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).map_err(|_| other("invalid HMAC key"))?;
    for part in parts {
        Mac::update(&mut mac, part);
    }
    Ok(Mac::finalize(mac).into_bytes().into())
}

/// Comparación en tiempo constante.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn truncate16(full: &[u8; 32]) -> [u8; 16] {
    let mut t = [0u8; 16];
    t.copy_from_slice(&full[..16]);
    t
}

pub struct Keys9 {
    enc: Zeroizing<[u8; 32]>,
    meta: Zeroizing<[u8; 32]>,
    idx: Zeroizing<[u8; 32]>,
    page: Zeroizing<[u8; 32]>,
    mac: Zeroizing<[u8; 32]>,
}

impl Keys9 {
    pub fn derive(master: &[u8; 32], file_id: &[u8; FILE_ID_LEN]) -> io::Result<Self> {
        let mut enc = Zeroizing::new([0u8; 32]);
        let mut meta = Zeroizing::new([0u8; 32]);
        let mut idx = Zeroizing::new([0u8; 32]);
        let mut page = Zeroizing::new([0u8; 32]);
        let mut mac = Zeroizing::new([0u8; 32]);
        hkdf_sha256(file_id, master, b"pon-db/v9/block-encryption", &mut *enc)?;
        hkdf_sha256(file_id, master, b"pon-db/v9/metadata-encryption", &mut *meta)?;
        hkdf_sha256(file_id, master, b"pon-db/v9/index-key", &mut *idx)?;
        hkdf_sha256(file_id, master, b"pon-db/v9/index-page-mac", &mut *page)?;
        hkdf_sha256(file_id, master, b"pon-db/v9/structure-mac", &mut *mac)?;
        Ok(Self { enc, meta, idx, page, mac })
    }

    /// Cifrador de los registros.
    pub fn block_cipher(&self, file_id: &[u8; FILE_ID_LEN]) -> BlockCipher9 {
        BlockCipher9::new(&self.enc, file_id)
    }

    /// Cifrador del bloque de metadatos (clave distinta de la de los registros).
    pub fn metadata_cipher(&self, file_id: &[u8; FILE_ID_LEN]) -> BlockCipher9 {
        BlockCipher9::new(&self.meta, file_id)
    }

    /// Función de hash con clave del índice.
    pub fn index_hasher(&self) -> IndexHasher {
        IndexHasher { key: Zeroizing::new(*self.idx) }
    }

    /// Etiquetador de las páginas del índice.
    pub fn page_mac(&self) -> PageMac {
        PageMac::new(&self.page)
    }

    /// MAC de 32 bytes que cierra el archivo: cubre la cabecera completa (offsets, número de páginas,
    /// cota del sondeo, capacidades...). Las páginas del índice, las tablas de coincidencias, los
    /// metadatos y los registros se autentican cada uno por su cuenta, así que abrir el archivo cuesta
    /// lo mismo sea cual sea su tamaño.
    pub fn footer_mac(&self, header: &[u8]) -> io::Result<[u8; 32]> {
        hmac_sha256(&self.mac[..], &[DOM_FOOTER, header])
    }

    /// Etiqueta (128 bits) de una tabla de coincidencias, ligada al archivo y a su offset.
    pub fn coincidence_tag(&self, file_id: &[u8; FILE_ID_LEN], pos: u64, table: &[u8]) -> io::Result<[u8; 16]> {
        let p = pos.to_le_bytes();
        let full = hmac_sha256(&self.mac[..], &[DOM_COINCIDENCE, &file_id[..], &p[..], table])?;
        Ok(truncate16(&full))
    }
}

/// Etiqueta de las páginas del índice: GMAC (AES-256-GCM sin texto cifrado y con la página como dato
/// asociado). Aprovecha la aceleración por hardware de AES y de la multiplicación sin acarreo, y es
/// mucho más rápida que un HMAC-SHA256 sobre 4 KiB, que es el coste criptográfico de cada búsqueda.
/// El nonce es el número de página (único en el archivo) y la clave es propia de este uso y de este
/// archivo: una página solo se verifica en su posición y en su archivo.
pub struct PageMac {
    cipher: Aes256Gcm,
}

impl PageMac {
    fn new(key: &[u8; 32]) -> Self {
        Self { cipher: Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key[..])) }
    }

    fn nonce(page_no: u64) -> [u8; 12] {
        let mut n = [0u8; 12];
        n[..8].copy_from_slice(&page_no.to_le_bytes());
        n
    }

    pub fn tag(&self, page_no: u64, data: &[u8]) -> io::Result<[u8; 16]> {
        let nonce = Self::nonce(page_no);
        let tag = self
            .cipher
            .encrypt_in_place_detached(Nonce::from_slice(&nonce), data, &mut [])
            .map_err(|_| other("GMAC computation failed"))?;
        let mut out = [0u8; 16];
        out.copy_from_slice(&tag);
        Ok(out)
    }

    /// Comprueba la etiqueta en tiempo constante.
    pub fn verify(&self, page_no: u64, data: &[u8], tag: &[u8]) -> io::Result<bool> {
        let expected = self.tag(page_no, data)?;
        Ok(ct_eq(&expected, tag))
    }
}

/// Hash con clave de las entradas del índice: `HMAC-SHA256(clave_índice, len(campo) || campo || valor)`
/// truncado a 8 bytes. Sin la clave maestra no se pueden probar valores candidatos contra el índice, y
/// el nombre del campo forma parte de la entrada, así que un mismo valor en dos campos da hashes distintos.
pub struct IndexHasher {
    key: Zeroizing<[u8; 32]>,
}

impl IndexHasher {
    pub fn hash(&self, field: &str, value: &[u8]) -> io::Result<u64> {
        let field_len = (field.len() as u32).to_le_bytes();
        let full = hmac_sha256(&self.key[..], &[DOM_INDEX, &field_len[..], field.as_bytes(), value])?;
        let mut a = [0u8; 8];
        a.copy_from_slice(&full[..8]);
        Ok(u64::from_le_bytes(a))
    }
}

/// AES-256-GCM con datos asociados `file_id || offset`: un bloque solo se descifra en el
/// archivo y en la posición exactas donde se escribió. Intercambiar, mover, duplicar o
/// trasplantar bloques entre archivos hace fallar la autenticación.
pub struct BlockCipher9 {
    cipher: Aes256Gcm,
    file_id: [u8; FILE_ID_LEN],
}

impl BlockCipher9 {
    fn new(key: &[u8; 32], file_id: &[u8; FILE_ID_LEN]) -> Self {
        Self {
            cipher: Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key[..])),
            file_id: *file_id,
        }
    }

    fn aad(&self, offset: u64) -> [u8; 24] {
        let mut a = [0u8; 24];
        a[..16].copy_from_slice(&self.file_id);
        a[16..].copy_from_slice(&offset.to_le_bytes());
        a
    }

    /// Cifra un registro que se escribirá en `offset`. Devuelve (ciphertext, tag); el nonce se deriva
    /// de la posición, no se guarda.
    pub fn seal(&self, plaintext: &[u8], offset: u64) -> io::Result<(Vec<u8>, [u8; 16])> {
        let nonce = nonce_for(offset);
        let aad = self.aad(offset);
        let ct_and_tag = self
            .cipher
            .encrypt(Nonce::from_slice(&nonce), Payload { msg: plaintext, aad: &aad })
            .map_err(|_| other("AES-GCM encryption failed"))?;
        if ct_and_tag.len() < 16 {
            return Err(other("AES-GCM output is shorter than its tag"));
        }
        let split = ct_and_tag.len() - 16;
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&ct_and_tag[split..]);
        Ok((ct_and_tag[..split].to_vec(), tag))
    }

    /// Descifra en el sitio: `buf` contiene el ciphertext y, si la autenticación es correcta, queda con el
    /// texto en claro. No reserva memoria ni copia el bloque: es el camino del scan, donde cada hilo
    /// reutiliza un único búfer. Con un fallo de autenticación el contenido de `buf` debe descartarse.
    pub fn open_in_place(&self, tag: &[u8], offset: u64, buf: &mut Vec<u8>) -> io::Result<()> {
        if tag.len() != 16 {
            return Err(corrupt(format!("malformed block at offset {}", offset)));
        }
        let nonce = nonce_for(offset);
        let aad = self.aad(offset);
        self.cipher
            .decrypt_in_place_detached(
                Nonce::from_slice(&nonce),
                &aad,
                buf.as_mut_slice(),
                GenericArray::from_slice(tag),
            )
            .map_err(|_| corrupt(format!("corrupt or tampered block at offset {}", offset)))
    }

    /// Descifra el bloque que está en `offset`; falla si el contenido, la posición o el archivo no coinciden.
    pub fn open(&self, block: &RawBlock, offset: u64) -> io::Result<Zeroizing<Vec<u8>>> {
        let mut payload = Vec::with_capacity(block.ciphertext.len() + 16);
        payload.extend_from_slice(&block.ciphertext);
        payload.extend_from_slice(&block.tag);
        let aad = self.aad(offset);
        self.cipher
            .decrypt(Nonce::from_slice(&nonce_for(offset)), Payload { msg: &payload, aad: &aad })
            .map(Zeroizing::new)
            .map_err(|_| corrupt(format!("corrupt or tampered block at offset {}", offset)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hkdf_matches_rfc_5869_test_case_1() {
        let ikm = [0x0bu8; 22];
        let salt: Vec<u8> = (0u8..=0x0c).collect();
        let info: Vec<u8> = (0xf0u8..=0xf9).collect();
        let mut okm = [0u8; 42];
        hkdf_sha256(&salt, &ikm, &info, &mut okm).unwrap();
        assert_eq!(
            hex::encode(okm),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        );
    }

    #[test]
    fn hmac_matches_rfc_4231_test_case_2() {
        let tag = hmac_sha256(b"Jefe", &[b"what do ya want ", b"for nothing?"]).unwrap();
        assert_eq!(
            hex::encode(tag),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn constant_time_compare() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab"));
    }

    #[test]
    fn keys_depend_on_master_and_file_id_and_are_independent() {
        let m = [1u8; 32];
        let a = Keys9::derive(&m, &[1u8; 16]).unwrap();
        let a2 = Keys9::derive(&m, &[1u8; 16]).unwrap();
        let b = Keys9::derive(&m, &[2u8; 16]).unwrap();
        let c = Keys9::derive(&[2u8; 32], &[1u8; 16]).unwrap();
        assert_eq!(*a.enc, *a2.enc);
        assert_eq!(*a.idx, *a2.idx);
        let all = [*a.enc, *a.meta, *a.idx, *a.page, *a.mac];
        for i in 0..all.len() {
            for j in (i + 1)..all.len() {
                assert_ne!(all[i], all[j], "the four derived keys must be independent");
            }
        }
        assert_ne!(*a.enc, *b.enc);
        assert_ne!(*a.idx, *b.idx);
        assert_ne!(*a.mac, *b.mac);
        assert_ne!(*a.enc, *c.enc);
        assert_ne!(*a.idx, *c.idx);
    }

    fn cipher(file_id: [u8; 16]) -> BlockCipher9 {
        let keys = Keys9::derive(&[7u8; 32], &file_id).unwrap();
        keys.block_cipher(&file_id)
    }

    fn sealed_block(c: &BlockCipher9, plaintext: &[u8], offset: u64) -> RawBlock {
        let (ciphertext, tag) = c.seal(plaintext, offset).unwrap();
        RawBlock { ciphertext, tag }
    }

    #[test]
    fn seal_open_roundtrip_only_at_the_original_offset_and_file() {
        let c = cipher([3u8; 16]);
        let block = sealed_block(&c, b"{\"id\":1}", 128);
        assert_eq!(c.open(&block, 128).unwrap().as_slice(), b"{\"id\":1}");
        assert!(c.open(&block, 129).is_err(), "a block moved to another offset must fail");
        assert!(cipher([4u8; 16]).open(&block, 128).is_err(), "a block from another file must fail");
    }

    #[test]
    fn open_in_place_agrees_with_open_and_rejects_the_same_attacks() {
        let c = cipher([3u8; 16]);
        let block = sealed_block(&c, b"{\"id\":42}", 300);

        let mut buf = block.ciphertext.clone();
        c.open_in_place(&block.tag, 300, &mut buf).unwrap();
        assert_eq!(buf.as_slice(), b"{\"id\":42}");
        assert_eq!(buf, c.open(&block, 300).unwrap().to_vec());

        let mut moved = block.ciphertext.clone();
        assert!(c.open_in_place(&block.tag, 301, &mut moved).is_err(), "other offset");

        let mut foreign = block.ciphertext.clone();
        assert!(cipher([4u8; 16]).open_in_place(&block.tag, 300, &mut foreign).is_err(), "other file");

        let mut bad = block.ciphertext.clone();
        bad[0] ^= 1;
        assert!(c.open_in_place(&block.tag, 300, &mut bad).is_err(), "tampered ciphertext");

        let mut bad_tag = block.tag;
        bad_tag[15] ^= 1;
        let mut ct = block.ciphertext.clone();
        assert!(c.open_in_place(&bad_tag, 300, &mut ct).is_err(), "tampered tag");

        let mut ct = block.ciphertext.clone();
        assert!(c.open_in_place(&block.tag[..15], 300, &mut ct).is_err(), "short tag");
    }

    #[test]
    fn the_nonce_comes_from_the_position_and_is_never_random() {
        assert_eq!(nonce_for(0x0102030405060708), [8, 7, 6, 5, 4, 3, 2, 1, 0, 0, 0, 0]);
        assert_ne!(nonce_for(128), nonce_for(129));

        let c = cipher([3u8; 16]);
        let a = c.seal(b"same plaintext", 500).unwrap();
        let b = c.seal(b"same plaintext", 500).unwrap();
        assert_eq!(a, b, "deterministic: same key, same offset, same plaintext");
        let other_offset = c.seal(b"same plaintext", 501).unwrap();
        assert_ne!(a.0, other_offset.0, "a different position must give a different keystream");
    }

    #[test]
    fn tampering_is_detected() {
        let c = cipher([3u8; 16]);
        let mut block = sealed_block(&c, b"secret", 200);
        block.ciphertext[0] ^= 1;
        assert!(c.open(&block, 200).is_err());
        block.ciphertext[0] ^= 1;
        block.tag[0] ^= 1;
        assert!(c.open(&block, 200).is_err());
    }

    #[test]
    fn tags_are_bound_to_position_and_file() {
        let k = Keys9::derive(&[7u8; 32], &[1u8; 16]).unwrap();
        let c1 = k.coincidence_tag(&[1u8; 16], 500, b"tbl").unwrap();
        assert_eq!(c1, k.coincidence_tag(&[1u8; 16], 500, b"tbl").unwrap());
        assert_ne!(c1, k.coincidence_tag(&[1u8; 16], 501, b"tbl").unwrap(), "offset");
        assert_ne!(c1, k.coincidence_tag(&[2u8; 16], 500, b"tbl").unwrap(), "file id");
        assert_ne!(c1, k.coincidence_tag(&[1u8; 16], 500, b"tbm").unwrap(), "content");
    }

    #[test]
    fn page_tags_are_bound_to_position_content_and_file() {
        let m = Keys9::derive(&[7u8; 32], &[1u8; 16]).unwrap().page_mac();
        let t = m.tag(5, b"entries").unwrap();
        assert_eq!(t, m.tag(5, b"entries").unwrap());
        assert_ne!(t, m.tag(6, b"entries").unwrap(), "position");
        assert_ne!(t, m.tag(5, b"entrieS").unwrap(), "content");
        let other_file = Keys9::derive(&[7u8; 32], &[2u8; 16]).unwrap().page_mac();
        assert_ne!(t, other_file.tag(5, b"entries").unwrap(), "file");

        assert!(m.verify(5, b"entries", &t).unwrap());
        assert!(!m.verify(5, b"entries", &[0u8; 16]).unwrap());
        assert!(!m.verify(6, b"entries", &t).unwrap(), "a page moved to another position");
        assert!(!other_file.verify(5, b"entries", &t).unwrap(), "a page from another file");
    }

    #[test]
    fn a_page_tag_detects_a_change_in_any_single_byte() {
        let m = Keys9::derive(&[7u8; 32], &[1u8; 16]).unwrap().page_mac();
        let page: Vec<u8> = (0..4080u32).map(|i| (i % 251) as u8).collect();
        let tag = m.tag(9, &page).unwrap();
        assert!(m.verify(9, &page, &tag).unwrap());
        for i in (0..page.len()).step_by(37) {
            let mut bad = page.clone();
            bad[i] ^= 0x01;
            assert!(!m.verify(9, &bad, &tag).unwrap(), "byte {}", i);
        }
        let mut bad_tag = tag;
        bad_tag[0] ^= 1;
        assert!(!m.verify(9, &page, &bad_tag).unwrap());
    }

    #[test]
    fn index_hash_depends_on_key_field_and_value() {
        let k1 = Keys9::derive(&[7u8; 32], &[1u8; 16]).unwrap().index_hasher();
        let k1b = Keys9::derive(&[7u8; 32], &[1u8; 16]).unwrap().index_hasher();
        let k2 = Keys9::derive(&[7u8; 32], &[2u8; 16]).unwrap().index_hasher();
        let k3 = Keys9::derive(&[8u8; 32], &[1u8; 16]).unwrap().index_hasher();

        let h = k1.hash("sku", b"PROD-1").unwrap();
        assert_eq!(h, k1b.hash("sku", b"PROD-1").unwrap());
        assert_ne!(h, k1.hash("sku", b"PROD-2").unwrap(), "value");
        assert_ne!(h, k1.hash("id", b"PROD-1").unwrap(), "field");
        assert_ne!(h, k2.hash("sku", b"PROD-1").unwrap(), "file id");
        assert_ne!(h, k3.hash("sku", b"PROD-1").unwrap(), "master key");
        // el prefijo de longitud evita que ("ab","c") y ("a","bc") coincidan
        assert_ne!(k1.hash("ab", b"c").unwrap(), k1.hash("a", b"bc").unwrap());
    }

    #[test]
    fn footer_mac_covers_every_byte_of_the_header() {
        let k = Keys9::derive(&[7u8; 32], &[1u8; 16]).unwrap();
        let m = k.footer_mac(&[0u8; 128]).unwrap();
        assert_eq!(m, k.footer_mac(&[0u8; 128]).unwrap());
        for i in 0..128 {
            let mut h = [0u8; 128];
            h[i] = 1;
            assert_ne!(m, k.footer_mac(&h).unwrap(), "header byte {}", i);
        }
    }
}
