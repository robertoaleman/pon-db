// SPDX-License-Identifier: AGPL-3.0-only
// PON-DB Engine database engine encapsulated in a single, portable and strictly encrypted binary format
// Copyright (C) 2026 Roberto C. Aleman F.
// https://github.com/robertoaleman/pon-db
use aes_gcm::{Aes256Gcm, Key, Nonce, KeyInit};
use aes_gcm::aead::{Aead};
use rand::{RngCore, thread_rng};

pub struct PonCipher {
    cipher: Aes256Gcm,
}

pub fn derive_session_key(master_key: &[u8; 32], hw_id: &[u8; 32]) -> [u8; 32] {
    let mut session_key = [0u8; 32];
    for i in 0..32 {
        session_key[i] = master_key[i] ^ hw_id[i];
    }
    session_key
}

impl PonCipher {
    pub fn new(key_bytes: [u8; 32]) -> Self {
        Self {
            cipher: Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key_bytes)),
        }
    }

    pub fn generate_nonce() -> [u8; 12] {
        let mut nonce = [0u8; 12];
        thread_rng().fill_bytes(&mut nonce);
        nonce
    }

    pub fn encrypt_with_tag(&self, plaintext: &[u8], nonce_bytes: &[u8; 12]) -> Option<(Vec<u8>, [u8; 16])> {
        let nonce = Nonce::from_slice(nonce_bytes);
        if let Ok(ct_at) = self.cipher.encrypt(nonce, plaintext) {
            let tag_pos = ct_at.len() - 16;
            let mut tag = [0u8; 16];
            tag.copy_from_slice(&ct_at[tag_pos..]);
            return Some((ct_at[..tag_pos].to_vec(), tag));
        }
        None
    }

    pub fn decrypt_with_tag(&self, ct: &[u8], nonce: &[u8; 12], tag: &[u8; 16]) -> Option<Vec<u8>> {
        let mut payload = Vec::with_capacity(ct.len() + 16);
        payload.extend_from_slice(ct);
        payload.extend_from_slice(tag);
        self.cipher.decrypt(Nonce::from_slice(nonce), payload.as_slice()).ok()
    }

   
}
