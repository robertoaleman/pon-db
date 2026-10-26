// SPDX-License-Identifier: AGPL-3.0-only
// PON-DB Engine database engine encapsulated in a single, portable and strictly encrypted binary format
// Copyright (C) 2026 Roberto C. Aleman F.
// https://github.com/robertoaleman/pon-db
use crate::security::PonCipher;
use crate::index_manager::ShadowIndex;
use std::io::{Write, Seek};
use serde_json::Value;
use zeroize::Zeroize;

pub struct Aggregator {
    pub record_count: u32,
    pub session_key: [u8; 32],
    pub shadow_index: ShadowIndex,
    pub indexed_field: String,
}

impl Aggregator {
    pub fn new(session_key: [u8; 32], indexed_field: String) -> Self {
        Self {
            record_count: 0,
            session_key,
            shadow_index: ShadowIndex::new(vec![indexed_field.clone()]),
            indexed_field,
        }
    }

    /// --- INGESTA ---
    pub fn ingest<W: Write + Seek>(
        &mut self, 
        json_str: &str, 
        out_file: &mut W
    ) -> std::io::Result<()> {
        let cipher = PonCipher::new(self.session_key);
        
        // 1. Obtener posición actual 
        let offset = out_file.stream_position()?;

        // 2. Extraer valor para el índice 
        let doc: Value = serde_json::from_str(json_str)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        
        if let Some(val) = doc.get(&self.indexed_field) {
            let val_string = match val {
                Value::String(s) => s.clone(),
                Value::Number(n) => n.to_string(),
                Value::Bool(b) => b.to_string(),
                _ => val.to_string(), // Fallback para otros tipos
            };

            let val_bytes = val_string.into_bytes();

            self.shadow_index.add_entry(&self.indexed_field, &val_bytes, offset);
        }

        // 3. Cifrado AES-256-GCM (Payload + Tag)
        let nonce = PonCipher::generate_nonce();
        let plain_bytes = json_str.as_bytes();
        
        if let Some((ciphertext, tag)) = cipher.encrypt_with_tag(plain_bytes, &nonce) {

            out_file.write_all(&nonce)?;
            out_file.write_all(&(ciphertext.len() as u32).to_le_bytes())?;
            out_file.write_all(&ciphertext)?;
            out_file.write_all(&tag)?;
            
            self.record_count += 1;
        }

         let mut temp = json_str.to_string();
        temp.zeroize(); 

        Ok(())
    }
}
