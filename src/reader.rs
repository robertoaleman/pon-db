// SPDX-License-Identifier: AGPL-3.0-only
// PON-DB Engine database engine encapsulated in a single, portable and strictly encrypted binary format
// Copyright (C) 2026 Roberto C. Aleman F.
// https://github.com/robertoaleman/pon-db
use std::io::{Read, Seek, SeekFrom};
use std::fs::File;
use sha2::{Sha256, Digest};
use crate::header::{PonHeaderV8, PON_HEADER_SIZE};
use crate::security::PonCipher;
use zeroize::Zeroize;
use colored::Colorize;

pub struct PonExporter {
    header: PonHeaderV8,
    cipher: PonCipher,
}

impl PonExporter {
    pub fn new(header: PonHeaderV8, session_key: [u8; 32]) -> Self {
        Self {
            header,
            cipher: PonCipher::new(session_key),
        }
    }

    /// Exporta el contenido del .pon a STDOUT en formato JSON Array
    pub fn export_to_stdout(&self, pon_path: &str) -> std::io::Result<[u8; 32]> {
        let mut file = File::open(pon_path)?;
        let mut hasher = Sha256::new();
        let mut count = 0;

        file.seek(SeekFrom::Start(PON_HEADER_SIZE as u64))?;
        println!("["); 

        loop {
            let mut nonce = [0u8; 12];
            if file.read_exact(&mut nonce).is_err() { break; }

            let mut len_bytes = [0u8; 4];
            file.read_exact(&mut len_bytes)?;
            let len = u32::from_le_bytes(len_bytes) as usize;

            let mut ciphertext = vec![0u8; len];
            file.read_exact(&mut ciphertext)?;

            let mut tag = [0u8; 16];
            file.read_exact(&mut tag)?;

            if let Some(mut plain_bytes) = self.cipher.decrypt_with_tag(&ciphertext, &nonce, &tag) {
                hasher.update(&plain_bytes);
                let row = String::from_utf8_lossy(&plain_bytes);
                
                if count > 0 { print!(",\n"); }
                print!("  {}", row);
                
                count += 1;
                plain_bytes.zeroize();  
            } else {
                eprintln!("\n{}", "ERROR: Integrity error in data block.".on_red());
                break;
            }

            if count >= self.header.total_rows { break; }
        }

        println!("\n]");  
        
        let recovered_hash: [u8; 32] = hasher.finalize().into();
        Ok(recovered_hash)
    }
}
