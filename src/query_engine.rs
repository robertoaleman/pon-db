// SPDX-License-Identifier: AGPL-3.0-only
// PON-DB Engine database engine encapsulated in a single, portable and strictly encrypted binary format
// Copyright (C) 2026 Roberto C. Aleman F.
// https://github.com/robertoaleman/pon-db
use std::hash::Hasher;
use crate::header::PonHeaderV8;
use crate::security::PonCipher;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::time::Instant;
use zeroize::Zeroize;
use colored::Colorize;

#[derive(Debug, Clone, Copy)]
pub enum QueryOp {
    Equal,
    NotEqual,
    GreaterThan,
    LessThan,
}

pub struct QueryEngine {
    header: PonHeaderV8,
    cipher: PonCipher,
}

impl QueryEngine {
    pub fn new(header: PonHeaderV8, session_key: [u8; 32]) -> Self {
        Self {
            header,
            cipher: PonCipher::new(session_key),
        }
    }

   pub fn execute_query(&self, path: &str, query_str: &str) -> std::io::Result<Vec<String>> {
       // --- Lógica de búsqueda ---
       let (field, op, value) = self.parse_query(query_str);
       let results = match op {
           QueryOp::Equal => self.execute_select(path, &field, &value)?,
           _ => self.execute_scan(path, &field, op, &value)?,
       };
   
       Ok(results)
   }

    fn lookup_hash_in_file(&self, file: &mut File, target_hash: u64) -> std::io::Result<Option<u64>> {
        let table_offset = self.header.index_table_offset;
        let file_len = file.metadata()?.len();
        let bytes_available = if file_len > table_offset { file_len - table_offset } else { 0 };
        let actual_index_rows = (bytes_available / 16) as i64;
        let mut low = 0;
        let mut high = actual_index_rows - 1;
    
        while low <= high {
            let mid = low + (high - low) / 2;
            let pos = table_offset + (mid as u64 * 16);
    
            file.seek(SeekFrom::Start(pos))?;
            let mut buffer = [0u8; 16];
            
            let n = file.read(&mut buffer)?;
            if n < 16 { break; } // Si no leyó los 16 bytes, llegamos al final real
            
            let h = u64::from_le_bytes(buffer[0..8].try_into().unwrap());
            let off = u64::from_le_bytes(buffer[8..16].try_into().unwrap());
    
            if h == target_hash {
                return Ok(Some(off));
            } else if h < target_hash {
                low = mid + 1;
            } else {
                high = mid - 1;
            }
        }
        Ok(None)
    }

    pub fn execute_select(&self, path: &str, _target_field: &str, search_value: &str) -> std::io::Result<Vec<String>> {
        let mut file = File::open(path)?;
        
        let mut s = std::collections::hash_map::DefaultHasher::new();
        s.write(search_value.as_bytes()); // <--- USAR write() NO .hash()
        let target_hash = s.finish();

        if let Some(ptr) = self.lookup_hash_in_file(&mut file, target_hash)? {
            let is_multi = (ptr >> 63) == 1;
            let clean_ptr = ptr & !(1 << 63);

            if is_multi {
                return self.fetch_multi_records(&mut file, clean_ptr);
            } else {
                return Ok(vec![self.read_at_offset(&mut file, clean_ptr)?]);
            }
        }
        Ok(vec![])
    }

    fn fetch_multi_records(&self, file: &mut File, coincidence_ptr: u64) -> std::io::Result<Vec<String>> {
        let mut results = Vec::new();
        file.seek(SeekFrom::Start(coincidence_ptr))?;
        
        let mut count_bytes = [0u8; 4];
        file.read_exact(&mut count_bytes)?;
        let count = u32::from_le_bytes(count_bytes);

        for _ in 0..count {
            let mut off_bytes = [0u8; 8];
            file.read_exact(&mut off_bytes)?;
            let off = u64::from_le_bytes(off_bytes);
            
            let current_pos = file.stream_position()?;
            if let Ok(json) = self.read_at_offset(file, off) {
                results.push(json);
            }
            file.seek(SeekFrom::Start(current_pos))?;
        }
        Ok(results)
    }

    fn read_at_offset(&self, file: &mut File, offset: u64) -> std::io::Result<String> {
        file.seek(SeekFrom::Start(offset))?;

        let mut nonce = [0u8; 12];
        file.read_exact(&mut nonce)?;

        let mut len_bytes = [0u8; 4];
        file.read_exact(&mut len_bytes)?;
        let len = u32::from_le_bytes(len_bytes) as usize;

        let mut ciphertext = vec![0u8; len];
        file.read_exact(&mut ciphertext)?;

        let mut tag = [0u8; 16];
        file.read_exact(&mut tag)?;

        if let Some(plain) = self.cipher.decrypt_with_tag(&ciphertext, &nonce, &tag) {
            let s = String::from_utf8_lossy(&plain).to_string();
            return Ok(s);
        }
        Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "Error de descifrado"))
    }

    fn execute_scan(&self, path: &str, field: &str, op: QueryOp, target_val: &str) -> std::io::Result<Vec<String>> {
        let start_timer = Instant::now();
        let mut file = File::open(path)?;
        let mut results = Vec::new();
        
        file.seek(SeekFrom::Start(self.header.body_offset))?;
        
        loop {
            let current_pos = file.stream_position()?;
            if current_pos >= self.header.index_table_offset { break; }

            let mut _cascade = [0u8; 8];
            if file.read_exact(&mut _cascade).is_err() { break; }

            let mut nonce = [0u8; 12];
            if file.read_exact(&mut nonce).is_err() { break; } 

            let mut len_bytes = [0u8; 4];
            if file.read_exact(&mut len_bytes).is_err() { break; }
            let len = u32::from_le_bytes(len_bytes) as usize;

            if len > 10_000_000 { break; } 

            let mut ciphertext = vec![0u8; len];
            file.read_exact(&mut ciphertext)?;
            
            let mut tag = [0u8; 16];
            file.read_exact(&mut tag)?;

            if let Some(mut plain_bytes) = self.cipher.decrypt_with_tag(&ciphertext, &nonce, &tag) {
                let json_str = String::from_utf8_lossy(&plain_bytes).to_string();
                if self.evaluate_condition(&json_str, field, &op, target_val) {
                    results.push(json_str);
                }
                plain_bytes.zeroize();
            }
        }

        println!("{} Scan O(k) en {:?}", " TIME ".on_yellow().black(), start_timer.elapsed());
        Ok(results)
    }

    fn parse_query(&self, query: &str) -> (String, QueryOp, String) {
        let operators = [
            ("!=", QueryOp::NotEqual), (">=", QueryOp::GreaterThan),
            ("<=", QueryOp::LessThan), ("=", QueryOp::Equal),
            (">", QueryOp::GreaterThan), ("<", QueryOp::LessThan),
        ];
        for (symbol, op) in operators {
            if query.contains(symbol) {
                let parts: Vec<&str> = query.split(symbol).collect();
                return (
                    parts[0].trim().to_string(), op,
                    parts[1].trim().trim_matches('\'').trim_matches('"').to_string()
                );
            }
        }
        (query.to_string(), QueryOp::Equal, "".to_string())
    }

    fn evaluate_condition(&self, json: &str, field: &str, op: &QueryOp, target: &str) -> bool {
        let pattern = format!("\"{}\":", field);
        if let Some(pos) = json.find(&pattern) {
            let start = pos + pattern.len();
            let remainder = &json[start..].trim_start();
            let val = remainder.split(|c| c == ',' || c == '}' || c == ']').next().unwrap_or("")
                               .trim().trim_matches('"');
            match op {
                QueryOp::Equal => val == target,
                QueryOp::NotEqual => val != target,
                QueryOp::GreaterThan => val.parse::<f64>().unwrap_or(0.0) > target.parse::<f64>().unwrap_or(0.0),
                QueryOp::LessThan => val.parse::<f64>().unwrap_or(0.0) < target.parse::<f64>().unwrap_or(0.0),
            }
        } else { false }
    }
}
