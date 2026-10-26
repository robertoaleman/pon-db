// SPDX-License-Identifier: AGPL-3.0-only
// PON-DB Engine database engine encapsulated in a single, portable and strictly encrypted binary format
// Copyright (C) 2026 Roberto C. Aleman F.
// https://github.com/robertoaleman/pon-db
use std::io::Write;
use std::fs::File;
use chrono::Local;
use rand::{distributions::Alphanumeric, Rng};

pub struct MasterkeyManager;

impl MasterkeyManager {
    pub fn generate_and_save() -> std::io::Result<([u8; 32], String)> {
        let mut key = [0u8; 32];
        rand::thread_rng().fill(&mut key);

        let random_id: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(8)
            .map(char::from)
            .collect();
        
        let date_str = Local::now().format("%Y-%m-%d").to_string();
        let filename = format!("masterkey_{}_{}.bin", random_id, date_str);

        {
            let mut file = File::create(&filename)?;
            file.write_all(&key)?;
        }

        Ok((key, filename))
    }
}