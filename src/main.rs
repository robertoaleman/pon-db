// SPDX-License-Identifier: AGPL-3.0-only
// PON-DB Engine database engine encapsulated in a single, portable and strictly encrypted binary format
// Copyright (C) 2026 Roberto C. Aleman F.
// https://github.com/robertoaleman/pon-db
mod header;
mod security;
mod key_manager;
mod aggregator;
mod reader;
mod index_manager;
mod query_engine;
mod messaging; 

use crate::aggregator::Aggregator;
use crate::header::PonHeaderV8;
use crate::index_manager::ShadowIndex;
use crate::messaging::{Tier, EfficiencyReport};
use crate::security::derive_session_key;

use std::time::Instant;
use std::fs::{File, OpenOptions};
use colored::Colorize;
use std::io::{Write, Read, BufReader, Seek, SeekFrom};
use sysinfo::System;

struct BareMetalScanner<R: Read> {
    reader: R,
}

impl<R: Read> BareMetalScanner<R> {
    fn new(reader: R) -> Self {
        Self { reader }
    }

    fn next_object(&mut self) -> Option<String> {
        let mut depth = 0;
        let mut in_quotes = false;
        let mut escaped = false;
        let mut obj_bytes = Vec::new();
        let mut found_start = false;

        let mut byte = [0u8; 1];
        while self.reader.read_exact(&mut byte).is_ok() {
            let b = byte[0];

            if !found_start {
                if b == b'{' {
                    found_start = true;
                    depth = 1;
                    obj_bytes.push(b);
                }
                continue; 
            }

            obj_bytes.push(b);
            if b == b'\\' && !escaped { escaped = true; continue; }
            if b == b'"' && !escaped { in_quotes = !in_quotes; }
            
            if !in_quotes {
                if b == b'{' { depth += 1; }
                else if b == b'}' { depth -= 1; }
            }
            escaped = false;
            if depth == 0 {
                return Some(String::from_utf8_lossy(&obj_bytes).to_string());
            }
        }
        None
    }
}

fn main() -> std::io::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    
    if args.len() < 2 {
        print_usage();
        return Ok(());
    }

    let input_path = &args[1];
    let neutral_hw_id = [0u8; 32];
    
    let mut fields_to_index = Vec::new();
    let mut is_query = false;
    let mut is_export = false;
    let mut custom_key_path: Option<String> = None;

    for arg in &args {
        if arg.starts_with("--index=") {
            let fields_raw = arg.replace("--index=", "");
            fields_to_index = fields_raw.split(',').map(|s| s.trim().to_string()).collect();
        }
        if arg == "query" { is_query = true; }
        if arg == "export" { is_export = true; }
        if arg.starts_with("--key=") {
            custom_key_path = Some(arg.replace("--key=", ""));
        }
    }

    let tier = Tier::Pro;
    messaging::print_startup_banner(&tier);

    if is_export {
        run_export_mode(input_path, neutral_hw_id, custom_key_path)?;
    } else if is_query {
        let sql = args.iter()
            .find(|a| a.contains('=') || a.contains('>') || a.contains('<') || a.contains('!'))
            .cloned()
            .unwrap_or_else(|| {
                let idx = args.iter().position(|r| r == "query").unwrap_or(0);
                args.get(idx + 1).cloned().expect("Error: Se requiere criterio (ej: id=100)")
            });
        
        run_query_mode(input_path, &sql, neutral_hw_id, custom_key_path)?;
    } else {
        // MODO INGESTA ILIMITADA
        if fields_to_index.is_empty() {
            fields_to_index.push("id".to_string());
        }
        run_ingest_mode(input_path, fields_to_index, neutral_hw_id, u32::MAX)?;
    }
    Ok(())
}

fn run_ingest_mode(path: &str, fields: Vec<String>, hw_id: [u8; 32], max_rows: u32) -> std::io::Result<()> {
    let start_time = Instant::now();
    let file_meta = std::fs::metadata(path)?;
    
    let mut sys = System::new_all();
    sys.refresh_all();
    let l3_size = sys.cpus().first().map(|_c| 32768 * 1024).unwrap_or(2048 * 1024);

    let (master_key, key_path) = key_manager::MasterkeyManager::generate_and_save()?;
    let neutral_id = [0u8; 32];
    let session_key = derive_session_key(&master_key, &neutral_id);

    let output_pon = format!("{}.pon", path);
    let mut out_file = OpenOptions::new().read(true).write(true).create(true).truncate(true).open(&output_pon)?;
    
    out_file.write_all(&[0u8; 128])?; 

    let mut agg = Aggregator::new(session_key, fields[0].clone());
    let mut indexer = ShadowIndex::new(fields.clone());

    let f = File::open(path)?;
    let mut scanner = BareMetalScanner::new(BufReader::new(f));
    let is_self_bound = false;

    while let Some(json_obj) = scanner.next_object() {
        if agg.record_count >= max_rows { break; }
        agg.ingest(&json_obj, &mut out_file)?;
    }

    println!("{} Sellando índices...", " INDEX ".on_yellow().black());
    indexer.collision_map = agg.shadow_index.collision_map; 
    let coincidence_offset = indexer.finalize_v8_5(&mut out_file)?;

    let index_table_offset = out_file.stream_position()?;
    let shards = indexer.get_sharded_buckets(65536); 
    for shard in shards {
        out_file.write_all(&shard)?;
    }

    let header = PonHeaderV8 {
        magic: *b"PON8",
        version: 85,
        created_at: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
        total_rows: agg.record_count,
        index_table_offset,
        coincidence_table_offset: coincidence_offset,
        ..PonHeaderV8::new(hw_id, l3_size, is_self_bound)
    };

    out_file.seek(SeekFrom::Start(0))?;
    out_file.write_all(&header.as_bytes())?;

    let report = EfficiencyReport {
        original_size: file_meta.len(),
        final_size: out_file.metadata()?.len(),
        original_hash: "CAPTURING...".to_string(),
        final_hash: "SEALED_V8.5".to_string(),
        rows_processed: agg.record_count,
        time_elapsed: start_time.elapsed().as_secs_f64(),
    };

    messaging::emit_efficiency_log(report, &format!("{}.log", output_pon))?;
    println!("\n{} Ingestion completed successfully.", " SUCCESS ".on_green());
    println!("{} Master key stored in: {}", " KEY ".on_yellow().black(), key_path);
    
    Ok(())
}

fn run_query_mode(path: &str, sql: &str, hw_id: [u8; 32], key_path: Option<String>) -> std::io::Result<()> {
    let k_path = key_path.unwrap_or_else(|| "masterkey.bin".to_string());
    let mut master_key = [0u8; 32];
    File::open(&k_path)?.read_exact(&mut master_key)?;
    
    let neutral_id = [0u8; 32];
    let session_key = derive_session_key(&master_key, &neutral_id);
    
    let mut file = File::open(path)?;
    
    let header = PonHeaderV8::validate(&mut file, hw_id)?;
    let engine = query_engine::QueryEngine::new(header, session_key);
    let results = engine.execute_query(path, sql)?;

    if results.is_empty() {
        println!("{}", "Result not found.".yellow());
    } else {
        for row in results {
            println!("{}", row.cyan());
        }
    }
    Ok(())
}

fn run_export_mode(path: &str, hw_id: [u8; 32], key_path: Option<String>) -> std::io::Result<()> {
    let k_path = key_path.unwrap_or_else(|| "masterkey.bin".to_string());
    let mut master_key = [0u8; 32];
    File::open(&k_path)?.read_exact(&mut master_key)?;
    
    let neutral_id = [0u8; 32];
    let session_key = derive_session_key(&master_key, &neutral_id);
    let mut file = File::open(path)?;
    
    let header = PonHeaderV8::validate(&mut file, hw_id)?;

    let exporter = reader::PonExporter::new(header, session_key);
    let recovered_hash = exporter.export_to_stdout(path)?;

    println!("\n{}", "==========================================".green());
    println!("{} {}", "INTEGRITY AUDIT:".bold(), "VERIFIED".green());
    println!("Hash: {}", hex::encode(recovered_hash).yellow());
    println!("{}", "==========================================".green());
    Ok(())
}

fn print_usage() {
    println!("\n{}", " ==============================================================================".white());
    println!("{}", "\n PON-DB Engine V8.4  | AGPLv3 Open Source Engine".bright_white().bold());
    println!("{}", " © 2026 pon-db.com | Author: Roberto C. Alemán".white());
    println!("\n{}", " Use of the software:".white());   
    println!("   Ingest:      ./pon-db dataset.json --index=sku");
    println!("   Search O(1): ./pon-db dataset.json.pon query \"sku=PROD-100\" --key=masterkey_xxxx.bin");
    println!("   Export:   ./pon-db dataset.json.pon export --key=masterkey_xxxx.bin");
    println!("{}", " ==============================================================================".white());
}
