// SPDX-License-Identifier: AGPL-3.0-only
// PON-DB Engine database engine encapsulated in a single, portable and strictly encrypted binary format
// Copyright (C) 2026 Roberto C. Aleman F.
// https://github.com/robertoaleman/pon-db
use serde::{Serialize, Deserialize};
use zeroize::Zeroize;
use std::io::{Read, Error, ErrorKind};
use std::time::{SystemTime, UNIX_EPOCH};
use sysinfo::System;

pub const PON_HEADER_SIZE: usize = 128; 

/// --- PON V8.4 Header ---
/// 
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Zeroize)]
pub struct PonHeaderV8 {
    pub magic: [u8; 4],               // 0..4
    pub version: u8,                  // 4
    pub data_model: u8,               // 5
    pub mode_flag: u8,                // 6 -> Bit 3: Hardware Binding
    pub security_type: u8,            // 7
    pub arch_tag: [u8; 4],            // 8..12
    pub created_at: u64,              // 12..20
    pub license_issue_date: u64,      // 20..28 (license)
    pub uptime_at_creation: u64,      // 28..36
    pub shard_size_bytes: u32,        // 36..40 (Default 64KB)
    pub bucket_count: u32,            // 40..44
    pub total_rows: u32,              // 44..48
    pub master_index_offset: u64,     // 48..56
    pub ribbon_filter_offset: u64,    // 56..64
    pub ribbon_filter_size: u32,      // 64..68
    pub math_mask: u64,               // 68..76
    pub index_bitmask: u64,           // 76..84
    pub index_table_offset: u64,      // 84..92
    pub body_offset: u64,             // 92..100
    pub creator_hash: [u8; 20],       // 100..120 (Hardware ID Binding)
    pub coincidence_table_offset: u64, // 120..128 
}

impl PonHeaderV8 {
    pub fn new(hw_id: [u8; 32], l3_size: u32, is_self_bound: bool) -> Self {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let uptime = System::uptime();
        
        let mut mode = 0x07; 
        let mut creator = [0u8; 20];

        if is_self_bound {
            mode |= 1 << 3; 
            creator.copy_from_slice(&hw_id[..20]);
        } else {
          
            creator = [0u8; 20]; 
        }

        Self {
            magic: *b"PON8",
            version: 0x0A, // Version 10 (V8.4 internal)
            data_model: 0x02,
            mode_flag: mode,
            security_type: 0x02,
            arch_tag: *b"X866",
            created_at: now,
            license_issue_date: now, // fecha de creacion
            uptime_at_creation: uptime,
            shard_size_bytes: l3_size,
            bucket_count: 0,
            total_rows: 0,
            master_index_offset: 0,
            ribbon_filter_offset: 0,
            ribbon_filter_size: 0,
            math_mask: 0,
            index_bitmask: 0,
            index_table_offset: 128,
            body_offset: 0,
            creator_hash: creator,
            coincidence_table_offset: 0,
        }
    }

    pub fn as_bytes(&self) -> [u8; 128] {
        let mut bytes = [0u8; 128];
        bytes[0..4].copy_from_slice(&self.magic);
        bytes[4] = self.version;
        bytes[5] = self.data_model;
        bytes[6] = self.mode_flag;
        bytes[7] = self.security_type;
        bytes[8..12].copy_from_slice(&self.arch_tag);
        bytes[12..20].copy_from_slice(&self.created_at.to_le_bytes());
        bytes[20..28].copy_from_slice(&self.license_issue_date.to_le_bytes());
        bytes[28..36].copy_from_slice(&self.uptime_at_creation.to_le_bytes());
        bytes[36..40].copy_from_slice(&self.shard_size_bytes.to_le_bytes());
        bytes[40..44].copy_from_slice(&self.bucket_count.to_le_bytes());
        bytes[44..48].copy_from_slice(&self.total_rows.to_le_bytes());
        bytes[48..56].copy_from_slice(&self.master_index_offset.to_le_bytes());
        bytes[56..64].copy_from_slice(&self.ribbon_filter_offset.to_le_bytes());
        bytes[64..68].copy_from_slice(&self.ribbon_filter_size.to_le_bytes());
        bytes[68..76].copy_from_slice(&self.math_mask.to_le_bytes());
        bytes[76..84].copy_from_slice(&self.index_bitmask.to_le_bytes());
        bytes[84..92].copy_from_slice(&self.index_table_offset.to_le_bytes());
        bytes[92..100].copy_from_slice(&self.body_offset.to_le_bytes());
        bytes[100..120].copy_from_slice(&self.creator_hash);
        bytes[120..128].copy_from_slice(&self.coincidence_table_offset.to_le_bytes());
        bytes
    }

    pub fn from_bytes(bytes: [u8; 128]) -> Self {
        Self {
            magic: [bytes[0], bytes[1], bytes[2], bytes[3]],
            version: bytes[4],
            data_model: bytes[5],
            mode_flag: bytes[6],
            security_type: bytes[7],
            arch_tag: [bytes[8], bytes[9], bytes[10], bytes[11]],
            created_at: u64::from_le_bytes(bytes[12..20].try_into().unwrap()),
            license_issue_date: u64::from_le_bytes(bytes[20..28].try_into().unwrap()),
            uptime_at_creation: u64::from_le_bytes(bytes[28..36].try_into().unwrap()),
            shard_size_bytes: u32::from_le_bytes(bytes[36..40].try_into().unwrap()),
            bucket_count: u32::from_le_bytes(bytes[40..44].try_into().unwrap()),
            total_rows: u32::from_le_bytes(bytes[44..48].try_into().unwrap()),
            master_index_offset: u64::from_le_bytes(bytes[48..56].try_into().unwrap()),
            ribbon_filter_offset: u64::from_le_bytes(bytes[56..64].try_into().unwrap()),
            ribbon_filter_size: u32::from_le_bytes(bytes[64..68].try_into().unwrap()),
            math_mask: u64::from_le_bytes(bytes[68..76].try_into().unwrap()),
            index_bitmask: u64::from_le_bytes(bytes[76..84].try_into().unwrap()),
            index_table_offset: u64::from_le_bytes(bytes[84..92].try_into().unwrap()),
            body_offset: u64::from_le_bytes(bytes[92..100].try_into().unwrap()),
            creator_hash: bytes[100..120].try_into().unwrap(),
            coincidence_table_offset: u64::from_le_bytes(bytes[120..128].try_into().unwrap()),
        }
    }

    pub fn validate<R: Read>(mut reader: R, current_hw_id: [u8; 32]) -> std::io::Result<Self> {
        let mut buffer = [0u8; 128];
        reader.read_exact(&mut buffer)?;
        let header = Self::from_bytes(buffer);

        if &header.magic != b"PON8" {
            return Err(Error::new(ErrorKind::InvalidData, "Header PON corrupto o incompatible."));
        }

        // verificar hardware 
        let is_locked = (header.mode_flag & (1 << 3)) != 0;
        if is_locked && header.creator_hash != current_hw_id[..20] {
            return Err(Error::new(ErrorKind::PermissionDenied, "Hardware ID mismatch."));
        }

        // Anti-Tamper
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let current_uptime = System::uptime();
        let elapsed_sys = now.saturating_sub(header.created_at);
        let elapsed_hw = current_uptime.saturating_sub(header.uptime_at_creation);
        
        if elapsed_hw > (elapsed_sys + 300) { 
            return Err(Error::new(ErrorKind::PermissionDenied, "Manipulación de reloj detectada (Anti-Tamper)."));
        }

        Ok(header)
    }
}
