// SPDX-License-Identifier: AGPL-3.0-only
// PON-DB Engine database engine encapsulated in a single, portable and strictly encrypted binary format
// Copyright (C) 2026 Roberto C. Aleman F.
// https://github.com/robertoaleman/pon-db
use std::collections::BTreeMap;
use std::io::{Write, Seek};

pub struct ShadowIndex {
    pub shards: BTreeMap<u64, u64>, 
    pub collision_map: std::collections::HashMap<u64, Vec<u64>>,
}

impl ShadowIndex {
    pub fn new(_fields: Vec<String>) -> Self {
        Self {
            shards: BTreeMap::new(),
            collision_map: std::collections::HashMap::new(),
        }
    }

    pub fn add_entry(&mut self, _field: &str, normalized_val: &[u8], offset: u64) {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        use std::hash::Hasher;
        hasher.write(normalized_val);
        let hash = hasher.finish();
        
        self.collision_map.entry(hash).or_insert_with(Vec::new).push(offset);
    }

    pub fn finalize_v8_5<W: Write + Seek>(&mut self, writer: &mut W) -> std::io::Result<u64> {
        let coincidence_start = writer.stream_position()?;
        
        // 
        // 
        for (hash, offsets) in &mut self.collision_map {
            if offsets.len() > 1 {
                Self::bitonic_sort_offsets(offsets);
                let table_pos = writer.stream_position()?;
                
                writer.write_all(&(offsets.len() as u32).to_le_bytes())?;
                for &off in offsets.iter() {
                    writer.write_all(&off.to_le_bytes())?;
                }
                
                let flagged_offset = table_pos | (1 << 63);
                self.shards.insert(*hash, flagged_offset);
            } else {
                self.shards.insert(*hash, offsets[0]);
            }
        }
        
        Ok(coincidence_start)
    }

    fn bitonic_sort_offsets(data: &mut Vec<u64>) {
        let n = data.len();
        if !n.is_power_of_two() {
            data.sort_unstable(); 
            return;
        }

        let mut j = 2;
        while j <= n {
            let mut k = j >> 1;
            while k > 0 {
                for i in 0..n {
                    let ij = i ^ k;
                    if ij > i {
                        if (i & j) == 0 && data[i] > data[ij] { data.swap(i, ij); }
                        if (i & j) != 0 && data[i] < data[ij] { data.swap(i, ij); }
                    }
                }
                k >>= 1;
            }
            j <<= 1;
        }
    }

    pub fn get_sharded_buckets(&self, shard_size_bytes: usize) -> Vec<Vec<u8>> {
        let mut all_buckets = Vec::new();
        let mut current_bucket = Vec::with_capacity(shard_size_bytes);
        
        //  
        for (hash, offset) in &self.shards {
            if current_bucket.len() + 16 > shard_size_bytes {
                all_buckets.push(current_bucket);
                current_bucket = Vec::with_capacity(shard_size_bytes);
            }
            current_bucket.extend_from_slice(&hash.to_le_bytes());
            current_bucket.extend_from_slice(&offset.to_le_bytes());
        }
        
        if !current_bucket.is_empty() {
            all_buckets.push(current_bucket);
        }
        all_buckets
    }
}
