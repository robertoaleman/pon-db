// SPDX-License-Identifier: AGPL-3.0-only
// PON-DB Engine: a database engine encapsulated in a single, portable, encrypted binary format
// Copyright (C) 2026 Roberto C. Aleman F.
// https://github.com/robertoaleman/pon-db
use crate::block::write_block;
use crate::index_manager::{index_key, lookup_field, ShadowIndex, COLLISION_FLAG};
use crate::ingest::{HashingReader, IngestStats};
use crate::scanner::{ObjectScanner, MAX_RECORD_LEN};
use crate::v9::header::{HeaderV9, CAPS_REV4, HEADER9_SIZE, MAX_META_LEN, PAGE_DATA_LEN, PAGE_SIZE};
use crate::v9::pages::{bucket_count_for, place_pages};
use crate::v9::keys::{BlockCipher9, IndexHasher, Keys9, FILE_ID_LEN};
use rand::{thread_rng, RngCore};
use serde_json::Value;
use std::fs::{File, OpenOptions};
use std::io::{self, BufReader, BufWriter, Seek, SeekFrom, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

fn invalid(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, msg.to_string())
}

/// Valida la lista de campos a indexar: no vacía, sin nombres vacíos ni con NUL; se quitan los repetidos
/// conservando el orden.
fn clean_fields(fields: &[String]) -> io::Result<Vec<String>> {
    if fields.is_empty() {
        return Err(invalid("at least one field must be indexed"));
    }
    let mut out: Vec<String> = Vec::with_capacity(fields.len());
    for f in fields {
        if f.is_empty() || f.contains('\0') {
            return Err(invalid("indexed field names must be non-empty and must not contain NUL"));
        }
        if !out.contains(f) {
            out.push(f.clone());
        }
    }
    Ok(out)
}

/// Cifra y escribe registros; lleva la cuenta del offset de cada bloque (parte del AAD)
/// y de las entradas del índice (una por registro y campo indexado presente).
struct BodyWriter {
    cipher: BlockCipher9,
    hasher: IndexHasher,
    fields: Vec<String>,
    index: ShadowIndex,
    next_offset: u64,
    record_count: u32,
    unindexed: u64,
}

impl BodyWriter {
    fn ingest<W: Write>(&mut self, json: &[u8], out: &mut W) -> io::Result<()> {
        let doc: Value = serde_json::from_slice(json)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("invalid JSON: {}", e)))?;

        // Los hashes se calculan antes de escribir nada: si algo falla, el estado no cambia.
        let mut hashes: Vec<u64> = Vec::with_capacity(self.fields.len());
        for field in &self.fields {
            if let Some(v) = lookup_field(&doc, field) {
                hashes.push(self.hasher.hash(field, index_key(v).as_bytes())?);
            }
        }
        hashes.sort_unstable();
        hashes.dedup();

        let count = self
            .record_count
            .checked_add(1)
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "record count exceeds u32::MAX"))?;

        let offset = self.next_offset;
        let (ciphertext, tag) = self.cipher.seal(json, offset)?;
        let written = write_block(out, &ciphertext, &tag)?;

        self.next_offset += written;
        self.record_count = count;
        if hashes.is_empty() {
            self.unindexed += 1;
        }
        for h in hashes {
            self.index.add_hash(h, offset);
        }
        Ok(())
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Ingiere un archivo JSON y escribe un `.pon` en formato V9 (revisión 4).
///
/// Layout: `[cabecera][metadatos cifrados][bloques][coincidencias + etiqueta][páginas del índice]
/// [tabla de shards][pie HMAC]`. La cabecera se escribe al final: un proceso interrumpido deja una
/// cabecera en ceros que se rechaza. Los nombres de los campos indexados solo aparecen en el bloque
/// de metadatos, cifrado y autenticado.
pub fn ingest_file9(
    input: &Path,
    output: &Path,
    fields: &[String],
    master_key: &[u8; 32],
) -> io::Result<IngestStats> {
    let fields = clean_fields(fields)?;

    let mut file_id = [0u8; FILE_ID_LEN];
    thread_rng().fill_bytes(&mut file_id);
    let keys = Keys9::derive(master_key, &file_id)?;

    let out_file = OpenOptions::new().write(true).create(true).truncate(true).open(output)?;
    let mut w = BufWriter::with_capacity(1 << 20, out_file);
    w.write_all(&[0u8; HEADER9_SIZE])?;

    // --- metadatos cifrados, justo tras la cabecera ---
    let metadata = serde_json::to_vec(&serde_json::json!({ "indexed_fields": fields }))
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
    let (meta_ct, meta_tag) = keys
        .metadata_cipher(&file_id)
        .seal(&metadata, HEADER9_SIZE as u64)?;
    let meta_len = write_block(&mut w, &meta_ct, &meta_tag)?;
    if meta_len > MAX_META_LEN as u64 {
        return Err(invalid("the list of indexed fields is too long"));
    }
    let body_start = HEADER9_SIZE as u64 + meta_len;

    // --- registros ---
    let reader = BufReader::with_capacity(1 << 20, HashingReader::new(File::open(input)?));
    let mut scanner = ObjectScanner::new(reader, MAX_RECORD_LEN);
    let mut body = BodyWriter {
        cipher: keys.block_cipher(&file_id),
        hasher: keys.index_hasher(),
        fields,
        index: ShadowIndex::new(),
        next_offset: body_start,
        record_count: 0,
        unindexed: 0,
    };

    let mut n: u64 = 0;
    while let Some(obj) = scanner.next_object()? {
        n += 1;
        let obj = Zeroizing::new(obj);
        body.ingest(&obj, &mut w)
            .map_err(|e| io::Error::new(e.kind(), format!("record #{}: {}", n, e)))?;
    }
    if body.record_count == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "no JSON objects found in the input file",
        ));
    }
    let original_sha256 = scanner.into_inner().into_inner().finish();

    // --- tablas de coincidencias: cuenta | offsets | etiqueta(16) ---
    let coincidence_start = body.next_offset;
    let mut pos = coincidence_start;
    let mut flat: Vec<(u64, u64)> = Vec::with_capacity(body.index.len());
    for (hash, offsets) in body.index.entries() {
        if offsets.len() > 1 {
            let count = u32::try_from(offsets.len()).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "too many records share one index key")
            })?;
            let mut table: Vec<u8> = Vec::with_capacity(4 + 8 * offsets.len());
            table.extend_from_slice(&count.to_le_bytes());
            for off in offsets {
                table.extend_from_slice(&off.to_le_bytes());
            }
            let tag = keys.coincidence_tag(&file_id, pos, &table)?;
            w.write_all(&table)?;
            w.write_all(&tag)?;
            flat.push((*hash, pos | COLLISION_FLAG));
            pos += table.len() as u64 + tag.len() as u64;
        } else {
            flat.push((*hash, offsets[0]));
        }
    }

    // --- índice: tabla hash estática por páginas de 4 KiB (255 entradas + etiqueta GMAC) ---
    // `flat` está ordenada por hash, y la página natural es monótona en el hash: las páginas se
    // generan en orden y se escriben a medida que se completan.
    let index_start = pos;
    let (bucket_count, page_count, max_probe) = if flat.is_empty() {
        (0usize, 0usize, 0usize)
    } else {
        let buckets = bucket_count_for(flat.len());
        let page_mac = keys.page_mac();
        let mut page_buf = [0u8; PAGE_SIZE];
        let stats = place_pages(&flat, buckets, |page_no, entries| {
            page_buf.fill(0);
            for (slot, (hash, ptr)) in entries.iter().enumerate() {
                let o = slot * 16;
                page_buf[o..o + 8].copy_from_slice(&hash.to_le_bytes());
                page_buf[o + 8..o + 16].copy_from_slice(&ptr.to_le_bytes());
            }
            let tag = page_mac.tag(page_no as u64, &page_buf[..PAGE_DATA_LEN])?;
            page_buf[PAGE_DATA_LEN..].copy_from_slice(&tag);
            w.write_all(&page_buf)
        })?;
        (buckets, stats.page_count, stats.max_probe)
    };

    // --- cabecera y pie ---
    let too_big = || io::Error::new(io::ErrorKind::InvalidData, "the index is too large for the format");
    let header = HeaderV9 {
        file_id,
        created_at: now_secs(),
        total_rows: body.record_count,
        bucket_count: u32::try_from(bucket_count).map_err(|_| too_big())?,
        body_offset: body_start,
        coincidence_table_offset: coincidence_start,
        index_table_offset: index_start,
        index_entry_count: flat.len() as u64,
        meta_len: meta_len as u32,
        capabilities: CAPS_REV4,
        page_count: u32::try_from(page_count).map_err(|_| too_big())?,
        max_probe: u32::try_from(max_probe).map_err(|_| too_big())?,
    };
    let header_bytes = header.as_bytes();
    let footer = keys.footer_mac(&header_bytes)?;
    w.write_all(&footer)?;

    w.flush()?;
    let mut file = w.into_inner().map_err(|e| e.into_error())?;
    file.seek(SeekFrom::Start(0))?;
    file.write_all(&header_bytes)?;
    file.sync_all()?;

    Ok(IngestStats {
        rows: body.record_count,
        unindexed: body.unindexed,
        index_entries: body.index.len(),
        original_sha256,
    })
}
