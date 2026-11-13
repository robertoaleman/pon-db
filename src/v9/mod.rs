// SPDX-License-Identifier: AGPL-3.0-only
// PON-DB Engine: a database engine encapsulated in a single, portable, encrypted binary format
// Copyright (C) 2026 Roberto C. Aleman F.
// https://github.com/robertoaleman/pon-db
//
// Formato V9: AES-256-GCM con AAD (file_id + offset), claves por archivo derivadas con HKDF,
// índice con clave en una tabla hash por páginas autenticadas, metadatos cifrados, y cabecera autenticada
// con HMAC-SHA256.
pub mod header;
pub mod keys;
pub mod pages;
pub mod reader;
pub mod writer;

#[cfg(test)]
mod tests {
    use super::header::{HeaderV9, PAGE_DATA_LEN, PAGE_SIZE};
    use super::pages::bucket_count_for;
    use super::reader::Reader9;
    use super::writer::ingest_file9;
    use crate::query_engine::{expr_matches_full, parse_expression, record_if_matches};
    use crate::testutil::TempDir;
    use serde_json::{json, Value};
    use sha2::{Digest, Sha256};
    use std::collections::hash_map::DefaultHasher;
    use std::collections::HashSet;
    use std::fs;
    use std::hash::Hasher;
    use std::io;
    use std::path::{Path, PathBuf};

    const MASTER: [u8; 32] = [7u8; 32];

    fn names(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    fn dataset(n: usize) -> Vec<Value> {
        (0..n)
            .map(|i| {
                json!({
                    "id": i,
                    "sku": format!("S{}", i % 10),
                    "price": i * 10,
                    "name": format!("Item, {}", i)
                })
            })
            .collect()
    }

    fn to_text(rows: &[Value]) -> String {
        rows.iter().map(|r| r.to_string()).collect::<Vec<_>>().join("\n")
    }

    fn build_text_multi(dir: &TempDir, name: &str, text: &str, fields: &[&str]) -> PathBuf {
        let input = dir.join(&format!("{}.json", name));
        fs::write(&input, text).unwrap();
        let output = dir.join(&format!("{}.pon", name));
        ingest_file9(&input, &output, &names(fields), &MASTER).unwrap();
        output
    }

    fn build_multi(dir: &TempDir, name: &str, rows: &[Value], fields: &[&str]) -> PathBuf {
        build_text_multi(dir, name, &to_text(rows), fields)
    }

    fn build(dir: &TempDir, name: &str, rows: &[Value], field: &str) -> PathBuf {
        build_multi(dir, name, rows, &[field])
    }

    fn build_text(dir: &TempDir, name: &str, text: &str, field: &str) -> PathBuf {
        build_text_multi(dir, name, text, &[field])
    }

    fn open(path: &Path) -> Reader9 {
        Reader9::open(path, &MASTER).unwrap()
    }

    fn header_of(path: &Path) -> HeaderV9 {
        *open(path).header()
    }

    /// Offset del primer registro (tras la cabecera y el bloque de metadatos).
    fn body_of(path: &Path) -> usize {
        header_of(path).body_offset as usize
    }

    fn q(r: &Reader9, criterion: &str) -> Vec<Value> {
        r.query(criterion)
            .unwrap()
            .iter()
            .map(|s| serde_json::from_str(s).unwrap())
            .collect()
    }

    fn export(r: &Reader9) -> io::Result<Vec<u8>> {
        let mut buf: Vec<u8> = Vec::new();
        r.export_to(&mut buf)?;
        Ok(buf)
    }

    /// Registros de igual longitud: se pueden intercambiar bloques sin cambiar el tamaño del archivo.
    fn equal_size_rows() -> Vec<Value> {
        (0..10).map(|i| json!({"id": 1000 + i, "tag": "abcd"})).collect()
    }

    fn mutate(path: &Path, f: impl FnOnce(&mut Vec<u8>)) {
        let mut bytes = fs::read(path).unwrap();
        f(&mut bytes);
        fs::write(path, &bytes).unwrap();
    }

    /// Hashes de todas las entradas del índice (páginas de la tabla hash, sin los huecos vacíos).
    fn index_hashes(path: &Path) -> HashSet<u64> {
        let h = header_of(path);
        let bytes = fs::read(path).unwrap();
        let mut out = HashSet::new();
        for page in 0..h.page_count as usize {
            let start = h.index_table_offset as usize + page * PAGE_SIZE;
            for entry in bytes[start..start + PAGE_DATA_LEN].chunks_exact(16) {
                let mut hash = [0u8; 8];
                hash.copy_from_slice(&entry[..8]);
                let mut ptr = [0u8; 8];
                ptr.copy_from_slice(&entry[8..]);
                if u64::from_le_bytes(ptr) != 0 {
                    out.insert(u64::from_le_bytes(hash));
                }
            }
        }
        out
    }

    // ---------------------------------------------------------------- funcionamiento normal

    #[test]
    fn export_reproduces_the_input_exactly() {
        let dir = TempDir::new("v9_roundtrip");
        let rows = dataset(50);
        let out = build(&dir, "d", &rows, "sku");
        let r = open(&out);

        let mut buf: Vec<u8> = Vec::new();
        let summary = r.export_to(&mut buf).unwrap();
        assert_eq!(summary.rows, 50);
        let exported: Vec<Value> = serde_json::from_slice(&buf).expect("export must be valid JSON");
        assert_eq!(exported, rows);
    }

    #[test]
    fn indexed_equality_returns_every_duplicate_and_nothing_else() {
        let dir = TempDir::new("v9_indexed");
        let out = build(&dir, "d", &dataset(50), "sku");
        let r = open(&out);

        let hits = q(&r, "sku=S3");
        assert_eq!(hits.len(), 5);
        assert!(hits.iter().all(|row| row["sku"] == "S3"));
        assert!(q(&r, "sku=nope").is_empty());
        assert_eq!(q(&r, "sku='S3'").len(), 5);
    }

    #[test]
    fn unique_lookup_and_numeric_spelling() {
        let dir = TempDir::new("v9_unique");
        let out = build(&dir, "d", &dataset(50), "id");
        let r = open(&out);

        let hits = q(&r, "id=7");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0]["id"], 7);
        assert_eq!(q(&r, "id=7.0").len(), 1);
        assert!(q(&r, "id=999").is_empty());
    }

    #[test]
    fn non_indexed_fields_and_ranges_use_a_scan() {
        let dir = TempDir::new("v9_scan");
        let out = build(&dir, "d", &dataset(50), "id");
        let r = open(&out);

        let hits = q(&r, "name=\"Item, 7\"");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0]["id"], 7);

        assert_eq!(q(&r, "price>=100").len(), 40);
        assert_eq!(q(&r, "price>100").len(), 39);
        assert_eq!(q(&r, "price<=100").len(), 11);
        assert_eq!(q(&r, "price<100").len(), 10);
        assert_eq!(q(&r, "price!=100").len(), 49);
    }

    #[test]
    fn a_large_index_resolves_every_key_within_the_probe_bound() {
        let dir = TempDir::new("v9_bigindex");
        let rows: Vec<Value> = (0..10_000).map(|i| json!({"id": i, "v": "x"})).collect();
        let out = build(&dir, "d", &rows, "id");
        let r = open(&out);
        let h = *r.header();

        assert_eq!(h.index_entry_count, 10_000);
        assert_eq!(h.bucket_count as usize, bucket_count_for(10_000));
        assert!(h.page_count >= h.bucket_count);
        assert!(h.max_probe >= 1 && h.max_probe <= 3, "max_probe = {}", h.max_probe);

        for id in [0u64, 1, 4095, 4096, 4097, 8191, 8192, 9999] {
            let hits = q(&r, &format!("id={}", id));
            assert_eq!(hits.len(), 1, "id={}", id);
            assert_eq!(hits[0]["id"], id);
        }
        for id in (0..10_000u64).step_by(7) {
            assert_eq!(ids(&r, &format!("id={}", id)), vec![id], "id={}", id);
        }
        assert!(q(&r, "id=10000").is_empty());
        assert!(q(&r, "id=abc").is_empty());

        // la caché de páginas guarda lo ya autenticado: nunca se lee una página más de una vez
        let (hits, misses) = r.page_cache_stats();
        assert!(misses <= h.page_count as u64, "{} misses for {} pages", misses, h.page_count);
        assert!(hits > misses);
    }

    #[test]
    fn opening_reads_no_index_page_and_a_lookup_reads_at_most_max_probe() {
        let dir = TempDir::new("v9_probe");
        let rows: Vec<Value> = (0..20_000).map(|i| json!({"id": i})).collect();
        let out = build(&dir, "d", &rows, "id");
        let r = open(&out);
        assert_eq!(r.page_cache_stats(), (0, 0), "open must not touch the index");

        let max_probe = r.header().max_probe as u64;
        for id in (0..20_000u64).step_by(97) {
            let (h0, m0) = r.page_cache_stats();
            assert_eq!(ids(&r, &format!("id={}", id)), vec![id]);
            let (h1, m1) = r.page_cache_stats();
            // dos ortografías candidatas del valor ("7" y "7.0"), cada una como mucho max_probe páginas
            assert!((h1 - h0) + (m1 - m0) <= 2 * max_probe, "id={}", id);
        }
    }

    #[test]
    fn records_without_the_indexed_field_are_counted() {
        let dir = TempDir::new("v9_unindexed");
        let input = dir.join("d.json");
        fs::write(&input, "{\"id\":1}\n{\"other\":2}\n{\"id\":3}").unwrap();
        let output = dir.join("d.pon");
        let stats = ingest_file9(&input, &output, &names(&["id"]), &MASTER).unwrap();
        assert_eq!(stats.rows, 3);
        assert_eq!(stats.unindexed, 1);
        assert_eq!(stats.index_entries, 2);
        assert_eq!(q(&open(&output), "other=2").len(), 1);
    }

    #[test]
    fn two_ingests_of_the_same_data_produce_different_files() {
        let dir = TempDir::new("v9_unique_files");
        let rows = dataset(5);
        let a = build(&dir, "a", &rows, "id");
        let b = build(&dir, "b", &rows, "id");
        assert_ne!(header_of(&a).file_id, header_of(&b).file_id);
        assert_ne!(fs::read(&a).unwrap(), fs::read(&b).unwrap());
    }

    #[test]
    fn stats_report_the_real_input_hash_and_counts() {
        let dir = TempDir::new("v9_stats");
        let mut rows = dataset(3);
        rows.push(json!({"other": 1}));
        let text = to_text(&rows);
        let input = dir.join("d.json");
        fs::write(&input, &text).unwrap();
        let output = dir.join("d.pon");
        let stats = ingest_file9(&input, &output, &names(&["id"]), &MASTER).unwrap();

        assert_eq!(stats.rows, 4);
        assert_eq!(stats.unindexed, 1);
        assert_eq!(stats.index_entries, 3);
        let expected: [u8; 32] = Sha256::digest(text.as_bytes()).into();
        assert_eq!(stats.original_sha256, expected);
        assert_eq!(crate::ingest::sha256_file(&input).unwrap(), expected);
    }

    #[test]
    fn pretty_printed_array_input_is_supported() {
        let dir = TempDir::new("v9_pretty");
        let rows = dataset(12);
        let out = build_text(&dir, "d", &serde_json::to_string_pretty(&rows).unwrap(), "sku");
        let r = open(&out);
        assert_eq!(q(&r, "sku=S1").len(), 2);
        let exported: Vec<Value> = serde_json::from_slice(&export(&r).unwrap()).unwrap();
        assert_eq!(exported, rows);
    }

    #[test]
    fn bad_inputs_fail_cleanly() {
        let dir = TempDir::new("v9_badinput");
        let output = dir.join("out.pon");
        let id = names(&["id"]);

        let empty = dir.join("empty.json");
        fs::write(&empty, "  [ ]  ").unwrap();
        assert!(ingest_file9(&empty, &output, &id, &MASTER).is_err());

        let broken = dir.join("broken.json");
        fs::write(&broken, "{\"id\":1}\n{bad json}").unwrap();
        let err = ingest_file9(&broken, &output, &id, &MASTER).err().expect("must fail");
        assert!(err.to_string().contains("record #2"));

        let unterminated = dir.join("unterminated.json");
        fs::write(&unterminated, "{\"id\":1}\n{\"id\":").unwrap();
        assert!(ingest_file9(&unterminated, &output, &id, &MASTER).is_err());

        assert!(ingest_file9(&dir.join("missing.json"), &output, &id, &MASTER).is_err());
    }

    #[test]
    fn the_list_of_indexed_fields_is_validated_and_deduplicated() {
        let dir = TempDir::new("v9_fieldlist");
        let input = dir.join("d.json");
        fs::write(&input, "{\"id\":1}").unwrap();
        let output = dir.join("d.pon");

        assert!(ingest_file9(&input, &output, &[], &MASTER).is_err());
        assert!(ingest_file9(&input, &output, &names(&[""]), &MASTER).is_err());
        assert!(ingest_file9(&input, &output, &names(&["a\0b"]), &MASTER).is_err());

        ingest_file9(&input, &output, &names(&["id", "id"]), &MASTER).unwrap();
        assert_eq!(open(&output).indexed_fields(), &["id".to_string()][..]);
    }

    #[test]
    fn blocks_store_no_nonce_and_the_header_declares_its_capabilities() {
        let dir = TempDir::new("v9_noncefree");
        let rows: Vec<Value> = (0..10).map(|i| json!({"id": i})).collect();
        let out = build(&dir, "d", &rows, "id");
        let h = header_of(&out);

        // cada bloque ocupa exactamente: 4 (longitud) + texto + 16 (tag); ya no hay 12 bytes de nonce
        let expected: u64 = rows.iter().map(|r| r.to_string().len() as u64 + 20).sum();
        assert_eq!(h.coincidence_table_offset - h.body_offset, expected);
        assert_eq!(h.capabilities, super::header::CAPS_REV4);
    }

    #[test]
    fn a_v8_file_is_rejected_with_a_clear_message() {
        let dir = TempDir::new("v9_v8");
        let p = dir.join("old.pon");
        let mut bytes = vec![0u8; 400];
        bytes[..4].copy_from_slice(b"PON8");
        fs::write(&p, &bytes).unwrap();
        let err = Reader9::open(&p, &MASTER).err().expect("V8 files are not supported");
        assert!(err.to_string().contains("no longer supported"), "{}", err);
    }

    #[test]
    fn a_file_from_the_previous_revision_is_rejected_with_a_clear_message() {
        let dir = TempDir::new("v9_rev");
        let out = build(&dir, "d", &dataset(5), "id");
        mutate(&out, |b| b[4] = 1);
        let err = Reader9::open(&out, &MASTER).err().expect("revision 1 is not supported");
        assert!(err.to_string().contains("revision"), "{}", err);
    }

    // ---------------------------------------------------------------- índice con clave y varios campos

    #[test]
    fn several_fields_can_be_indexed_and_each_uses_the_index() {
        let dir = TempDir::new("v9_multi");
        let out = build_multi(&dir, "d", &dataset(50), &["sku", "id"]);
        let r = open(&out);

        assert_eq!(r.indexed_fields(), &["sku".to_string(), "id".to_string()][..]);
        assert_eq!(r.header().index_entry_count, 60, "10 distinct skus + 50 distinct ids");

        assert_eq!(q(&r, "sku=S3").len(), 5);
        let one = q(&r, "id=7");
        assert_eq!(one.len(), 1);
        assert_eq!(one[0]["sku"], "S7");
        assert!(q(&r, "sku=nope").is_empty());
        assert_eq!(q(&r, "price=70").len(), 1, "a field that is not indexed is still searchable by scan");
    }

    #[test]
    fn the_same_value_in_two_fields_does_not_collide() {
        let dir = TempDir::new("v9_fieldsep");
        let text = "{\"id\":1,\"a\":\"x\",\"b\":\"y\"}\n{\"id\":2,\"a\":\"y\",\"b\":\"x\"}";
        let out = build_text_multi(&dir, "d", text, &["a", "b"]);
        let r = open(&out);

        let ids = |criterion: &str| -> Vec<u64> {
            q(&r, criterion).iter().map(|row| row["id"].as_u64().unwrap_or(0)).collect()
        };
        assert_eq!(ids("a=x"), vec![1]);
        assert_eq!(ids("b=x"), vec![2]);
        assert_eq!(ids("a=y"), vec![2]);
        assert_eq!(ids("b=y"), vec![1]);
    }

    #[test]
    fn dotted_paths_can_be_indexed() {
        let dir = TempDir::new("v9_dotted");
        let text = "{\"id\":1,\"address\":{\"city\":\"Mérida\"}}\n{\"id\":2,\"address\":{\"city\":\"Quito\"}}\n{\"id\":3,\"address\":{\"city\":\"Mérida\"}}";
        let out = build_text_multi(&dir, "d", text, &["address.city"]);
        let r = open(&out);

        assert_eq!(r.header().index_entry_count, 2);
        let merida: Vec<u64> = q(&r, "address.city=Mérida").iter().map(|x| x["id"].as_u64().unwrap_or(0)).collect();
        assert_eq!(merida, vec![1, 3]);
        assert_eq!(q(&r, "address.city=Quito").len(), 1);
    }

    #[test]
    fn the_index_cannot_be_attacked_with_a_dictionary_without_the_key() {
        let dir = TempDir::new("v9_keyed");
        let rows = dataset(50);
        let a = build(&dir, "a", &rows, "id");
        let b = build(&dir, "b", &rows, "id");

        let hashes_a = index_hashes(&a);
        assert_eq!(hashes_a.len(), 50);

        // El hash sin clave de las alphas anteriores (SipHash-1-3, claves 0): ningún valor se reconoce.
        for i in 0..50 {
            let mut h = DefaultHasher::new();
            h.write(i.to_string().as_bytes());
            assert!(!hashes_a.contains(&h.finish()), "value {} is recoverable without the key", i);
        }
        // Mismos datos y misma clave maestra, pero otro file_id: los índices no se parecen en nada.
        assert!(hashes_a.is_disjoint(&index_hashes(&b)));
    }

    #[test]
    fn indexed_field_names_do_not_appear_in_the_file() {
        let dir = TempDir::new("v9_hidden");
        let rows: Vec<Value> = (0..20).map(|i| json!({"tracking_code": format!("ZZ-{}", i), "n": i})).collect();
        let out = build(&dir, "d", &rows, "tracking_code");

        let bytes = fs::read(&out).unwrap();
        assert!(!bytes.windows(13).any(|w| w == b"tracking_code"));
        assert_eq!(q(&open(&out), "tracking_code=ZZ-7").len(), 1);
    }

    #[test]
    fn a_tampered_metadata_block_is_detected_when_opening() {
        let dir = TempDir::new("v9_meta_tamper");
        let out = build(&dir, "d", &dataset(5), "id");
        mutate(&out, |b| b[128 + 4] ^= 1); // primer byte del ciphertext de los metadatos
        let err = Reader9::open(&out, &MASTER).err().expect("tampered metadata must fail");
        assert!(err.to_string().contains("tampered"), "{}", err);
    }

    #[test]
    fn metadata_from_another_file_is_rejected() {
        let dir = TempDir::new("v9_meta_splice");
        let rows = dataset(5);
        let a = build(&dir, "a", &rows, "id");
        let b = build(&dir, "b", &rows, "id");
        let meta_len = header_of(&a).meta_len as usize;

        let donor = fs::read(&b).unwrap();
        mutate(&a, |bytes| bytes[128..128 + meta_len].copy_from_slice(&donor[128..128 + meta_len]));
        let err = Reader9::open(&a, &MASTER).err().expect("foreign metadata must fail");
        assert!(err.to_string().contains("tampered"), "{}", err);
    }

    // ---------------------------------------------------------------- lo que V8 no detectaba

    #[test]
    fn wrong_master_key_fails_at_open() {
        let dir = TempDir::new("v9_wrongkey");
        let out = build(&dir, "d", &dataset(5), "id");
        let err = Reader9::open(&out, &[9u8; 32]).err().expect("wrong key must fail at open");
        assert!(err.to_string().contains("authentication"));
    }

    #[test]
    fn a_tampered_block_is_reported_by_scan_and_export() {
        let dir = TempDir::new("v9_tamper");
        let out = build(&dir, "d", &dataset(10), "id");
        let body = body_of(&out);
        mutate(&out, |b| b[body + 4] ^= 0xFF); // primer byte del ciphertext del primer registro

        let r = open(&out); // la estructura no cambió
        assert!(r.query("price>0").is_err());
        assert!(export(&r).is_err());
    }

    #[test]
    fn editing_the_header_is_rejected() {
        let dir = TempDir::new("v9_header");
        let out = build(&dir, "d", &dataset(10), "id");
        mutate(&out, |b| b[32] ^= 1); // total_rows
        assert!(Reader9::open(&out, &MASTER).is_err());
    }

    #[test]
    fn editing_the_footer_is_rejected() {
        let dir = TempDir::new("v9_footer");
        let out = build(&dir, "d", &dataset(10), "id");
        mutate(&out, |b| {
            let last = b.len() - 1;
            b[last] ^= 1;
        });
        assert!(Reader9::open(&out, &MASTER).is_err());
    }

    #[test]
    fn truncated_or_extended_files_are_rejected() {
        let dir = TempDir::new("v9_len");
        let out = build(&dir, "d", &dataset(10), "id");

        mutate(&out, |b| b.truncate(b.len() - 1));
        assert!(Reader9::open(&out, &MASTER).is_err());

        let out2 = build(&dir, "e", &dataset(10), "id");
        mutate(&out2, |b| b.push(0));
        assert!(Reader9::open(&out2, &MASTER).is_err());
    }

    #[test]
    fn a_tampered_index_page_is_detected_on_lookup() {
        let dir = TempDir::new("v9_page");
        let out = build(&dir, "d", &dataset(50), "id");
        let idx = header_of(&out).index_table_offset as usize;
        mutate(&out, |b| b[idx + 3] ^= 1);

        let r = open(&out); // la cabecera no cambió, el pie sigue siendo válido
        assert!(r.query("id=7").is_err());
    }

    /// Resultado de una consulta de igualdad por id: Err si se detecta una alteración.
    fn lookup_id(r: &Reader9, id: u64) -> io::Result<Vec<u64>> {
        Ok(r.query(&format!("id={}", id))?
            .iter()
            .map(|s| serde_json::from_str::<Value>(s).unwrap()["id"].as_u64().unwrap_or(u64::MAX))
            .collect())
    }

    #[test]
    fn swapped_or_emptied_index_pages_are_detected_and_never_hide_a_record() {
        let dir = TempDir::new("v9_pageswap");
        let rows: Vec<Value> = (0..5000).map(|i| json!({"id": i})).collect();
        let swapped = build(&dir, "a", &rows, "id");
        let emptied = build(&dir, "b", &rows, "id");
        let h = header_of(&swapped);
        assert!(h.page_count >= 20);
        let page = |p: usize| h.index_table_offset as usize + p * PAGE_SIZE;

        // dos páginas intercambiadas de sitio
        mutate(&swapped, |b| {
            let a: Vec<u8> = b[page(3)..page(3) + PAGE_SIZE].to_vec();
            let c: Vec<u8> = b[page(4)..page(4) + PAGE_SIZE].to_vec();
            b[page(3)..page(3) + PAGE_SIZE].copy_from_slice(&c);
            b[page(4)..page(4) + PAGE_SIZE].copy_from_slice(&a);
        });
        // una página puesta a cero (con su etiqueta): ocultaría los registros que indexa
        mutate(&emptied, |b| b[page(7)..page(7) + PAGE_SIZE].fill(0));

        for out in [&swapped, &emptied] {
            let r = open(out); // la cabecera no cambió
            let (mut failures, mut served) = (0, 0);
            for id in 0..5000u64 {
                match lookup_id(&r, id) {
                    Err(_) => failures += 1,
                    Ok(found) => {
                        assert_eq!(found, vec![id], "a damaged index must fail, never answer wrongly (id={})", id);
                        served += 1;
                    }
                }
            }
            assert!(failures > 0, "the damaged pages must be noticed");
            assert!(served > 4000, "keys on intact pages keep working ({} served)", served);
        }
    }

    #[test]
    fn a_tampered_coincidence_table_is_detected_on_lookup() {
        let dir = TempDir::new("v9_coin");
        let out = build(&dir, "d", &dataset(50), "sku");
        let coin = header_of(&out).coincidence_table_offset as usize;
        mutate(&out, |b| b[coin + 4] ^= 1); // primer offset de la primera tabla

        let r = open(&out);
        let failures = (0..10).filter(|i| r.query(&format!("sku=S{}", i)).is_err()).count();
        assert_eq!(failures, 1, "exactly the damaged table must fail");
    }

    #[test]
    fn swapping_two_blocks_is_detected() {
        let dir = TempDir::new("v9_swap");
        let out = build(&dir, "d", &equal_size_rows(), "id");
        let h = header_of(&out);
        let body = h.body_offset as usize;
        let block = ((h.coincidence_table_offset - h.body_offset) / 10) as usize;
        assert_eq!(block * 10, (h.coincidence_table_offset - h.body_offset) as usize);

        mutate(&out, |b| {
            let a: Vec<u8> = b[body..body + block].to_vec();
            let c: Vec<u8> = b[body + block..body + 2 * block].to_vec();
            b[body..body + block].copy_from_slice(&c);
            b[body + block..body + 2 * block].copy_from_slice(&a);
        });

        let r = open(&out); // cabecera, índice y pie intactos
        assert!(export(&r).is_err(), "swapped blocks must not decrypt at their new position");
        assert!(r.query("id>0").is_err());
    }

    #[test]
    fn a_block_transplanted_from_another_file_is_rejected() {
        let dir = TempDir::new("v9_splice");
        let rows = equal_size_rows();
        let a = build(&dir, "a", &rows, "id");
        let b = build(&dir, "b", &rows, "id");
        let h = header_of(&a);
        let block = ((h.coincidence_table_offset - h.body_offset) / 10) as usize;

        let donor = fs::read(&b).unwrap();
        let start = h.body_offset as usize + 3 * block;
        mutate(&a, |bytes| bytes[start..start + block].copy_from_slice(&donor[start..start + block]));

        let r = open(&a);
        assert!(export(&r).is_err(), "same key, same position, different file: must be rejected");
    }

    #[test]
    fn deleting_a_block_is_detected() {
        let dir = TempDir::new("v9_delete");
        let out = build(&dir, "d", &equal_size_rows(), "id");
        let h = header_of(&out);
        let body = h.body_offset as usize;
        let block = ((h.coincidence_table_offset - h.body_offset) / 10) as usize;

        mutate(&out, |b| {
            b.drain(body + 4 * block..body + 5 * block);
        });
        assert!(Reader9::open(&out, &MASTER).is_err());
    }

    #[test]
    fn deleting_a_block_and_patching_the_header_is_still_detected() {
        let dir = TempDir::new("v9_delete_patch");
        let out = build(&dir, "d", &equal_size_rows(), "id");
        let h = header_of(&out);
        let body = h.body_offset as usize;
        let block = ((h.coincidence_table_offset - h.body_offset) / 10) as usize;

        // Un atacante sin clave elimina un bloque y ajusta a mano total_rows y todos los offsets.
        mutate(&out, |b| {
            b.drain(body + 4 * block..body + 5 * block);
            let shift = block as u64;
            let fields: [(usize, u64); 3] = [
                (48, h.coincidence_table_offset - shift),
                (56, h.index_table_offset - shift),
                (32, 9),
            ];
            for (at, value) in fields {
                if at == 32 {
                    b[at..at + 4].copy_from_slice(&(value as u32).to_le_bytes());
                } else {
                    b[at..at + 8].copy_from_slice(&value.to_le_bytes());
                }
            }
        });
        let err = Reader9::open(&out, &MASTER).err().expect("must be rejected");
        assert!(err.to_string().contains("authentication"));
    }

    #[test]
    fn numbers_are_found_whatever_their_spelling_in_the_file_or_in_the_query() {
        let dir = TempDir::new("v9_canon");
        let text = [
            r#"{"id":7,"n":7.0}"#,
            r#"{"id":8,"n":7}"#,
            r#"{"id":9,"n":"7"}"#,
            r#"{"id":10,"n":"7.0"}"#,
            r#"{"id":11,"n":1e3}"#,
            r#"{"id":12,"n":1000}"#,
            r#"{"id":13,"n":0.10}"#,
            r#"{"id":14,"n":0.1}"#,
        ]
        .join("\n");
        let out = build_text_multi(&dir, "d", &text, &["n"]);
        let r = open(&out);

        // el número 7, escrito como 7.0 o 7, y la cadena "7"; la cadena "7.0" no es igual a "7"
        assert_eq!(ids(&r, "n=7"), vec![7, 8, 9]);
        // los números y la cadena "7.0"
        assert_eq!(ids(&r, "n=7.0"), vec![7, 8, 10]);
        for spelling in ["1000", "1e3", "1000.00"] {
            assert_eq!(ids(&r, &format!("n={}", spelling)), vec![11, 12], "{}", spelling);
        }
        for spelling in ["0.1", "0.10"] {
            assert_eq!(ids(&r, &format!("n={}", spelling)), vec![13, 14], "{}", spelling);
        }
        // cuatro claves de índice: "7" (los números 7.0 y 7 y la cadena "7"), "7.0" (la cadena), "1000" y "0.1"
        assert_eq!(r.header().index_entry_count, 4);
    }

    #[test]
    fn get_looks_a_key_up_without_the_expression_parser_and_works_on_any_field() {
        let dir = TempDir::new("v9_get");
        let out = build(&dir, "d", &dataset(50), "id");
        let r = open(&out);

        assert_eq!(r.get("id", "7").unwrap().len(), 1);
        assert!(r.get("id", "nope").unwrap().is_empty());
        assert!(r.get("id", "7.5").unwrap().is_empty());
        // un campo sin índice se resuelve igualmente (por recorrido)
        assert_eq!(r.get("price", "70").unwrap().len(), 1);
        // una cadena con operadores o AND dentro no se interpreta como expresión
        assert!(r.get("name", "Item, 7 AND id=3").unwrap().is_empty());
        assert_eq!(r.get("name", "Item, 7").unwrap().len(), 1);
    }

    // ---------------------------------------------------------------- expresiones AND / OR y planificador

    fn ids(r: &Reader9, criterion: &str) -> Vec<u64> {
        q(r, criterion).iter().map(|row| row["id"].as_u64().unwrap_or(u64::MAX)).collect()
    }

    #[test]
    fn and_picks_the_most_selective_indexed_condition_as_the_driver() {
        let dir = TempDir::new("v9_and");
        let out = build_multi(&dir, "d", &dataset(50), &["sku", "id"]);
        let r = open(&out);

        // sku=S3 reúne 5 registros e id=13 solo 1: el conductor es id y basta un candidato
        assert_eq!(r.explain("sku=S3 AND id=13").unwrap(), "index: 1 candidate record(s) out of 50");
        assert_eq!(r.explain("id=13 AND sku=S3").unwrap(), "index: 1 candidate record(s) out of 50");
        assert_eq!(ids(&r, "sku=S3 AND id=13"), vec![13]);
        assert!(ids(&r, "sku=S3 AND id=14").is_empty());

        // las demás condiciones se verifican sobre los candidatos
        assert!(r.explain("sku=S3 AND price>100").unwrap().starts_with("index: 5"));
        assert_eq!(ids(&r, "sku=S3 AND price>100"), vec![13, 23, 33, 43]);
    }

    #[test]
    fn or_unites_the_candidates_of_every_branch() {
        let dir = TempDir::new("v9_or");
        let out = build_multi(&dir, "d", &dataset(50), &["sku", "id"]);
        let r = open(&out);

        assert_eq!(r.explain("id=1 OR id=2 OR sku=S9").unwrap(), "index: 7 candidate record(s) out of 50");
        assert_eq!(ids(&r, "id=1 OR id=2 OR sku=S9"), vec![1, 2, 9, 19, 29, 39, 49]);
        assert_eq!(ids(&r, "id=1 OR id=1"), vec![1], "a record reachable twice is returned once");
        assert!(ids(&r, "sku=nope OR id=nope").is_empty());
    }

    #[test]
    fn a_branch_without_an_indexed_equality_scans_but_never_changes_the_answer() {
        let dir = TempDir::new("v9_orscan");
        let out = build(&dir, "d", &dataset(50), "id");
        let r = open(&out);

        assert!(r.explain("id=1 OR price=20").unwrap().starts_with("scan"));
        assert_eq!(ids(&r, "id=1 OR price=20"), vec![1, 2]);
        assert!(r.explain("price>100").unwrap().starts_with("scan"));
        assert!(r.explain("id>5").unwrap().starts_with("scan"), "a range on an indexed field is not an equality");
        assert!(r.explain("id!=5").unwrap().starts_with("scan"));
    }

    #[test]
    fn a_low_selectivity_condition_prefers_the_parallel_scan() {
        let dir = TempDir::new("v9_lowsel");
        // g vale 0 o 1: 2500 registros por valor, más que max(1024, 5000 / 32)
        let rows: Vec<Value> = (0..5000).map(|i| json!({"id": i, "g": i % 2})).collect();
        let out = build_multi(&dir, "d", &rows, &["g", "id"]);
        let r = open(&out);

        assert!(r.explain("g=0").unwrap().starts_with("scan"));
        assert_eq!(q(&r, "g=0").len(), 2500);
        // unida a una condición selectiva vuelve a usar el índice
        assert_eq!(r.explain("g=0 AND id=10").unwrap(), "index: 1 candidate record(s) out of 5000");
        assert_eq!(ids(&r, "g=0 AND id=10"), vec![10]);
        assert!(ids(&r, "g=1 AND id=10").is_empty());
    }

    #[test]
    fn every_plan_returns_the_rows_a_full_evaluation_returns() {
        let dir = TempDir::new("v9_equiv");
        let rows = dataset(300);
        let out = build_multi(&dir, "d", &rows, &["sku", "id"]);
        let r = open(&out);

        let expressions = [
            "sku=S3", "id=7", "id=7 OR id=8", "sku=S3 AND id=13", "sku=S3 AND id=14", "sku=S1 OR sku=S2",
            "sku=S1 AND sku=S2", "sku=S1 AND price>=1000 OR id=5", "price>2900 OR sku=S0 AND id=10",
            "name=\"Item, 7\" OR id=8", "id=5 OR price>2900", "sku=nope OR id=nope", "sku=S3 AND price!=130",
            "id=7.0 AND sku=S7", "id=299 OR id=0 OR id=150", "price>=0", "id!=3 AND sku=S3",
        ];
        for criterion in expressions {
            let parsed = parse_expression(criterion).unwrap();
            let expected: Vec<u64> = rows
                .iter()
                .filter(|row| expr_matches_full(row.to_string().as_bytes(), &parsed).unwrap())
                .map(|row| row["id"].as_u64().unwrap_or(u64::MAX))
                .collect();
            assert_eq!(ids(&r, criterion), expected, "{}", criterion);
        }
    }

    // ---------------------------------------------------------------- scan paralelo

    fn id_of(plain: &[u8]) -> io::Result<u64> {
        let v: Value = serde_json::from_slice(plain)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        Ok(v["id"].as_u64().unwrap_or(u64::MAX))
    }

    #[test]
    fn parallel_scan_keeps_file_order_for_any_thread_count() {
        let dir = TempDir::new("v9_par_order");
        let rows: Vec<Value> = (0..1000).map(|i| json!({"id": i, "v": "x"})).collect();
        let out = build(&dir, "d", &rows, "id");
        let r = open(&out);

        for threads in [1usize, 2, 3, 8, 64] {
            let mut ids: Vec<u64> = Vec::new();
            let n = r
                .scan_ordered_with(
                    threads,
                    |plain: &[u8]| id_of(plain),
                    |id: u64| {
                        ids.push(id);
                        Ok(())
                    },
                )
                .unwrap();
            assert_eq!(n, 1000, "threads={}", threads);
            assert_eq!(ids, (0..1000u64).collect::<Vec<u64>>(), "threads={}", threads);
        }
    }

    #[test]
    fn the_first_bad_block_is_reported_after_delivering_every_earlier_row() {
        let dir = TempDir::new("v9_par_err");
        let rows: Vec<Value> = (0..300).map(|i| json!({"id": i, "v": "x"})).collect();
        let out = build(&dir, "d", &rows, "id");

        // posición del bloque nº 150: se recorren las longitudes declaradas
        let bytes = fs::read(&out).unwrap();
        let mut pos = body_of(&out);
        for _ in 0..150 {
            let len = u32::from_le_bytes([bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3]]) as usize;
            pos += 20 + len;
        }
        mutate(&out, |b| b[pos + 4] ^= 0xFF);

        let r = open(&out);
        for threads in [1usize, 4] {
            let mut seen = 0usize;
            let err = r
                .scan_ordered_with(
                    threads,
                    |plain: &[u8]| id_of(plain),
                    |_id: u64| {
                        seen += 1;
                        Ok(())
                    },
                )
                .err()
                .expect("a tampered block must fail the scan");
            assert_eq!(seen, 150, "threads={}", threads);
            assert!(err.to_string().contains("tampered"), "{}", err);
        }
    }

    #[test]
    fn a_failing_sink_stops_the_scan_without_hanging() {
        let dir = TempDir::new("v9_par_sink");
        let rows: Vec<Value> = (0..5000).map(|i| json!({"id": i, "v": "x"})).collect();
        let out = build(&dir, "d", &rows, "id");
        let r = open(&out);

        for threads in [1usize, 4] {
            let err = r
                .scan_ordered_with(
                    threads,
                    |plain: &[u8]| id_of(plain),
                    |_id: u64| Err(io::Error::new(io::ErrorKind::Other, "stop here")),
                )
                .err()
                .expect("the sink error must propagate");
            assert!(err.to_string().contains("stop here"));
        }
    }

    #[test]
    fn a_record_larger_than_the_read_chunk_is_handled() {
        let dir = TempDir::new("v9_bigrecord");
        // En los tests el trozo de lectura mide 4 KiB: este registro ocupa unas diez veces más.
        let rows = vec![
            json!({"id": 1, "pad": "a"}),
            json!({"id": 2, "pad": "x".repeat(40_000)}),
            json!({"id": 3, "pad": "b"}),
        ];
        let out = build(&dir, "d", &rows, "id");
        let r = open(&out);

        let exported: Vec<Value> = serde_json::from_slice(&export(&r).unwrap()).unwrap();
        assert_eq!(exported, rows);
        assert_eq!(q(&r, "id>=1").len(), 3);
        assert_eq!(q(&r, "id=2").len(), 1);
        for threads in [1usize, 4] {
            let mut ids: Vec<u64> = Vec::new();
            r.scan_ordered_with(threads, |plain: &[u8]| id_of(plain), |id: u64| {
                ids.push(id);
                Ok(())
            })
            .unwrap();
            assert_eq!(ids, vec![1, 2, 3], "threads={}", threads);
        }
    }

    #[test]
    fn a_corrupted_length_field_is_reported_after_the_rows_before_it() {
        let dir = TempDir::new("v9_badlen");
        let rows: Vec<Value> = (0..100).map(|i| json!({"id": i, "v": "x"})).collect();
        let out = build(&dir, "d", &rows, "id");

        let bytes = fs::read(&out).unwrap();
        let mut pos = body_of(&out);
        for _ in 0..10 {
            let len = u32::from_le_bytes([bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3]]) as usize;
            pos += 20 + len;
        }
        // la longitud declarada del bloque nº 10 pasa a 4 GiB - 1
        mutate(&out, |b| b[pos..pos + 4].copy_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF]));

        let r = open(&out);
        for threads in [1usize, 4] {
            let mut seen = 0usize;
            let err = r
                .scan_ordered_with(threads, |plain: &[u8]| id_of(plain), |_id: u64| {
                    seen += 1;
                    Ok(())
                })
                .err()
                .expect("a corrupted length must fail the scan");
            assert_eq!(seen, 10, "threads={}", threads);
            assert!(err.to_string().contains("maximum") || err.to_string().contains("exceeds"), "{}", err);
        }
        assert!(export(&r).is_err());
    }

    #[test]
    fn filtering_in_parallel_returns_the_same_rows_as_one_thread() {
        let dir = TempDir::new("v9_par_filter");
        let rows: Vec<Value> = (0..2000).map(|i| json!({"id": i, "price": (i * 7) % 100})).collect();
        let out = build(&dir, "d", &rows, "id");
        let r = open(&out);
        let expr = parse_expression("price>=90").unwrap();

        let run = |threads: usize| -> Vec<String> {
            let mut found: Vec<String> = Vec::new();
            r.scan_ordered_with(
                threads,
                |plain: &[u8]| record_if_matches(plain, &expr),
                |row: Option<String>| {
                    if let Some(x) = row {
                        found.push(x);
                    }
                    Ok(())
                },
            )
            .unwrap();
            found
        };

        let single = run(1);
        let expected: Vec<Value> = rows.iter().filter(|v| v["price"].as_u64().unwrap_or(0) >= 90).cloned().collect();
        assert_eq!(single.len(), expected.len());
        assert_eq!(run(8), single);
        assert_eq!(run(3), single);
    }
}
