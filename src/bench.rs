// SPDX-License-Identifier: AGPL-3.0-only
// PON-DB Engine: a database engine encapsulated in a single, portable, encrypted binary format
// Copyright (C) 2026 Roberto C. Aleman F.
// https://github.com/robertoaleman/pon-db
//
// Medición de búsquedas por clave (KV) sobre un archivo ya construido. Cada búsqueda incluye todo lo
// que hace una consulta real: hash con clave, página del índice (leída y autenticada), lectura del
// registro, descifrado AES-GCM y comprobación del valor. Las claves son valores reales del campo,
// tomados al azar del propio índice.
use crate::v9::reader::Reader9;
use std::io::{self, Write};
use std::time::Instant;

#[derive(Debug, Clone, Copy)]
pub struct Latency {
    pub ops_per_sec: f64,
    pub mean_us: f64,
    pub p50_us: f64,
    pub p90_us: f64,
    pub p99_us: f64,
    pub p999_us: f64,
    pub max_us: f64,
}

#[derive(Debug)]
pub struct BenchReport {
    pub lookups: usize,
    pub single: Latency,
    pub threads: usize,
    pub parallel_ops_per_sec: f64,
    /// (aciertos, fallos) de la caché de páginas en la tanda de un hilo.
    pub single_cache: (u64, u64),
}

fn percentile(sorted_ns: &[u64], p: f64) -> f64 {
    if sorted_ns.is_empty() {
        return 0.0;
    }
    let idx = ((sorted_ns.len() - 1) as f64 * p).round() as usize;
    sorted_ns[idx] as f64 / 1000.0
}

fn missed() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "a key that exists in the file was not found")
}

pub fn run_bench<W: Write>(
    reader: &Reader9,
    field: &str,
    count: usize,
    threads: usize,
    mut out: W,
) -> io::Result<BenchReport> {
    let keys = reader.sample_values(field, count)?;
    if keys.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "no keys could be sampled (empty file, or no record has that field)",
        ));
    }
    let threads = threads.max(1);

    // 1) un hilo, con la caché de páginas vacía: latencia de cada búsqueda
    reader.clear_page_cache();
    let mut ns: Vec<u64> = Vec::with_capacity(keys.len());
    let started = Instant::now();
    for key in &keys {
        let t = Instant::now();
        let rows = reader.get(field, key)?;
        ns.push(t.elapsed().as_nanos() as u64);
        if rows.is_empty() {
            return Err(missed());
        }
    }
    let total = started.elapsed().as_secs_f64();
    let single_cache = reader.page_cache_stats();
    ns.sort_unstable();
    let mean_us = ns.iter().sum::<u64>() as f64 / ns.len() as f64 / 1000.0;
    let single = Latency {
        ops_per_sec: keys.len() as f64 / total.max(1e-9),
        mean_us,
        p50_us: percentile(&ns, 0.50),
        p90_us: percentile(&ns, 0.90),
        p99_us: percentile(&ns, 0.99),
        p999_us: percentile(&ns, 0.999),
        max_us: ns.last().copied().unwrap_or(0) as f64 / 1000.0,
    };

    // 2) varios hilos sobre el mismo lector, de nuevo con la caché vacía: rendimiento total
    reader.clear_page_cache();
    let per_thread = ((keys.len() + threads - 1) / threads).max(1);
    let started = Instant::now();
    let outcome: io::Result<()> = std::thread::scope(|s| {
        let handles: Vec<_> = keys
            .chunks(per_thread)
            .map(|chunk| {
                s.spawn(move || -> io::Result<()> {
                    for key in chunk {
                        if reader.get(field, key)?.is_empty() {
                            return Err(missed());
                        }
                    }
                    Ok(())
                })
            })
            .collect();
        let mut result: io::Result<()> = Ok(());
        for handle in handles {
            let this = match handle.join() {
                Ok(r) => r,
                Err(_) => Err(io::Error::new(io::ErrorKind::Other, "a benchmark thread panicked")),
            };
            if result.is_ok() {
                result = this;
            }
        }
        result
    });
    outcome?;
    let parallel_ops_per_sec = keys.len() as f64 / started.elapsed().as_secs_f64().max(1e-9);

    writeln!(
        out,
        "PON-DB key lookups: field '{}', {} sampled keys, {} records",
        field,
        keys.len(),
        reader.total_rows()
    )?;
    writeln!(
        out,
        "  1 thread : {:>12.0} lookups/s   mean {:.2} us   p50 {:.2}   p90 {:.2}   p99 {:.2}   p99.9 {:.2}   max {:.2}",
        single.ops_per_sec, single.mean_us, single.p50_us, single.p90_us, single.p99_us, single.p999_us, single.max_us
    )?;
    writeln!(out, "  {} threads: {:>12.0} lookups/s", threads, parallel_ops_per_sec)?;
    writeln!(
        out,
        "  index page cache in the 1-thread run: {} hits, {} misses",
        single_cache.0, single_cache.1
    )?;
    writeln!(
        out,
        "  each lookup = keyed hash + index page (read and authenticated) + record read + AES-GCM + value check"
    )?;

    Ok(BenchReport { lookups: keys.len(), single, threads, parallel_ops_per_sec, single_cache })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TempDir;
    use crate::v9::writer::ingest_file9;
    use serde_json::json;
    use std::fs;
    use std::path::Path;

    const MASTER: [u8; 32] = [7u8; 32];

    fn open_ids(dir: &TempDir, n: usize, fields: &[&str]) -> Reader9 {
        let text: String = (0..n)
            .map(|i| json!({"id": i, "tag": format!("t{}", i % 7)}).to_string())
            .collect::<Vec<_>>()
            .join("\n");
        let input = dir.join("d.json");
        fs::write(&input, text).unwrap();
        let output = dir.join("d.pon");
        let fields: Vec<String> = fields.iter().map(|f| f.to_string()).collect();
        ingest_file9(&input, &output, &fields, &MASTER).unwrap();
        Reader9::open(Path::new(&output), &MASTER).unwrap()
    }

    #[test]
    fn the_benchmark_finds_every_sampled_key_and_reports_ordered_percentiles() {
        let dir = TempDir::new("bench_ok");
        let r = open_ids(&dir, 3000, &["id"]);
        let mut out: Vec<u8> = Vec::new();
        let report = run_bench(&r, "id", 800, 3, &mut out).unwrap();

        assert_eq!(report.lookups, 800);
        assert_eq!(report.threads, 3);
        assert!(report.single.ops_per_sec > 0.0 && report.parallel_ops_per_sec > 0.0);
        let s = report.single;
        assert!(s.p50_us <= s.p90_us && s.p90_us <= s.p99_us && s.p99_us <= s.p999_us && s.p999_us <= s.max_us);
        assert!(s.mean_us > 0.0);

        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("lookups/s") && text.contains("1 thread") && text.contains("3 threads"), "{}", text);
        assert_eq!(report.single_cache.0 + report.single_cache.1 > 0, true);
    }

    #[test]
    fn sampled_values_are_real_keys() {
        let dir = TempDir::new("bench_sample");
        let r = open_ids(&dir, 500, &["id", "tag"]);
        for field in ["id", "tag"] {
            let values = r.sample_values(field, 50).unwrap();
            assert_eq!(values.len(), 50);
            for v in values {
                assert!(!r.get(field, &v).unwrap().is_empty(), "{}={}", field, v);
            }
        }
    }

    #[test]
    fn only_indexed_fields_can_be_benchmarked() {
        let dir = TempDir::new("bench_err");
        let r = open_ids(&dir, 100, &["id"]);
        let mut out: Vec<u8> = Vec::new();
        assert!(run_bench(&r, "tag", 10, 1, &mut out).is_err());
        assert!(run_bench(&r, "missing", 10, 1, &mut out).is_err());
    }
}
