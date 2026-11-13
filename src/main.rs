// SPDX-License-Identifier: AGPL-3.0-only
// PON-DB Engine: a database engine encapsulated in a single, portable, encrypted binary format
// Copyright (C) 2026 Roberto C. Aleman F.
// https://github.com/robertoaleman/pon-db
mod bench;
mod block;
mod index_manager;
mod ingest;
mod key_manager;
mod messaging;
mod query_engine;
mod scanner;
mod serve;
#[cfg(test)]
mod testutil;
mod v9;

use colored::Colorize;
use std::fs;
use std::io::{self, BufWriter, Write};
use std::path::Path;
use std::time::Instant;
use zeroize::Zeroizing;

use crate::key_manager::MasterkeyManager;
use crate::v9::reader::Reader9;
use crate::v9::writer::ingest_file9;

const FORMAT_LABEL: &str = "PON V9 (revision 4)";
const STRUCTURE_AUTH: &str = "HMAC-SHA256 footer over the header; per-page GMAC tags on the hash index; per-table tags; \
     block AAD = file id + offset; deterministic nonce; keyed index (HMAC-SHA256); encrypted metadata";

#[derive(Debug, PartialEq, Eq)]
enum Mode {
    Ingest,
    Query(String),
    Export,
    Serve,
    Bench,
}

#[derive(Debug)]
struct Cli {
    input: String,
    mode: Mode,
    index_fields: Vec<String>,
    key_path: Option<String>,
    force: bool,
    /// Solo para `bench`.
    field: Option<String>,
    count: Option<usize>,
    threads: Option<usize>,
}

fn invalid(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, msg.into())
}

/// Interpreta los argumentos (`args[0]` es el nombre del programa).
/// El criterio de `query` es el primer argumento que no empieza por `--` tras la palabra `query`,
/// por lo que `--key=...` puede ir antes o después sin confundirse con la consulta.
fn parse_args(args: &[String]) -> Result<Cli, String> {
    let input = args.get(1).ok_or_else(|| "missing input file".to_string())?.clone();

    let mut index_fields: Vec<String> = Vec::new();
    let mut key_path: Option<String> = None;
    let mut force = false;
    let mut want_query = false;
    let mut want_export = false;
    let mut want_serve = false;
    let mut want_bench = false;
    let mut bench_field: Option<String> = None;
    let mut bench_count: Option<usize> = None;
    let mut bench_threads: Option<usize> = None;
    let mut criterion: Option<String> = None;
    let mut expecting_criterion = false;

    for arg in &args[2..] {
        if expecting_criterion && !arg.starts_with("--") {
            criterion = Some(arg.clone());
            expecting_criterion = false;
            continue;
        }
        if let Some(v) = arg.strip_prefix("--index=") {
            index_fields = v
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
        } else if let Some(v) = arg.strip_prefix("--key=") {
            key_path = Some(v.to_string());
        } else if arg == "--force" {
            force = true;
        } else if arg == "query" {
            want_query = true;
            expecting_criterion = true;
        } else if arg == "export" {
            want_export = true;
        } else if arg == "serve" {
            want_serve = true;
        } else if arg == "bench" {
            want_bench = true;
        } else if let Some(v) = arg.strip_prefix("--field=") {
            bench_field = Some(v.to_string());
        } else if let Some(v) = arg.strip_prefix("--count=") {
            bench_count = Some(v.parse::<usize>().ok().filter(|n| *n >= 1).ok_or_else(|| format!("invalid --count={}", v))?);
        } else if let Some(v) = arg.strip_prefix("--threads=") {
            bench_threads = Some(v.parse::<usize>().ok().filter(|n| *n >= 1).ok_or_else(|| format!("invalid --threads={}", v))?);
        } else {
            return Err(format!("unrecognized argument: {}", arg));
        }
    }

    if [want_query, want_export, want_serve, want_bench].iter().filter(|w| **w).count() > 1 {
        return Err("choose only one of 'query', 'export', 'serve' and 'bench'".to_string());
    }
    let mode = if want_export {
        Mode::Export
    } else if want_serve {
        Mode::Serve
    } else if want_bench {
        if bench_field.is_none() {
            return Err("bench needs --field=<indexed field>".to_string());
        }
        Mode::Bench
    } else if want_query {
        match criterion {
            Some(c) => Mode::Query(c),
            None => return Err("query needs a criterion, e.g. query \"sku=PROD-100\"".to_string()),
        }
    } else {
        Mode::Ingest
    };
    if mode != Mode::Ingest && !index_fields.is_empty() {
        return Err("--index only applies when ingesting".to_string());
    }

    if mode != Mode::Bench && (bench_field.is_some() || bench_count.is_some() || bench_threads.is_some()) {
        return Err("--field, --count and --threads only apply to bench".to_string());
    }

    Ok(Cli {
        input,
        mode,
        index_fields,
        key_path,
        force,
        field: bench_field,
        count: bench_count,
        threads: bench_threads,
    })
}

fn main() {
    if let Err(e) = run() {
        if e.kind() == io::ErrorKind::BrokenPipe {
            std::process::exit(0);
        }
        eprintln!("{} {}", " ERROR ".on_red().white(), e);
        std::process::exit(1);
    }
}

fn run() -> io::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 || args[1] == "-h" || args[1] == "--help" {
        print_usage();
        return Ok(());
    }

    let cli = parse_args(&args).map_err(|e| invalid(e))?;
    match &cli.mode {
        Mode::Ingest => run_ingest(&cli.input, &cli.index_fields, cli.force),
        Mode::Query(criterion) => run_query(&cli.input, criterion, cli.key_path.as_deref()),
        Mode::Export => run_export(&cli.input, cli.key_path.as_deref()),
        Mode::Serve => run_serve(&cli.input, cli.key_path.as_deref()),
        Mode::Bench => {
            let field = cli.field.clone().unwrap_or_default();
            let threads = cli
                .threads
                .unwrap_or_else(|| std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1));
            run_bench(&cli.input, cli.key_path.as_deref(), &field, cli.count.unwrap_or(100_000), threads)
        }
    }
}

fn run_ingest(input: &str, fields: &[String], force: bool) -> io::Result<()> {
    // Sin --index se indexa `id`.
    let fields: Vec<String> = if fields.is_empty() { vec!["id".to_string()] } else { fields.to_vec() };

    let output = format!("{}.pon", input);
    if Path::new(&output).exists() && !force {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!("{} already exists (use --force to overwrite it)", output),
        ));
    }

    let started = Instant::now();
    let original_size = fs::metadata(input)?.len();

    let (master_key, key_path) = MasterkeyManager::generate_and_save()?;
    let tmp = format!("{}.tmp", output);

    // Si algo falla no quedan ni archivo parcial ni clave huérfana.
    let stats = match ingest_file9(Path::new(input), Path::new(&tmp), &fields, &master_key) {
        Ok(s) => s,
        Err(e) => {
            let _ = fs::remove_file(&tmp);
            let _ = fs::remove_file(&key_path);
            return Err(e);
        }
    };
    if let Err(e) = fs::rename(&tmp, &output) {
        let _ = fs::remove_file(&tmp);
        let _ = fs::remove_file(&key_path);
        return Err(e);
    }

    let final_size = fs::metadata(&output)?.len();
    let final_sha256 = ingest::sha256_file(Path::new(&output))?;
    let log_path = format!("{}.log", output);
    messaging::emit_ingest_log(
        &messaging::IngestReport {
            original_size,
            final_size,
            original_sha256: stats.original_sha256,
            final_sha256,
            rows_processed: stats.rows,
            unindexed_rows: stats.unindexed,
            indexed_field: fields.join(","),
            time_elapsed: started.elapsed().as_secs_f64(),
            format_label: FORMAT_LABEL.to_string(),
            structure_auth: STRUCTURE_AUTH.to_string(),
        },
        Path::new(&log_path),
    )?;

    println!("{} Ingestion completed: {} rows -> {}", " SUCCESS ".on_green(), stats.rows, output);
    println!("      {} index entries for the field(s): {}.", stats.index_entries, fields.join(", "));
    if stats.unindexed > 0 {
        println!(
            "{} {} record(s) contain none of the indexed fields: stored, but not reachable through the index.",
            " WARN ".on_yellow().black(),
            stats.unindexed
        );
    }
    println!("{} Master key stored in: {}", " KEY ".on_yellow().black(), key_path.display());
    println!("      Keep it safe and apart from the .pon file: without it the data cannot be recovered.");
    Ok(())
}

fn load_master_key(key_path: Option<&str>) -> io::Result<Zeroizing<[u8; 32]>> {
    let path = key_path.ok_or_else(|| invalid("missing --key=<master key file>"))?;
    MasterkeyManager::load_key(Path::new(path))
}

fn run_query(path: &str, criterion: &str, key_path: Option<&str>) -> io::Result<()> {
    let master = load_master_key(key_path)?;
    let started = Instant::now();
    let rows = Reader9::open(Path::new(path), &master)?.query(criterion)?;

    // Los resultados van a stdout (limpios, aptos para tuberías); los mensajes a stderr.
    let stdout = io::stdout();
    let mut out = BufWriter::new(stdout.lock());
    for row in &rows {
        writeln!(out, "{}", row)?;
    }
    out.flush()?;

    if rows.is_empty() {
        eprintln!("{}", "Result not found.".yellow());
    } else {
        eprintln!("{} {} row(s) in {:?}", " TIME ".on_yellow().black(), rows.len(), started.elapsed());
    }
    Ok(())
}

/// Mide búsquedas por clave sobre un campo indexado (ver `bench.rs`).
fn run_bench(path: &str, key_path: Option<&str>, field: &str, count: usize, threads: usize) -> io::Result<()> {
    let master = load_master_key(key_path)?;
    let reader = Reader9::open(Path::new(path), &master)?;
    let stdout = io::stdout();
    bench::run_bench(&reader, field, count, threads, stdout.lock())?;
    Ok(())
}

/// Abre el archivo una vez y atiende una consulta por línea de la entrada estándar (ver `serve.rs`).
fn run_serve(path: &str, key_path: Option<&str>) -> io::Result<()> {
    let master = load_master_key(key_path)?;
    let reader = Reader9::open(Path::new(path), &master)?;
    eprintln!(
        "{} serving {} ({} records; indexed: {}). One query per line, \\q to quit.",
        " SERVE ".on_green(),
        path,
        reader.total_rows(),
        reader.indexed_fields().join(", ")
    );
    let stdin = io::stdin();
    let stdout = io::stdout();
    serve::serve_loop(&reader, stdin.lock(), stdout.lock())
}

fn run_export(path: &str, key_path: Option<&str>) -> io::Result<()> {
    let master = load_master_key(key_path)?;
    let reader = Reader9::open(Path::new(path), &master)?;

    let stdout = io::stdout();
    let mut out = BufWriter::new(stdout.lock());
    let summary = reader.export_to(&mut out)?;
    out.flush()?;

    // El resumen va a stderr: `export > restored.json` produce un JSON válido.
    eprintln!(
        "{} {} records exported; every block passed AES-GCM authentication.",
        " OK ".on_green(),
        summary.rows
    );
    eprintln!("SHA-256 of exported content: {}", hex::encode(summary.sha256));
    eprintln!("The file structure (header and index) was authenticated with HMAC-SHA256.");
    Ok(())
}

fn print_usage() {
    println!("PON-DB Engine 9.0 (alpha) | AGPLv3 Open Source Engine");
    println!("(c) 2026 pon-db.com | Author: Roberto C. Aleman F.");
    println!();
    println!("Usage:");
    println!("  Ingest:   pon-db-engine dataset.json [--index=FIELD[,FIELD...]] [--force]");
    println!("  Query:    pon-db-engine dataset.json.pon query \"sku=PROD-100\" --key=masterkey_xxxx.bin");
    println!("            operators: =  !=  >  >=  <  <=   combine conditions with AND / OR ");
    println!("            e.g. \"sku=S3 OR price>=100\"   (equality on an indexed field uses the index)");
    println!("  Export:   pon-db-engine dataset.json.pon export --key=masterkey_xxxx.bin > restored.json");
    println!("  Serve:    pon-db-engine dataset.json.pon serve --key=masterkey_xxxx.bin   (one query per line, JSON replies)");
    println!("  Bench:    pon-db-engine dataset.json.pon bench --field=id [--count=100000] [--threads=N] --key=masterkey_xxxx.bin");
    println!();
    println!("Environment: PON_THREADS=N limits the threads used by full scans (default: all cores).");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        let mut v = vec!["pon-db-engine".to_string()];
        v.extend(list.iter().map(|s| s.to_string()));
        v
    }

    #[test]
    fn defaults_to_ingest() {
        let cli = parse_args(&args(&["data.json"])).unwrap();
        assert_eq!(cli.mode, Mode::Ingest);
        assert!(cli.index_fields.is_empty());
        assert!(!cli.force);
    }

    #[test]
    fn ingest_flags() {
        let cli = parse_args(&args(&["data.json", "--index=sku", "--force"])).unwrap();
        assert_eq!(cli.index_fields, vec!["sku".to_string()]);
        assert!(cli.force);
    }

    #[test]
    fn several_indexed_fields() {
        let cli = parse_args(&args(&["data.json", "--index=sku, city ,address.zip"])).unwrap();
        assert_eq!(
            cli.index_fields,
            vec!["sku".to_string(), "city".to_string(), "address.zip".to_string()]
        );
        let none = parse_args(&args(&["data.json", "--index=,,"])).unwrap();
        assert!(none.index_fields.is_empty());
    }

    #[test]
    fn query_criterion_is_found_wherever_the_key_flag_is() {
        let a = parse_args(&args(&["d.pon", "query", "sku=A", "--key=k.bin"])).unwrap();
        assert_eq!(a.mode, Mode::Query("sku=A".to_string()));
        assert_eq!(a.key_path.as_deref(), Some("k.bin"));

        let b = parse_args(&args(&["d.pon", "--key=k.bin", "query", "sku=A"])).unwrap();
        assert_eq!(b.mode, Mode::Query("sku=A".to_string()));

        let c = parse_args(&args(&["d.pon", "query", "--key=k.bin", "price>=500"])).unwrap();
        assert_eq!(c.mode, Mode::Query("price>=500".to_string()));
    }

    #[test]
    fn paths_containing_operator_characters_are_not_mistaken_for_queries() {
        let cli = parse_args(&args(&["data=2026!.json.pon", "query", "id=1", "--key=k.bin"])).unwrap();
        assert_eq!(cli.input, "data=2026!.json.pon");
        assert_eq!(cli.mode, Mode::Query("id=1".to_string()));
    }

    #[test]
    fn serve_mode() {
        let cli = parse_args(&args(&["d.pon", "serve", "--key=k.bin"])).unwrap();
        assert_eq!(cli.mode, Mode::Serve);
        assert!(parse_args(&args(&["d.pon", "serve", "export"])).is_err());
        assert!(parse_args(&args(&["d.pon", "serve", "--index=sku"])).is_err());
    }

    #[test]
    fn bench_mode_and_its_options() {
        let cli = parse_args(&args(&["d.pon", "bench", "--field=id", "--count=500", "--threads=4", "--key=k.bin"])).unwrap();
        assert_eq!(cli.mode, Mode::Bench);
        assert_eq!((cli.field.as_deref(), cli.count, cli.threads), (Some("id"), Some(500), Some(4)));
        assert!(parse_args(&args(&["d.pon", "bench", "--key=k.bin"])).is_err(), "--field is required");
        assert!(parse_args(&args(&["d.pon", "bench", "--field=id", "--count=0"])).is_err());
        assert!(parse_args(&args(&["d.pon", "bench", "--field=id", "--threads=x"])).is_err());
        assert!(parse_args(&args(&["d.pon", "query", "a=1", "--field=id"])).is_err(), "bench options only with bench");
        assert!(parse_args(&args(&["d.pon", "bench", "serve", "--field=id"])).is_err());
    }

    #[test]
    fn compound_criteria_are_one_argument() {
        let cli = parse_args(&args(&["d.pon", "query", "sku=S3 AND price>=100", "--key=k.bin"])).unwrap();
        assert_eq!(cli.mode, Mode::Query("sku=S3 AND price>=100".to_string()));
    }

    #[test]
    fn export_mode() {
        let cli = parse_args(&args(&["d.pon", "export", "--key=k.bin"])).unwrap();
        assert_eq!(cli.mode, Mode::Export);
    }

    #[test]
    fn invalid_combinations_are_errors() {
        assert!(parse_args(&args(&[])).is_err());
        assert!(parse_args(&args(&["d.pon", "query"])).is_err());
        assert!(parse_args(&args(&["d.pon", "query", "--key=k.bin"])).is_err());
        assert!(parse_args(&args(&["d.pon", "query", "a=1", "export"])).is_err());
        assert!(parse_args(&args(&["d.pon", "--bogus"])).is_err());
        assert!(parse_args(&args(&["d.pon", "export", "--index=sku"])).is_err());
    }

    #[test]
    fn the_old_format_flag_is_gone() {
        assert!(parse_args(&args(&["d.json", "--format=v8"])).is_err());
        assert!(parse_args(&args(&["d.json", "--format=v9"])).is_err());
    }
}
