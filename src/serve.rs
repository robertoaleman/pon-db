// SPDX-License-Identifier: AGPL-3.0-only
// PON-DB Engine: a database engine encapsulated in a single, portable, encrypted binary format
// Copyright (C) 2026 Roberto C. Aleman F.
// https://github.com/robertoaleman/pon-db
//
// Modo persistente: el archivo se abre y su estructura se autentica UNA vez; después cada línea de
// la entrada es una consulta y cada consulta recibe exactamente una línea JSON de respuesta.
// Las páginas del índice se autentican la primera vez que se leen y se reutilizan después.
//
//   consulta        `sku=S3`, `id=7 AND sku=S7`, `price>=100 OR id=1` ...
//   \explain <q>    cómo se resolvería la consulta (índice o recorrido)
//   \stats          filas, campos indexados y aciertos/fallos de la caché de páginas del índice
//   \q              termina
//
// Respuestas: {"ok":true,"count":N,"micros":T,"rows":[...]}  |  {"ok":true,"plan":"..."}  |
//             {"ok":true,"rows":N,"indexed_fields":[...],"page_cache":{"hits":H,"misses":M}}  |
//             {"ok":false,"error":"..."}
use crate::v9::reader::Reader9;
use std::io::{self, BufRead, Write};
use std::time::Instant;

fn json_str(s: &str) -> String {
    serde_json::to_string(s).unwrap_or_else(|_| "\"\"".to_string())
}

fn error_line(msg: &str) -> String {
    format!("{{\"ok\":false,\"error\":{}}}", json_str(msg))
}

/// Un registro guardado con sangrías ocupa varias líneas; en JSON válido los saltos de línea solo pueden
/// estar entre símbolos (dentro de una cadena van escapados), así que cambiarlos por espacios es seguro.
fn one_line(row: &str) -> String {
    row.replace(|c: char| c == '\n' || c == '\r', " ")
}

fn respond(reader: &Reader9, cmd: &str) -> String {
    if cmd == "\\stats" {
        let (hits, misses) = reader.page_cache_stats();
        let fields = serde_json::to_string(reader.indexed_fields()).unwrap_or_else(|_| "[]".to_string());
        return format!(
            "{{\"ok\":true,\"rows\":{},\"indexed_fields\":{},\"page_cache\":{{\"hits\":{},\"misses\":{}}}}}",
            reader.total_rows(),
            fields,
            hits,
            misses
        );
    }
    if let Some(rest) = cmd.strip_prefix("\\explain") {
        return match reader.explain(rest.trim()) {
            Ok(plan) => format!("{{\"ok\":true,\"plan\":{}}}", json_str(&plan)),
            Err(e) => error_line(&e.to_string()),
        };
    }
    if cmd.starts_with('\\') {
        return error_line("unknown command (use \\stats, \\explain <query> or \\q)");
    }

    let started = Instant::now();
    match reader.query(cmd) {
        Ok(rows) => {
            let micros = started.elapsed().as_micros();
            let body: Vec<String> = rows.iter().map(|r| one_line(r)).collect();
            format!(
                "{{\"ok\":true,\"count\":{},\"micros\":{},\"rows\":[{}]}}",
                body.len(),
                micros,
                body.join(",")
            )
        }
        Err(e) => error_line(&e.to_string()),
    }
}

/// Atiende consultas hasta el final de la entrada o hasta `\q`. Un error de una consulta se informa
/// en su respuesta y no detiene el servicio.
pub fn serve_loop<R: BufRead, W: Write>(reader: &Reader9, input: R, mut out: W) -> io::Result<()> {
    for line in input.lines() {
        let line = line?;
        let cmd = line.trim();
        if cmd.is_empty() {
            continue;
        }
        if cmd == "\\q" || cmd == "\\quit" {
            break;
        }
        let response = respond(reader, cmd);
        out.write_all(response.as_bytes())?;
        out.write_all(b"\n")?;
        out.flush()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TempDir;
    use crate::v9::writer::ingest_file9;
    use serde_json::{json, Value};
    use std::fs;
    use std::io::Cursor;
    use std::path::Path;

    const MASTER: [u8; 32] = [7u8; 32];

    fn open_with(dir: &TempDir, text: &str, fields: &[&str]) -> Reader9 {
        let input = dir.join("d.json");
        fs::write(&input, text).unwrap();
        let output = dir.join("d.pon");
        let fields: Vec<String> = fields.iter().map(|f| f.to_string()).collect();
        ingest_file9(&input, &output, &fields, &MASTER).unwrap();
        Reader9::open(Path::new(&output), &MASTER).unwrap()
    }

    fn dataset_text(n: usize) -> String {
        (0..n)
            .map(|i| json!({"id": i, "sku": format!("S{}", i % 10), "price": i * 10}).to_string())
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn run(reader: &Reader9, script: &str) -> Vec<Value> {
        let mut out: Vec<u8> = Vec::new();
        serve_loop(reader, Cursor::new(script.as_bytes().to_vec()), &mut out).unwrap();
        String::from_utf8(out)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).expect("every response is one JSON line"))
            .collect()
    }

    #[test]
    fn each_line_gets_exactly_one_json_response() {
        let dir = TempDir::new("serve_basic");
        let r = open_with(&dir, &dataset_text(50), &["sku", "id"]);
        let script = "sku=S3\nid=7 AND sku=S7\nid=7 AND sku=S8\nprice>=480\n\\explain sku=S3\n\\stats\nbogus\n\n\\q\nsku=S4\n";
        let replies = run(&r, script);

        assert_eq!(replies.len(), 7, "nothing is answered after \\q, blank lines are skipped");
        assert_eq!(replies[0]["ok"], true);
        assert_eq!(replies[0]["count"], 5);
        assert_eq!(replies[1]["count"], 1);
        assert_eq!(replies[2]["count"], 0);
        assert_eq!(replies[3]["count"], 2);
        assert!(replies[4]["plan"].as_str().unwrap_or("").starts_with("index"));
        assert_eq!(replies[5]["rows"], 50);
        assert_eq!(replies[5]["indexed_fields"], json!(["sku", "id"]));
        assert_eq!(replies[6]["ok"], false);
        assert!(replies[6]["error"].as_str().unwrap_or("").contains("invalid query"));
    }

    #[test]
    fn errors_do_not_stop_the_service() {
        let dir = TempDir::new("serve_errors");
        let r = open_with(&dir, &dataset_text(20), &["id"]);
        let replies = run(&r, "id=1 AND\n\\nope\nid=7\n");
        assert_eq!(replies.len(), 3);
        assert_eq!(replies[0]["ok"], false);
        assert_eq!(replies[1]["ok"], false);
        assert_eq!(replies[2]["count"], 1);
    }

    #[test]
    fn repeated_lookups_reuse_the_authenticated_page() {
        let dir = TempDir::new("serve_cache");
        let r = open_with(&dir, &dataset_text(50), &["id"]);
        let replies = run(&r, "id=7\nid=8\nid=9\nid=10\n\\stats\n");

        for reply in &replies[..4] {
            assert_eq!(reply["count"], 1);
        }
        let cache = &replies[4]["page_cache"];
        assert_eq!(cache["misses"], 1, "the single page is read and verified once");
        assert!(cache["hits"].as_u64().unwrap_or(0) >= 3, "{}", cache);
    }

    #[test]
    fn records_stored_with_indentation_still_fit_on_one_line() {
        let dir = TempDir::new("serve_pretty");
        let rows: Vec<Value> = (0..5).map(|i| json!({"id": i, "tags": ["a", "b"], "note": "x\ny"})).collect();
        let r = open_with(&dir, &serde_json::to_string_pretty(&rows).unwrap(), &["id"]);

        let mut out: Vec<u8> = Vec::new();
        serve_loop(&r, Cursor::new(b"id=3\n".to_vec()), &mut out).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert_eq!(text.lines().count(), 1, "one query, one line: {}", text);

        let reply: Value = serde_json::from_str(text.trim()).unwrap();
        assert_eq!(reply["count"], 1);
        assert_eq!(reply["rows"][0]["id"], 3);
        assert_eq!(reply["rows"][0]["note"], "x\ny", "escaped newlines inside strings are preserved");
    }
}
