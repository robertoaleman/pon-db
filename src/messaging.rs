// SPDX-License-Identifier: AGPL-3.0-only
// PON-DB Engine: a database engine encapsulated in a single, portable, encrypted binary format
// Copyright (C) 2026 Roberto C. Aleman F.
// https://github.com/robertoaleman/pon-db
use std::fs::File;
use std::io::{self, Write};
use std::path::Path;

pub struct IngestReport {
    pub original_size: u64,
    pub final_size: u64,
    pub original_sha256: [u8; 32],
    pub final_sha256: [u8; 32],
    pub rows_processed: u32,
    pub unindexed_rows: u64,
    pub indexed_field: String,
    pub time_elapsed: f64,
    /// Formato escrito, p. ej. "PON V9 (revision 1)".
    pub format_label: String,
    /// Qué autenticación tiene la estructura (cabecera, índice) además de los bloques.
    pub structure_auth: String,
}

/// Texto del informe. Solo contiene datos medidos: tamaños, hashes SHA-256 reales y tiempos.
pub fn render_ingest_report(report: &IngestReport, timestamp: &str) -> String {
    let ratio = if report.original_size == 0 {
        "n/a".to_string()
    } else {
        format!("{:.2}%", report.final_size as f64 * 100.0 / report.original_size as f64)
    };
    let throughput = if report.time_elapsed > 0.0 {
        report.rows_processed as f64 / report.time_elapsed
    } else {
        0.0
    };

    format!(
        "==========================================================\n\
         \x20       PON-DB INGEST REPORT\n\
         ==========================================================\n\
         TIMESTAMP:        {}\n\
         FORMAT:           {}\n\
         ----------------------------------------------------------\n\
         ORIGINAL SIZE:    {} bytes\n\
         FINAL SIZE:       {} bytes\n\
         SIZE RATIO:       {} (final / original)\n\
         ROWS PROCESSED:   {}\n\
         INDEXED FIELDS:   {}\n\
         ROWS WITH NONE:   {}\n\
         TIME ELAPSED:     {:.6} seconds\n\
         THROUGHPUT:       {:.2} rows/sec\n\
         ----------------------------------------------------------\n\
         ORIGINAL SHA-256: {}\n\
         FINAL SHA-256:    {}\n\
         ----------------------------------------------------------\n\
         RECORD ENCRYPTION: AES-256-GCM (each record authenticated)\n\
         STRUCTURE AUTH:    {}\n\
         LICENSE:           AGPLv3 OPEN SOURCE\n\
         HARDWARE ID:       NEUTRAL (UNIVERSAL BINDING)\n\
         ==========================================================\n",
        timestamp,
        report.format_label,
        report.original_size,
        report.final_size,
        ratio,
        report.rows_processed,
        report.indexed_field,
        report.unindexed_rows,
        report.time_elapsed,
        throughput,
        hex::encode(report.original_sha256),
        hex::encode(report.final_sha256),
        report.structure_auth,
    )
}

pub fn emit_ingest_log(report: &IngestReport, output_path: &Path) -> io::Result<()> {
    let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    let mut f = File::create(output_path)?;
    f.write_all(render_ingest_report(report, &timestamp).as_bytes())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(original_size: u64, elapsed: f64) -> IngestReport {
        IngestReport {
            original_size,
            final_size: 150,
            original_sha256: [0xAB; 32],
            final_sha256: [0xCD; 32],
            rows_processed: 10,
            unindexed_rows: 2,
            indexed_field: "sku".to_string(),
            time_elapsed: elapsed,
            format_label: "PON V9 (revision 4)".to_string(),
            structure_auth: "HMAC-SHA256 footer".to_string(),
        }
    }

    #[test]
    fn report_contains_real_values_and_no_unverified_claims() {
        let text = render_ingest_report(&sample(100, 2.0), "2026-01-01 00:00:00");
        assert!(text.contains(&"ab".repeat(32)));
        assert!(text.contains(&"cd".repeat(32)));
        assert!(text.contains("150.00%"));
        assert!(text.contains("5.00 rows/sec"));
        assert!(text.contains("sku"));
        assert!(text.contains("FORMAT:           PON V9 (revision 4)"));
        assert!(text.contains("STRUCTURE AUTH:    HMAC-SHA256 footer"));
        for banned in ["MATHEMATICALLY SEALED", "CAPTURING", "VERIFIED (GREEN)"] {
            assert!(!text.contains(banned));
        }
    }

    #[test]
    fn degenerate_inputs_do_not_produce_nan_or_inf() {
        let text = render_ingest_report(&sample(0, 0.0), "t");
        assert!(text.contains("n/a"));
        assert!(!text.contains("NaN"));
        assert!(!text.contains("inf"));
    }
}
