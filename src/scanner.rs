// SPDX-License-Identifier: AGPL-3.0-only
// PON-DB Engine: a database engine encapsulated in a single, portable, encrypted binary format
// Copyright (C) 2026 Roberto C. Aleman F.
// https://github.com/robertoaleman/pon-db
use std::io::{self, BufRead};

/// Tamaño máximo de un objeto JSON individual al ingerir (16 MiB).
pub const MAX_RECORD_LEN: usize = 16 * 1024 * 1024;

/// Extrae objetos JSON de nivel superior de un flujo (NDJSON, un array `[ {...}, {...} ]`
/// o simplemente objetos concatenados). Lleva la cuenta de llaves ignorando las que están
/// dentro de cadenas. Devuelve los bytes originales del objeto, sin re-serializar.
pub struct ObjectScanner<R: BufRead> {
    reader: R,
    max_len: usize,
}

impl<R: BufRead> ObjectScanner<R> {
    pub fn new(reader: R, max_len: usize) -> Self {
        Self { reader, max_len }
    }

    pub fn into_inner(self) -> R {
        self.reader
    }

    /// `Ok(None)` al llegar limpiamente al final del flujo.
    /// Error si un objeto queda sin cerrar o supera `max_len`.
    pub fn next_object(&mut self) -> io::Result<Option<Vec<u8>>> {
        let max_len = self.max_len;
        let mut obj: Vec<u8> = Vec::new();
        let mut depth: usize = 0;
        let mut in_string = false;
        let mut escaped = false;

        loop {
            let (used, finished) = {
                let buf = self.reader.fill_buf()?;
                if buf.is_empty() {
                    if depth == 0 {
                        return Ok(None);
                    }
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "unterminated JSON object at end of input",
                    ));
                }

                let mut used = 0usize;
                let mut finished = false;
                for &b in buf {
                    used += 1;

                    if depth == 0 {
                        if b == b'{' {
                            depth = 1;
                            obj.push(b);
                        }
                        continue;
                    }

                    obj.push(b);
                    if obj.len() > max_len {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("JSON object larger than {} bytes", max_len),
                        ));
                    }

                    if in_string {
                        if escaped {
                            escaped = false;
                        } else if b == b'\\' {
                            escaped = true;
                        } else if b == b'"' {
                            in_string = false;
                        }
                    } else {
                        match b {
                            b'"' => in_string = true,
                            b'{' => depth += 1,
                            b'}' => {
                                depth -= 1;
                                if depth == 0 {
                                    finished = true;
                                    break;
                                }
                            }
                            _ => {}
                        }
                    }
                }
                (used, finished)
            };

            self.reader.consume(used);
            if finished {
                return Ok(Some(obj));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufReader, Cursor};

    fn scan_all(text: &str) -> io::Result<Vec<String>> {
        let mut s = ObjectScanner::new(Cursor::new(text.as_bytes().to_vec()), MAX_RECORD_LEN);
        let mut out = Vec::new();
        while let Some(o) = s.next_object()? {
            out.push(String::from_utf8(o).unwrap());
        }
        Ok(out)
    }

    #[test]
    fn ndjson_and_array_inputs() {
        assert_eq!(scan_all("{\"a\":1}\n{\"a\":2}\n").unwrap(), vec!["{\"a\":1}", "{\"a\":2}"]);
        assert_eq!(
            scan_all("[ {\"a\":1}, {\"a\":{\"b\":2}} ]").unwrap(),
            vec!["{\"a\":1}", "{\"a\":{\"b\":2}}"]
        );
    }

    #[test]
    fn braces_and_escaped_quotes_inside_strings_are_ignored() {
        let text = r#"{"s":"} { \" }","n":1}{"s":"\\"}"#;
        let got = scan_all(text).unwrap();
        assert_eq!(got.len(), 2);
        assert_eq!(got[0], r#"{"s":"} { \" }","n":1}"#);
        assert_eq!(got[1], r#"{"s":"\\"}"#);
    }

    #[test]
    fn empty_input_yields_nothing() {
        assert!(scan_all("").unwrap().is_empty());
        assert!(scan_all("  [ ]  ").unwrap().is_empty());
    }

    #[test]
    fn unterminated_object_is_an_error() {
        assert!(scan_all("{\"a\":1}{\"a\":").is_err());
    }

    #[test]
    fn oversized_object_is_an_error() {
        let big = format!("{{\"a\":\"{}\"}}", "x".repeat(200));
        let mut s = ObjectScanner::new(Cursor::new(big.into_bytes()), 100);
        assert!(s.next_object().is_err());
    }

    #[test]
    fn objects_spanning_buffer_boundaries_are_reassembled() {
        let text = format!("{{\"k\":\"{}\"}}", "y".repeat(100));
        let reader = BufReader::with_capacity(7, Cursor::new(text.clone().into_bytes()));
        let mut s = ObjectScanner::new(reader, MAX_RECORD_LEN);
        let got = s.next_object().unwrap().unwrap();
        assert_eq!(String::from_utf8(got).unwrap(), text);
        assert!(s.next_object().unwrap().is_none());
    }
}
