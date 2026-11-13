// SPDX-License-Identifier: AGPL-3.0-only
// PON-DB Engine: a database engine encapsulated in a single, portable, encrypted binary format
// Copyright (C) 2026 Roberto C. Aleman F.
// https://github.com/robertoaleman/pon-db
use serde_json::Value;
use std::collections::BTreeMap;

/// Bit 63 del offset: indica que apunta a la tabla de coincidencias y no a un bloque.
pub const COLLISION_FLAG: u64 = 1 << 63;

/// Busca un campo en un documento. Admite rutas con puntos (`address.city`).
pub fn lookup_field<'a>(doc: &'a Value, field: &str) -> Option<&'a Value> {
    if let Some(v) = doc.get(field) {
        return Some(v);
    }
    if field.contains('.') {
        let mut current = doc;
        for part in field.split('.') {
            current = current.get(part)?;
        }
        return Some(current);
    }
    None
}

/// Forma canónica de un número JSON: los enteros (`7`, `7.0`, `1e0`) dan `"7"`; el resto, la
/// representación más corta del `f64`. Así un valor numérico tiene UNA clave de índice, sea cual sea
/// la ortografía con que se escribió, y una consulta por un entero necesita un solo hash.
pub fn canonical_number(n: &serde_json::Number) -> String {
    if let Some(i) = n.as_i64() {
        return i.to_string();
    }
    if let Some(u) = n.as_u64() {
        return u.to_string();
    }
    match n.as_f64() {
        Some(f) if f.is_finite() && f.fract() == 0.0 && f.abs() < 9.0e15 => (f as i64).to_string(),
        Some(f) => serde_json::Number::from_f64(f).map(|x| x.to_string()).unwrap_or_else(|| n.to_string()),
        None => n.to_string(),
    }
}

/// Forma canónica de un texto que representa un número (`None` si no lo es).
fn canonical_from_text(s: &str) -> Option<String> {
    let t = s.trim();
    if let Ok(i) = t.parse::<i64>() {
        return Some(i.to_string());
    }
    if let Ok(u) = t.parse::<u64>() {
        return Some(u.to_string());
    }
    match t.parse::<f64>() {
        Ok(f) if f.is_finite() && f.fract() == 0.0 && f.abs() < 9.0e15 => Some((f as i64).to_string()),
        Ok(f) if f.is_finite() => serde_json::Number::from_f64(f).map(|x| x.to_string()),
        _ => None,
    }
}

/// Texto normalizado con el que se indexa un valor JSON: las cadenas tal cual, los números en forma
/// canónica, los booleanos como `true` / `false` y el resto como su JSON compacto.
pub fn index_key(val: &Value) -> String {
    match val {
        Value::String(s) => s.clone(),
        Value::Number(n) => canonical_number(n),
        Value::Bool(b) => b.to_string(),
        other => other.to_string(),
    }
}

/// Claves de índice con las que pudo guardarse el valor que escribe el usuario: el texto tal cual
/// (por si el campo es una cadena, p. ej. `"007"`) y, si parece un número, su forma canónica. Para
/// un entero como `7` coinciden y hay una sola clave. Los resultados siempre se verifican contra el
/// registro descifrado.
pub fn candidate_keys(query_value: &str) -> Vec<String> {
    let mut keys = vec![query_value.to_string()];
    if let Some(canonical) = canonical_from_text(query_value) {
        if canonical != query_value {
            keys.push(canonical);
        }
    }
    keys
}

/// Índice en memoria: hash -> offsets de bloque (en orden de inserción, es decir ascendente).
/// Un registro aporta una entrada por cada campo indexado que contiene.
pub struct ShadowIndex {
    entries: BTreeMap<u64, Vec<u64>>,
}

impl ShadowIndex {
    pub fn new() -> Self {
        Self { entries: BTreeMap::new() }
    }

    /// Número de claves distintas.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Entradas ordenadas por hash: hash -> offsets de bloque (ascendentes).
    pub fn entries(&self) -> &BTreeMap<u64, Vec<u64>> {
        &self.entries
    }

    /// Añade una entrada: `hash` es el hash con clave de (campo, valor) y `offset` el bloque del registro.
    pub fn add_hash(&mut self, hash: u64, offset: u64) {
        self.entries.entry(hash).or_default().push(offset);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn index_keys_per_json_type() {
        assert_eq!(index_key(&json!("abc")), "abc");
        assert_eq!(index_key(&json!(12.5)), "12.5");
        assert_eq!(index_key(&json!(7)), "7");
        assert_eq!(index_key(&json!(-7)), "-7");
        assert_eq!(index_key(&json!(true)), "true");
        assert_eq!(index_key(&json!(null)), "null");
    }

    #[test]
    fn numbers_have_one_canonical_key_whatever_their_spelling() {
        let parse = |t: &str| serde_json::from_str::<Value>(t).unwrap();
        for spelling in ["7", "7.0", "7.00", "0.7e1", "70e-1", "-0", "-0.0"] {
            let expected = if spelling.starts_with('-') { "0" } else { "7" };
            let key = index_key(&parse(spelling));
            if spelling.starts_with('-') {
                assert_eq!(key, "0", "{}", spelling);
            } else {
                assert_eq!(key, expected, "{}", spelling);
            }
        }
        assert_eq!(index_key(&parse("1e3")), "1000");
        assert_eq!(index_key(&parse("0.10")), "0.1");
        assert_eq!(index_key(&parse("12.50")), "12.5");
        assert_eq!(index_key(&parse("9007199254740993")), "9007199254740993", "exact integers keep every digit");
        assert_eq!(index_key(&parse("18446744073709551615")), "18446744073709551615");
    }

    #[test]
    fn a_query_value_has_one_candidate_key_when_it_is_already_canonical() {
        assert_eq!(candidate_keys("1000"), vec!["1000".to_string()]);
        assert_eq!(candidate_keys("7"), vec!["7".to_string()]);
        assert_eq!(candidate_keys("-3"), vec!["-3".to_string()]);
        assert_eq!(candidate_keys("PROD-1"), vec!["PROD-1".to_string()]);
        assert_eq!(candidate_keys(""), vec!["".to_string()]);
    }

    #[test]
    fn other_numeric_spellings_add_their_canonical_key() {
        assert_eq!(candidate_keys("12.50"), vec!["12.50".to_string(), "12.5".to_string()]);
        assert_eq!(candidate_keys("7.0"), vec!["7.0".to_string(), "7".to_string()]);
        assert_eq!(candidate_keys("007"), vec!["007".to_string(), "7".to_string()]);
        assert_eq!(candidate_keys("1e3"), vec!["1e3".to_string(), "1000".to_string()]);
        assert_eq!(candidate_keys("+5"), vec!["+5".to_string(), "5".to_string()]);
        assert_eq!(candidate_keys(" 7 "), vec![" 7 ".to_string(), "7".to_string()]);
        // no numéricos: nunca una segunda clave
        for text in ["NaN", "inf", "abc", "1.2.3", "0x10"] {
            assert_eq!(candidate_keys(text).len(), 1, "{}", text);
        }
    }

    #[test]
    fn lookup_field_supports_dotted_paths() {
        let doc = json!({"a": {"b": 5}, "x.y": 1});
        assert_eq!(lookup_field(&doc, "a.b"), Some(&json!(5)));
        assert_eq!(lookup_field(&doc, "x.y"), Some(&json!(1)));
        assert_eq!(lookup_field(&doc, "nope"), None);
    }

    #[test]
    fn entries_are_sorted_by_hash_and_keep_offsets_in_order() {
        let mut idx = ShadowIndex::new();
        idx.add_hash(30, 500);
        idx.add_hash(10, 128);
        idx.add_hash(30, 700);
        idx.add_hash(20, 300);
        assert_eq!(idx.len(), 3);

        let keys: Vec<u64> = idx.entries().keys().copied().collect();
        assert_eq!(keys, vec![10, 20, 30]);
        assert_eq!(idx.entries()[&30u64], vec![500, 700]);
    }
}
