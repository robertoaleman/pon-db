// SPDX-License-Identifier: AGPL-3.0-only
// PON-DB Engine: a database engine encapsulated in a single, portable, encrypted binary format
// Copyright (C) 2026 Roberto C. Aleman F.
// https://github.com/robertoaleman/pon-db
//
// Consultas: interpretación de criterios y evaluación sobre un registro JSON.
// No depende del formato de archivo.
use crate::block::corrupt;
use crate::index_manager::lookup_field;
use serde_json::Value;
use std::cmp::Ordering;
use std::io;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueryOp {
    Equal,
    NotEqual,
    GreaterThan,
    GreaterOrEqual,
    LessThan,
    LessOrEqual,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Query {
    pub field: String,
    pub op: QueryOp,
    pub value: String,
}

fn unquote(s: &str) -> &str {
    let b = s.as_bytes();
    if b.len() >= 2 {
        let first = b[0];
        let last = b[b.len() - 1];
        if (first == b'"' && last == b'"') || (first == b'\'' && last == b'\'') {
            return &s[1..s.len() - 1];
        }
    }
    s
}

/// Interpreta `campo<op>valor` con op en `= == != > >= < <=`.
/// Se corta en el PRIMER operador, de modo que el valor puede contener `=`, `>` o `<`.
pub fn parse_query(q: &str) -> io::Result<Query> {
    let b = q.as_bytes();
    for i in 0..b.len() {
        let c = b[i];
        let next_is_eq = i + 1 < b.len() && b[i + 1] == b'=';
        let (op, op_len) = match (c, next_is_eq) {
            (b'!', true) => (QueryOp::NotEqual, 2),
            (b'>', true) => (QueryOp::GreaterOrEqual, 2),
            (b'>', false) => (QueryOp::GreaterThan, 1),
            (b'<', true) => (QueryOp::LessOrEqual, 2),
            (b'<', false) => (QueryOp::LessThan, 1),
            (b'=', true) => (QueryOp::Equal, 2),
            (b'=', false) => (QueryOp::Equal, 1),
            _ => continue,
        };

        let field = q[..i].trim();
        if field.is_empty() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "query has no field name before the operator"));
        }
        let value = unquote(q[i + op_len..].trim());
        return Ok(Query {
            field: field.to_string(),
            op,
            value: value.to_string(),
        });
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        "invalid query: use <field><op><value> with op in = != > >= < <=",
    ))
}

/// Número JSON, o cadena que "parece" un número (empieza por dígito, signo o punto).
fn parse_num(s: &str) -> Option<f64> {
    let t = s.trim();
    let first = *t.as_bytes().first()?;
    if !(first.is_ascii_digit() || first == b'-' || first == b'+' || first == b'.') {
        return None;
    }
    t.parse::<f64>().ok().filter(|x| x.is_finite())
}

fn as_number(v: &Value) -> Option<f64> {
    match v {
        Value::Number(n) => n.as_f64(),
        Value::String(s) => parse_num(s),
        _ => None,
    }
}

fn value_equals(actual: &Value, target: &str) -> bool {
    match actual {
        Value::String(s) => s == target,
        Value::Number(n) => match (n.as_f64(), parse_num(target)) {
            (Some(a), Some(t)) => a == t,
            _ => n.to_string() == target,
        },
        Value::Bool(b) => b.to_string() == target,
        Value::Null => target == "null",
        other => other.to_string() == target,
    }
}

/// Compara numéricamente si ambos lados son números; como texto si ambos son texto;
/// en cualquier otro caso no hay orden (el registro no coincide).
fn compare(actual: &Value, target: &str) -> Option<Ordering> {
    match (as_number(actual), parse_num(target)) {
        (Some(a), Some(t)) => a.partial_cmp(&t),
        (None, None) => match actual {
            Value::String(s) => Some(s.as_str().cmp(target)),
            _ => None,
        },
        _ => None,
    }
}

/// Un registro sin el campo consultado nunca coincide (tampoco con `!=`).
fn matches_condition(doc: &Value, q: &Query) -> bool {
    match lookup_field(doc, &q.field) {
        Some(v) => matches_value(v, q),
        None => false,
    }
}

/// Aplica el operador de la consulta al valor ya localizado del campo.
fn matches_value(actual: &Value, q: &Query) -> bool {
    match q.op {
        QueryOp::Equal => value_equals(actual, &q.value),
        QueryOp::NotEqual => !value_equals(actual, &q.value),
        QueryOp::GreaterThan => compare(actual, &q.value) == Some(Ordering::Greater),
        QueryOp::GreaterOrEqual => matches!(
            compare(actual, &q.value),
            Some(Ordering::Greater) | Some(Ordering::Equal)
        ),
        QueryOp::LessThan => compare(actual, &q.value) == Some(Ordering::Less),
        QueryOp::LessOrEqual => matches!(
            compare(actual, &q.value),
            Some(Ordering::Less) | Some(Ordering::Equal)
        ),
    }
}

// ---------------------------------------------------------------------------------------------
// Camino rápido: localizar un campo de primer nivel sin construir el objeto JSON completo.
//
// Los registros son objetos JSON válidos (se validaron al ingerir y están autenticados). Se
// recorre el texto saltando cadenas y estructuras anidadas, sin reservar memoria, y solo el
// valor del campo buscado se interpreta con serde_json. Ante cualquier cosa inusual (claves con
// escapes no decodificables, sintaxis inesperada) se devuelve `Unsupported` y se usa el camino completo, de modo
// que el resultado es siempre el mismo que con `serde_json::from_slice` del objeto entero.
// ---------------------------------------------------------------------------------------------

enum Extract {
    Found(Value),
    Missing,
    Unsupported,
}

fn skip_ws(b: &[u8], mut i: usize) -> usize {
    while i < b.len() && matches!(b[i], b' ' | b'\n' | b'\r' | b'\t') {
        i += 1;
    }
    i
}

/// `b[i]` es la comilla de apertura; devuelve la posición siguiente a la comilla de cierre.
fn skip_string(b: &[u8], mut i: usize) -> Option<usize> {
    i += 1;
    while i < b.len() {
        match b[i] {
            b'\\' => i += 2,
            b'"' => return Some(i + 1),
            _ => i += 1,
        }
    }
    None
}

/// Devuelve la posición siguiente al valor JSON que empieza en `i`.
fn skip_value(b: &[u8], i: usize) -> Option<usize> {
    match *b.get(i)? {
        b'"' => skip_string(b, i),
        b'{' | b'[' => {
            let mut depth = 0usize;
            let mut j = i;
            loop {
                match *b.get(j)? {
                    b'"' => {
                        j = skip_string(b, j)?;
                        continue;
                    }
                    b'{' | b'[' => depth += 1,
                    b'}' | b']' => {
                        depth -= 1;
                        if depth == 0 {
                            return Some(j + 1);
                        }
                    }
                    _ => {}
                }
                j += 1;
            }
        }
        _ => {
            let mut j = i;
            while j < b.len() && !matches!(b[j], b',' | b'}' | b']' | b' ' | b'\n' | b'\r' | b'\t') {
                j += 1;
            }
            if j == i {
                None
            } else {
                Some(j)
            }
        }
    }
}

fn extract_top_level(plain: &[u8], field: &str) -> Extract {
    let key = field.as_bytes();
    if key.contains(&b'\\') || key.contains(&b'"') {
        return Extract::Unsupported;
    }

    let mut i = skip_ws(plain, 0);
    if plain.get(i) != Some(&b'{') {
        return Extract::Unsupported;
    }
    i += 1;

    let mut found: Option<(usize, usize)> = None;
    loop {
        i = skip_ws(plain, i);
        match plain.get(i) {
            Some(b'}') => break,
            Some(b'"') => {}
            _ => return Extract::Unsupported,
        }
        let after_key = match skip_string(plain, i) {
            Some(e) => e,
            None => return Extract::Unsupported,
        };
        let raw_key = &plain[i + 1..after_key - 1];
        // Una clave con escapes (p. ej. "pri\u0063e") se decodifica con serde_json antes de comparar.
        let is_target = if raw_key.contains(&b'\\') {
            match serde_json::from_slice::<String>(&plain[i..after_key]) {
                Ok(k) => k.as_bytes() == key,
                Err(_) => return Extract::Unsupported,
            }
        } else {
            raw_key == key
        };

        i = skip_ws(plain, after_key);
        if plain.get(i) != Some(&b':') {
            return Extract::Unsupported;
        }
        i = skip_ws(plain, i + 1);
        let value_end = match skip_value(plain, i) {
            Some(e) => e,
            None => return Extract::Unsupported,
        };
        if is_target {
            found = Some((i, value_end)); // con claves repetidas, serde_json se queda con la última
        }

        i = skip_ws(plain, value_end);
        match plain.get(i) {
            Some(b',') => i += 1,
            Some(b'}') => break,
            _ => return Extract::Unsupported,
        }
    }

    match found {
        None => Extract::Missing,
        Some((s, e)) => match serde_json::from_slice::<Value>(&plain[s..e]) {
            Ok(v) => Extract::Found(v),
            Err(_) => Extract::Unsupported,
        },
    }
}

// ---------------------------------------------------------------------------------------------
// Expresiones: condiciones unidas con AND y OR (AND tiene precedencia sobre OR; sin paréntesis).
// ---------------------------------------------------------------------------------------------

/// Expresión en forma normal disyuntiva: un OR de grupos, cada grupo es un AND de condiciones.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Expr {
    pub groups: Vec<Vec<Query>>,
}

enum Piece {
    Pred(String),
    And,
    Or,
}

fn is_ws(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\n' | b'\r')
}

/// `AND` / `OR` en mayúsculas en la posición `i`, seguidos de un blanco o del final del texto.
fn keyword_at(b: &[u8], i: usize) -> Option<(Piece, usize)> {
    let end_ok = |len: usize| i + len == b.len() || is_ws(b[i + len]);
    if b[i..].starts_with(b"AND") && end_ok(3) {
        return Some((Piece::And, 3));
    }
    if b[i..].starts_with(b"OR") && end_ok(2) {
        return Some((Piece::Or, 2));
    }
    None
}

fn bad_expression(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, msg.to_string())
}

/// Divide el texto en condiciones y operadores. Una palabra `AND` / `OR` en mayúsculas rodeada de
/// blancos es un operador, salvo dentro de un valor entre comillas (`name="Tom AND Jerry"`). Una comilla
/// solo abre un valor si va justo tras un operador de comparación, así que `O'Brien` no la abre.
fn split_expression(input: &str) -> io::Result<Vec<Piece>> {
    let b = input.as_bytes();
    let n = b.len();

    let mut lead = 0;
    while lead < n && is_ws(b[lead]) {
        lead += 1;
    }
    if lead < n && keyword_at(b, lead).is_some() {
        return Err(bad_expression("a condition cannot start with AND / OR"));
    }

    let mut pieces: Vec<Piece> = Vec::new();
    let mut start = 0usize;
    let mut i = 0usize;
    let mut quote: Option<u8> = None;
    let mut prev: u8 = 0; // último byte no blanco visto

    while i < n {
        let c = b[i];
        if let Some(q) = quote {
            if c == q {
                quote = None;
            }
            prev = c;
            i += 1;
            continue;
        }
        if (c == b'"' || c == b'\'') && matches!(prev, b'=' | b'<' | b'>' | b'!') {
            quote = Some(c);
            prev = c;
            i += 1;
            continue;
        }
        if is_ws(c) {
            let mut j = i;
            while j < n && is_ws(b[j]) {
                j += 1;
            }
            if j < n {
                if let Some((kw, kw_len)) = keyword_at(b, j) {
                    pieces.push(Piece::Pred(input[start..i].to_string()));
                    pieces.push(kw);
                    let mut k = j + kw_len;
                    while k < n && is_ws(b[k]) {
                        k += 1;
                    }
                    start = k;
                    i = k;
                    prev = 0;
                    continue;
                }
            }
            i = j;
            continue;
        }
        prev = c;
        i += 1;
    }
    pieces.push(Piece::Pred(input[start..].to_string()));
    Ok(pieces)
}

/// Interpreta `cond [AND cond]... [OR cond [AND cond]...]...`.
pub fn parse_expression(input: &str) -> io::Result<Expr> {
    let pieces = split_expression(input)?;
    let mut groups: Vec<Vec<Query>> = vec![Vec::new()];

    for piece in pieces {
        match piece {
            Piece::Pred(text) => {
                let t = text.trim();
                if t.is_empty() {
                    return Err(bad_expression("missing condition next to AND / OR"));
                }
                if keyword_at(t.as_bytes(), 0).is_some() {
                    return Err(bad_expression("two operators in a row (AND / OR)"));
                }
                let q = parse_query(t)?;
                let last = groups.len() - 1;
                groups[last].push(q);
            }
            Piece::And => {}
            Piece::Or => groups.push(Vec::new()),
        }
    }
    Ok(Expr { groups })
}

// ---------------------------------------------------------------------------------------------
// Evaluación de una expresión sobre un registro.
// ---------------------------------------------------------------------------------------------

/// Evalúa una condición. `full` guarda el documento completo: solo se interpreta si hace falta
/// (rutas con punto o JSON inusual) y se reutiliza para el resto de condiciones del registro.
fn pred_matches(plain: &[u8], q: &Query, full: &mut Option<Value>) -> io::Result<bool> {
    // Las rutas con punto (`a.b`) tienen su propia regla de búsqueda: van por el camino completo.
    if !q.field.contains('.') {
        match extract_top_level(plain, &q.field) {
            Extract::Found(v) => return Ok(matches_value(&v, q)),
            Extract::Missing => return Ok(false),
            Extract::Unsupported => {}
        }
    }
    if full.is_none() {
        let doc: Value = serde_json::from_slice(plain)
            .map_err(|e| corrupt(format!("stored record is not valid JSON: {}", e)))?;
        *full = Some(doc);
    }
    Ok(match full.as_ref() {
        Some(doc) => matches_condition(doc, q),
        None => false,
    })
}

/// ¿Cumple el registro la expresión? Cada condición usa el camino rápido cuando es posible.
pub(crate) fn expr_matches(plain: &[u8], expr: &Expr) -> io::Result<bool> {
    let mut full: Option<Value> = None;
    for group in &expr.groups {
        let mut all = true;
        for q in group {
            if !pred_matches(plain, q, &mut full)? {
                all = false;
                break;
            }
        }
        if all {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Camino completo: interpreta el registro entero. Es la referencia de la semántica.
#[cfg(test)]
pub(crate) fn expr_matches_full(plain: &[u8], expr: &Expr) -> io::Result<bool> {
    let doc: Value = serde_json::from_slice(plain)
        .map_err(|e| corrupt(format!("stored record is not valid JSON: {}", e)))?;
    Ok(expr.groups.iter().any(|g| g.iter().all(|q| matches_condition(&doc, q))))
}

/// El texto del registro si cumple la expresión.
pub(crate) fn record_if_matches(plain: &[u8], expr: &Expr) -> io::Result<Option<String>> {
    if expr_matches(plain, expr)? {
        Ok(Some(String::from_utf8_lossy(plain).into_owned()))
    } else {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn p(s: &str) -> Query {
        parse_query(s).unwrap()
    }

    #[test]
    fn parses_every_operator() {
        assert_eq!(p("a=1").op, QueryOp::Equal);
        assert_eq!(p("a==1").op, QueryOp::Equal);
        assert_eq!(p("a!=1").op, QueryOp::NotEqual);
        assert_eq!(p("a>1").op, QueryOp::GreaterThan);
        assert_eq!(p("a>=1").op, QueryOp::GreaterOrEqual);
        assert_eq!(p("a<1").op, QueryOp::LessThan);
        assert_eq!(p("a<=1").op, QueryOp::LessOrEqual);
        assert_eq!(p("price >= 500").value, "500");
        assert_eq!(p("price >= 500").field, "price");
    }

    #[test]
    fn value_may_contain_operator_characters_and_quotes() {
        assert_eq!(p("name=a=b").value, "a=b");
        assert_eq!(p("expr=x>=y").value, "x>=y");
        assert_eq!(p("name=\"Smith, John\"").value, "Smith, John");
        assert_eq!(p("name='O''Brien'").value, "O''Brien");
        assert_eq!(p("name=").value, "");
    }

    #[test]
    fn rejects_malformed_queries() {
        assert!(parse_query("no operator here").is_err());
        assert!(parse_query("=5").is_err());
        assert!(parse_query("").is_err());
        assert!(parse_query("only!bang").is_err());
    }

    #[test]
    fn non_ascii_text_does_not_panic() {
        let q = p("ciudad=Mérida");
        assert_eq!(q.value, "Mérida");
        assert_eq!(p("ñame=ü").field, "ñame");
    }

    #[test]
    fn numeric_comparisons_exclude_non_numeric_values() {
        let q = p("price>-5");
        assert!(matches_condition(&json!({"price": 3}), &q));
        assert!(matches_condition(&json!({"price": "3.5"}), &q));
        assert!(!matches_condition(&json!({"price": "N/A"}), &q));
        assert!(!matches_condition(&json!({"price": null}), &q));
        assert!(!matches_condition(&json!({"other": 1}), &q));
    }

    #[test]
    fn inclusive_operators_include_the_boundary() {
        let doc = json!({"price": 500});
        assert!(matches_condition(&doc, &p("price>=500")));
        assert!(!matches_condition(&doc, &p("price>500")));
        assert!(matches_condition(&doc, &p("price<=500")));
        assert!(!matches_condition(&doc, &p("price<500")));
    }

    #[test]
    fn equality_handles_strings_numbers_and_commas() {
        assert!(matches_condition(&json!({"name": "Smith, John"}), &p("name=\"Smith, John\"")));
        assert!(matches_condition(&json!({"price": 12.5}), &p("price=12.50")));
        assert!(!matches_condition(&json!({"price": 12.5}), &p("price=12.6")));
        assert!(matches_condition(&json!({"ok": true}), &p("ok=true")));
        assert!(matches_condition(&json!({"a": 1}), &p("a!=2")));
    }

    #[test]
    fn nested_and_dotted_fields() {
        let doc = json!({"a": {"price": 1}, "price": 2});
        assert!(matches_condition(&doc, &p("price=2")));
        assert!(matches_condition(&doc, &p("a.price=1")));
        assert!(!matches_condition(&doc, &p("a.price=2")));
    }

    #[test]
    fn the_fast_path_agrees_with_a_full_parse() {
        let docs = [
            r#"{"id":1,"price":12.5,"name":"a","ok":true,"n":null,"tag":"x"}"#,
            "{\n  \"id\" : 2 ,\n  \"price\" : 10 ,\n  \"name\" : \"x, y\"\n}",
            r#"{"a":{"id":99,"price":1},"id":1,"price":12.50}"#,
            r#"{"id":1,"id":2,"price":5}"#,
            r#"{"name":"he said \"hi\", {ok}","id":3,"s":"a\"b"}"#,
            r#"{"pri\u0063e": 7, "id": 4}"#,
            r#"{"id":5,"friends":[{"id":6}],"price":{"x":1}}"#,
            r#"{"id":1e0,"price":-0.5,"name":"007"}"#,
            r#"{}"#,
            r#"{"id":"1","price":"N/A"}"#,
            r#"{"name":"Mérida","id":8}"#,
            r#"{"s":"\\","id":9,"t":"}"}"#,
            r#"{"a":[1,[2,{"id":77}]],"id":10}"#,
        ];
        let queries = [
            "id=1", "id=2", "id<2", "id>=1", "id!=1", "price>10", "price=12.5", "price!=12.5",
            "price<=10", "name=a", "name=\"x, y\"", "name=007", "name=Mérida", "ok=true", "n=null",
            "tag=x", "missing=1", "s=a\"b", "s=}", "t=}", "a=1", "friends=1", "price=N/A",
            "id=1 AND price>10", "id=1 OR id=2", "id=2 AND name=\"x, y\" OR price<=10",
            "missing=1 OR id=3", "ok=true AND n=null AND tag=x", "a.id=99 AND id=1", "id=4 OR a.id=77",
        ];
        for d in docs {
            for qs in queries {
                let e = parse_expression(qs).unwrap();
                let fast = expr_matches(d.as_bytes(), &e).unwrap();
                let full = expr_matches_full(d.as_bytes(), &e).unwrap();
                assert_eq!(fast, full, "doc={} query={}", d, qs);
            }
        }
    }

    #[test]
    fn dotted_paths_still_use_the_full_semantics() {
        let doc = r#"{"a":{"id":99},"id":1}"#;
        let e = parse_expression("a.id=99").unwrap();
        assert!(record_if_matches(doc.as_bytes(), &e).unwrap().is_some());
        let e = parse_expression("a.id=99 AND id=1").unwrap();
        assert!(record_if_matches(doc.as_bytes(), &e).unwrap().is_some());
        let e = parse_expression("a.id=98 OR id=2").unwrap();
        assert!(record_if_matches(doc.as_bytes(), &e).unwrap().is_none());
    }

    fn shape(e: &Expr) -> Vec<Vec<String>> {
        e.groups
            .iter()
            .map(|g| g.iter().map(|q| format!("{}:{:?}:{}", q.field, q.op, q.value)).collect())
            .collect()
    }

    fn ex(s: &str) -> Expr {
        parse_expression(s).unwrap()
    }

    #[test]
    fn expressions_group_conditions_with_and_binding_tighter_than_or() {
        assert_eq!(shape(&ex("a=1")), vec![vec!["a:Equal:1"]]);
        assert_eq!(
            shape(&ex("a=1 AND b>2 AND c!=x")),
            vec![vec!["a:Equal:1", "b:GreaterThan:2", "c:NotEqual:x"]]
        );
        assert_eq!(shape(&ex("a=1 OR b=2")), vec![vec!["a:Equal:1"], vec!["b:Equal:2"]]);
        assert_eq!(
            shape(&ex("a=1 OR b=2 AND c=3")),
            vec![vec!["a:Equal:1"], vec!["b:Equal:2", "c:Equal:3"]]
        );
        assert_eq!(
            shape(&ex("  price >= 5   AND  sku = 'S3' ")),
            vec![vec!["price:GreaterOrEqual:5", "sku:Equal:S3"]]
        );
    }

    #[test]
    fn quotes_protect_operators_and_apostrophes_do_not_open_quotes() {
        assert_eq!(
            shape(&ex("name=\"Tom AND Jerry\" AND id=3")),
            vec![vec!["name:Equal:Tom AND Jerry", "id:Equal:3"]]
        );
        assert_eq!(
            shape(&ex("name='a OR b' OR id=3")),
            vec![vec!["name:Equal:a OR b"], vec!["id:Equal:3"]]
        );
        assert_eq!(
            shape(&ex("name=O'Brien AND id=3")),
            vec![vec!["name:Equal:O'Brien", "id:Equal:3"]]
        );
        // minúsculas y palabras pegadas a otras no son operadores
        assert_eq!(shape(&ex("a=x and y")), vec![vec!["a:Equal:x and y"]]);
        assert_eq!(shape(&ex("a=1 ANDROID=2")), vec![vec!["a:Equal:1 ANDROID=2"]]);
    }

    #[test]
    fn malformed_expressions_are_rejected() {
        for bad in [
            "", "   ", "AND a=1", "OR a=1", "a=1 AND", "a=1 OR", "a=1 AND AND b=2", "a=1 OR AND b=2",
            "a=1 AND b", "a=1 AND  ",
        ] {
            assert!(parse_expression(bad).is_err(), "{:?} should be rejected", bad);
        }
    }

    #[test]
    fn expressions_evaluate_with_and_or_semantics() {
        let doc = r#"{"id":7,"sku":"S7","price":70}"#.as_bytes();
        let m = |s: &str| expr_matches(doc, &ex(s)).unwrap();
        assert!(m("id=7 AND sku=S7"));
        assert!(!m("id=7 AND sku=S8"));
        assert!(m("id=1 OR sku=S7"));
        assert!(!m("id=1 OR sku=S8"));
        assert!(m("id=1 AND sku=S1 OR price>=70"));
        assert!(!m("id=1 AND sku=S7 OR price>70"));
        assert!(!m("missing=1 OR other=2"));
    }

    #[test]
    fn text_comparison_is_lexicographic_when_both_sides_are_text() {
        assert!(matches_condition(&json!({"s": "beta"}), &p("s>alpha")));
        assert!(!matches_condition(&json!({"s": "alpha"}), &p("s>beta")));
    }
}
