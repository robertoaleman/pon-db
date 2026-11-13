// SPDX-License-Identifier: AGPL-3.0-only
// PON-DB Engine: a database engine encapsulated in a single, portable, encrypted binary format
// Copyright (C) 2026 Roberto C. Aleman F.
// https://github.com/robertoaleman/pon-db
use crate::block::{corrupt, read_block, RawBlock, BLOCK_HEADER, BLOCK_OVERHEAD};
use crate::index_manager::{candidate_keys, index_key, lookup_field, COLLISION_FLAG};
use crate::query_engine::{parse_expression, record_if_matches, Expr, Query, QueryOp};
use crate::scanner::MAX_RECORD_LEN;
use crate::v9::header::{HeaderV9, FOOTER_LEN, HEADER9_SIZE, PAGE_DATA_LEN, PAGE_ENTRIES, PAGE_SIZE, TAG_LEN};
use crate::v9::keys::{ct_eq, BlockCipher9, IndexHasher, Keys9, PageMac};
use crate::v9::pages::natural_page;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
use std::sync::{Arc, Mutex, MutexGuard};
use zeroize::Zeroizing;

/// Resultado de una exportación.
pub struct ExportSummary {
    /// Registros exportados (todos pasaron la verificación AES-GCM).
    pub rows: u32,
    /// SHA-256 de la concatenación de los registros exportados (informativo).
    pub sha256: [u8; 32],
}

fn le_u64(b: &[u8]) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[..8]);
    u64::from_le_bytes(a)
}

/// Tamaño de cada lectura del hilo lector (8 MiB). En los tests es pequeño para ejercitar muchos
/// trozos y el caso de un registro mayor que el trozo.
const CHUNK_BYTES: usize = if cfg!(test) { 4096 } else { 8 * 1024 * 1024 };

/// Hilos de trabajo: `PON_THREADS` si es un entero >= 1; si no, todos los núcleos disponibles.
fn worker_threads() -> usize {
    if let Some(n) = std::env::var("PON_THREADS")
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
    {
        if n >= 1 {
            return n.min(256);
        }
    }
    std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1)
}

/// Lectura por posición: no depende ni modifica el cursor del archivo, así que `&File` se puede
/// compartir entre hilos y entre consultas de un proceso de larga vida.
#[cfg(unix)]
fn read_exact_at(file: &File, buf: &mut [u8], offset: u64) -> io::Result<()> {
    use std::os::unix::fs::FileExt;
    file.read_exact_at(buf, offset)
}

#[cfg(windows)]
fn read_exact_at(file: &File, mut buf: &mut [u8], mut offset: u64) -> io::Result<()> {
    use std::os::windows::fs::FileExt;
    while !buf.is_empty() {
        match file.seek_read(buf, offset) {
            Ok(0) => break,
            Ok(n) => {
                buf = &mut buf[n..];
                offset += n as u64;
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    if buf.is_empty() {
        Ok(())
    } else {
        Err(io::Error::new(io::ErrorKind::UnexpectedEof, "failed to fill whole buffer"))
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Páginas del índice ya autenticadas (las más recientes; al llenarse sale la más antigua).
const PAGE_CACHE_CAPACITY: usize = 4096; // 4096 × 4 KiB = 16 MiB como máximo

/// Una consulta usa el índice si los candidatos no superan `max(1024, filas / 32)`: por encima de eso,
/// el recorrido paralelo y secuencial es más rápido que miles de lecturas aleatorias.
const INDEX_MAX_DIVISOR: u64 = 32;
const INDEX_MIN_LIMIT: u64 = 1024;

struct PageCache {
    map: HashMap<u64, Arc<Vec<u8>>>,
    order: VecDeque<u64>,
    capacity: usize,
}

impl PageCache {
    fn new(capacity: usize) -> Self {
        Self { map: HashMap::new(), order: VecDeque::new(), capacity }
    }

    fn get(&self, key: u64) -> Option<Arc<Vec<u8>>> {
        self.map.get(&key).cloned()
    }

    fn insert(&mut self, key: u64, value: Arc<Vec<u8>>) {
        if self.map.insert(key, value).is_none() {
            self.order.push_back(key);
            while self.order.len() > self.capacity {
                if let Some(old) = self.order.pop_front() {
                    self.map.remove(&old);
                }
            }
        }
    }
}

/// Resultado de sondear el índice para una condición.
struct Probe {
    /// Punteros de las entradas de índice halladas (una por ortografía candidata del valor).
    ptrs: Vec<u64>,
    /// Registros que comparten esas entradas.
    size: u64,
}

enum Plan {
    /// Offsets de los registros candidatos (ordenados, sin repetidos); hay que verificar la expresión.
    Index(Vec<u64>),
    /// Recorrer todo el cuerpo de datos.
    Scan,
}

/// Un trozo contiguo del cuerpo de datos que contiene bloques completos.
struct Chunk {
    /// Offset del archivo en el que empieza `data`.
    base: u64,
    data: Vec<u8>,
    /// Por cada bloque: (posición dentro de `data`, longitud total), en orden de archivo.
    blocks: Vec<(usize, usize)>,
}

type ChunkMessage = io::Result<Chunk>;

/// Añade `want` bytes más a `data` con una sola lectura grande (sin poner a cero el espacio antes).
fn fill(file: &mut File, data: &mut Vec<u8>, want: usize) -> io::Result<()> {
    let before = data.len();
    // `File` implementa `Read` y `Write`, y ambos tienen `by_ref`: se nombra el de `Read`.
    Read::by_ref(file).take(want as u64).read_to_end(data)?;
    if data.len() - before != want {
        return Err(corrupt("truncated data body"));
    }
    Ok(())
}

/// Hilo lector. Lee el cuerpo de datos en trozos grandes (una lectura por trozo, no cuatro por registro)
/// y solo recorre las longitudes para delimitar los bloques: no copia ni reserva memoria por registro.
/// Un bloque que queda cortado al final del trozo se arrastra al siguiente; un registro mayor que el
/// trozo se completa leyendo más. Ante un error entrega antes los bloques ya delimitados y después el
/// error, de modo que los fallos se notifican en el orden del archivo.
fn read_chunks(path: &Path, start: u64, end: u64, tx: &SyncSender<ChunkMessage>) {
    let opened = File::open(path).and_then(|mut f| {
        f.seek(SeekFrom::Start(start))?;
        Ok(f)
    });
    let mut file = match opened {
        Ok(f) => f,
        Err(e) => {
            let _ = tx.send(Err(e));
            return;
        }
    };

    let mut pos = start; // offset del archivo de data[0]
    let mut data: Vec<u8> = Vec::new(); // bytes leídos y aún no entregados
    let mut target = CHUNK_BYTES; // tamaño que se intenta tener en `data`

    while pos < end {
        // 1) leer hasta `target` bytes sin salirse de la región de datos
        let unread = end - pos - data.len() as u64;
        let want = (target.saturating_sub(data.len()) as u64).min(unread) as usize;
        if want > 0 {
            if let Err(e) = fill(&mut file, &mut data, want) {
                let _ = tx.send(Err(e));
                return;
            }
        }

        // 2) delimitar los bloques completos
        let mut blocks: Vec<(usize, usize)> = Vec::new();
        let mut p = 0usize;
        let mut failure: Option<io::Error> = None;
        while data.len() - p >= BLOCK_HEADER {
            let len = u32::from_le_bytes([data[p], data[p + 1], data[p + 2], data[p + 3]]) as u64;
            if len > MAX_RECORD_LEN as u64 {
                failure = Some(corrupt("record larger than the supported maximum"));
                break;
            }
            let total = len + BLOCK_OVERHEAD;
            if total > end - (pos + p as u64) {
                failure = Some(corrupt("block length exceeds the available data"));
                break;
            }
            if ((data.len() - p) as u64) < total {
                break; // bloque incompleto: faltan bytes
            }
            blocks.push((p, total as usize));
            p += total as usize;
        }

        // 3) entregar lo delimitado
        if blocks.is_empty() {
            if let Some(e) = failure {
                let _ = tx.send(Err(e));
                return;
            }
            if pos + data.len() as u64 >= end {
                let _ = tx.send(Err(corrupt("truncated data block")));
                return;
            }
            target = data.len() + CHUNK_BYTES; // un registro mayor que el trozo: seguir leyendo
            continue;
        }
        let leftover = data.split_off(p);
        let chunk = Chunk { base: pos, data, blocks };
        // Si el consumidor ya terminó (error), `send` falla y el lector se detiene.
        if tx.send(Ok(chunk)).is_err() {
            return;
        }
        pos += p as u64;
        data = leftover;
        target = CHUNK_BYTES;
        if let Some(e) = failure {
            let _ = tx.send(Err(e));
            return;
        }
    }
}

/// Un `.pon` V9 abierto y con su estructura autenticada.
///
/// `open` verifica el pie HMAC de la cabecera antes de fiarse de ningún offset y lee el bloque de
/// metadatos: su coste no depende del tamaño del archivo. Después, cada página del índice, cada tabla de
/// coincidencias y cada bloque se autentican justo antes de usarse, así que una consulta por clave lee
/// como mucho `max_probe` páginas de 4 KiB y el registro.
pub struct Reader9 {
    path: PathBuf,
    /// Abierto una vez; las lecturas puntuales usan `read_exact_at`.
    file: File,
    header: HeaderV9,
    keys: Keys9,
    cipher: BlockCipher9,
    hasher: IndexHasher,
    /// Campos indexados, leídos del bloque de metadatos (cifrado y autenticado).
    indexed_fields: Vec<String>,
    page_mac: PageMac,
    page_cache: Mutex<PageCache>,
    page_hits: AtomicU64,
    page_misses: AtomicU64,
}

/// Extrae la lista de campos indexados del bloque de metadatos descifrado.
fn parse_metadata(plain: &[u8]) -> io::Result<Vec<String>> {
    let v: serde_json::Value = serde_json::from_slice(plain)
        .map_err(|e| corrupt(format!("invalid metadata block: {}", e)))?;
    let list = v
        .get("indexed_fields")
        .and_then(|f| f.as_array())
        .ok_or_else(|| corrupt("metadata block lacks the indexed_fields list"))?;
    let mut fields = Vec::with_capacity(list.len());
    for f in list {
        match f.as_str() {
            Some(name) => fields.push(name.to_string()),
            None => return Err(corrupt("indexed field names must be strings")),
        }
    }
    Ok(fields)
}

impl Reader9 {
    pub fn open(path: &Path, master_key: &[u8; 32]) -> io::Result<Self> {
        let mut file = File::open(path)?;
        let file_len = file.metadata()?.len();
        if file_len < HEADER9_SIZE as u64 + FOOTER_LEN {
            return Err(corrupt("file is too small to be a PON V9 file"));
        }

        let mut header_bytes = [0u8; HEADER9_SIZE];
        file.read_exact(&mut header_bytes)?;
        let header = HeaderV9::from_bytes(&header_bytes)?;
        header.check_layout(file_len)?;

        let keys = Keys9::derive(master_key, &header.file_id)?;

        // El pie autentica la cabecera completa (offsets, geometría del índice, capacidades).
        let mut footer = [0u8; FOOTER_LEN as usize];
        file.seek(SeekFrom::Start(file_len - FOOTER_LEN))?;
        file.read_exact(&mut footer)?;
        let expected = keys.footer_mac(&header_bytes)?;
        if !ct_eq(&expected, &footer) {
            return Err(corrupt(
                "structure authentication failed: wrong master key, or the file header was modified",
            ));
        }

        // Metadatos: justo tras la cabecera; cifrados con su propia clave y ligados a su posición.
        file.seek(SeekFrom::Start(HEADER9_SIZE as u64))?;
        let meta_block = read_block(&mut file, header.meta_len as u64)?;
        if meta_block.encoded_len() != header.meta_len as u64 {
            return Err(corrupt("metadata block length does not match the header"));
        }
        let meta_plain = keys.metadata_cipher(&header.file_id).open(&meta_block, HEADER9_SIZE as u64)?;
        let indexed_fields = parse_metadata(&meta_plain[..])?;

        let cipher = keys.block_cipher(&header.file_id);
        let hasher = keys.index_hasher();
        let page_mac = keys.page_mac();
        Ok(Self {
            path: path.to_path_buf(),
            file,
            header,
            keys,
            cipher,
            hasher,
            indexed_fields,
            page_mac,
            page_cache: Mutex::new(PageCache::new(PAGE_CACHE_CAPACITY)),
            page_hits: AtomicU64::new(0),
            page_misses: AtomicU64::new(0),
        })
    }

    #[cfg(test)]
    pub fn header(&self) -> &HeaderV9 {
        &self.header
    }

    /// Campos que tienen índice (leídos de los metadatos cifrados).
    pub fn indexed_fields(&self) -> &[String] {
        &self.indexed_fields
    }

    pub fn total_rows(&self) -> u32 {
        self.header.total_rows
    }

    /// (aciertos, fallos) de la caché de páginas autenticadas del índice.
    pub fn page_cache_stats(&self) -> (u64, u64) {
        (self.page_hits.load(Ordering::Relaxed), self.page_misses.load(Ordering::Relaxed))
    }

    /// Página del índice ya autenticada: de la caché o leída del disco (un `pread` de 4 KiB y una
    /// etiqueta GMAC). Se autentica la primera vez que se lee; en un proceso de larga vida las
    /// consultas siguientes la encuentran ya verificada.
    fn page(&self, page_no: usize) -> io::Result<Arc<Vec<u8>>> {
        if let Some(bytes) = lock(&self.page_cache).get(page_no as u64) {
            self.page_hits.fetch_add(1, Ordering::Relaxed);
            return Ok(bytes);
        }
        self.page_misses.fetch_add(1, Ordering::Relaxed);

        let mut bytes = vec![0u8; PAGE_SIZE];
        let at = self.header.index_table_offset + (page_no as u64) * PAGE_SIZE as u64;
        read_exact_at(&self.file, &mut bytes, at)?;
        if !self.page_mac.verify(page_no as u64, &bytes[..PAGE_DATA_LEN], &bytes[PAGE_DATA_LEN..])? {
            return Err(corrupt(format!("index page {} failed authentication", page_no)));
        }
        let shared = Arc::new(bytes);
        lock(&self.page_cache).insert(page_no as u64, Arc::clone(&shared));
        Ok(shared)
    }

    /// Puntero de la entrada de índice con este hash. Lee como mucho `max_probe` páginas, y esa cota
    /// está en la cabecera autenticada: el coste no depende del tamaño del archivo (O(1)).
    fn lookup_ptr(&self, target: u64) -> io::Result<Option<u64>> {
        if self.header.page_count == 0 {
            return Ok(None);
        }
        let natural = natural_page(target, self.header.bucket_count as usize);
        for i in 0..self.header.max_probe as usize {
            let page_no = natural + i;
            if page_no >= self.header.page_count as usize {
                break;
            }
            let page = self.page(page_no)?;
            for slot in 0..PAGE_ENTRIES {
                let o = slot * 16;
                let ptr = le_u64(&page[o + 8..o + 16]);
                if ptr == 0 {
                    return Ok(None); // página sin llenar: aquí termina la cadena de sondeo
                }
                if le_u64(&page[o..o + 8]) == target {
                    return Ok(Some(ptr));
                }
            }
            // página llena y sin la clave: sigue en la siguiente
        }
        Ok(None)
    }

    fn check_coincidence_ptr(&self, pos: u64) -> io::Result<()> {
        let region_start = self.header.coincidence_table_offset;
        let region_end = self.header.index_table_offset;
        if pos < region_start || pos.saturating_add(4 + TAG_LEN) > region_end {
            return Err(corrupt("coincidence pointer outside its table region"));
        }
        Ok(())
    }

    /// Registros que comparten una entrada de índice: 1, o la cuenta de su tabla de coincidencias.
    /// La cuenta se lee sin autenticar la tabla porque solo sirve para elegir el plan: los datos se
    /// autentican al usarlos y el resultado siempre se verifica contra el registro descifrado.
    fn group_len(&self, ptr: u64) -> io::Result<u64> {
        if (ptr & COLLISION_FLAG) == 0 {
            return Ok(1);
        }
        let pos = ptr & !COLLISION_FLAG;
        self.check_coincidence_ptr(pos)?;
        let mut count = [0u8; 4];
        read_exact_at(&self.file, &mut count, pos)?;
        Ok(u32::from_le_bytes(count) as u64)
    }

    /// Convierte el puntero de una entrada de índice en offsets de bloques (autenticando la tabla).
    fn resolve(&self, ptr: u64) -> io::Result<Vec<u64>> {
        if (ptr & COLLISION_FLAG) == 0 {
            return Ok(vec![ptr]);
        }
        let pos = ptr & !COLLISION_FLAG;
        self.check_coincidence_ptr(pos)?;
        let region_end = self.header.index_table_offset;

        let mut count_bytes = [0u8; 4];
        read_exact_at(&self.file, &mut count_bytes, pos)?;
        let count = u32::from_le_bytes(count_bytes) as u64;
        let table_len = 4 + count * 8;
        if table_len + TAG_LEN > region_end - pos {
            return Err(corrupt("coincidence table exceeds its region"));
        }

        let mut raw = vec![0u8; (table_len + TAG_LEN) as usize];
        read_exact_at(&self.file, &mut raw, pos)?;
        let (table, tag) = raw.split_at(table_len as usize);
        let expected = self.keys.coincidence_tag(&self.header.file_id, pos, table)?;
        if !ct_eq(&expected, tag) {
            return Err(corrupt(format!("coincidence table at offset {} failed authentication", pos)));
        }
        Ok(table[4..].chunks_exact(8).map(le_u64).collect())
    }

    /// Lee el bloque que empieza en `offset`. Una lectura especulativa de 2 KiB suele bastar para el
    /// registro entero (un solo `pread`); si no, se lee el resto.
    fn read_block_at(&self, offset: u64) -> io::Result<RawBlock> {
        let end = self.header.coincidence_table_offset;
        if offset < self.header.body_offset || offset >= end {
            return Err(corrupt(format!("record offset {} is outside the data body", offset)));
        }
        let remaining = end - offset;
        if remaining < BLOCK_OVERHEAD {
            return Err(corrupt("truncated data block"));
        }

        let first = remaining.min(2048) as usize;
        let mut buf = vec![0u8; first];
        read_exact_at(&self.file, &mut buf, offset)?;
        let len = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as u64;
        if len > MAX_RECORD_LEN as u64 {
            return Err(corrupt("record larger than the supported maximum"));
        }
        if len + BLOCK_OVERHEAD > remaining {
            return Err(corrupt("block length exceeds the available data"));
        }
        let total = (len + BLOCK_OVERHEAD) as usize;
        if total > first {
            buf.resize(total, 0);
            read_exact_at(&self.file, &mut buf[first..], offset + first as u64)?;
        }

        let tag_at = BLOCK_HEADER + len as usize;
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&buf[tag_at..tag_at + 16]);
        buf.truncate(tag_at);
        buf.drain(..BLOCK_HEADER);
        Ok(RawBlock { ciphertext: buf, tag })
    }

    fn read_record(&self, offset: u64) -> io::Result<Zeroizing<Vec<u8>>> {
        let block = self.read_block_at(offset)?;
        self.cipher.open(&block, offset)
    }

    /// ¿Se puede resolver esta condición con el índice? Solo la igualdad sobre un campo indexado.
    fn is_indexed_eq(&self, q: &Query) -> bool {
        q.op == QueryOp::Equal && self.indexed_fields.iter().any(|f| *f == q.field)
    }

    /// Sondea el índice para `campo=valor` (probando las ortografías equivalentes del valor).
    fn probe(&self, q: &Query) -> io::Result<Probe> {
        let mut ptrs: Vec<u64> = Vec::new();
        let mut size: u64 = 0;
        for key in candidate_keys(&q.value) {
            let hash = self.hasher.hash(&q.field, key.as_bytes())?;
            if let Some(ptr) = self.lookup_ptr(hash)? {
                size = size.saturating_add(self.group_len(ptr)?);
                ptrs.push(ptr);
            }
        }
        Ok(Probe { ptrs, size })
    }

    fn index_limit(&self) -> u64 {
        (self.header.total_rows as u64 / INDEX_MAX_DIVISOR).max(INDEX_MIN_LIMIT)
    }

    /// Elige cómo resolver la expresión.
    ///
    /// Cada grupo AND necesita un "conductor": de sus igualdades sobre campos indexados se toma la más
    /// selectiva (la que reúne menos registros, que se conoce antes de leer ningún bloque). Los
    /// candidatos de todos los grupos se unen y después se verifica la expresión completa contra cada
    /// registro descifrado, así que el plan solo afecta a la velocidad, nunca al resultado. Si algún
    /// grupo no tiene ninguna igualdad indexada, o los candidatos son demasiados, se recorre todo.
    fn plan(&self, expr: &Expr) -> io::Result<Plan> {
        let limit = self.index_limit();
        let mut expected: u64 = 0;
        let mut candidates: Vec<u64> = Vec::new();

        for group in &expr.groups {
            let mut driver: Option<Probe> = None;
            for q in group.iter().filter(|q| self.is_indexed_eq(q)) {
                let probe = self.probe(q)?;
                let better = match &driver {
                    None => true,
                    Some(d) => probe.size < d.size,
                };
                if better {
                    driver = Some(probe);
                }
            }
            let driver = match driver {
                Some(d) => d,
                None => return Ok(Plan::Scan),
            };
            expected = expected.saturating_add(driver.size);
            if expected > limit {
                return Ok(Plan::Scan);
            }
            for ptr in driver.ptrs {
                candidates.extend(self.resolve(ptr)?);
            }
        }

        candidates.sort_unstable();
        candidates.dedup();
        Ok(Plan::Index(candidates))
    }

    /// Cómo se resolvería una consulta (útil para entender su coste).
    pub fn explain(&self, criterion: &str) -> io::Result<String> {
        let expr = parse_expression(criterion)?;
        Ok(match self.plan(&expr)? {
            Plan::Index(c) => format!("index: {} candidate record(s) out of {}", c.len(), self.header.total_rows),
            Plan::Scan => format!("scan: all {} records are read", self.header.total_rows),
        })
    }

    /// Recorre el cuerpo de datos autenticando cada bloque y entrega los resultados de `work` a
    /// `sink` **en el orden del archivo**. Un hilo lee el archivo en trozos grandes; el resto descifra
    /// en el sitio (un búfer reutilizable por hilo) y aplica `work` al texto en claro. `work` recibe el
    /// registro como un `&[u8]` prestado: debe copiar lo que quiera conservar.
    /// `PON_THREADS` limita los hilos; por defecto se usan todos los núcleos.
    /// Un bloque corrupto, un archivo truncado o un recuento distinto de `total_rows` es un error.
    pub fn scan_ordered<T, F, S>(&self, work: F, sink: S) -> io::Result<u32>
    where
        F: Fn(&[u8]) -> io::Result<T> + Sync,
        T: Send,
        S: FnMut(T) -> io::Result<()>,
    {
        self.scan_ordered_with(worker_threads(), work, sink)
    }

    pub(crate) fn scan_ordered_with<T, F, S>(&self, threads: usize, work: F, mut sink: S) -> io::Result<u32>
    where
        F: Fn(&[u8]) -> io::Result<T> + Sync,
        T: Send,
        S: FnMut(T) -> io::Result<()>,
    {
        let start = self.header.body_offset;
        let end = self.header.coincidence_table_offset;
        let path = &self.path;

        std::thread::scope(|scope| {
            // Capacidad 2: el lector va como mucho 2 trozos por delante (acota la memoria).
            let (tx, rx) = sync_channel::<ChunkMessage>(2);
            scope.spawn(move || read_chunks(path, start, end, &tx));
            let outcome = self.consume(&rx, threads, &work, &mut sink);
            // Si salimos antes de tiempo, soltar el receptor desbloquea al lector.
            drop(rx);
            outcome
        })
    }

    fn consume<T, F, S>(
        &self,
        rx: &Receiver<ChunkMessage>,
        threads: usize,
        work: &F,
        sink: &mut S,
    ) -> io::Result<u32>
    where
        F: Fn(&[u8]) -> io::Result<T> + Sync,
        T: Send,
        S: FnMut(T) -> io::Result<()>,
    {
        let mut rows: u32 = 0;
        for message in rx.iter() {
            let chunk = message?;
            for result in self.process_chunk(&chunk, threads, work) {
                sink(result?)?;
                rows = rows
                    .checked_add(1)
                    .ok_or_else(|| corrupt("more than u32::MAX records in the data body"))?;
            }
        }
        if rows != self.header.total_rows {
            return Err(corrupt(format!(
                "found {} records but the header declares {} (file truncated or altered)",
                rows, self.header.total_rows
            )));
        }
        Ok(rows)
    }

    /// Descifra en `scratch` el bloque que ocupa `data[start..start + total]` del trozo.
    fn open_chunk_block(&self, chunk: &Chunk, start: usize, total: usize, scratch: &mut Vec<u8>) -> io::Result<()> {
        let block = &chunk.data[start..start + total];
        let len = total - BLOCK_OVERHEAD as usize;
        scratch.clear();
        scratch.extend_from_slice(&block[BLOCK_HEADER..BLOCK_HEADER + len]);
        self.cipher
            .open_in_place(&block[BLOCK_HEADER + len..], chunk.base + start as u64, scratch)
    }

    /// Procesa los bloques de un trozo; devuelve un resultado por bloque, en el mismo orden.
    fn process_chunk<T, F>(&self, chunk: &Chunk, threads: usize, work: &F) -> Vec<io::Result<T>>
    where
        F: Fn(&[u8]) -> io::Result<T> + Sync,
        T: Send,
    {
        let run = |blocks: &[(usize, usize)]| -> Vec<io::Result<T>> {
            // Un búfer por hilo y trozo; el texto en claro se borra al soltarlo.
            let mut scratch: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::new());
            let mut out: Vec<io::Result<T>> = Vec::with_capacity(blocks.len());
            for &(start, total) in blocks {
                let result = match self.open_chunk_block(chunk, start, total, &mut scratch) {
                    Ok(()) => work(&scratch[..]),
                    Err(e) => Err(e),
                };
                out.push(result);
            }
            out
        };

        if threads <= 1 || chunk.blocks.len() < 2 * threads {
            return run(&chunk.blocks[..]);
        }

        let per_thread = (chunk.blocks.len() + threads - 1) / threads;
        let mut out: Vec<io::Result<T>> = Vec::with_capacity(chunk.blocks.len());
        std::thread::scope(|s| {
            let handles: Vec<_> = chunk
                .blocks
                .chunks(per_thread)
                .map(|slice| {
                    let run = &run;
                    s.spawn(move || run(slice))
                })
                .collect();
            for handle in handles {
                match handle.join() {
                    Ok(results) => out.extend(results),
                    Err(_) => out.push(Err(io::Error::new(io::ErrorKind::Other, "a scan worker thread panicked"))),
                }
            }
        });
        out
    }

    /// Resuelve una expresión (`cond [AND cond]... [OR ...]`). Usa el índice cuando el plan lo permite;
    /// en otro caso recorre el cuerpo de datos en paralelo. Siempre verifica contra el registro descifrado.
    pub fn query(&self, criterion: &str) -> io::Result<Vec<String>> {
        let expr = parse_expression(criterion)?;
        self.run_expr(&expr)
    }

    /// Búsqueda por clave: `campo=valor` por el índice, sin pasar por el analizador de expresiones.
    pub fn get(&self, field: &str, value: &str) -> io::Result<Vec<String>> {
        let expr = Expr {
            groups: vec![vec![Query { field: field.to_string(), op: QueryOp::Equal, value: value.to_string() }]],
        };
        self.run_expr(&expr)
    }

    fn run_expr(&self, expr: &Expr) -> io::Result<Vec<String>> {
        let mut results: Vec<String> = Vec::new();

        if let Plan::Index(offsets) = self.plan(expr)? {
            for off in offsets {
                let plain = self.read_record(off)?;
                if let Some(row) = record_if_matches(&plain, expr)? {
                    results.push(row);
                }
            }
            return Ok(results);
        }

        self.scan_ordered(
            |plain: &[u8]| record_if_matches(plain, expr),
            |row: Option<String>| {
                if let Some(r) = row {
                    results.push(r);
                }
                Ok(())
            },
        )?;
        Ok(results)
    }

    /// Vacía la caché de páginas y sus contadores (para medir en frío).
    pub fn clear_page_cache(&self) {
        *lock(&self.page_cache) = PageCache::new(PAGE_CACHE_CAPACITY);
        self.page_hits.store(0, Ordering::Relaxed);
        self.page_misses.store(0, Ordering::Relaxed);
    }

    /// Valores reales del campo indexado `field`, tomados de entradas del índice al azar (para medir).
    pub fn sample_values(&self, field: &str, count: usize) -> io::Result<Vec<String>> {
        use rand::Rng;
        if !self.indexed_fields.iter().any(|f| f.as_str() == field) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("'{}' is not an indexed field of this file", field),
            ));
        }
        let mut rng = rand::thread_rng();
        let mut values: Vec<String> = Vec::with_capacity(count);
        let max_attempts = count.saturating_mul(20).saturating_add(100);
        let mut attempts = 0usize;
        while values.len() < count && attempts < max_attempts && self.header.page_count > 0 {
            attempts += 1;
            let page = self.page(rng.gen_range(0..self.header.page_count as usize))?;
            let o = rng.gen_range(0..PAGE_ENTRIES) * 16;
            let ptr = le_u64(&page[o + 8..o + 16]);
            if ptr == 0 {
                continue;
            }
            let offsets = self.resolve(ptr)?;
            let off = match offsets.first() {
                Some(&off) => off,
                None => continue,
            };
            let plain = self.read_record(off)?;
            let doc: serde_json::Value = match serde_json::from_slice(&plain[..]) {
                Ok(d) => d,
                Err(_) => continue,
            };
            if let Some(v) = lookup_field(&doc, field) {
                values.push(index_key(v));
            }
        }
        Ok(values)
    }

    /// Escribe todo el contenido como un array JSON. Cualquier fallo de autenticación es un error.
    pub fn export_to<W: Write>(&self, out: &mut W) -> io::Result<ExportSummary> {
        let mut hasher = Sha256::new();
        let mut first = true;
        out.write_all(b"[\n")?;
        let rows = self.scan_ordered(
            |plain: &[u8]| Ok(Zeroizing::new(plain.to_vec())),
            |plain: Zeroizing<Vec<u8>>| {
                hasher.update(&plain[..]);
                if !first {
                    out.write_all(b",\n")?;
                }
                first = false;
                out.write_all(b"  ")?;
                out.write_all(&plain[..])?;
                Ok(())
            },
        )?;
        out.write_all(b"\n]\n")?;
        Ok(ExportSummary { rows, sha256: hasher.finalize().into() })
    }
}
