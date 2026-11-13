# Changelog

## 9.0.0-alpha.7 — O(1) key lookups: a hash table of authenticated pages (format revision 4)

This changes the file format: files from earlier alphas are rejected with
"unsupported PON V9 format revision N" and must be re-created from the original JSON.

### Index: from sorted shards to a static hash table
- **Key lookup is O(1).** The keyed hashes are uniform and queries only ask for equality, so the order bought
  nothing: the index is now a static hash table of 4 KiB pages (255 entries of 16 bytes + a 16-byte tag). The
  natural page of a hash is `floor(hash * bucket_count / 2^64)`; a full page overflows into the next one; the
  builder places the entries in hash order (the natural page is monotonic), measures the longest probe and writes it
  in the authenticated header as `max_probe`. A lookup reads at most `max_probe` pages whatever the size of the file
  (simulated, 75 % load: one page in practice, two at most with 38 million keys).
- **Opening a file is O(1).** The sorted shards needed a shard table (`24 bytes per 4096 entries`) that was read and
  authenticated on every open: O(n/4096), about 6 MB for 1 000 million entries. It is gone: the footer now covers the
  128-byte header only, and every page carries its own tag.
- **Page tags are GMAC** (AES-256-GCM with no plaintext, the 4080 entry bytes as associated data, nonce = page
  number, a dedicated per-file HKDF key `pon-db/v9/index-page-mac`). It uses the AES and carry-less multiplication
  hardware and is much cheaper than an HMAC-SHA256 over 4 KiB, which was the cryptographic cost of every lookup. A
  page verifies only at its position and in its file: swapped pages, zeroed pages and pages from another file fail.
- Read unit per lookup: 4 KiB instead of 64 KiB. Page cache: up to 4096 verified pages (16 MiB).
- Header: `bucket_count`, `page_count` and `max_probe` replace `shard_entries` and `shard_table_offset`; capability bit 3
  (paged hash index) is required. Layout checks cover the table geometry (`page_count`, `max_probe`, capacity).
- Cost: the index is about 33 % larger (75 % load factor), under 5 % of a typical file.

### Numbers have one index key
- A number is indexed in canonical form: `7`, `7.0`, `70e-1` and `0.7e1` are the same key `"7"`; other numbers use the
  shortest `f64` form. A query for an integer therefore needs **one** hash and one probe (before: two, `"7"` and
  `"7.0"`). Equality semantics are unchanged; every candidate is still verified against the decrypted record.

### API and tools
- `Reader9::get(field, value)`: key lookup without the expression parser; works on any field (a field without index
  is resolved by a scan).
- **`bench`**: `pon-db-engine file.pon bench --field=id [--count=N] [--threads=T] --key=...`. It samples real keys from
  the file and reports lookups per second, the latency distribution (mean, p50, p90, p99, p99.9, max) and the
  multi-thread throughput, always through the full path (keyed hash, authenticated page, record read, AES-GCM, value check).
- `serve` reports `page_cache` (was `shard_cache`).

### Tests
- 132 tests. New: page placement (monotonic natural page, uniform hashes, overflow chains, spill beyond the last
  bucket, untouched pages), page tags (position, content, file, any single byte), header geometry checks, a 10 000-key
  index where every key is found and no lookup reads more than `max_probe` pages, opening reads no index page,
  swapped or zeroed pages are detected and never hide a record, canonical numbers, `get`, the benchmark.
- The reference model in Python reproduces the new layout with real AES-GCM / GMAC / HMAC; the parser and the query
  planner were checked again against a brute-force evaluation on 30 000 random queries.

## 9.0.0-alpha.6 — deterministic nonce, capabilities, AND/OR queries, persistent mode (format revision 3)

Ideas taken from the book *Encrypted Data Virtual Machines* (Cap. VI §2.3, Cap. II §9, annex D.2/D.3, pattern 9).
 

### Format (revision 3)
- **Deterministic nonce.** The AES-GCM nonce is `offset (u64) || version (u32)`, derived from the block position and
  no longer stored. Unique by construction (per-file keys, each offset written once), so the 2^32 birthday bound of
  random nonces disappears, the RNG is not needed at ingest, and every record is **12 bytes smaller** (a block is now
  `LEN(4) | CIPHERTEXT | TAG(16)`, overhead 20 instead of 32). The version slot is `0` and reserved for a variant that
  rewrites blocks in place.
- **Header with `aead_algo`, `access_mode` and `capabilities`.** Only AES-256-GCM and key-only access are implemented;
  other values are reserved and rejected. The capability bit map (keyed index, encrypted metadata, deterministic
  nonce) must match exactly: an unknown capability is rejected, since it could change how the file is read. Future
  algorithms or access modes will not need another revision.

### Queries
- **`AND` / `OR`.** `sku=S3 AND price>=100`, `id=1 OR id=2`, `a=1 OR b=2 AND c=3` (AND binds tighter, no parentheses;
  uppercase keywords between spaces; quote values that contain them). Parser checked by round trip on 20 000
  generated expressions.
- **Query planner.** For each AND group the most selective equality on an indexed field drives the lookup (its record
  count is known before any record is read); the candidates of the OR branches are united and the whole expression
  is checked on every candidate after decrypting it, so the plan changes the speed and never the result. No indexed
  equality in a branch, or more than `max(1024, rows / 32)` candidates, means a parallel scan. Checked against a full
  evaluation on 30 000 random queries.
- A single-condition query keeps its semantics and its fast path.

### Persistent mode
- **`serve`**: the file is opened and authenticated once; one query per stdin line, one JSON line per reply
  (`{"ok":true,"count":N,"micros":T,"rows":[...]}`), plus `\explain <query>`, `\stats` and `\q`. A failed query
  does not end the session. No network listener.
- The reader keeps the file open and reads by position (`pread`), keeps a cache of up to 256 authenticated index shards
  (16 MiB), and reads a record with one speculative 2 KiB read.

### Tests
- 112 tests. New: nonce derived from the position, capability / algorithm / access-mode checks, expression parsing
  and evaluation, plan selection (driver choice, OR union, scan fallback, low selectivity), equivalence of every plan
  with a full evaluation, the serve protocol and its shard cache.

## 9.0.0-alpha.5 — faster full scans: chunked reads and in-place decryption (no format change)

Files written by 9.0.0-alpha.4 open unchanged.

### Performance
- **Reader thread:** it no longer reads each record with four small reads and one allocation. It reads the data
  body in 8 MiB chunks (one read per chunk, no zero-fill) and only walks the length fields to find the block
  boundaries. A block cut at the end of a chunk is carried over to the next one; a record larger than a chunk is
  completed by reading more. This sequential part was the likely limit of the thread scaling measured in alpha.2.
- **Workers:** each thread decrypts straight from the chunk into one reusable buffer
  (`decrypt_in_place_detached`), instead of allocating a ciphertext copy, a payload copy and a plaintext vector per
  record. The plaintext buffer is wiped when the thread finishes its share of a chunk.
- `scan_ordered` now hands the record to the filter as a borrowed `&[u8]` (it was an owned buffer).

### Robustness
- A record whose declared length exceeds 16 MiB (the ingest limit) is rejected before any memory is reserved
  for it; a length that exceeds the data region is rejected as before. In both cases the rows before the damaged
  block are still delivered, then the error.

### Tests
- 92 tests. New: `open_in_place` agrees with `open` and rejects the same attacks, a record 10 times larger than the
  read chunk, a corrupted length field. Chunk boundaries are exercised in every scan test (4 KiB chunks under
  `cargo test`).
- The chunking algorithm was also checked against a plain sequential walk on 8 000 random files (valid, with a
  corrupted length, and truncated).

## 9.0.0-alpha.4 — keyed index, several indexed fields, encrypted metadata (format revision 2)

This changes the file format: files written by earlier alphas are rejected with
"unsupported PON V9 format revision 1" and must be re-created from the original JSON. V9 has not been published
yet, so no compatibility with earlier alphas is kept.

### Security
- **Keyed index.** An entry is `HMAC-SHA256(index key, len(field) || field || value)` truncated to 8 bytes, with an
  index key derived per file (HKDF). The unkeyed SipHash is gone, and with it the offline dictionary attack on the
  index (and the dependence on `DefaultHasher`, which Rust does not keep stable between versions). Two files built
  from the same data and master key have unrelated indexes.
- **Encrypted metadata.** The list of indexed fields is stored in an AES-256-GCM block with its own key, bound to
  the file and its position. Field names no longer appear in the file, and the header no longer carries the
  unkeyed fingerprint of the field name.

### Added
- **Several indexed fields:** `--index=sku,city,address.zip`. Each record adds one entry per indexed field it
  contains; the field name is part of the hash, so the same value in two fields never collides. `field=value`
  on any indexed field uses the index; other queries scan.
- Header: `meta_len` replaces the field fingerprint; format revision 2.
- The ingest summary and report list the indexed fields; a record is counted as "not indexed" only when it has none
  of them.

### Tests
- 89 tests (35 of them end-to-end tests of the V9 file). New: multi-field lookups, same value in two fields, dotted index paths, a dictionary
  attack against the index finds nothing, field names do not appear in the file, tampered metadata, metadata
  transplanted from another file, previous revision and V8 files rejected, field list validation.
- The attack tests now locate blocks through the header (`body_offset`), since the metadata block comes first.

### Still open before the first stable release
- Queries do not traverse arrays of objects (`friends.name=Noah`).

## 9.0.0-alpha.3 — formats before V9 are no longer supported

Versions before 9 are declared unmaintained, and V9 is the baseline from here on.

### Removed
- Everything specific to the V8 format: its header, cipher, aggregator, exporter, query engine and index writer,
  and the `--format` option. `query` and `export` open V9 files only. A V8 file is rejected with
  "this is a PON V8 file: formats before V9 are no longer supported".
- The hardware-id binding of the V8 header and the `master XOR hardware id` session key.
- The V8 specification in the README.

### Changed
- `ingest.rs` keeps only the shared pieces (`IngestStats`, `HashingReader`, `sha256_file`); `query_engine.rs`
  is now format-independent (query parsing and evaluation); `ExportSummary` moved to `v9/reader.rs`.
- The ingest summary prints how many distinct values of the indexed field were indexed.
- Tests: 79 (the V8 end-to-end tests were replaced by their V9 equivalents; added: V8 files are rejected,
  the real input hash, indented JSON input).
- Files written by 9.0.0-alpha.1 and 9.0.0-alpha.2 open unchanged (the V9 format did not change).

## 9.0.0-alpha.2 — faster scans (no format change)

Files written by 9.0.0-alpha.1 open unchanged.

### Performance
- **Parallel scan (V9):** one reader thread feeds batches of blocks to worker threads that decrypt, authenticate
  and filter them; a collector delivers results in file order. Memory is bounded (batches of at most 8192 blocks
  or 8 MiB, at most two queued). `PON_THREADS=N` limits the threads; the default is every available core.
- **Filters without building the full JSON object:** a top-level field is located by walking the text and only
  that value is parsed. Keys with escapes are decoded, duplicate keys keep the last value, and anything unusual
  falls back to the full parse. Checked against `json.loads` on 60 000 random hostile documents (780 000 field
  lookups, no differences). A record that is not valid JSON elsewhere than in the queried field is no longer
  noticed by a query (records are validated when ingested and authenticated when read).
- 1 MiB read buffer for the scan.
- `[profile.dev.package."*"] opt-level = 3`: dependencies (AES, SHA, serde_json) are optimized in debug builds.

### Behavior kept
- Every block is still authenticated, the record count is still checked against the header, and the first bad
  block in file order is reported after delivering all the rows before it. A failing consumer stops the scan.
- Results keep the file order for any thread count.

### Tests
- 4 new tests for the pipeline (order for 1 to 64 threads, first error, no hang when the consumer fails,
  same rows as one thread) and 2 for the fast path (agreement with the full parse, dotted paths): 100 in total.
- V8 files are still scanned by a single thread.

## 9.0.0-alpha.1 — V9 format, stage 1: HKDF, per-block AAD and authenticated structure

New files are written in the **V9** format by default (`--format=v8` keeps the old one). `query` and `export`
detect the format; V8 files remain readable. Files written by 8.5.0 need no migration.

### Added
- **Per-file keys:** HKDF-SHA256 over the master key with a random 16-byte `file_id` as salt gives separate
  block-encryption and structure-MAC keys. The XOR with the hardware id is gone in V9.
- **AAD per block:** AES-256-GCM binds every block to `file_id || offset`. Swapping, moving, duplicating
  or transplanting blocks between files now fails authentication (V8 did not detect any of these).
- **Authenticated structure:** a 32-byte HMAC-SHA256 footer covers the whole header and the shard table;
  a wrong master key, an edited header or offsets, truncation, extension and deleted records are rejected
  when the file is opened.
- **Authenticated, sharded index:** the index is split into 64 KiB shards, each with an HMAC tag held in the
  shard table; coincidence tables carry their own tags. A lookup reads the (small) shard table plus one shard,
  so it stays O(log n) without verifying the whole index.
- `export` and `query` report the authentication state of the structure; `--format=v8|v9` for ingest.
- 32 new tests (RFC 5869 and RFC 4231 vectors, and the attacks above), 94 in total.
- New dependencies: `hkdf` and `hmac` (RustCrypto, 0.12).

### Not changed yet (stage 2 and 3)
- The index hash is still unkeyed SipHash-1-3, so the index can be attacked with a dictionary offline.
- One indexed field only. No `migrate` command yet. Queries do not traverse arrays of objects.
- Rollback to an older intact copy cannot be detected without external state.
- This is an alpha: stage 2 changes the index, so files written by this version will not open in later alphas.

## 8.5.0 — Phase 1: correctness and hardening (no format break)

Files written by 8.4.x remain readable; see "Compatibility" below.

### Fixed — functionality
- `body_offset` is now written to the header (it was always `0`, so scans started at the header).
- `query` scans no longer read a phantom 8-byte `_cascade` per block that the writer never wrote.
  Before this fix **every non-equality query (e.g. `price>500`) returned "Result not found."**
- Scans stop at `coincidence_table_offset` (end of the data body) instead of `index_table_offset`.
- `>=` and `<=` were evaluated as `>` and `<`; they now include the boundary.
- `field=value` no longer ignores the field. It uses the index only when the field is the indexed one
  (header `index_bitmask` now stores a fingerprint of the field name) and otherwise scans.
  Index hits are verified against the decrypted record, so hash collisions cannot produce false positives.
- Query values are matched across numeric spellings (`12.50` finds `12.5`, `1000` finds `1000.0`).
- Record matching uses `serde_json` instead of text search: values containing commas, nested objects with
  the same field name, and non-numeric values in numeric comparisons are handled correctly.
  Dotted paths (`a.b`) are supported.
- The query criterion is no longer "the first argument containing `=`, `<`, `>` or `!`": `--key=...` before
  the query, or an input path containing those characters, no longer breaks it.
- `export` no longer prints `VERIFIED` unconditionally. A block that fails AES-GCM, a truncated file, or a
  record count different from `total_rows` is an error with exit code 1.
- `export > file.json` now produces valid JSON: banners and summaries go to stderr.
- The uptime-based "anti-tamper" check was removed: it rejected valid files moved to a machine with a longer uptime.
- `shard_size_bytes` now records the real shard size (65536) instead of a hard-coded fake "L3 size" (32 MiB);
  `bucket_count` is now filled in.
- The version byte is unified (`0x0A`, as in the specification); `85` is still accepted when reading.

### Fixed — ingest
- The index is updated only after a block has been written (no dangling index entries).
- Invalid JSON aborts the ingest with the record number, leaving no partial `.pon` and no orphan key file.
- Invalid UTF-8 is an error instead of being silently replaced (`from_utf8_lossy`).
- A single object is limited to 16 MiB; an unterminated object at end of input is an error.
- An existing `.pon` is no longer overwritten unless `--force` is given.
- Empty input is an error. `--index=a,b` is an error (V8 indexes one field) instead of silently using only `a`.
- Records lacking the indexed field are counted and reported.
- The cipher is created once instead of once per record; input is scanned with a buffer and output is buffered.

### Security
- The master key file is created with mode `0600` and `create_new` (never overwrites). Loading a key readable
  by other users prints a warning. Key files must be exactly 32 bytes. There is no default key path anymore:
  `--key=` is required for `query` and `export`.
- Block lengths are validated against the bytes remaining in the data body before allocating memory, and
  coincidence pointers, record offsets and header offsets are range-checked.
- Keys and decrypted records are held in `Zeroizing` buffers (the previous `zeroize` call wiped a copy).
- The "GREEN COMPLIANCE REPORT" no longer claims "VERIFIED" / "MATHEMATICALLY SEALED" and no longer prints
  placeholder hashes. The report (`.pon.log`) now contains real SHA-256 digests of the input and the output.

### Housekeeping
- Removed 10 dependencies with no reference in the code (`ed25519-dalek`, `machine-uid`, `indicatif`, `libc`,
  `csv`, `lz4_flex`, `getrandom`, `fxhash`, `bincode`, `uuid`), plus `sysinfo` (it only fed the fake L3 size
  and the uptime check) and the `serde`/`zeroize` derive features.
- `Cargo.toml`: author name, description, `license`, `rust-version`, release profile `opt-level = 3`.
- README: copy-pasteable commands, spec aligned with the code (block order, `body_offset`, `index_bitmask`,
  reserved fields), accurate complexity claims, and a section on the known limitations of V8.
  A leftover license paragraph about a "kernel, bootloader and userland" was removed.
- Added `.gitignore` (keys and `.pon` files are never committed), `.gitattributes` (LF line endings),
  a CI workflow, and unit and end-to-end tests (`cargo test`).

### Compatibility
- 8.5.0 reads files from 8.4.x. On those files `field=value` queries fall back to a scan
  (they carry no field fingerprint); re-ingest to get indexed lookups.
- The block format, index format and hash function are unchanged, so files written by 8.5.0 can still be
  exported, and queried by exact match on the indexed field, with 8.4.x. Range queries and scans never worked
  in 8.4.x (see above): use 8.5.0.

### Not changed (needs the V9 format)
- Header, index and coincidence tables are unauthenticated; AES-GCM blocks carry no AAD.
- Index hash is unkeyed SipHash-1-3 (`DefaultHasher`), allowing offline dictionary attacks on the index.
- Session key is `master XOR hw_id`, not an HKDF output.
- Single indexed field only.
