<h1 align="center">PON-DB</h1>
<p align="center">
  <b>Author : Roberto C. Alemán F.</b><br/><b>Zulia, Venezuela</b><br/><img src="https://flagcdn.com/ve.svg" alt="Flag of Venezuela" width="48">
</p>
<p align="center">
  <a href="https://pon-db.com">Website</a><br/><br/>
  <b>License: GNU Affero General Public License (AGPL-3.0-only)</b><br/>
  <b>Current version: 9.0.0-alpha.7 (file format V9, revision 4)</b><br/>

[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/S2Y6296BZ2)

</p>


# What is PON-DB Engine?
PON stands for Positional Object Notation. It is a set of rules, a data normalization protocol, a file format specification, and the RA-CHAMPI algorithm that allows operations performed at the speed that could be obtained by processing the data stored on disk as a direct extension of physical memory.

PON-DB Engine is a database engine encapsulated in a single, portable, and encrypted binary format, designed to treat the data file not as a conventional storage structure, but as a direct extension of physical memory. Its architecture is based on the creation of high-density .pon files, wherein each point of information possesses an exact and predetermined address, thereby eliminating the need for intermediate translation layers or heavyweight relational management systems.

In this same line of thought, we could also see it as an autonomous database, an engine that stores the data, and an analyzer that reads and finds it according to the rules of the algorithm.

PON-DB software is a practical implementation of data-centric computing principles, where the priority shifts from the application to the efficiency, permanence, and autonomy of the data. This paradigm seeks to treat data as the permanent source of value, allowing it to exist independently of applications. In the case of PON-DB, this translates into files that are not simply passive containers, but "intelligent" structures that integrate their own search and encryption engine, enabling fast indexed queries (a binary search over a sorted hash index, O(log n)) without relying on an external or cumbersome database infrastructure.

Under this approach, PON-DB breaks with the traditional CPU-centric model, where data must constantly be moved to the application for processing. Instead, by encapsulating access logic and security directly in the file format (such as the .pon file), it achieves what data-centric computing defines as operational agility and flexibility: data becomes "liquid" and portable. This allows the software to act simply as a minimal key to unlock the potential of the data.

## Getting Started

### Prerequisites
* Rust 1.75 or higher
* Cargo package manager

### 1. Build

```bash
git clone https://github.com/robertoaleman/pon-db.git
cd pon-db
cargo build --release
cargo test
```

The binary is `target/release/pon-db-engine`.

### 2. Ingest and index data

Ingest a JSON dataset (newline-delimited objects, or an array of objects) and index one or more fields:

```bash
./target/release/pon-db-engine dataset.json --index=sku
./target/release/pon-db-engine dataset.json --index=sku,city,address.zip --force
```

Files are written in the **V9** format. Versions before 9 are no longer supported: a V8 file is rejected with a clear message and must be re-created from the original JSON.

What happens during ingest:
* The input is scanned object by object; each object must be valid JSON (the first invalid one aborts the ingest and nothing is left behind).
* Every record is encrypted with AES-256-GCM and appended to the data body. In V9 each file gets its own keys, derived from the master key with HKDF-SHA256, and each block is bound to its file and position.
* Every indexed field (default: `id`) adds one entry per record to a static hash table of 4 KiB pages. Entries are keyed hashes (HMAC-SHA256) of the field name and the value, so they are useless without the master key, and the same value in two fields never collides. Numbers are indexed in canonical form (`7`, `7.0` and `1e0` are the same key). Dotted paths (`address.zip`) can be indexed. The names of the indexed fields are stored only in an encrypted metadata block.
* A new random master key is written to `masterkey_XXXXXXXX_YYYY-MM-DD.bin` (created with mode `0600` on Unix; it never overwrites an existing file).
* `dataset.json.pon` is written, plus `dataset.json.pon.log` with an ingest report (sizes, SHA-256 of input and output, timing).
* An existing `.pon` is never overwritten unless you pass `--force`.

**Keep the master key apart from the `.pon` file. Without it the data cannot be recovered.**

### 3. Query

Exact match (`=`) on an indexed field uses the index:

```bash
./target/release/pon-db-engine dataset.json.pon query "sku=PROD-100" --key=masterkey_ABC12345_2026-10-26.bin
```

Any other query is a full scan of the data body (every record is decrypted):

```bash
./target/release/pon-db-engine dataset.json.pon query "price>=500" --key=masterkey_ABC12345_2026-10-26.bin
```

* Operators: `=`, `!=`, `>`, `>=`, `<`, `<=`. The query is split at the first operator, so values may contain `=`, `<` or `>`. Surrounding single or double quotes around the value are removed.
* Combine conditions with `AND` and `OR` (uppercase, surrounded by spaces; `AND` binds tighter than `OR`; no parentheses): `"sku=S3 AND price>=100"`, `"id=1 OR id=2 OR sku=S9"`, `"sku=S1 AND price>=1000 OR id=5"`. Put a value that contains the word `AND` / `OR` between quotes: `name="Tom AND Jerry"`. Lowercase `and` / `or` are plain text.
* Dotted paths reach nested fields: `address.city=Merida`.
* Comparisons are numeric when both sides are numbers (or numeric-looking text) and textual when both are text. A record whose field is missing or non-numeric never matches a numeric comparison.
* Results are printed to **stdout** as one JSON document per line; timing and status messages go to **stderr**, so output can be piped.
* A corrupted or tampered block makes the query fail with an error; it is never skipped silently.

#### Performance notes

* **A key lookup is O(1).** An exact match on an indexed field computes one keyed hash (an integer has a single candidate key), reads at most `max_probe` pages of 4 KiB, authenticates them with a GMAC tag, and reads one record. `max_probe` is measured when the file is built and written in the authenticated header; with the 75 % load factor a lookup reads one page in practice. Opening the file does not depend on its size either: it verifies the 128-byte header and reads the metadata block. `bench` measures all of this on your hardware.
* **Query plan.** For every `AND` group the engine looks up each equality on an indexed field and takes the most selective one (the one that matches the fewest records; that number is known before any record is read) as the *driver*. The drivers of all the `OR` branches are united, and the whole expression is then checked against each candidate record after decrypting it, so the plan only changes the speed, never the result. If a branch has no equality on an indexed field (a range, a field without index), or the candidates exceed `max(1024, rows / 32)`, the data body is scanned in parallel instead. In `serve` mode `\explain <query>` shows the plan.
* Any other query (ranges, other fields) is a **full scan**: every record is read, decrypted and authenticated. The scan is parallel: one thread reads the file in 8 MiB chunks (one large read per chunk) and only walks the block lengths to find the record boundaries; the other threads decrypt each record in place, in a reusable per-thread buffer, and filter it, and results come out in file order. It uses all available cores; set `PON_THREADS=N` to limit it (`PON_THREADS=1` for a single thread).
* A filter on a top-level field is evaluated without building the whole JSON object; anything unusual falls back to full parsing, so the results are identical.
* Always benchmark the **release** build (`cargo build --release`); the debug build is more than an order of magnitude slower.

### Persistent mode: `serve`

Opening a file costs a few milliseconds (key derivation, the footer HMAC, the metadata block). To answer many queries without paying that each time, keep the file open:

```bash
./target/release/pon-db-engine dataset.json.pon serve --key=masterkey_ABC12345_2026-10-26.bin
```

Each line on stdin is a query; each query gets exactly one JSON line on stdout (`\q` ends the session; records stored with indentation are folded onto one line):

```
sku=S3 AND price>=100
{"ok":true,"count":4,"micros":212,"rows":[{"id":13,...},...]}
\explain id=1 OR sku=S9
{"ok":true,"plan":"index: 6 candidate record(s) out of 50"}
\stats
{"ok":true,"rows":50,"indexed_fields":["sku","id"],"page_cache":{"hits":9,"misses":1}}
```

Index pages are authenticated the first time they are read and kept in memory (up to 4096 pages, 16 MiB), so repeated lookups skip the tag check. A failed query returns `{"ok":false,"error":"..."}` and the session continues. There is no network listener: `serve` talks only through stdin and stdout.

### Measuring key lookups: `bench`

```bash
./target/release/pon-db-engine dataset.json.pon bench --field=id --count=200000 --threads=8 --key=masterkey_ABC12345_2026-10-26.bin
```

It samples `--count` real values of the indexed field from the file itself, then looks each one up through the whole path (keyed hash, index page read and authenticated, record read, AES-GCM, value check). It reports lookups per second with one thread, the latency distribution (mean, p50, p90, p99, p99.9, max in microseconds), and the throughput with `--threads` threads sharing one reader. The index page cache starts empty in each run. Results depend on the operating system's page cache: run it once to warm the file and once more, and say which one you report. To compare with another engine, load the same records there and measure the same random lookups on the same machine.

### 4. Export (no vendor lock-in)

```bash
./target/release/pon-db-engine dataset.json.pon export --key=masterkey_ABC12345_2026-10-26.bin > restored.json
```

`restored.json` is a valid JSON array. The command exits with a non-zero status if any block fails authentication, if the file is truncated, or if the number of records differs from the header.

### Exit codes

`0` success (including "Result not found."), `1` any error.

# Security model and known limitations

## What V9 provides and its limits

* Every record is encrypted and authenticated with AES-256-GCM under a **per-file key** (HKDF-SHA256 over the master key, with a random 16-byte file id as salt). The nonce is **not random and not stored**: it is derived from the position of the block (`offset ‖ version`), which is unique within a file, so there is no birthday bound on the number of records. The AEAD associated data is `file id || block offset`, so a block only decrypts in the file and at the position where it was written: blocks cannot be swapped, moved, duplicated or transplanted from another file.
* The **header is authenticated** by a 32-byte HMAC-SHA256 footer, checked when the file is opened (the offsets, the geometry of the index table and the probe bound are all in it). A wrong master key is reported at that point, and so is any edit of the header, and any truncation or extension.
* Every **index page** (GMAC, hardware-accelerated) and every **coincidence table** (HMAC) carries its own tag, bound to its position and to the file, and is verified before it is used. Pages that are swapped, zeroed, or taken from another file are detected, and a damaged index fails the lookup instead of silently hiding a record.
* Deleting or truncating records is detected: the row count and every offset are covered by the footer, and the following blocks no longer match their positions.
* The **index is keyed**: an entry is `HMAC-SHA256(index key, field name || value)` truncated to 8 bytes, with an index key derived per file. Someone holding the `.pon` file without the master key cannot test candidate values against the index (no dictionary attack), and two files built from the same data and the same master key have unrelated indexes.
* The **names of the indexed fields** and the rest of the metadata live in an encrypted, authenticated block: they do not appear in the file.

Limits of V9:
* **Rollback is not detectable**: replacing the file with an older, intact copy produced with the same key cannot be noticed without state kept outside the file (keep the SHA-256 printed in the ingest report).
* Someone holding the file can still see how many records there are, the size of each record, how many index entries exist, and **which entries refer to several records** (that several records share a value in an indexed field, though not which value or which field).
* The whole index is held in memory while ingesting, and query results are collected in memory.
* On Windows the master key file gets the default ACLs of the directory.
* V9 is an **alpha**: the format (now revision 4) is frozen when the first stable version is published. Files from earlier revisions are rejected with a clear message and must be re-created from the original JSON.

---

# PON-DB File Format Specification V9 (.pon, magic `PON9`)

* **Format:** V9, revision 4.
* **Design paradigm:** single binary file; per-file keys; authenticated header; encrypted metadata; the keyed hash index is a static hash table of authenticated 4 KiB pages, so a key lookup reads a bounded number of pages whatever the size of the file.

## V9.1 File structure
```
[ Header 128 ][ Metadata ][ Data body ][ Coincidence tables ][ Index pages ][ Footer 32 ]
```
The header is written last, so an interrupted ingest leaves a header of zeros that is rejected.

## V9.2 Keys
```
master key (32-byte file) --HKDF-SHA256(salt = file_id, ikm = master)-->
    block key     info = "pon-db/v9/block-encryption"      (AES-256-GCM, records)
    metadata key  info = "pon-db/v9/metadata-encryption"   (AES-256-GCM, metadata block)
    index key     info = "pon-db/v9/index-key"             (HMAC-SHA256, index entries)
    page key      info = "pon-db/v9/index-page-mac"        (GMAC, index pages)
    structure key info = "pon-db/v9/structure-mac"         (HMAC-SHA256, footer and coincidence tags)
```

## V9.3 Header (128 bytes, little-endian)
| Offset | Field | Type | Description |
| :--- | :--- | :--- | :--- |
| 0..4 | `magic` | `[u8; 4]` | `PON9`. |
| 4 | `format_rev` | `u8` | `4`. Other values are rejected. |
| 5 | `data_model` | `u8` | `0x02`. |
| 6 | `aead_algo` | `u8` | `1` = AES-256-GCM. Other values are reserved and rejected. |
| 7 | `access_mode` | `u8` | `1` = key only. Modes that add a hardware proof are reserved and rejected. |
| 8..24 | `file_id` | `[u8; 16]` | Random per file; salt of the key derivation and part of every AAD. |
| 24..32 | `created_at` | `u64` | Unix time in seconds. |
| 32..36 | `total_rows` | `u32` | Number of records. |
| 36..40 | `bucket_count` | `u32` | Pages of the addressing space of the hash table. |
| 40..48 | `body_offset` | `u64` | First data block (`128 + meta_len`). |
| 48..56 | `coincidence_table_offset` | `u64` | End of the data body. |
| 56..64 | `index_table_offset` | `u64` | Start of the index pages. |
| 64..72 | `index_entry_count` | `u64` | Number of index entries (distinct hashes, all fields). |
| 72..76 | `meta_len` | `u32` | Length of the metadata block (20 ≤ `meta_len` ≤ 1 MiB). |
| 76..80 | `capabilities` | `u32` | Bit map: bit 0 keyed index, bit 1 encrypted metadata, bit 2 deterministic nonce, bit 3 paged hash index. Revision 4 requires exactly these four; a file that declares a capability the reader does not know is rejected, because a capability may change how the rest is read. |
| 80..84 | `page_count` | `u32` | Index pages written (`≥ bucket_count`; the overflow of the last pages may add some). |
| 84..88 | `max_probe` | `u32` | Pages that must be read, at most, to decide whether a key is present (measured when the file is built). |
| 88..128 | reserved | | Must be zero. |

Layout rules (checked on open): `body_offset = 128 + meta_len`; `body_offset ≤ coincidence_table_offset ≤ index_table_offset ≤ file_len − 32`; `file_len − 32 − index_table_offset = 4096 × page_count`; if `page_count = 0` there are no entries, `bucket_count = 0` and `max_probe = 0`; otherwise `1 ≤ bucket_count ≤ page_count`, `1 ≤ max_probe ≤ page_count` and `1 ≤ index_entry_count ≤ 255 × page_count`; and `total_rows × 20 ≤ coincidence_table_offset − body_offset`.

## V9.4 Metadata block
At offset 128, `meta_len` bytes, in the same layout as a data block (see V9.5) but encrypted with the **metadata key** and **AAD = `file_id (16) || 128 (u64 LE)`**. The plaintext is JSON: `{"indexed_fields":["sku","city"]}` (names as given on the command line; dotted paths allowed; duplicates removed).

## V9.5 Data block
```
| CIPHERTEXT LENGTH (u32) | CIPHERTEXT (N) | TAG (16) |
```
AES-256-GCM with the block key. **The nonce is not stored**: it is `block offset (u64 LE) || version (u32 LE)`, with version `0` (the slot is reserved so that a variant that rewrites blocks in place can number their versions without changing the format). It is unique because every file has its own keys (HKDF with a random `file_id`) and every offset is written once. **AAD = `file_id (16) || block offset (u64 LE)`**. Readers check the declared length against the bytes left in the region before allocating.

## V9.6 Coincidence tables
Keys shared by several records: `COUNT (u32) | OFFSET × COUNT (u64) | TAG (16)`, where
`TAG = HMAC-SHA256(structure key, "pon-db/v9/coincidence\0" || file_id || table_offset (u64) || COUNT || OFFSETS)[..16]`.

## V9.7 Index entries
An entry is `HASH (u64) | POINTER (u64)`. A record contributes one entry for each indexed field it contains. A pointer with bit 63 set refers to a coincidence table; otherwise it is the offset of a block. A pointer is never 0 (that value marks an empty slot).

`HASH = u64 LE of the first 8 bytes of HMAC-SHA256(index key, "pon-db/v9/index-entry\0" || len(field) (u32 LE) || field || value)`

where `field` is the field name (UTF-8) and `value` is the normalized value: strings as they are; **numbers in canonical form** (integers, however they were written, as their decimal digits: `7`, `7.0`, `70e-1` and `0.7e1` are all `7`; other numbers as the shortest representation of the `f64`: `12.50` is `12.5`); booleans as `true` / `false`; any other JSON value as its compact JSON text. A query tries the text it was given and, if that looks like a number, its canonical form (for an integer they coincide: one candidate), and verifies every candidate against the decrypted record, so hash collisions can only add candidates, never wrong results.

## V9.8 Index pages
The table is `page_count` pages of 4096 bytes: 255 entries of 16 bytes packed from the front (the unused slots are zero) followed by a 16-byte tag.

* **Natural page** of a hash: `floor(HASH × bucket_count / 2^64)`, with `bucket_count = ceil(index_entry_count / (255 × 0.75))` (a 75 % target load).
* **Overflow:** when the natural page is full, the entry goes to the next page, and so on (linear probing by pages, without wrap-around; the pages that the overflow of the last bucket needs are appended after the addressing space). The builder places the entries in ascending hash order (the natural page is monotonic in the hash), measures the longest probe and writes it as `max_probe`.
* **Search rule:** for a hash with natural page `p`, read pages `p, p+1, ...` up to `max_probe` pages or the end of the table; stop at the first page that has an empty slot (the chain ends there); a page that is full and does not hold the hash sends the search to the next one.
* **Tag:** GMAC, that is AES-256-GCM with the **page key**, nonce `page number (u64 LE) || 0 (u32)`, empty plaintext and the 4080 entry bytes as the associated data. The key is specific to this use and to this file, and the page number is in the nonce: a page only verifies at its position and in its file.

## V9.9 Footer
`HMAC-SHA256(structure key, "pon-db/v9/footer\0" || header (128))`, 32 bytes, verified in constant time when the file is opened. It covers every field of the header (offsets, the geometry of the index table, `max_probe`, capabilities); the pages, the coincidence tables, the metadata and the records are authenticated one by one when they are read, so opening a file costs the same whatever its size.

## V9.10 Lookup (`field=value` on an indexed field)
1. Open: read the header, derive the keys, read the footer and verify it; read and decrypt the metadata block to learn which fields are indexed.
2. Compute the keyed hash of (field, value) for each candidate key; read the page (or pages, up to `max_probe`) of the search rule, verify their tags, and find the entry.
3. If the pointer is flagged, read and verify the coincidence table.
4. Read each block, decrypt it with its offset as AAD, and compare the field value (the hash only finds candidates).

For an expression with `AND` / `OR`, steps 2 and 3 are done for every equality on an indexed field to learn how many records each one matches (the count of a coincidence table is read without authenticating it, only to choose the plan); the most selective one of each `AND` group drives the lookup, the candidates of all the `OR` branches are united, and step 4 checks the **whole expression** on each candidate. A branch without an indexed equality, or too many candidates, scans the data body instead.

## License

- **Code**: [GNU AGPL-3.0-only](LICENSE).
- **Documentation** (this README): [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/). You may share and adapt it with attribution, under the same license.

Copyright (C) 2026 Roberto C. Alemán F.

## Contact
If you would like to contact me, you can write to roberto@pon-db.com

[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/S2Y6296BZ2)

## Important
I am currently not accepting pull requests (PRs);
if you would like to make a suggestion, please post it in the issues section or you can write to roberto@pon-db.com

<p align="center">
  <b>Author : Roberto C. Alemán F., Zulia, Venezuela.</b><br/><img src="https://flagcdn.com/ve.svg" alt="Flag of Venezuela" width="32">
</p>
<p align="center">
  <a href="https://pon-db.com" title="Official website of pon-db">Website</a><br/>
  <b>License: GNU Affero General Public License (AGPL-3.0-only)</b>
</p>
