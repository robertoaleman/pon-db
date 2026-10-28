<h1 align="center">PON-DB</h1>
<p align="center">
  <b>Author : Roberto C. Alemán F.</b><br/><b>Zulia, Venezuela</b><br/><img src="https://flagcdn.com/ve.svg" alt="Bandera de Venezuela" width="48">
<p align="center">
  <a href="https://pon-db.com">Website</a><br/><br/>
   <b>License: GNU Affero General Public License (AGPL-3.0-only) </b></br>
   <b>Current version available: v8.4</b></br>
 
[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/S2Y6296BZ2) 

</p>


# What is PON-DB Engine?
PON stands for Positional Object Notation. It is a set of rules, a data normalization protocol, a file format specification, and the RA-CHAMPI algorithm that allows operations performed at the speed that could be obtained by processing the data stored on disk as a direct extension of physical memory.

PON-DB Engine is a database engine encapsulated in a single, portable, and strictly encrypted binary format, designed to treat the data file not as a conventional storage structure, but as a direct extension of physical memory. Its architecture is based on the creation of high-density .pon files, wherein each point of information possesses an exact and predetermined address, thereby eliminating the need for intermediate translation layers or heavyweight relational management systems.

In this same line of thought, we could also see it as an autonomous database, an engine that stores the data, and an analyzer that reads and finds it according to the rules of the algorithm.

PON-DB software is a practical implementation of data-centric computing principles, where the priority shifts from the application to the efficiency, permanence, and autonomy of the data. This paradigm seeks to treat data as the permanent source of value, allowing it to exist independently of applications. In the case of PON-DB, this translates into files that are not simply passive containers, but "intelligent" structures that integrate their own search and encryption engine, enabling O(1) queries without relying on an external or cumbersome database infrastructure.

Under this approach, PON-DB breaks with the traditional CPU-centric model, where data must constantly be moved to the application for processing. Instead, by encapsulating access logic and security directly in the file format (such as the .pon file), it achieves what data-centric computing defines as operational agility and flexibility: data becomes "liquid" and portable. This allows the software to act simply as a minimal key to unlock the potential of the data, guaranteeing extreme performance and decentralized security that remains constant regardless of the environment where the information resides.

## Getting Started

### Prerequisites
* Rust 1.75 or higher
* Cargo package manager

### 1. Build and Install

Clone the repository and build the optimized release binary:

```bash
git clone [https://github.com/robertoaleman/pon-db.git](https://github.com/robertoaleman/pon-db.git)
cd pon-db-engine
cargo build --release
```
2. Ingesting and Indexing Data
To ingest a raw JSON dataset and build a solid-state .pon binary file with an indexed field, run:

```
./target/release/pon-db-engine dataset.json --index=sku
```

What happens during ingest:
The engine streams the dataset line by line with low memory consumption.
The indexed field (e.g., sku) is hashed into a sharded index table for O(1) direct addressing.
All data blocks are encrypted using AES-256-GCM.
A master key file (masterkey_XXXXXXXX_YYYY-MM-DD.bin) is automatically generated.
A PON-DB GREEN COMPLIANCE REPORT is emitted upon successful execution.

3. Querying Data
  
A. Fast O(1) Hash Index LookupTo execute an exact-match query using the generated master key:

```
./target/release/pon-db-engine dataset.json.pon query "price>500" --key=masterkey_ABC12345_2026-10-26.bi
```
4. Exporting Data (No Vendor Lock-in)

To verify dataset integrity and export all decrypted records back to standard JSON format stdout:
```
./target/release/pon-db-engine dataset.json.pon export --key=masterkey_ABC12345_2026-10-26.bin > restored_dataset.json
```

# PON-DB File Format Specification (.pon)

* **Version:** V8.5  
* **Design Paradigm:** Single binary, solid-state flat-file architecture with O(1) direct file addressing.
---

## 1. File Structure Overview
A `.pon` file is structured sequentially into logical blocks:
1. **Header (128 bytes)**: Fixed-size metadata container controlling engine validation, security flags, and structural offsets .
2. **Data Body Section**: Continuously appended, AES-256-GCM encrypted record payloads .
3. **Index Table Section (Sharded)**: Sorted 16-byte index entries (`[HASH: 8] [OFFSET: 8]`) organized into sharded buckets for fast binary search .
4. **Coincidence Table Section**: Overflow collision resolution tables for handling multi-record hashes .

---

## 2. Header Layout (`PonHeaderV8` — 128 Bytes)
The file begins with a strict 128-byte header . All numeric multi-byte values are stored in **little-endian** format.

| Offset Range | Field Name | Type | Description |
| :--- | :--- | :--- | :--- |
| **0..4** | `magic` | `[u8; 4]` | Magic bytes identifier, always `*b"PON8"` . |
| **4** | `version` | `u8` | Engine version identifier (`0x0A` for V8.5 internal) . |
| **5** | `data_model` | `u8` | Data model revision (`0x02`) . |
| **6** | `mode_flag` | `u8` | Operational configuration flags (Bit 3 controls Hardware Binding) . |
| **7** | `security_type` | `u8` | Encryption/Security scheme identifier (`0x02` for AES-256-GCM) . |
| **8..12** | `arch_tag` | `[u8; 4]` | Architecture tag (`*b"X866"`) . |
| **12..20** | `created_at` | `u64` | Unix timestamp (seconds) when the `.pon` file was created . |
| **20..28** | `license_issue_date`| `u64` | License issuance timestamp . |
| **28..36** | `uptime_at_creation`| `u64` | System hardware uptime at creation (used for anti-tamper checks). |
| **36..40** | `shard_size_bytes` | `u32` | Shard/bucket size in bytes (optimized to L3 cache size, default 64KB). |
| **40..44** | `bucket_count` | `u32` | Total number of index buckets. |
| **44..48** | `total_rows` | `u32` | Total number of records ingested into the database. |
| **48..56** | `master_index_offset`| `u64` | File offset pointer to the master index. |
| **56..64** | `ribbon_filter_offset`| `u64` | File offset pointer to the ribbon filter. |
| **64..68** | `ribbon_filter_size`| `u32` | Size of the ribbon filter in bytes. |
| **68..76** | `math_mask` | `u64` | Mathematical operation bitmask. |
| **76..84** | `index_bitmask` | `u64` | Index availability bitmask. |
| **84..92** | `index_table_offset`| `u64` | File offset where the sharded index table starts (typically `128`). |
| **92..100** | `body_offset` | `u64` | File offset where the encrypted data body begins. |
| **100..120** | `creator_hash` | `[u8; 20]` | Hardware ID binding hash (or zeroed `[0u8; 20]` for universal mode). |
| **120..128** | `coincidence_table_offset`| `u64` | File offset pointing to the collision/coincidence resolution table 

---

## 3. Data Body Block Structure
Starting at `body_offset`, each record is sequentially written as an authenticated encrypted block using **AES-256-GCM**
```
+-------------------+----------------------+-----------------------+---------------------+
| NONCE (12 bytes)  | CIPHERTEXT LENGTH    | CIPHERTEXT (N bytes)  | AUTH TAG (16 bytes) |
|                   | (4 bytes, u32 LE)    |                       |                     |
+-------------------+----------------------+-----------------------+---------------------+
```
* **Nonce**: 12 cryptographically random bytes generated per record .
* **Ciphertext Length**: A 4-byte unsigned integer (`u32` little-endian) defining the length N of the encrypted JSON string .
* **Ciphertext**: N bytes of encrypted JSON data payload .
* **Auth Tag**: 16-byte AES-GCM authentication tag verifying payload integrity and authenticity .
---
## 4. Sharded Index Table Structure
Following the data body, the engine stores index records as flat 16-byte entries grouped into sharded buckets
```
+----------------------------+----------------------------+
| HASH (8 bytes, u64 LE)     | PHYSICAL OFFSET (8 bytes)  |
+----------------------------+----------------------------+
```
* **Hash**: 8-byte hash value derived from the indexed field value using `DefaultHasher`.
* **Physical Offset**: 8-byte pointer (`u64` little-endian) indicating the exact byte address of the corresponding block in the data body.
  * *Collision Flag*: If the highest bit (`bit 63`) of the physical offset is set to `1`, it acts as a pointer flag (`ptr | (1 << 63)`), indicating that multiple rows share this hash. The lower bits point to an entry in the **Coincidence Table** rather than a direct data block.

---

## 5. Coincidence (Collision) Table Structure
When multiple records hash to the same index key, they are resolved via the coincidence table located at `coincidence_table_offset`.
```
+----------------------+--------------------------+--------------------------+  
| COUNT (4 bytes, u32) | OFFSET #1 (8 bytes, u64) | OFFSET #2 (8 bytes, u64) |  
+----------------------+--------------------------+--------------------------+ 
```
* **Count**: A 4-byte integer (`u32`) specifying how many colliding record offsets are stored.
* **Offsets Array**: A sequence of 8-byte file addresses (`u64` little-endian) pointing directly to each matching record's physical block location in the file.



## License

- **Code**: [GNU AGPL-3.0-only](LICENSE).
- **Documentation** (`docs/` and this README): [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/). You may share and adapt it with attribution, under the same license.
Copyright (C) 2026 Roberto C. Alemán F.

## Contact 
If you would like to contact me, you can write to roberto@pon-db.com

[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/S2Y6296BZ2)

## Important
I am currently not accepting pull requests (PRs); 
if you would like to make a suggestion, please post it in the issues section or you can write to roberto@pon-db.com

<p align="center">
  <b>Author : Roberto C. Alemán F., Zulia, Venezuela.</b><br/><img src="https://flagcdn.com/ve.svg" alt="Bandera de Venezuela" width="32">
  </br>
<p align="center">
  <a href="https://pon-db.com" title="Official website of pon-db">Website</a> </br>
   <b>License: GNU Affero General Public License (AGPL-3.0-only) </b></br>
</p>
