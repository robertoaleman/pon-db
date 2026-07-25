### Licensing & Terms of Use

This repository contains **documentation and integration samples**. 
Please note that the **PON-Reader** binary and the **PON-DB Engine** are proprietary software but these are free software programs, according to:

PON-Reader is a lightweight reader for .pon files and is free without limitations.

PON-Engine is a .pon file generator and is free in its community version, which allows you to generate .pon files with up to 1 million records, taking into account the JSON or JSONL file to be ingested.

Example Test:
| Command | Mean [s] | Min [s] | Max [s] | Relative |
|:---|---:|---:|---:|---:|
| `systemd-run --user --scope -p MemoryMax=0.5M -p MemorySwapMax=0 ./pon-db-engine 1M.jsonl.pon query tx_id=999999 --key=masterkey_X1tdU6vy_2026-07-23.bin \| grep -q '999999'` | 1.751 ± 0.236 | 1.434 | 2.183 | 9.50 ± 2.31 |
| `systemd-run --user --scope -p MemoryMax=1M -p MemorySwapMax=0 ./pon-db-engine 1M.jsonl.pon query tx_id=999999 --key=masterkey_X1tdU6vy_2026-07-23.bin \| grep -q '999999'` | 0.184 ± 0.037 | 0.129 | 0.235 | 1.00 |
| `systemd-run --user --scope -p MemoryMax=2M -p MemorySwapMax=0 ./pon-db-engine 1M.jsonl.pon query tx_id=999999 --key=masterkey_X1tdU6vy_2026-07-23.bin \| grep -q '999999'` | 0.203 ± 0.031 | 0.169 | 0.238 | 1.10 ± 0.28 |
| `systemd-run --user --scope -p MemoryMax=3M -p MemorySwapMax=0 ./pon-db-engine 1M.jsonl.pon query tx_id=999999 --key=masterkey_X1tdU6vy_2026-07-23.bin \| grep -q '999999'` | 0.270 ± 0.066 | 0.165 | 0.365 | 1.46 ± 0.46 |
| `systemd-run --user --scope -p MemoryMax=4M -p MemorySwapMax=0 ./pon-db-engine 1M.jsonl.pon query tx_id=999999 --key=masterkey_X1tdU6vy_2026-07-23.bin \| grep -q '999999'` | 0.228 ± 0.045 | 0.170 | 0.324 | 1.24 ± 0.35 |
| `systemd-run --user --scope -p MemoryMax=8M -p MemorySwapMax=0 ./pon-db-engine 1M.jsonl.pon query tx_id=999999 --key=masterkey_X1tdU6vy_2026-07-23.bin \| grep -q '999999'` | 0.227 ± 0.056 | 0.146 | 0.327 | 1.23 ± 0.39 |
| `systemd-run --user --scope -p MemoryMax=12M -p MemorySwapMax=0 ./pon-db-engine 1M.jsonl.pon query tx_id=999999 --key=masterkey_X1tdU6vy_2026-07-23.bin \| grep -q '999999'` | 0.202 ± 0.032 | 0.150 | 0.243 | 1.10 ± 0.28 |


How to Use

*   **Official Documentation:** [View Documentation](https://pon-db.com/howtouse.html)
*   **Official License:** [View License Agreement](https://pon-db.com/legal/license-pon-reader.html)
*   **Copyright Notice:** © 2026 **Roberto C. Aleman F.** All rights reserved.




