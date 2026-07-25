### Licensing & Terms of Use

This repository contains **documentation and integration samples**. 
Please note that the **PON-Reader** binary and the **PON-DB Engine** are proprietary software but these are free software programs, according to:

PON-Reader is a lightweight reader for .pon files and is free without limitations.
You can download from:
https://huggingface.co/buckets/pondbengine/ponfiles/tree/pon-db-reader

PON-Engine is a .pon file generator and is free in its community version, which allows you to generate .pon files with up to 1 million records, taking into account the JSON or JSONL file to be ingested. This versions you can get with my book in https://pon-db.com

## Example of use:

# Option 2: Users Dataset

You can test PON-Reader with the .pon file available at:
https://huggingface.co/buckets/pondbengine/ponfiles

PON file: https://huggingface.co/buckets/pondbengine/ponfiles/tree/users_1m.json.pon
Key: https://huggingface.co/buckets/pondbengine/ponfiles/tree/masterkey_w2xuWpVD_2026-03-27.bin

# The original dataset comes from:
https://jsoneditoronline.org/indepth/datasets/json-file-example/

You can compare both and compare the results.

-----------------
# Option 2.1: Trading Dataset 100k rows

Original dataset: https://huggingface.co/buckets/pondbengine/ponfiles/tree/100k.jsonl
PON file:  https://huggingface.co/buckets/pondbengine/ponfiles/tree/100k.jsonl.pon
Key: https://huggingface.co/buckets/pondbengine/ponfiles/tree/masterkey_PEdkWK0b_2026-07-25.bin

Example of Use.

 ./pon-db-engine 100k.jsonl.pon query "tx_id=1" --key=masterkey_PEdkWK0b_2026-07-25.bin
{"tx_id":1,"tx_hash":"0x0652ce9e99614e938cf0454504105562a6565f696d1d4b7d94ae7175e4a8a417","timestamp":"2026-06-25T12:08:47.114Z","symbol":"LINK_USDC","type":"MARKET_SELL","status":"CANCELED","price":77.2182,"amount":853.571359,"total_value":65911.2439,"fee":70.1416,"account_id":"ACC-938333","counterparty_id":"ACC-602416","mempool_latency_ns":508,"engine_id":"ME-CORE-04"}
 ./pon-db-engine 100k.jsonl.pon query "tx_id=99999" --key=masterkey_PEdkWK0b_2026-07-25.bin
{"tx_id":99999,"tx_hash":"0x57f6beb68ffa48539ddae710b536f8ced4dc5a5968a1425eadd2196bc987d761","timestamp":"2026-06-25T12:09:12.207Z","symbol":"LINK_USDC","type":"LIMIT_SELL","status":"CANCELED","price":142.4318,"amount":19.148063,"total_value":2727.2931,"fee":2.4693,"account_id":"ACC-724137","counterparty_id":"ACC-963740","mempool_latency_ns":734,"engine_id":"ME-CORE-04"}

---------------

#Option 2.2: Trading Dataset 1M rows

Original dataset: https://huggingface.co/buckets/pondbengine/ponfiles/tree/1M.jsonl
PON file: https://huggingface.co/buckets/pondbengine/ponfiles/tree/1M.jsonl.pon
Key: https://huggingface.co/buckets/pondbengine/ponfiles/tree/masterkey_X1tdU6vy_2026-07-23.bin

Example of Use.

 ./pon-db-engine 1M.jsonl.pon query "tx_id=475135" --key=masterkey_X1tdU6vy_2026-07-23.bin
{"tx_id":475135,"tx_hash":"0x4be1ed863414423facd023d4ec796cf9ae66250f217845e6bc93cf4b7ae60109","timestamp":"2026-06-24T02:43:28.078Z","symbol":"XRP_USD","type":"MARKET_BUY","status":"FILLED","price":191.4826,"amount":834.469546,"total_value":159786.3983,"fee":258.2406,"account_id":"ACC-143153","counterparty_id":"ACC-500743","mempool_latency_ns":705,"engine_id":"ME-CORE-04"}
 ./pon-db-engine 1M.jsonl.pon query "tx_id=745123" --key=masterkey_X1tdU6vy_2026-07-23.bin
{"tx_id":745123,"tx_hash":"0x0501b248ad404130bc63ba601a565c36d97db33a7082477db9dad747a7a9dca3","timestamp":"2026-06-24T02:44:35.575Z","symbol":"ADA_EUR","type":"MARKET_BUY","status":"REJECTED","price":119.7921,"amount":493.09617,"total_value":59069.0257,"fee":58.8232,"account_id":"ACC-138159","counterparty_id":"ACC-226113","mempool_latency_ns":811,"engine_id":"ME-CORE-02"}

-----------------------

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




