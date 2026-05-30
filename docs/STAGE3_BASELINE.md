# Stage 3 performance baseline

Measure Stage 3 throughput before and after backend changes.

## Local repro

```bash
# Requires Xray on PATH or OPENRAY_V2RAY_CORE set
export OPENRAY_DEBUG=1

# Subprocess (legacy)
export OPENRAY_STAGE3_BACKEND=subprocess
python repro_concurrency.py

# Worker pool (default)
export OPENRAY_STAGE3_BACKEND=pool
python repro_concurrency.py

# API daemon backend
export OPENRAY_STAGE3_BACKEND=api
python repro_concurrency.py
```

Optional env vars:

- `OPENRAY_REPRO_N` — number of iterations (default 10)
- `OPENRAY_REPRO_TIMEOUT` — per-check timeout seconds (default 15)
- `OPENRAY_STAGE3_POOL_SIZE` — pool workers (default `STAGE3_WORKERS`)
- `OPENRAY_STAGE3_BASE_PORT` — first fixed HTTP port (default 31000)

## CI baseline (ubuntu-latest)

Record on GitHub Actions with `STAGE3_WORKERS=16`:

1. Wall time of the "Run proxies checker" step
2. `proxies_per_min` from debug log line: `stage3 backend=...`
3. Peak memory if available from runner metrics

Typical expectation after pool rollout: **2–4x** proxies/min vs subprocess on the same runner.

## Backend comparison

```bash
python scripts/compare_stage3_backends.py -i output/all_valid_proxies.txt -n 20
```

Compare mismatch rate between `subprocess`, `pool`, and `api` before promoting defaults.

Stage 3 optional deps (`grpcio`, `protobuf`) are listed in `requirment.txt` at the repo root.
