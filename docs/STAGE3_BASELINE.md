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

## Why GitHub Actions may not feel faster

The **pool** backend only reduces Xray startup/port overhead (roughly 1–3s per proxy). On `check-proxies.yml` most wall time is still:

1. **Re-checking up to `STAGE3_MAX` (5000) existing proxies** — each waits on network (`OPENRAY_STAGE3_MIN_ATTEMPT_S`, timeouts).
2. **Fetching sources + Stage 2** for new proxies.
3. **Six converter runs** (`sub2clash_singbox.py`) after `src.main`.
4. **Git merge/push**.

So total workflow time can stay similar even when Stage 3 orchestration is faster.

After the CI tuning fix, logs include:

```
Stage3 validate_many: backend=pool n=... timeout_s=12 pool_size=16
stage3 backend=pool checked=... proxies_per_min=...
```

Compare `proxies_per_min` between runs, not only the job duration.

To cut hourly job time further (trade-offs):

- `OPENRAY_STAGE3_MAX=1500` — re-check fewer existing proxies per run.
- Use split workflows: `check-new-proxies` + `check-previous-proxies` instead of full `check-proxies` every time.
