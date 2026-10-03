# Measured Stage 3 baseline

Python and the supervised subprocess backend remain the default. The final controlled Windows comparison used the same 16 candidates (12 positive / 4 refused endpoints), four workers, three rounds, and exact outcome comparison. Subprocess median was 2.648 s, pool 2.879 s, TCP prefilter 4.676 s; mismatches were zero. These results support neither the former unmeasured 2–4x pool claim nor a native rewrite. Different hardware/networks may change the result; promote an alternative only after equivalent outcomes and repeated representative measurements.

```bash
python tools/install_cores.py
python -m openray.benchmarks --input output/all_valid_proxies.txt --core --core-count 16 --workers 4 --rounds 3
python scripts/compare_stage3_backends.py -i output/all_valid_proxies.txt -n 16 -t 5 --backends subprocess,pool,api
python tools/state_benchmark.py --database benchmark-results/migration-final.sqlite3
python tools/endurance.py --seconds 86400 --workers 4
```

The comparison CLI preserves `-i`, `-n`, `-t` and `--backends`; input parsing is offline and the actual network comparisons use controlled fixtures. It no longer probes arbitrary public input endpoints. `repro_concurrency.py` also uses the controlled harness and retains iteration/timeout environment aliases. Benchmark core fixtures require a repository development checkout, not a standalone runtime wheel.

Reports include elapsed wall time, CPU, RSS, handles/FDs, child counts, success counts and latency percentiles. Do not compute throughput by summing overlapping candidate durations. Do not confuse a post-render RSS sample with peak RSS or a smoke soak with the 24-hour gate. See `implementation.md` and `evidence/` for measurements, qualification and the release acceptance status.
