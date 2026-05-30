import os
import statistics
import sys
import time

sys.path.insert(0, os.path.join(os.getcwd(), 'src'))

from stage3.engine import get_engine
from stage3.metrics import get_summary
from constants import V2RAY_CORE_PATH, STAGE3_BACKEND


def main() -> int:
    if not V2RAY_CORE_PATH or not os.path.exists(V2RAY_CORE_PATH):
        print(f"Xray core not found at {V2RAY_CORE_PATH}")
        return 1

    test_uri = (
        "vless://00000000-0000-0000-0000-000000000000@1.2.3.4:443"
        "?encryption=none&security=tls&type=tcp#Test"
    )
    n = int(os.environ.get('OPENRAY_REPRO_N', '10'))
    timeout_s = int(os.environ.get('OPENRAY_REPRO_TIMEOUT', '15'))

    print(f"Backend={STAGE3_BACKEND} core={V2RAY_CORE_PATH} n={n} timeout={timeout_s}s")
    engine = get_engine(force_new=True)

    durations: list = []
    t0 = time.perf_counter()
    for _ in range(n):
        start = time.perf_counter()
        res = engine.validate_one(test_uri, timeout_s=timeout_s)
        durations.append(time.perf_counter() - start)
        print(f"  result={res} duration={durations[-1]:.2f}s")

    elapsed = time.perf_counter() - t0
    summary = get_summary()
    print(f"\nTotal wall: {elapsed:.2f}s")
    if durations:
        print(f"p50={statistics.median(durations):.2f}s p95={sorted(durations)[int(len(durations)*0.95)]:.2f}s")
    print(f"proxies_per_min={(n / elapsed) * 60:.1f}" if elapsed > 0 else "proxies_per_min=0")
    if summary:
        print(summary.format_line())
    engine.shutdown()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
