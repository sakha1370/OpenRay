"""Controlled concurrency repro; does not probe unrelated public endpoints."""

import os
import sys

from openray.benchmarks import main


if __name__ == "__main__":
    raise SystemExit(
        main(
            [
                "--core",
                "--count",
                "1000",
                "--core-count",
                os.environ.get("OPENRAY_REPRO_N", "16"),
                "--timeout",
                os.environ.get("OPENRAY_REPRO_TIMEOUT", "5"),
                *sys.argv[1:],
            ]
        )
    )
