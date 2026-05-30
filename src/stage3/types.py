from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Optional


class BackendKind(str, Enum):
    SUBPROCESS = 'subprocess'
    POOL = 'pool'
    API = 'api'


@dataclass
class TimingStats:
    config_ms: float = 0.0
    spawn_ms: float = 0.0
    ready_ms: float = 0.0
    fetch_ms: float = 0.0
    teardown_ms: float = 0.0

    @property
    def total_ms(self) -> float:
        return self.config_ms + self.spawn_ms + self.ready_ms + self.fetch_ms + self.teardown_ms


@dataclass
class CheckResult:
    uri: str
    result: Optional[bool]
    timing: TimingStats = field(default_factory=TimingStats)


@dataclass
class Stage3Summary:
    backend: str
    checked: int = 0
    ok: int = 0
    failed: int = 0
    none_count: int = 0
    total_ms: float = 0.0
    timings: list = field(default_factory=list)

    def record(self, result: Optional[bool], timing: TimingStats) -> None:
        self.checked += 1
        self.total_ms += timing.total_ms
        self.timings.append(timing.total_ms)
        if result is True:
            self.ok += 1
        elif result is False:
            self.failed += 1
        else:
            self.none_count += 1

    def p50_s(self) -> float:
        if not self.timings:
            return 0.0
        s = sorted(self.timings)
        return s[len(s) // 2] / 1000.0

    def p95_s(self) -> float:
        if not self.timings:
            return 0.0
        s = sorted(self.timings)
        idx = min(len(s) - 1, int(len(s) * 0.95))
        return s[idx] / 1000.0

    def proxies_per_min(self) -> float:
        if self.total_ms <= 0:
            return 0.0
        return (self.checked / self.total_ms) * 60000.0

    def format_line(self) -> str:
        return (
            f"stage3 backend={self.backend} checked={self.checked} ok={self.ok} "
            f"failed={self.failed} none={self.none_count} p50={self.p50_s():.2f}s "
            f"p95={self.p95_s():.2f}s proxies_per_min={self.proxies_per_min():.1f}"
        )
