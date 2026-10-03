"""Compatibility facade; lifecycle managed by openray.validation."""

from openray.legacy_stage3 import Stage3Engine


class SubprocessBackend(Stage3Engine):
    def __init__(self):
        super().__init__(kind="subprocess")
