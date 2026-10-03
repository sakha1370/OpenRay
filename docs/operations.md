# Operations, rollout and recovery

## Installation

Use CPython 3.13 or newer. The tested core installer supports Windows and Linux AMD64. The local verification ran CPython 3.13.15 AMD64 on Windows 11 ARM64 under Windows emulation. Other architectures need verified core assets before being treated as supported.

```bash
python -m venv .venv
# Activate .venv using the command appropriate to your shell.
python -m pip install -r requirements-dev.lock
python -m pip install --no-deps --no-build-isolation -e .
python tools/install_cores.py
python -m unittest discover -v
ruff check openray tests tools
ruff format --check .
```

Runtime and transitive package versions are pinned in `requirements.lock`; `requirment.txt` remains a compatibility alias. Core archives have SHA-256 pins in `openray/assets/cores.lock.json`. Rule assets use commit pins in `rules.lock.json`. Python distribution hashes are not yet in the dependency lock. Review and regenerate pins deliberately, run protocol integrations and both actual client checks, then canary a core or rule update. Never download floating latest releases during a collector run.

Core installation retries transient connection/DNS errors, interrupted responses and HTTP 408/429/5xx up to four attempts, waiting 1, 2 and 4 seconds. Each attempt starts a fresh archive and checksum. Certificate errors, permanent HTTP errors, oversized bodies and checksum mismatches fail closed; an unsuccessful download cannot replace an installed binary. The publishing job downloads only sing-box and mihomo for its independent client gates.

The package can be installed as a wheel. Root selection is explicit `--root`, `OPENRAY_ROOT`, then the working directory; installation never directs mutable state into site-packages. Source templates fall back to packaged assets when absent. A wheel does not bundle the MaxMind database: provide the existing repository database with confirmed provenance/redistribution terms, or use the deterministic `XX` fallback for unknown locations. This checkout has no project LICENSE file; release ownership must resolve that separately.

## Migration and first run

Stop legacy schedulers before migration. Keep `.state` legacy JSON/binary files and published lists unchanged as recovery inputs. Migration makes checksummed copies under the SQLite directory's `backups/legacy-*`, verifies them, streams binary history and commits the import transaction. Truncated input rolls back; rerunning a completed migration is a no-op. Scores use the maximum across aliases of a connection, preventing double counting. Nested Iran totals and operator counters remain separate.

```bash
python -m openray migrate
python -m openray status
python tools/verify_migration.py .state/openray.sqlite3 --deep-history
python -m openray backup .state/backups/pre-cutover.sqlite3
python -m openray run --mode combined --report .state/latest-run.json
```

Historical accepted proxies are retained at migration; this does not claim they have been revalidated by the new engine. Only successful new connectivity checks can promote new candidates. Inspect the report's snapshot path, core errors, conversion omissions and due backlog. `python -m openray verify SNAPSHOT_DIRECTORY` checks file hashes, deduplication, partition parity and JSON/YAML parsing. Build-only `export` stages a snapshot; `export --install`, `run --install` and `publish` require both client schema validators and reject invalid configurations.

## Configuration and scheduling

Configuration is validated once per invocation. Legacy launch modules and the five-argument converter command remain available; run `python -m openray --help` for the new CLI. Operator flags are mutually exclusive; local/Iran modes default to `others`, never to global. `--context iran` records generic Iranian results explicitly. A site check has its own versioned health and cannot change connectivity scores.

| Setting | Default / contract |
|---|---|
| `OPENRAY_ROOT`, `OPENRAY_DATABASE`, `OPENRAY_SOURCES` | Working directory, `.state/openray.sqlite3`, `sources.txt` |
| `OPENRAY_STAGE3_WORKERS` / `OPENRAY_STAGE3_POOL_SIZE` | 8; maximum 128; memory setting also caps workers |
| `OPENRAY_MEMORY_MB` | 2048; heuristic reserves 256 MiB plus 96 MiB per worker |
| `OPENRAY_FETCH_WORKERS`, `OPENRAY_QUEUE_SIZE` | 8, four times worker count |
| `OPENRAY_RUN_BUDGET_S`, CLI `--budget` | 3000 seconds; reserves up to 60 seconds for exports/client gates |
| `OPENRAY_STAGE3_MAX` | 5000 per validation category/target |
| `OPENRAY_STAGE3_NEW_TIMEOUT_S`, `OPENRAY_STAGE3_EXISTING_TIMEOUT_S` | 12 seconds each, including queue lease/startup/probe |
| `OPENRAY_FETCH_TIMEOUT`, `OPENRAY_SOURCE_CACHE_MB` | 15 seconds per request attempt, 128 MiB cached source bodies |
| `OPENRAY_ALIVE_CHECK_COOLDOWN_H`, `OPENRAY_ALIVE_DEATH_AFTER_H` | 8 hours; at least two confirmed failures spanning 72 hours before global removal |
| `OPENRAY_STAGE3_BACKEND` | `subprocess`; `pool`/`api`/`xray_api` experimental Xray reuse |
| `OPENRAY_XRAY`, `OPENRAY_V2RAY_CORE`, `V2RAY_CORE_PATH` | Core path override; verified `.tools` before ambient PATH detection otherwise |
| `OPENRAY_SINGBOX`, `OPENRAY_MIHOMO` | Complementary core path overrides |
| `OPENRAY_TEST_URL`, `OPENRAY_TEST_STATUS`, `OPENRAY_TEST_BODY_SHA256` | Cloudflare 204; optional exact decoded body digest |
| `OPENRAY_CHECK_SITES` | `1`; `0` omits additional site checks |
| `OPENRAY_ALLOW_PRIVATE_SOURCES` | `0`; explicit `1` permits private-address/outside-root source inputs |
| `OPENRAY_CLIENT_TUN` | `0`; `1` uses the source template's TUN preset, requiring platform privileges |
| `OPENRAY_EXPORT_V2RAY` | Off; emits optional `output/v2ray_configs/<remark>.json` |

The collector does not use ICMP or a successful TCP connect as evidence of a working proxy. Disabling Stage 3 is rejected. Fixed base ports, import-time speed calibration, minimum artificial wait time and the legacy thread/ping settings are retired. The optional TCP prefilter is off by default and skips UDP protocols. Pool reuse removes and installs an outbound under a worker lease, recycles after 100 jobs, and uses a fresh HTTP client for every candidate. The experimental Xray HandlerService API assumes a trusted host; its loopback control port is not authenticated. The default subprocess backend does not expose that API.

Leases expire and are paged by oldest due time; cooldown-zero invocations cannot count the same candidate twice in one run. Source traversal also uses persistent oldest-fetch ordering so later sources do not starve when budgets expire. Combined runs allocate separate budgets to discovery, accepted connectivity, new connectivity and each site. New unprocessed candidates stay queued, never appended as valid. A batch without a successful target control records ambiguous failures as `target_failure`; this conservative policy can retain stale proxies during a prolonged outage or an all-failed batch.

`source_failure`, `core_failure`, `unsupported`, `invalid_config` and `target_failure` do not increment proxy-failure counters. Unsupported configurations retry after an hour; infrastructure outcomes retry after a minute. Pending ambiguous failures are journaled before attribution; recovery never attributes an interrupted batch's failures to proxies. `observed_at` and target versions prevent old bundles from regressing current health; observations cannot release another run's lease.

## Publishing and regional observations

```bash
python -m openray publish SNAPSHOT_DIRECTORY
python -m openray run --mode iran --mci --report .state/mci-run.json
python -m openray publish-bundle PATH_FROM_RUN_REPORT
python tools/import_regional.py
```

Publishing validates an immutable snapshot and applies only output paths in a temporary detached worktree built from the fetched remote commit. Installation preflights every member and stale-file deletion before writing; export paths containing symlinks or Windows junctions are rejected, including links to other files inside the repository. Use real export directories. It never resets, stashes or force pushes the caller's checkout. A non-fast-forward race retries against new remote code with the same snapshot, up to three attempts. The caller's local modifications remain intact. Retry a failed publication using the retained snapshot path.

Regional observations are append-only bundles on `operator-observations`, never direct edits to `main`. Global collection fetches/imports that branch; imports are transactional and idempotent. Bundle and observation ID collisions are rejected. Local success increments its operator and the Iran aggregate, leaving global counters unchanged. `auto_update.sh` keeps legacy operator flags and `--skip-git`; publishing is enabled by its existing default behavior. No real remote was pushed during local engineering verification.

Raw subscriptions, score exports, country/protocol groups, site lists and seven pairs of converted configurations keep their public paths. All 95 baseline country groups and canonical protocol groups exist even when empty. Empty files correctly mean no current members. Install writes every member atomically and the manifest last. Git publication is one commit. Direct readers of several local files should verify the manifest/retry or read the immutable snapshot directory: filesystem replacement of an entire multi-file subscription tree is not atomic.

## State retention, backup and rollback

SQLite uses WAL, FULL synchronization, foreign keys and explicit transactions. Keep it on a local persistent disk. Use the SQLite backup command rather than copying a live database/WAL by hand. Backups contain credentials and must inherit private directory/ACL permissions.

```bash
python -m openray backup .state/backups/checkpoint.sqlite3
python -m openray maintenance --retention-days 90
python -m openray maintenance --apply --retention-days 90
# Stop all collectors; restore uses a NEW destination, never overwrites a live database.
python -m openray --database .state/restored.sqlite3 restore .state/backups/checkpoint.sqlite3
python -m openray --database .state/restored.sqlite3 status
```

Maintenance is a dry run unless `--apply` is specified, rejects active leases, checks integrity and creates a backup first. It expires old tested hashes/cache bodies, archives observation identity tombstones, preserves counters/exactly-once semantics, prunes acknowledged snapshots while keeping two, and retains unpublished regional bundles. Maintenance retains two maintenance backups; legacy migration backups remain until the cutover gate. Candidate rows and event identity tombstones can still grow with distinct connections/events: monitor database and backup disk usage; deleting them requires a separate lifecycle policy that preserves identity/counter semantics.

Rollback consists of stopping the new scheduler, choosing a verified checkpoint/new destination and a known-good code/core pin set, restoring, verifying and resuming one coordinator. Do not attempt to resume old writers against SQLite. If returning to the legacy engine during the initial canary, restore the read-only legacy seed copies and their matching code revision as a unit. Never overwrite the new database with legacy JSON exports.

## Deployment and release gates

`deploy/openray.service` and `.timer` provide an unprivileged Linux persistent-state collector with memory/task/file limits and cgroup termination. Place a virtual environment and verified cores in `/opt/openray`, provision user `openray` and writable `.state`, and keep code read-only. The service stages snapshots without pushing. A separately authorized publisher should consume the reported snapshot and retain an offsite checkpoint. Controlled deadline/cancellation tests prove normal owned-child cleanup; forced parent death outside a supervisor, particularly standalone Windows termination, has no local acceptance evidence. No service was installed on the user's computer.

CI covers Linux/Windows, offline/unit tests, actual core integrations, Ruff and a bounded benchmark. Both GitHub runner jobs passed 45 tests and fresh pinned dependency/core installation after the Windows source-root alias fix; see [GitHub evidence](evidence/github-ci.json). Workflow/action references are immutable. Hosted collection restores an integrity-checked checkpoint artifact, uses read-only collection permissions, imports regional bundles, stages a snapshot, then hands it to a separate write-enabled publisher. Global workflow concurrency queues runs instead of cancelling a running writer. The active `Check Proxies` schedule remains hourly (`0 * * * *`); combined runs discover new sources and validate due connectivity/site work before gated publication.

Hosted Actions checkpoint only at job teardown. A hard runner loss before upload can lose that invocation's observations. Artifact retention is 90 days; it is not permanent/offsite state storage. A production persistent-disk deployment plus independent backups is required for tighter RPO. The checkpoint restore helper refuses a legacy fallback after a versioned publication exists without a recoverable checkpoint.

Before declaring the production rollout accepted:

1. Keep the Linux/Windows workflow matrix green on the intended runners. Both GitHub-hosted platforms are now verified; deployments on other hosts still need their own acceptance.
2. Run `python tools/endurance.py --seconds 86400 --workers 4` on the target host. Local evidence is a 30-second smoke soak, not the 24-hour gate.
3. Run one representative week in shadow/canary mode on the global network and each required Iranian operator. Verify no unexplained capability/output loss, score continuity, due backlog draining within the configured cadence, bounded RSS/handles/processes and restore/publication recovery.
4. Exercise SSR against a representative controlled server. Its actual mihomo schema is verified locally; server interoperability remains unproven. Juicity has no faithful installed adapter and remains an explicit unsupported outcome.
5. Resolve distribution/license provenance, move checkpoints offsite and prove restore on the deployment host. Then retire archived legacy JSON/binary seed inputs and obsolete tracked generated artifacts.

Run reports contain wall time (including export checks), validation time, checks/minute, p50/p95/p99, typed outcomes, core errors, due backlog, snapshot and bundle paths. Alert on nonzero core errors, invalid client gates, absent snapshots, repeated budget exhaustion, growing backlog, stale published snapshots, missing backups and unusual conversion omissions. Exit codes: `0` completed/staged, `2` infrastructure/input/publication failure, `3` rejected client export gate, `130` cancellation with completed observations retained. A partial-budget run can exit `0` after staging completed valid work; inspect `budget_exhausted` and backlog to assess capacity.
