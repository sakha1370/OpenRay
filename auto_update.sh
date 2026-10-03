#!/usr/bin/env bash
set -euo pipefail
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
cd "$repo"
python_bin=${OPENRAY_PYTHON:-python3}
skip_git=false
args=()
for arg in "$@"; do
  if [[ "$arg" == "--skip-git" ]]; then skip_git=true; else args+=("$arg"); fi
done
"$python_bin" -m openray run --mode iran --install --report .state/local-run.json "${args[@]}"
if [[ "$skip_git" == false ]]; then
  mapfile -t bundles < <("$python_bin" -c 'from openray.config import Settings; print("\n".join(str(p) for p in sorted((Settings.from_env().database.parent / "runs").glob("*.bundle.json"))))')
  for bundle in "${bundles[@]}"; do
    [[ -n "$bundle" ]] || continue
    "$python_bin" -m openray publish-bundle "$bundle"
  done
fi
