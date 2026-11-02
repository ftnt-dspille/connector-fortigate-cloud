#!/usr/bin/env bash
# Build the connector bundle FortiSOAR installs:
# dist/fortigate-cloud-<version with underscores>.tgz, unpacking to a single
# fortigate-cloud/ directory.
#
# The .tgz filename must replace the version dots with underscores: FortiSOAR's
# upload handler routes on the underscored form and misroutes dotted names.
# The connector's own README.md and release_notes.md ship inside the package;
# only the repo-root copies are excluded.
set -euo pipefail

cd "$(dirname "$0")/.."
NAME=$(python3 -c "import json;print(json.load(open('fortigate-cloud/info.json'))['name'])")
VERSION=$(python3 -c "import json;print(json.load(open('fortigate-cloud/info.json'))['version'])")
FILENAME="${NAME}-${VERSION//./_}.tgz"
OUT="dist/${FILENAME}"

EXCLUDE='^(\.git/|\.gitignore$|dist/|scripts/|tests/|\.venv/|README\.md$|release_notes\.md$|devices_snapshot\.json$|\.env.*$|fortigate_cloud$|__pycache__/|.*\.pyc$|\.DS_Store$|\.pytest_cache/|\.mypy_cache/|\.ruff_cache/)'

if git rev-parse --is-inside-work-tree >/dev/null 2>&1 && [ -n "$(git ls-files)" ]; then
    mapfile -t FILES < <(git ls-files | grep -Ev "$EXCLUDE")
else
    mapfile -t FILES < <(find . -type f \
        | sed 's|^\./||' \
        | grep -Ev "$EXCLUDE")
fi
if [ ${#FILES[@]} -eq 0 ]; then
    echo "package: no files matched" >&2
    exit 1
fi

for required in info.json connector.py operations.py constants.py \
                make_rest_api_call.py device_actions.py fos_actions.py \
                generic_api_call.py fgt_proxy_actions.py release_notes.md; do
    printf '%s\n' "${FILES[@]}" | grep -qx "fortigate-cloud/$required" \
        || { echo "package: fortigate-cloud/$required missing from the bundle" >&2; exit 1; }
done

rm -rf dist && mkdir -p "dist/stage/${NAME}"
for f in "${FILES[@]}"; do
    mkdir -p "dist/stage/$(dirname "$f")"
    cp "$f" "dist/stage/$(dirname "$f")/"
done
tar czf "$OUT" -C dist/stage "${NAME}"
rm -rf dist/stage

echo "$OUT ($(printf '%s\n' "${FILES[@]}" | wc -l | tr -d ' ') files, $(du -h "$OUT" | cut -f1))"
