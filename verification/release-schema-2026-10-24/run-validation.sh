#!/usr/bin/env bash
# Validate the manifest schema itself, all valid fixtures and every rejection case.
# Every invalid fixture must fail with a field path (starting with $.) and the
# expected reason; the script exits non-zero if any expectation is not met.

set -euo pipefail
cd "$(dirname "$0")"

OUT_DIR="output"
OUT_FILE="${OUT_DIR}/validation-2026-10-24.txt"
mkdir -p "$OUT_DIR"
exec > >(tee "$OUT_FILE") 2>&1

echo "# Release manifest schema v1.0 validation"
echo "run_at=$(date -Iseconds)"
echo "host=$(uname -srm)"
echo "python=$(python3 --version 2>&1)"
python3 - <<'PY'
import importlib.metadata as metadata
for package in ("jsonschema", "cryptography"):
    try:
        print(f"{package}={metadata.version(package)}")
    except metadata.PackageNotFoundError:
        print(f"{package}=missing")
PY
echo "workspace_head=$(git -C ../.. rev-parse HEAD 2>/dev/null || echo unknown)"
echo

echo "## JSON Schema self-check"
python3 - <<'PY'
import json
from jsonschema import Draft202012Validator

schema = json.load(open("manifest.schema.json", encoding="utf-8"))
Draft202012Validator.check_schema(schema)
print(f"OK manifest.schema.json ($id={schema['$id']})")
PY
echo

echo "## Valid fixtures (schema + semantic rules + signature with test key)"
failures=0
for dir in samples/valid/*/; do
    manifest="${dir}manifest.json"
    if output=$(python3 validate_manifest.py --trusted-key samples/keys/test-ed25519-public.pem "$manifest" 2>&1); then
        echo "$output"
        echo "EXPECTED PASS: $manifest -> OK"
    else
        echo "$output"
        echo "EXPECTED PASS: $manifest -> FAILED"
        failures=$((failures + 1))
    fi
    echo
done

echo "## Invalid fixtures (must be rejected with field path and reason)"
while IFS='|' read -r case_dir expected; do
    [ -z "$case_dir" ] && continue
    manifest="samples/invalid/${case_dir}/manifest.json"
    if output=$(python3 validate_manifest.py "$manifest" 2>&1); then
        rc=0
    else
        rc=$?
    fi
    echo "$output"
    if [ "$rc" -ne 1 ]; then
        echo "EXPECTED REJECT: $manifest -> wrong exit code $rc"
        failures=$((failures + 1))
    elif ! grep -qF -- "$expected" <<<"$output"; then
        echo "EXPECTED REJECT: $manifest -> reason not found: $expected"
        failures=$((failures + 1))
    elif ! grep -q '\$\.' <<<"$output"; then
        echo "EXPECTED REJECT: $manifest -> output has no field path"
        failures=$((failures + 1))
    else
        echo "EXPECTED REJECT: $manifest -> OK"
    fi
    echo
done <<'CASES'
missing-required-field|missing required field 'health'
image-tag-not-digest|image repository must not contain a tag
artifact-hash-mismatch|sha256 mismatch
artifact-size-mismatch|size mismatch
unknown-field|unknown field 'unexpected_release_note'
inline-secret|inline secret value is forbidden
unsupported-schema-version|unsupported schemaVersion '1.1'
project-name-mismatch|compose project name must equal appId
secret-ref-unknown|is not declared in secrets[]
config-target-outside-root|managed app root
config-mode-world-writable|world-writable
compose-duplicate-service|duplicate compose service name
secret-ref-unmanaged|does not match '^/run/dockroll-secrets/
bind-path-relative|sharedResources[0].path
invalid-timestamp|not a valid UTC timestamp
timestamp-order|signedAt must not be earlier than createdAt
duplicate-env-name|duplicate environment variable name
host-network-ports|ports must not be declared when network.mode is host or none
restart-on-failure-no-retries|missing required field 'maxRetries'
platform-arch-mismatch|is not covered by compatibility.arch
health-timeout-exceeds-interval|must be less than intervalSeconds
label-key-invalid|does not match '^[a-z0-9]
too-many-secrets|violates maxItems=64
bind-mount-docker-sock|Docker socket must not be bind-mounted
bind-mount-outside-allowlist|outside the allowlist
bind-mount-writable-config|must be readOnly
bind-mount-other-app|under the app-specific root
CASES

echo "## Manifest size guard (pre-parse 1 MiB limit)"
oversize="output/.tmp-too-large-manifest.json"
python3 - <<'PY'
import json
from pathlib import Path
base = json.loads(Path("samples/valid/single-container/manifest.json").read_text())
base["metadata"]["description"] = "x" * (1024 * 1024)
Path("output/.tmp-too-large-manifest.json").write_text(json.dumps(base, separators=(",", ":")))
PY
if output=$(python3 validate_manifest.py "$oversize" 2>&1); then
    rc=0
else
    rc=$?
fi
echo "$output"
if [ "$rc" -eq 1 ] && grep -qF "manifest.too-large" <<<"$output"; then
    echo "EXPECTED REJECT: oversized manifest -> OK"
else
    echo "EXPECTED REJECT: oversized manifest -> FAILED"
    failures=$((failures + 1))
fi
rm -f "$oversize"
echo

echo "## Fixture hashes"
find . -type f ! -path './output/*' ! -path './__pycache__/*' -print0 \
    | sort -z \
    | xargs -0 sha256sum
echo

echo "## Test signing key"
echo "keyId=test-fixture-ed25519-2026"
echo "public_key_sha256=$(sha256sum samples/keys/test-ed25519-public.pem | cut -d' ' -f1)"
echo "note=test fixture key only; it is not a trust root and must not be used for production releases"
echo

if [ "$failures" -ne 0 ]; then
    echo "RESULT: FAIL ($failures expectation(s) not met)"
    exit 1
fi
echo "RESULT: PASS (3 valid fixtures accepted, 27 invalid fixtures rejected, oversized manifest rejected)"
