#!/usr/bin/env bash
# Download pinned Compose release binaries and the Go toolchain used by the
# compatibility checks. Binaries stay outside the wiki; only hashes are recorded
# in the committed evidence.
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
evidence_dir="$(cd -- "$script_dir/.." && pwd)"
workspace_dir="$(cd -- "$evidence_dir/../.." && pwd)"
bin_dir="${COMPAT_BIN_DIR:-$workspace_dir/.tmp/compat/bin}"
tooling_dir="${COMPAT_TOOLING_DIR:-$workspace_dir/.tmp/compat/tooling}"
go_version="${GO_VERSION:-1.27.3}"

mkdir -p "$bin_dir" "$tooling_dir"
cd "$bin_dir"

download() {
  local version="$1" arch="$2" release_arch="$3"
  local out="docker-compose-${version}-${arch}"
  if [[ -x "$out" ]]; then
    echo "skip existing $out"
    return
  fi
  echo "download $out"
  curl -fSL --connect-timeout 20 --max-time 600 --retry 3 --retry-delay 2 \
    -o "$out.tmp" \
    "https://github.com/docker/compose/releases/download/v${version}/docker-compose-linux-${release_arch}"
  chmod +x "$out.tmp"
  mv "$out.tmp" "$out"
}

for version in 5.0.0 5.0.1 5.6.0 5.6.1; do
  download "$version" amd64 x86_64
  if [[ "$version" != "5.0.0" ]]; then
    download "$version" arm64 aarch64
  fi
done

echo "== compose binaries =="
for version in 5.0.0 5.0.1 5.6.0 5.6.1; do
  local_bin="$bin_dir/docker-compose-${version}-amd64"
  printf '%-28s %s\n' "$(basename "$local_bin")" "$("$local_bin" version --short)"
done
for version in 5.0.1 5.6.0 5.6.1; do
  printf '%-28s %s\n' "docker-compose-${version}-arm64" \
    "$(file -b "$bin_dir/docker-compose-${version}-arm64" | cut -c1-70)"
done

(
  cd "$bin_dir"
  sha256sum docker-compose-*-amd64 docker-compose-*-arm64 > SHA256SUMS
)
echo "wrote $bin_dir/SHA256SUMS"

echo "== Go toolchain =="
go_archive="go${go_version}.linux-amd64.tar.gz"
go_dir="$tooling_dir/go${go_version}"
if [[ ! -x "$go_dir/go/bin/go" ]]; then
  releases_json="$tooling_dir/go-releases.json"
  curl -fSL --connect-timeout 20 --max-time 120 --retry 3 -o "$releases_json" "https://go.dev/dl/?mode=json"
  expected_sha="$(python3 - "$releases_json" "$go_version" <<'PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as fh:
    releases = json.load(fh)
name = f"go{sys.argv[2]}.linux-amd64.tar.gz"
for release in releases:
    for item in release.get("files", []):
        if item.get("filename") == name and item.get("kind") == "archive":
            print(item["sha256"])
            raise SystemExit(0)
raise SystemExit(f"no checksum for {name}")
PY
)"
  curl -fSL --connect-timeout 20 --max-time 900 --retry 3 -o "$tooling_dir/$go_archive" "https://go.dev/dl/$go_archive"
  echo "$expected_sha  $tooling_dir/$go_archive" | sha256sum -c -
  rm -rf "$go_dir"
  mkdir -p "$go_dir"
  tar -C "$go_dir" --strip-components=1 -xzf "$tooling_dir/$go_archive"
fi
"$go_dir/go/bin/go" version
echo "toolchain: $go_dir/go/bin/go"

{
  echo "downloaded_at: $(date -Is)"
  echo "bin_dir: $bin_dir"
  echo "go: $go_version"
  echo "sha256:"
  sed 's/^/  /' "$bin_dir/SHA256SUMS"
  echo "go archive sha256: $(sha256sum "$tooling_dir/$go_archive" | cut -d' ' -f1)"
} > "$bin_dir/download-metadata.txt"

echo "metadata: $bin_dir/download-metadata.txt"
