#!/usr/bin/env bash
# Orchestrate the full compatibility run for the pinned tooling.
# Usage: run-all.sh [RUN_ID]
set -uo pipefail
export PYTHONDONTWRITEBYTECODE=1

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
evidence_dir="$(cd -- "$script_dir/.." && pwd)"
workspace_dir="$(cd -- "$evidence_dir/../.." && pwd)"
run_id="${1:-$(date +%Y%m%dT%H%M%S)}"
suffix="$(printf '%s' "$run_id" | tr '[:upper:]' '[:lower:]' | tr -cd 'a-z0-9')"
log_root="$evidence_dir/logs/$run_id"
bin_dir="${COMPAT_BIN_DIR:-$workspace_dir/.tmp/compat/bin}"
plugin_root="$bin_dir/../plugin-config"
tooling_dir="${COMPAT_TOOLING_DIR:-$workspace_dir/.tmp/compat/tooling}"
go_toolchain="$tooling_dir/go1.27.3/go/bin/go"
mkdir -p "$log_root"/{matrix,fields,timeout,sdk,tools}

status=0
step() { printf '\n##### %s\n' "$*"; }
fail() { status=1; printf 'FAILED: %s\n' "$*"; }

lower_suffix="$suffix"

# ---------------------------------------------------------------- environment
step "environment"
{
  echo "run_id: $run_id"
  date -Is
  echo
  uname -a
  echo
  cat /etc/os-release
  echo
  echo "nproc: $(getconf _NPROCESSORS_ONLN)"
  grep -E 'MemTotal|MemAvailable' /proc/meminfo
  df -B1 --output=size,used,avail,pcent,target "$workspace_dir"
  echo
  echo "== service manager =="
  systemctl --version | head -1 || true
  systemctl is-system-running 2>&1 || true
  systemctl is-active docker 2>&1 || true
  command -v supervisord || echo "supervisord: not found"
  dpkg-query -W supervisor 2>&1 || true
  echo
  echo "== docker =="
  docker version 2>&1
  echo
  docker info --format 'ServerVersion={{.ServerVersion}}' 2>&1
  docker info --format 'OperatingSystem={{.OperatingSystem}} OSType={{.OSType}} Architecture={{.Architecture}}' 2>&1
  docker info --format 'KernelVersion={{.KernelVersion}}' 2>&1
  docker info --format 'Driver={{.Driver}}' 2>&1
  docker info --format 'DockerRootDir={{.DockerRootDir}}' 2>&1
  docker version --format 'api={{.Server.APIVersion}} min_api={{.Server.MinAPIVersion}}' 2>&1
  docker version --format 'components={{json .Server.Components}}' 2>&1
  docker context show 2>&1
  ls -l /var/run/docker.sock 2>&1 || true
  echo
  echo "== compose =="
  docker compose version 2>&1
  docker compose version --short 2>&1
  command -v docker-compose || true
  readlink -f "$(command -v docker-compose)" 2>/dev/null || true
  docker-compose version 2>&1 || true
  python3 -c 'import compose; print(compose.__version__)' 2>&1 || true
  echo
  echo "== go =="
  go version 2>&1
  echo "GOROOT=${GOROOT:-unset}"
  echo
  echo "== proxy presence (values intentionally hidden) =="
  env | grep -i proxy | sed 's/=.*/=<set>/' || echo "no proxy variables"
  echo
  echo "== git =="
  git -C "$workspace_dir/.wiki" rev-parse HEAD 2>&1 || true
  git -C "$workspace_dir/.wiki" status --short 2>&1 | head -40 || true
  echo
  echo "== image digest =="
  docker image inspect busybox:1.37.0 --format '{{json .RepoDigests}}' 2>&1 || true
  echo
  echo "== ports (target range) =="
  ss -ltn 2>/dev/null | grep -E '1810[1-3]|1811[1-3]' || echo "target ports 18101-18103/18111-18113 are free"
} > "$log_root/00-environment.txt" 2>&1

# -------------------------------------------------------------------- tooling
step "tooling"
{
  echo "== downloaded tooling =="
  cat "$bin_dir/download-metadata.txt" 2>&1 || true
  echo
  echo "== script and sample hashes =="
  cd "$evidence_dir"
  find scripts samples -type f -print0 | sort -z | xargs -0 sha256sum
  echo
  echo "== compose binary versions (amd64) =="
  for version in 5.0.0 5.0.1 5.6.0 5.6.1; do
    "$bin_dir/docker-compose-${version}-amd64" version --short
  done
  echo
  echo "== arm64 binary file types =="
  for version in 5.0.1 5.6.0 5.6.1; do
    file "$bin_dir/docker-compose-${version}-arm64"
  done
  echo
  echo "== installed plugin =="
  sha256sum "$(readlink -f "$(command -v docker-compose)")" 2>&1 || true
  echo
  echo "== Go toolchain =="
  env -u GOROOT "$go_toolchain" version
  sha256sum "$tooling_dir"/*.tar.gz 2>/dev/null || true
} > "$log_root/01-tooling.txt" 2>&1

# Ensure plugin configs exist for direct timeout/SDK invocations.
for version in 5.0.1 5.6.0 5.6.1; do
  mkdir -p "$plugin_root/$version-amd64/cli-plugins"
  ln -sf "$bin_dir/docker-compose-${version}-amd64" "$plugin_root/$version-amd64/cli-plugins/docker-compose"
done

# --------------------------------------------------------------------- matrix
run_matrix() {
  local version="$1" arch="$2" port="$3"
  step "matrix $version/$arch"
  if python3 "$script_dir/run_matrix.py" \
    --version "$version" --arch "$arch" --port "$port" \
    --run-id "$run_id" --suffix "$lower_suffix" \
    --bin-dir "$bin_dir" --log-root "$log_root/matrix" \
    >> "$log_root/matrix-stdout.txt" 2>&1; then
    echo "matrix $version/$arch: PASS"
  else
    fail "matrix $version/$arch"
  fi
}

run_matrix 5.0.1 amd64 18101
run_matrix 5.6.0 amd64 18102
run_matrix 5.6.1 amd64 18103
run_matrix 5.0.1 arm64 18111
run_matrix 5.6.0 arm64 18112
run_matrix 5.6.1 arm64 18113

# --------------------------------------------------------------------- fields
for version in 5.0.1 5.6.0 5.6.1; do
  step "fields $version"
  if python3 "$script_dir/run_fields.py" \
    --version "$version" --bin-dir "$bin_dir" \
    --log-root "$log_root/fields" --run-id "$run_id" \
    >> "$log_root/fields-stdout.txt" 2>&1; then
    echo "fields $version: PASS"
  else
    fail "fields $version"
  fi
done

# ------------------------------------------------------------ timeout probes
step "timeout/cancel probe (build)"
timeout_bin="$log_root/tools/timeoutprobe"
if ( cd "$script_dir/probe-timeout" && \
     env -u GOROOT GOMODCACHE="$workspace_dir/.tmp/gomod" \
       GOCACHE="$workspace_dir/.tmp/gocache-1273" GOPATH="$workspace_dir/.tmp/gopath" \
       GOFLAGS=-mod=mod "$go_toolchain" build -o "$timeout_bin" . ) \
     > "$log_root/tools/timeoutprobe-build.txt" 2>&1; then
  echo "timeoutprobe: built"
  env -u GOROOT "$go_toolchain" version -m "$timeout_bin" > "$log_root/sdk/buildinfo-timeoutprobe.txt" 2>&1 || true
else
  fail "timeoutprobe build"
fi

compose_timeout_file="$evidence_dir/samples/compose-timeout.yaml"
for version in 5.0.1 5.6.1; do
  for mode in kill interrupt; do
    step "timeout probe $version/$mode"
    project="ota-timeout-$(printf '%s' "$version" | tr -d '.')-$mode-$lower_suffix"
    if [[ -x "$timeout_bin" ]]; then
      if env DOCKER_CONFIG="$plugin_root/$version-amd64" \
        "$timeout_bin" -mode "$mode" -project "$project" \
        -compose-file "$compose_timeout_file" -timeout 3s \
        -json "$log_root/timeout/$version-$mode.json" \
        > "$log_root/timeout/$version-$mode.txt" 2>&1; then
        echo "timeout $version/$mode: PASS"
      else
        fail "timeout $version/$mode"
      fi
    fi
  done
done

# ------------------------------------------------------------------------ SDK
step "SDK probe"
build_sdk() {
  local go_bin="$1" out="$2" cache="$3" label="$4"
  ( cd "$script_dir/sdk-probe" && \
    env -u GOROOT GOMODCACHE="$workspace_dir/.tmp/gomod" GOCACHE="$cache" \
      GOPATH="$workspace_dir/.tmp/gopath" GOFLAGS=-mod=mod GOSUMDB=off \
      "$go_bin" build -o "$out" . ) > "$log_root/sdk/build-$label.txt" 2>&1
}

sdk_1273="$log_root/tools/sdkprobe-go1.27.3"
if build_sdk "$go_toolchain" "$sdk_1273" "$workspace_dir/.tmp/gocache-1273" "go1.27.3"; then
  echo "sdk build go1.27.3: PASS"
  env -u GOROOT "$go_toolchain" version -m "$sdk_1273" > "$log_root/sdk/buildinfo-go1.27.3.txt" 2>&1 || true
  if "$sdk_1273" > "$log_root/sdk/go1.27.3.txt" 2>&1; then
    echo "sdk run go1.27.3: PASS"
  else
    fail "sdk run go1.27.3"
  fi
else
  fail "sdk build go1.27.3"
fi

sdk_1260="$log_root/tools/sdkprobe-go1.26.0"
system_go_root="$(go env GOROOT)"
system_go="$system_go_root/bin/go"
if build_sdk "$system_go" "$sdk_1260" "$workspace_dir/.tmp/gocache-1260" "go1.26.0"; then
  echo "sdk build go1.26.0: PASS"
  "$system_go" version -m "$sdk_1260" > "$log_root/sdk/buildinfo-go1.26.0.txt" 2>&1 || true
  if "$sdk_1260" > "$log_root/sdk/go1.26.0.txt" 2>&1; then
    echo "sdk run go1.26.0: PASS"
  else
    fail "sdk run go1.26.0"
  fi
else
  fail "sdk build go1.26.0"
fi

# -------------------------------------------------------------------- summary
step "summary"
python3 "$script_dir/summarize.py" "$log_root" > "$log_root/summary.txt" 2>&1
cat "$log_root/summary.txt"
if ! python3 "$script_dir/summarize.py" "$log_root" > /dev/null 2>&1; then
  fail "summary"
fi

echo
if [[ "$status" -eq 0 ]]; then
  echo "ALL CHECKS PASSED (log root: $log_root)"
else
  echo "SOME CHECKS FAILED (log root: $log_root)"
fi
exit "$status"
