#!/usr/bin/env python3
"""Run the planned OTA Compose command/config subset for one Compose version/arch.

The runner is deliberately explicit: every child process, exit code, stdout/stderr
and timing is written to a log file, and a machine-readable summary is produced.
It never calls `docker compose down -v`; the named volume is inspected after
`down` and then removed with an explicit, separately logged `docker volume rm`.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shlex
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

DIGEST = "busybox@sha256:bdf57e528e45e4433820e045b29b4597825a1c9e38353532d90a01445013f82e"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


class Runner:
    def __init__(self, args: argparse.Namespace) -> None:
        self.version = args.version
        self.arch = args.arch
        self.docker = args.docker
        self.port = args.port
        self.bin_dir = Path(args.bin_dir).resolve()
        self.bin = self.bin_dir / f"docker-compose-{self.version}-{self.arch}"
        self.templates = Path(args.templates).resolve()
        self.log_root = Path(args.log_root).resolve()
        self.run_id = args.run_id
        self.project = f"ota-compat-{self.version.replace('.', '')}-{self.arch}-{args.suffix}"
        self.run_dir = self.log_root / f"{self.version}-{self.arch}"
        self.project_dir = self.run_dir / "project"
        self.records: list[dict] = []
        self.checks: list[dict] = []
        self.extra: dict = {}
        self.started_at = utc_now()
        self.cleanup_volume_removed = False

        if self.run_dir.exists():
            raise SystemExit(f"run directory already exists: {self.run_dir}")
        self.run_dir.mkdir(parents=True)
        shutil.copytree(self.templates, self.project_dir)

        if not self.bin.exists():
            raise SystemExit(f"compose binary missing: {self.bin} (run download-tooling.sh)")

        self.compose_sha = sha256(self.bin)

        # A private Docker config directory lets DOCKER_CONFIG select the plugin
        # binary without touching the host's installed Compose.
        self.plugin_dir = self.bin_dir.parent / "plugin-config" / f"{self.version}-{self.arch}"
        plugin = self.plugin_dir / "cli-plugins" / "docker-compose"
        plugin.parent.mkdir(parents=True, exist_ok=True)
        if plugin.is_symlink() or plugin.exists():
            plugin.unlink()
        plugin.symlink_to(self.bin)

        self.env = os.environ.copy()
        self.env.update(
            {
                "DOCKER_CONFIG": str(self.plugin_dir),
                "HOST_PORT": str(self.port),
                "APP_VERSION": "1",
                "COMPOSE_PROJECT_NAME": self.project,
            }
        )

    # ---------------------------------------------------------------- process
    def _write_log(self, index: int, step: str, argv: list[str], out: str, err: str,
                   code: int | None, timed_out: bool, duration_ms: int) -> Path:
        path = self.run_dir / f"{index:02d}-{step}.log"
        body = [
            f"# step: {step}",
            f"# started_at: {self.started_at}",
            f"# compose_version: {self.version}",
            f"# arch: {self.arch}",
            f"# project: {self.project}",
            f"# command: {shlex.join(argv)}",
            "# env: DOCKER_CONFIG=..., HOST_PORT=..., APP_VERSION=1",
            f"# exit_code: {code}",
            f"# timed_out: {timed_out}",
            f"# duration_ms: {duration_ms}",
            "",
            "=== stdout ===",
            out.rstrip("\n"),
            "",
            "=== stderr ===",
            err.rstrip("\n"),
            "",
        ]
        path.write_text("\n".join(body), encoding="utf-8")
        return path

    def run(self, step: str, argv: list[str], timeout: int = 300) -> dict:
        index = len(self.records) + 1
        started = time.monotonic()
        timed_out = False
        try:
            proc = subprocess.run(
                argv, env=self.env, capture_output=True, text=True, timeout=timeout
            )
            out, err, code = proc.stdout, proc.stderr, proc.returncode
        except subprocess.TimeoutExpired as exc:
            out = (exc.stdout or "") if isinstance(exc.stdout, str) else ""
            err = (exc.stderr or "") if isinstance(exc.stderr, str) else ""
            code = None
            timed_out = True
        duration_ms = int((time.monotonic() - started) * 1000)
        path = self._write_log(index, step, argv, out, err, code, timed_out, duration_ms)
        record = {
            "step": step,
            "argv": argv,
            "exit_code": code,
            "timed_out": timed_out,
            "duration_ms": duration_ms,
            "log": path.name,
            "stdout": out,
            "stderr": err,
        }
        self.records.append(record)
        return record

    @property
    def docker_base(self) -> list[str]:
        return [
            self.docker,
            "compose",
            "-p",
            self.project,
            "-f",
            str(self.project_dir / "compose.yaml"),
            "--project-directory",
            str(self.project_dir),
        ]

    def compose(self, step: str, args: list[str], file: str = "compose.yaml",
                timeout: int = 300) -> dict:
        if self.arch == "amd64":
            argv = [self.docker, "compose", "-p", self.project,
                    "-f", str(self.project_dir / file),
                    "--project-directory", str(self.project_dir)] + args
        else:
            argv = [
                self.docker, "run", "--rm", "--platform", "linux/arm64",
                "--label", f"ota-compat.cli-run={self.run_id}",
                "-v", "/var/run/docker.sock:/var/run/docker.sock",
                "-v", f"{self.project_dir}:{self.project_dir}",
                "-v", f"{self.bin}:/usr/local/bin/docker-compose:ro",
                "-v", "/etc/ssl/certs:/etc/ssl/certs:ro",
                "-e", f"HOST_PORT={self.port}",
                "-e", "APP_VERSION=1",
                "-w", str(self.project_dir),
                DIGEST,
                "/usr/local/bin/docker-compose",
                "-p", self.project,
                "-f", str(self.project_dir / file),
                "--project-directory", str(self.project_dir),
            ] + args
        return self.run(step, argv, timeout=timeout)

    def host(self, step: str, args: list[str], timeout: int = 120) -> dict:
        return self.run(step, [self.docker] + args, timeout=timeout)

    def version_probe(self, step: str = "version") -> dict:
        if self.arch == "amd64":
            argv = [self.docker, "compose", "version", "--short"]
        else:
            argv = [
                self.docker, "run", "--rm", "--platform", "linux/arm64",
                "--label", f"ota-compat.cli-run={self.run_id}",
                "-v", "/var/run/docker.sock:/var/run/docker.sock",
                "-v", f"{self.bin}:/usr/local/bin/docker-compose:ro",
                DIGEST, "/usr/local/bin/docker-compose", "version", "--short",
            ]
        return self.run(step, argv, timeout=120)

    # ----------------------------------------------------------------- checks
    def check(self, name: str, expected: str, actual: str, ok: bool | None = None) -> None:
        if ok is None:
            ok = expected == actual
        self.checks.append(
            {"name": name, "expected": expected, "actual": actual, "ok": bool(ok)}
        )

    def passed(self) -> bool:
        return all(item["ok"] for item in self.checks)

    # ------------------------------------------------------------------ steps
    def parse_ps(self, record: dict) -> list[dict]:
        items: list[dict] = []
        text = record["stdout"].strip()
        if not text:
            return items
        try:
            parsed = json.loads(text)
            if isinstance(parsed, list):
                return parsed
            if isinstance(parsed, dict):
                return [parsed]
        except json.JSONDecodeError:
            pass
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                items.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return items

    def wait_healthy(self) -> dict:
        deadline = time.monotonic() + 120
        last = None
        attempts = 0
        while time.monotonic() < deadline:
            attempts += 1
            record = self.compose("ps-poll", ["ps", "--format", "json"], timeout=60)
            last = record
            items = self.parse_ps(record)
            by_service = {item.get("Service"): item for item in items}
            web = by_service.get("web", {})
            worker = by_service.get("worker", {})
            if (
                web.get("State") == "running"
                and web.get("Health") == "healthy"
                and worker.get("State") == "running"
            ):
                record["attempts"] = attempts
                return record
            time.sleep(2)
        if last is not None:
            last["attempts"] = attempts
        return last or {"stdout": "", "stderr": "no ps output", "attempts": attempts}

    def http_get(self, step: str) -> dict:
        url = f"http://127.0.0.1:{self.port}/version"
        index = len(self.records) + 1
        started = time.monotonic()
        out = err = ""
        code: int | None = None
        for attempt in range(10):
            try:
                with urllib.request.urlopen(url, timeout=3) as resp:
                    out = resp.read().decode("utf-8", "replace")
                    code = resp.status
                    break
            except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
                err = f"{type(exc).__name__}: {exc}"
                time.sleep(1)
        duration_ms = int((time.monotonic() - started) * 1000)
        path = self._write_log(index, step, ["GET", url], out, err, code, False, duration_ms)
        record = {
            "step": step,
            "argv": ["GET", url],
            "exit_code": code,
            "timed_out": False,
            "duration_ms": duration_ms,
            "log": path.name,
            "stdout": out,
            "stderr": err,
        }
        self.records.append(record)
        return record

    def exec_capture(self, step: str, service: str, args: list[str]) -> dict:
        return self.compose(step, ["exec", "-T", service] + args, timeout=120)

    def main(self) -> int:
        version_record = self.version_probe()
        first_line = version_record["stdout"].strip().splitlines()
        short = first_line[0] if first_line else ""
        if short.startswith("Docker Compose version"):
            short = short.split()[-1].lstrip("v")
        self.check("compose version --short", self.version, short)

        config_quiet = self.compose("config-quiet", ["config", "--quiet"])
        self.check("config --quiet exit code", "0", str(config_quiet["exit_code"]))

        config = self.compose("config", ["config"])
        self.check("config exit code", "0", str(config["exit_code"]))
        config_text = config["stdout"]
        self.check("config contains pinned digest", DIGEST, DIGEST,
                   DIGEST in config_text)
        self.check("config contains healthcheck", "healthcheck", "healthcheck",
                   "healthcheck" in config_text)
        self.check("config contains resolved restart", "unless-stopped", "unless-stopped",
                   "unless-stopped" in config_text)
        self.check("config resolves HOST_PORT", f'published: "{self.port}"',
                   f'published: "{self.port}"',
                   f'published: "{self.port}"' in config_text and "host_ip: 127.0.0.1" in config_text)
        env_in_config = "APP_VERSION: \"1\"" in config_text or "APP_VERSION: '1'" in config_text
        self.check("config resolves APP_VERSION", "APP_VERSION: \"1\"", "present" if env_in_config else "absent",
                   env_in_config)

        config_json = self.compose("config-json", ["config", "--format", "json"])
        config_json_ok = config_json["exit_code"] == 0
        self.check("config --format json supported", "exit 0", str(config_json["exit_code"]),
                   config_json_ok)
        if config_json_ok:
            try:
                parsed = json.loads(config_json["stdout"])
                image = parsed.get("services", {}).get("web", {}).get("image", "")
                self.check("config json image digest", DIGEST, image, image == DIGEST)
            except json.JSONDecodeError as exc:
                self.check("config json parsed", "valid JSON", f"error: {exc}", False)
        else:
            self.check("config json parsed", "valid JSON", "not supported", False)

        pull = self.compose("pull", ["pull"], timeout=420)
        self.check("pull exit code", "0", str(pull["exit_code"]))

        up = self.compose("up", ["up", "-d"], timeout=420)
        self.check("up -d exit code", "0", str(up["exit_code"]))
        if up["exit_code"] != 0:
            self.finish()
            return 1

        ps = self.wait_healthy()
        items = self.parse_ps(ps)
        by_service = {item.get("Service"): item for item in items}
        web = by_service.get("web", {})
        worker = by_service.get("worker", {})
        self.check("ps exit code", "0", str(ps["exit_code"]))
        self.check("ps web state", "running", str(web.get("State", "")))
        self.check("ps web health", "healthy", str(web.get("Health", "")))
        self.check("ps worker state", "running", str(worker.get("State", "")))
        self.check("ps wait attempts <= 60", "<= 60", str(ps.get("attempts", "?")),
                   isinstance(ps.get("attempts"), int) and ps["attempts"] <= 60)

        ps_plain = self.compose("ps-plain", ["ps"])
        self.check("ps exit code (plain)", "0", str(ps_plain["exit_code"]))
        self.check("ps plain shows web healthy", "healthy", "healthy",
                   "web" in ps_plain["stdout"] and "healthy" in ps_plain["stdout"])

        ps_final = self.compose("ps", ["ps", "--format", "json"])
        self.check("ps exit code (final)", "0", str(ps_final["exit_code"]))

        web_id = self.compose("ps-web-id", ["ps", "-q", "web"]).get("stdout", "").strip()
        worker_id = self.compose("ps-worker-id", ["ps", "-q", "worker"]).get("stdout", "").strip()

        env_value = self.exec_capture("exec-env", "web", ["printenv", "APP_VERSION"])
        self.check("env APP_VERSION", "1", env_value["stdout"].strip())

        config_value = self.exec_capture("exec-config", "web", ["cat", "/config/app.conf"])
        self.check("config dir mount initial", "cfg-1", config_value["stdout"].strip())

        volume_value = self.exec_capture("exec-volume", "web", ["cat", "/data/app-version"])
        self.check("named volume initial", "1", volume_value["stdout"].strip())

        worker_token = self.exec_capture("exec-env-file", "worker", ["printenv", "WORKER_TOKEN"])
        self.check("env_file WORKER_TOKEN", "env-file-token", worker_token["stdout"].strip())

        worker_log = self.exec_capture("exec-shared-volume", "worker", ["cat", "/data/worker.log"])
        self.check("shared named volume", "worker-ok", "present" if "worker-ok" in worker_log["stdout"] else "absent",
                   "worker-ok" in worker_log["stdout"])

        http_initial = self.http_get("http-initial")
        self.check("host port /version initial", "version-1", http_initial["stdout"].strip(),
                   http_initial["stdout"].strip() == "version-1")

        # Bind-mount visibility from the host into the running container.
        (self.project_dir / "www" / "version").write_text("version-2\n", encoding="utf-8")
        http_updated = self.http_get("http-bind-updated")
        self.check("bind mount reflects host update", "version-2", http_updated["stdout"].strip(),
                   http_updated["stdout"].strip() == "version-2")

        # Read-only config directory bind mount visibility.
        (self.project_dir / "config" / "app.conf").write_text("cfg-2\n", encoding="utf-8")
        config_updated = self.exec_capture("exec-config-updated", "web", ["cat", "/config/app.conf"])
        self.check("config dir reflects host update", "cfg-2", config_updated["stdout"].strip())

        restart_policy = self.host(
            "inspect-restart", ["inspect", "--format", "{{json .HostConfig.RestartPolicy}}", web_id]
        )
        try:
            policy = json.loads(restart_policy["stdout"].strip())
        except json.JSONDecodeError:
            policy = {}
        self.check("web restart policy", "unless-stopped", str(policy.get("Name", "")),
                   policy.get("Name") == "unless-stopped")
        worker_policy = self.host(
            "inspect-worker-restart",
            ["inspect", "--format", "{{json .HostConfig.RestartPolicy}}", worker_id],
        )
        try:
            wpolicy = json.loads(worker_policy["stdout"].strip())
        except json.JSONDecodeError:
            wpolicy = {}
        self.check("worker restart policy", "on-failure:2", f"{wpolicy.get('Name')}:{wpolicy.get('MaximumRetryCount')}",
                   wpolicy.get("Name") == "on-failure" and wpolicy.get("MaximumRetryCount") == 2)

        health = self.host("inspect-health", ["inspect", "--format", "{{json .State.Health}}", web_id])
        try:
            health_obj = json.loads(health["stdout"].strip())
        except json.JSONDecodeError:
            health_obj = {}
        self.check("healthcheck status", "healthy", str(health_obj.get("Status", "")),
                   health_obj.get("Status") == "healthy")

        image = self.host("inspect-image", ["inspect", "--format", "{{.Config.Image}}", web_id])
        self.check("runtime image digest", DIGEST, image["stdout"].strip(),
                   image["stdout"].strip() == DIGEST)

        volume = self.host("volume-inspect", ["volume", "inspect", f"{self.project}_data", "--format", "{{json .}}"])
        self.check("named volume exists", "0", str(volume["exit_code"]))

        volume_labels = self.host(
            "volume-labels",
            ["volume", "ls", "--filter", f"label=com.docker.compose.project={self.project}", "--format", "{{.Name}}"],
        )
        self.check("volume project label", f"{self.project}_data", volume_labels["stdout"].strip(),
                   f"{self.project}_data" in volume_labels["stdout"])

        down_args = ["down"]
        down = self.compose("down", down_args, timeout=300)
        self.check("down exit code", "0", str(down["exit_code"]))
        down_has_volume_flag = any(arg in ("-v", "--volumes") for arg in down_args)
        self.check("down did not use -v", "no volume removal flag",
                   "with volume flag" if down_has_volume_flag else "no volume removal flag",
                   not down_has_volume_flag)

        containers = self.host(
            "post-down-containers",
            ["ps", "-a", "--filter", f"label=com.docker.compose.project={self.project}", "--format", "{{.Names}}"],
        )
        self.check("post-down containers removed", "", containers["stdout"].strip())

        networks = self.host(
            "post-down-networks",
            ["network", "ls", "--filter", f"label=com.docker.compose.project={self.project}", "--format", "{{.Name}}"],
        )
        self.check("post-down network removed", "", networks["stdout"].strip())

        volume_after = self.host(
            "post-down-volume",
            ["volume", "ls", "--filter", f"name={self.project}_data", "--format", "{{.Name}}"],
        )
        self.check("post-down named volume retained", f"{self.project}_data", volume_after["stdout"].strip(),
                   f"{self.project}_data" in volume_after["stdout"])

        self.check("bind files retained after down", "present", "present",
                   (self.project_dir / "config" / "app.conf").exists()
                   and (self.project_dir / "www" / "version").exists())

        rm_volume = self.host("cleanup-volume", ["volume", "rm", f"{self.project}_data"])
        self.cleanup_volume_removed = rm_volume["exit_code"] == 0
        self.check("explicit test volume cleanup", "0", str(rm_volume["exit_code"]))

        self.finish()
        return 0 if self.passed() else 1

    def finish(self) -> None:
        finished_at = utc_now()
        summary = {
            "run_id": self.run_id,
            "compose_version": self.version,
            "arch": self.arch,
            "project": self.project,
            "port": self.port,
            "compose_binary": str(self.bin),
            "compose_binary_sha256": self.compose_sha,
            "started_at": self.started_at,
            "finished_at": finished_at,
            "passed": self.passed(),
            "checks_total": len(self.checks),
            "checks_passed": sum(1 for item in self.checks if item["ok"]),
            "checks": self.checks,
            "extra": self.extra,
            "commands": [
                {
                    "step": record["step"],
                    "argv": record["argv"],
                    "exit_code": record["exit_code"],
                    "timed_out": record["timed_out"],
                    "duration_ms": record["duration_ms"],
                    "log": record["log"],
                }
                for record in self.records
            ],
        }
        (self.run_dir / "summary.json").write_text(
            json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        total = summary["checks_total"]
        ok = summary["checks_passed"]
        print(f"[{self.version}/{self.arch}] {ok}/{total} checks passed "
              f"({'PASS' if summary['passed'] else 'FAIL'}) -> {self.run_dir / 'summary.json'}")
        for item in self.checks:
            if not item["ok"]:
                print(f"  FAIL {item['name']}: expected {item['expected']!r}, got {item['actual']!r}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", required=True, help="Compose version without leading v")
    parser.add_argument("--arch", choices=["amd64", "arm64"], required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--suffix", default="01")
    parser.add_argument("--bin-dir", default=os.environ.get("COMPAT_BIN_DIR", ""))
    parser.add_argument("--log-root", default=os.environ.get("COMPAT_LOG_ROOT", ""))
    parser.add_argument("--templates", default=str(Path(__file__).resolve().parent.parent / "samples"))
    parser.add_argument("--docker", default=os.environ.get("DOCKER_CLI", "docker"))
    args = parser.parse_args()
    if not args.bin_dir or not args.log_root:
        parser.error("--bin-dir and --log-root (or COMPAT_BIN_DIR/COMPAT_LOG_ROOT) are required")
    runner = Runner(args)
    return runner.main()


if __name__ == "__main__":
    sys.exit(main())
