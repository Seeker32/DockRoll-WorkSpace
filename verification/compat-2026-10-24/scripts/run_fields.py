#!/usr/bin/env python3
"""Probe out-of-subset Compose fields and the pre-minimum version boundary.

These are not OTA-supported features; the goal is to record whether a release
warns, rejects, ignores or enforces each field so the support matrix can say
"unsupported", "ignored" or "behaviour differs" with evidence.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from run_matrix import Runner  # noqa: E402


def semver(value: str) -> tuple[int, int, int]:
    match = re.search(r"(\d+)\.(\d+)\.(\d+)", value)
    if not match:
        raise ValueError(f"not a semantic version: {value!r}")
    return tuple(int(part) for part in match.groups())  # type: ignore[return-value]


def fields(version: str, bin_dir: Path, log_root: Path, run_id: str) -> int:
    args = argparse.Namespace(
        version=version,
        arch="amd64",
        docker=os.environ.get("DOCKER_CLI", "docker"),
        port=18120,
        bin_dir=str(bin_dir),
        templates=str(Path(__file__).resolve().parent.parent / "samples"),
        log_root=str(log_root),
        run_id=run_id,
        suffix=f"fields",
    )
    r = Runner(args)
    expected_version = version
    version_record = r.version_probe("version")
    actual_version = version_record["stdout"].strip().splitlines()[0].split()[-1].lstrip("v")
    r.check("compose version", expected_version, actual_version)

    deploy_project = f"ota-fields-{version.replace('.', '')}-deploy"
    r.project = deploy_project  # type: ignore[assignment]

    config = r.compose("deploy-config", ["config", "--quiet"], file="compose-deploy.yaml")
    r.check("deploy config accepted", "0", str(config["exit_code"]))
    up = r.compose("deploy-up", ["up", "-d"], file="compose-deploy.yaml")
    r.check("deploy up accepted", "0", str(up["exit_code"]))
    cid = r.compose("deploy-id", ["ps", "-q", "limited"], file="compose-deploy.yaml")["stdout"].strip()
    inspect = r.host("deploy-inspect", ["inspect", "--format", "{{.HostConfig.NanoCpus}} {{.HostConfig.Memory}}", cid])
    values = inspect["stdout"].strip().split()
    r.extra["deploy_limits_default"] = values
    r.check("deploy inspect", "2 values", str(len(values)), len(values) == 2)
    down = r.compose("deploy-down", ["down"], file="compose-deploy.yaml")
    r.check("deploy down", "0", str(down["exit_code"]))

    compat_up = r.compose("deploy-compat-up", ["--compatibility", "up", "-d"], file="compose-deploy.yaml")
    r.check("--compatibility accepted", "0", str(compat_up["exit_code"]))
    cid2 = r.compose("deploy-compat-id", ["ps", "-q", "limited"], file="compose-deploy.yaml")["stdout"].strip()
    inspect2 = r.host("deploy-compat-inspect",
                      ["inspect", "--format", "{{.HostConfig.NanoCpus}} {{.HostConfig.Memory}}", cid2])
    values2 = inspect2["stdout"].strip().split()
    r.extra["deploy_limits_compatibility"] = values2
    r.check("deploy compat inspect", "2 values", str(len(values2)), len(values2) == 2)
    down2 = r.compose("deploy-compat-down", ["down"], file="compose-deploy.yaml")
    r.check("deploy compat down", "0", str(down2["exit_code"]))

    profile_project = f"ota-fields-{version.replace('.', '')}-profile"
    r.project = profile_project  # type: ignore[assignment]
    services = r.compose("profile-services", ["config", "--services"], file="compose-profile.yaml")
    base_services = sorted(services["stdout"].split())
    r.check("default profile services", "base", ",".join(base_services),
            base_services == ["base"])
    services_debug = r.compose("profile-services-debug",
                               ["--profile", "debug", "config", "--services"],
                               file="compose-profile.yaml")
    debug_services = sorted(services_debug["stdout"].split())
    r.check("debug profile services", "base,extra", ",".join(debug_services),
            debug_services == ["base", "extra"])
    p_up = r.compose("profile-up", ["up", "-d"], file="compose-profile.yaml")
    r.check("profile up", "0", str(p_up["exit_code"]))
    p_ps = r.compose("profile-ps", ["ps", "--format", "json"], file="compose-profile.yaml")
    p_items = r.parse_ps(p_ps)
    r.check("profile skips extra service", "1 container", str(len(p_items)), len(p_items) == 1)
    p_down = r.compose("profile-down", ["down"], file="compose-profile.yaml")
    r.check("profile down", "0", str(p_down["exit_code"]))

    obsolete_project = f"ota-fields-{version.replace('.', '')}-obsolete"
    r.project = obsolete_project  # type: ignore[assignment]
    obsolete = r.compose("obsolete-config", ["config", "--quiet"], file="compose-obsolete.yaml")
    r.check("unknown field config --quiet rejected", "1", str(obsolete["exit_code"]))
    r.check("unknown field named in stderr", "unknown_ota_field", "present",
            "unknown_ota_field" in obsolete["stderr"])
    obsolete_full = r.compose("obsolete-config-full", ["config"], file="compose-obsolete.yaml")
    r.check("unknown field config rejected", "1", str(obsolete_full["exit_code"]))

    r.finish()
    return 0 if r.passed() else 1


def pre_minimum(bin_dir: Path, log_root: Path, run_id: str) -> int:
    version = "5.0.0"
    args = argparse.Namespace(
        version=version,
        arch="amd64",
        docker=os.environ.get("DOCKER_CLI", "docker"),
        port=18121,
        bin_dir=str(bin_dir),
        templates=str(Path(__file__).resolve().parent.parent / "samples"),
        log_root=str(log_root),
        run_id=run_id,
        suffix="pre-minimum",
    )
    r = Runner(args)
    record = r.version_probe("version")
    actual = record["stdout"].strip().splitlines()[0].split()[-1].lstrip("v")
    r.check("pre-minimum compose version", version, actual)
    r.check("pre-minimum rejected by 5.0.1 boundary", "5.0.0 < 5.0.1",
            f"{actual} < 5.0.1", semver(actual) < semver("5.0.1"))
    r.finish()
    return 0 if r.passed() else 1


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", required=True)
    parser.add_argument("--bin-dir", required=True)
    parser.add_argument("--log-root", required=True)
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args()
    bin_dir = Path(args.bin_dir).resolve()
    log_root = Path(args.log_root).resolve()
    status = fields(args.version, bin_dir, log_root, args.run_id)
    if args.version == "5.0.1":
        status |= pre_minimum(bin_dir, log_root, args.run_id)
    return status


if __name__ == "__main__":
    sys.exit(main())
