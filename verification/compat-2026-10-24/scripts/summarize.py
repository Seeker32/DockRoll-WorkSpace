#!/usr/bin/env python3
"""Summarise a run-all.sh log root as plain text tables (no Markdown page)."""

from __future__ import annotations

import json
import sys
from pathlib import Path


def load_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def main() -> int:
    root = Path(sys.argv[1]).resolve()
    failures: list[str] = []
    print(f"# compatibility summary: {root}")

    print("\n## Compose command/config matrix\n")
    print("| compose | arch | checks | result | failed checks |")
    print("| --- | --- | --- | --- | --- |")
    for path in sorted(root.glob("matrix/*/summary.json")):
        data = load_json(path)
        if not data:
            failures.append(f"unreadable matrix summary: {path}")
            continue
        failed = [item["name"] for item in data["checks"] if not item["ok"]]
        ok = data["passed"] and not failed
        if not ok:
            failures.append(f"matrix {data['compose_version']}/{data['arch']}: {failed}")
        print(
            f"| {data['compose_version']} | {data['arch']} | "
            f"{data['checks_passed']}/{data['checks_total']} | "
            f"{'PASS' if ok else 'FAIL'} | {', '.join(failed) or '-'} |"
        )

    print("\n## Field / boundary probes\n")
    print("| compose | checks | result | deploy limits default (NanoCpus, Memory) | deploy limits --compatibility | failed checks |")
    print("| --- | --- | --- | --- | --- | --- |")
    for path in sorted(root.glob("fields/*/summary.json")):
        data = load_json(path)
        if not data:
            failures.append(f"unreadable field summary: {path}")
            continue
        failed = [item["name"] for item in data["checks"] if not item["ok"]]
        ok = data["passed"] and not failed
        if not ok:
            failures.append(f"fields {data['compose_version']}: {failed}")
        extra = data.get("extra", {})
        default = " ".join(extra.get("deploy_limits_default", [])) or "-"
        compat = " ".join(extra.get("deploy_limits_compatibility", [])) or "-"
        print(
            f"| {data['compose_version']} | {data['checks_passed']}/{data['checks_total']} | "
            f"{'PASS' if ok else 'FAIL'} | {default} | {compat} | {', '.join(failed) or '-'} |"
        )

    print("\n## os/exec timeout and cancellation\n")
    print("| compose | mode | timed out | ctx error | wait exit | process state | containers after kill | cleanup verified |")
    print("| --- | --- | --- | --- | --- | --- | --- | --- |")
    for path in sorted(root.glob("timeout/*.json")):
        data = load_json(path)
        if not data:
            failures.append(f"unreadable timeout result: {path}")
            continue
        container_found = data.get("container_found_after_timeout", data.get("container_found"))
        ok = bool(data.get("timed_out") and container_found and data.get("cleanup_verified"))
        if not ok:
            failures.append(f"timeout {path.stem}: timed_out={data.get('timed_out')} "
                            f"container_found={container_found} "
                            f"cleanup_verified={data.get('cleanup_verified')}")
        print(
            f"| {data.get('compose_version')} | {data.get('mode')} | {data.get('timed_out')} | "
            f"{data.get('context_error')} | {data.get('wait', {}).get('exit_code')} | "
            f"{data.get('wait', {}).get('process_state')} | {data.get('container_names_after_timeout')} | "
            f"{data.get('cleanup_verified')} |"
        )

    print("\n## Go SDK probe\n")
    print("| toolchain | client module | negotiated API | server version | server API | min API | containers | result |")
    print("| --- | --- | --- | --- | --- | --- | --- | --- |")
    sdk_ok = 0
    sdk_total = 0
    for path in sorted(root.glob("sdk/go*.txt")):
        data = load_json(path)
        sdk_total += 1
        if not data:
            failures.append(f"unreadable sdk output: {path}")
            print(f"| {path.stem} | - | - | - | - | - | - | FAIL |")
            continue
        ok = not data.get("error") and data.get("negotiated_api") == data.get("server_api_version") \
            and data.get("ping_api_version") == data.get("server_api_version")
        if ok:
            sdk_ok += 1
        else:
            failures.append(f"sdk {path.stem}: {data.get('error') or 'api mismatch'}")
        print(
            f"| {data.get('go_version')} | {data.get('client_module')}@{data.get('client_module_version')} | "
            f"{data.get('negotiated_api')} | {data.get('server_version')} | {data.get('server_api_version')} | "
            f"{data.get('server_min_api_version')} | {data.get('containers_total')} | "
            f"{'PASS' if ok else 'FAIL'} |"
        )
    if sdk_total == 0:
        failures.append("no SDK output found")

    print("\n## Verdict\n")
    if failures:
        print(f"FAIL: {len(failures)} item(s)")
        for item in failures:
            print(f"- {item}")
        return 1
    print("PASS: all recorded checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
