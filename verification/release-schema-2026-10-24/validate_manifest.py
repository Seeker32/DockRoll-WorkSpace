#!/usr/bin/env python3
"""Validate DockRoll release manifest v1.0.

Two layers are applied:

1. JSON Schema (Draft 2020-12) for structure, required fields, enums and
   unknown-field rejection.
2. Semantic rules that JSON Schema cannot express: digest pinning, artifact
   hash/size, controlled secret references, app_id/project-name mapping,
   managed config root, takeover/service-set rules and signature verification.

Errors are always reported as ``<field path>: <reason>`` so logs can point at
the offending field without re-running the validator.
"""

from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
import posixpath
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

try:
    import jsonschema
except ImportError:  # pragma: no cover
    sys.exit(
        "ERROR: jsonschema is required; install dependencies with: "
        "python3 -m pip install -r requirements.txt"
    )

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519

    CRYPTO_AVAILABLE = True
except ImportError:  # pragma: no cover - only used when cryptography is absent
    CRYPTO_AVAILABLE = False

SCHEMA_PATH = Path(__file__).with_name("manifest.schema.json")
SUPPORTED_SCHEMA_VERSIONS = ("1.0",)
MAX_MANIFEST_BYTES = 1024 * 1024
TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
MIN_COMPOSE_VERSION = (5, 0, 1)
CONFIG_ROOT_PREFIX = "/etc/dockroll/apps/"
BIND_SOURCE_PREFIXES = (
    "/etc/dockroll/apps/",
    "/var/lib/dockroll/apps/",
    "/srv/",
    "/opt/",
)
SEMVER_RE = re.compile(r"^([0-9]+)\.([0-9]+)\.([0-9]+)")
SECRET_ENV_NAME_RE = re.compile(
    r"(?i)(password|passwd|secret|token|api[_-]?key|private[_-]?key|credential)"
)
SAFE_REL_PATH_RE = re.compile(r"^[A-Za-z0-9._/-]+$")


@dataclass(frozen=True)
class ValidationIssue:
    path: str
    reason: str
    rule: str


@dataclass
class ValidationResult:
    manifest: str
    ok: bool
    errors: list[ValidationIssue] = field(default_factory=list)
    release_id: str | None = None
    app_id: str | None = None
    release_type: str | None = None
    schema_version: str | None = None
    manifest_digest: str | None = None


def format_path(parts: Iterable[Any]) -> str:
    result = "$"
    for part in parts:
        if isinstance(part, int):
            result += f"[{part}]"
        elif isinstance(part, str) and re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", part):
            result += f".{part}"
        else:
            result += f"[{json.dumps(part, ensure_ascii=False)}]"
    return result


def json_schema_issues(error: jsonschema.ValidationError) -> list[ValidationIssue]:
    """Turn a jsonschema error into precise field-path issues."""

    path = format_path(error.absolute_path)
    message = error.message

    if error.validator == "required":
        match = re.search(r"'([^']+)' is a required property", message)
        if match:
            return [
                ValidationIssue(
                    f"{path}.{match.group(1)}" if path != "$" else f"$.{match.group(1)}",
                    f"missing required field '{match.group(1)}'",
                    "schema.required",
                )
            ]

    if error.validator == "additionalProperties":
        names = re.findall(r"'([^']+)'", message)
        if names:
            return [
                ValidationIssue(
                    f"{path}.{name}" if path != "$" else f"$.{name}",
                    f"unknown field '{name}' is not allowed",
                    "schema.additionalProperties",
                )
                for name in names
            ]

    if error.validator == "propertyNames":
        match = re.search(r"'([^']+)' does not match", message)
        if match:
            name = match.group(1)
            return [
                ValidationIssue(
                    f"{path}[{json.dumps(name, ensure_ascii=False)}]",
                    f"invalid property name '{name}': {error.message}",
                    "schema.propertyNames",
                )
            ]

    if error.validator in {"maxItems", "minItems", "maxProperties", "minProperties"}:
        if isinstance(error.instance, list):
            count, unit = len(error.instance), "items"
        elif isinstance(error.instance, dict):
            count, unit = len(error.instance), "properties"
        else:
            count, unit = None, "entries"
        if count is not None:
            return [
                ValidationIssue(
                    path,
                    f"{unit} count {count} violates {error.validator}={error.validator_value}",
                    f"schema.{error.validator}",
                )
            ]

    if error.validator == "uniqueItems":
        return [ValidationIssue(path, "array contains duplicate entries", "schema.uniqueItems")]

    if error.validator in {"oneOf", "anyOf"}:
        return [
            ValidationIssue(
                path,
                "value does not match exactly one allowed variant (check release_type payload and nested statements)",
                f"schema.{error.validator}",
            )
        ]

    if error.validator in {"false", None}:
        return [ValidationIssue(path, "field is not allowed in this context", "schema.forbidden")]

    return [ValidationIssue(path, message, f"schema.{error.validator}")]


def _canonical_json(value: Any, current: str = "$") -> str:
    """RFC 8785-style canonical JSON for the types allowed in a manifest.

    Keys are sorted by UTF-16 code units (the JCS rule), not Python code
    points. This matters for non-BMP characters; label keys are additionally
    restricted to ASCII by the schema. Floating point numbers are rejected so
    the bytes stay stable across implementations.
    """

    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return "null"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        raise ValueError(
            f"{current}: floating point numbers are not supported by the "
            "canonicalizer; use integer units"
        )
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, list):
        return "[" + ",".join(
            _canonical_json(child, f"{current}[{index}]") for index, child in enumerate(value)
        ) + "]"
    if isinstance(value, dict):
        for key in value:
            if not isinstance(key, str):
                raise ValueError(f"{current}: object keys must be strings")
        items = sorted(value.items(), key=lambda item: item[0].encode("utf-16-be"))
        return "{" + ",".join(
            json.dumps(key, ensure_ascii=False) + ":" + _canonical_json(child, f"{current}.{key}")
            for key, child in items
        ) + "}"
    raise ValueError(f"{current}: unsupported JSON value type {type(value).__name__}")


def canonical_bytes(manifest: dict[str, Any]) -> bytes:
    """Canonical JSON for signing: RFC 8785 subset without signature.signature.

    The signature envelope (algorithm, key_id, signed_at, canonicalization) is
    signed; only the signature value itself is excluded. Keys are sorted by
    UTF-16 code units and only objects, arrays, strings, integers, booleans and
    null are accepted, so the result is byte-stable across implementations.
    """

    payload = copy.deepcopy(manifest)
    signature = payload.get("signature")
    if isinstance(signature, dict):
        signature.pop("signature", None)
    return _canonical_json(payload).encode("utf-8")


def parse_timestamp(value: str) -> datetime | None:
    try:
        return datetime.strptime(value, TIMESTAMP_FORMAT).replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return None


def manifest_digest(manifest: dict[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(manifest)).hexdigest()


def prescan_issues(manifest: dict[str, Any]) -> list[ValidationIssue]:
    """Checks that should still run when the document fails schema validation."""

    issues: list[ValidationIssue] = []

    secrets = manifest.get("secrets")
    if isinstance(secrets, list):
        for index, entry in enumerate(secrets):
            if not isinstance(entry, dict):
                continue
            for key in ("value", "plaintext", "data"):
                if key in entry:
                    issues.append(
                        ValidationIssue(
                            f"$.secrets[{index}].{key}",
                            "inline secret value is forbidden; declare a controlled ref instead",
                            "secret.inline",
                        )
                    )

    container = manifest.get("container")
    if isinstance(container, dict):
        env = container.get("env")
        if isinstance(env, list):
            for index, entry in enumerate(env):
                if not isinstance(entry, dict):
                    continue
                name = entry.get("name")
                if "value" in entry and isinstance(name, str) and SECRET_ENV_NAME_RE.search(name):
                    issues.append(
                        ValidationIssue(
                            f"$.container.env[{index}].value",
                            f"environment variable '{name}' looks secret; use secret_ref instead of an inline value",
                            "secret.inline",
                        )
                    )

    mounts = container.get("mounts") if isinstance(container, dict) else None
    if isinstance(mounts, list):
        for index, mount in enumerate(mounts):
            if not isinstance(mount, dict) or mount.get("type") != "bind":
                continue
            source = mount.get("source")
            if not isinstance(source, str):
                continue
            if source == "/var/run/docker.sock":
                issues.append(
                    ValidationIssue(
                        f"$.container.mounts[{index}].source",
                        "Docker socket must not be bind-mounted; use the Docker SDK instead",
                        "mount.docker-socket-forbidden",
                    )
                )
            elif not source.startswith(BIND_SOURCE_PREFIXES):
                issues.append(
                    ValidationIssue(
                        f"$.container.mounts[{index}].source",
                        "bind mount source is outside the allowlist "
                        "(/etc/dockroll/apps/<app_id>/, /var/lib/dockroll/apps/<app_id>/, /srv/<app_id>/, /opt/<app_id>/)",
                        "mount.source-not-allowed",
                    )
                )

    network = container.get("network") if isinstance(container, dict) else None
    if isinstance(network, dict) and network.get("mode") in {"host", "none"}:
        if "ports" in container:
            issues.append(
                ValidationIssue(
                    "$.container.ports",
                    "ports must not be declared when network.mode is host or none",
                    "network.ports-forbidden",
                )
            )
        if "name" in network:
            issues.append(
                ValidationIssue(
                    "$.container.network.name",
                    "network.name must not be set when network.mode is host or none",
                    "network.name-forbidden",
                )
            )

    images: list[tuple[str, Any]] = []
    if isinstance(container, dict) and isinstance(container.get("image"), dict):
        images.append(("$.container.image.repository", container["image"].get("repository")))
    compose = manifest.get("compose")
    if isinstance(compose, dict) and isinstance(compose.get("services"), list):
        for index, service in enumerate(compose["services"]):
            if isinstance(service, dict) and isinstance(service.get("image"), dict):
                images.append(
                    (f"$.compose.services[{index}].image.repository", service["image"].get("repository"))
                )
    for path, repository in images:
        if not isinstance(repository, str):
            continue
        last_segment = repository.rsplit("/", 1)[-1]
        if ":" in last_segment or "@" in repository:
            issues.append(
                ValidationIssue(
                    path,
                    "image repository must not contain a tag; pin the image with digest",
                    "image.tag-forbidden",
                )
            )

    return issues


def parse_semver(value: str) -> tuple[int, int, int] | None:
    match = SEMVER_RE.match(value)
    if not match:
        return None
    return tuple(int(part) for part in match.groups())  # type: ignore[return-value]


def artifact_issues(
    manifest: dict[str, Any], manifest_dir: Path, release_type: str
) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []

    artifacts: list[tuple[str, dict[str, Any]]] = []
    compose = manifest.get("compose")
    if isinstance(compose, dict):
        if isinstance(compose.get("file"), dict):
            artifacts.append(("$.compose.file", compose["file"]))
        env_files = compose.get("env_files")
        if isinstance(env_files, list):
            for index, artifact in enumerate(env_files):
                if isinstance(artifact, dict):
                    artifacts.append((f"$.compose.env_files[{index}]", artifact))
    config = manifest.get("config")
    if isinstance(config, dict) and isinstance(config.get("files"), list):
        for index, entry in enumerate(config["files"]):
            if isinstance(entry, dict) and isinstance(entry.get("source"), dict):
                artifacts.append((f"$.config.files[{index}].source", entry["source"]))

    base_dir = manifest_dir.resolve()
    for path, artifact in artifacts:
        raw_path = artifact.get("path")
        expected_sha = artifact.get("sha256")
        expected_size = artifact.get("size_bytes")
        if not isinstance(raw_path, str) or not isinstance(expected_sha, str) or not isinstance(
            expected_size, int
        ):
            continue
        if not SAFE_REL_PATH_RE.match(raw_path):
            issues.append(
                ValidationIssue(
                    f"{path}.path",
                    "artifact path must be a relative path with a safe character set",
                    "artifact.path-invalid",
                )
            )
            continue
        relative = Path(raw_path)
        if relative.is_absolute() or ".." in relative.parts:
            issues.append(
                ValidationIssue(
                    f"{path}.path",
                    "artifact path must not be absolute or contain '..'",
                    "artifact.path-escape",
                )
            )
            continue
        try:
            resolved = (base_dir / relative).resolve()
            resolved.relative_to(base_dir)
        except (OSError, ValueError):
            issues.append(
                ValidationIssue(
                    f"{path}.path",
                    "artifact path escapes the release directory",
                    "artifact.path-escape",
                )
            )
            continue
        if not resolved.is_file():
            issues.append(
                ValidationIssue(
                    f"{path}.path",
                    f"artifact file not found: {raw_path}",
                    "artifact.missing",
                )
            )
            continue

        actual_size = resolved.stat().st_size
        if actual_size != expected_size:
            issues.append(
                ValidationIssue(
                    f"{path}.size_bytes",
                    f"size mismatch: declared {expected_size}, actual {actual_size}",
                    "artifact.size-mismatch",
                )
            )

        digest = hashlib.sha256()
        with resolved.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        actual_sha = digest.hexdigest()
        if actual_sha != expected_sha:
            issues.append(
                ValidationIssue(
                    f"{path}.sha256",
                    f"sha256 mismatch: declared {expected_sha}, actual {actual_sha}",
                    "artifact.hash-mismatch",
                )
            )

    # release_type is already cross-checked by the schema; this guards an
    # invalid document that reached semantic validation through future changes.
    if release_type == "compose" and not isinstance(compose, dict):
        issues.append(
            ValidationIssue("$.compose", "compose release requires a compose block", "payload.missing")
        )
    return issues


def semantic_issues(
    manifest: dict[str, Any],
    manifest_dir: Path,
    trusted_key: Path | None,
) -> tuple[list[ValidationIssue], str | None]:
    issues: list[ValidationIssue] = []
    seen: set[tuple[str, str, str]] = set()

    def add(path: str, reason: str, rule: str) -> None:
        key = (path, reason, rule)
        if key not in seen:
            seen.add(key)
            issues.append(ValidationIssue(path, reason, rule))

    schema_version = manifest.get("schema_version")
    if isinstance(schema_version, str) and schema_version not in SUPPORTED_SCHEMA_VERSIONS:
        add(
            "$.schema_version",
            f"unsupported schema_version '{schema_version}'; supported {', '.join(SUPPORTED_SCHEMA_VERSIONS)} "
            "(major must match and newer minor versions are rejected before field validation)",
            "schema-version.unsupported",
        )

    created_at = manifest.get("created_at")
    signed_at = manifest.get("signature", {}).get("signed_at") if isinstance(manifest.get("signature"), dict) else None
    created_dt = parse_timestamp(created_at) if isinstance(created_at, str) else None
    signed_dt = parse_timestamp(signed_at) if isinstance(signed_at, str) else None
    if isinstance(created_at, str) and created_dt is None:
        add(
            "$.created_at",
            "created_at is not a valid UTC timestamp (expected YYYY-MM-DDTHH:MM:SSZ)",
            "timestamp.invalid",
        )
    if isinstance(signed_at, str) and signed_dt is None:
        add(
            "$.signature.signed_at",
            "signed_at is not a valid UTC timestamp (expected YYYY-MM-DDTHH:MM:SSZ)",
            "timestamp.invalid",
        )
    if created_dt is not None and signed_dt is not None and signed_dt < created_dt:
        add(
            "$.signature.signed_at",
            "signed_at must not be earlier than created_at",
            "timestamp.order",
        )

    app_id = manifest.get("app_id")
    release_id = manifest.get("release_id")
    release_type = manifest.get("release_type")
    ownership = manifest.get("ownership") if isinstance(manifest.get("ownership"), dict) else {}

    project_name = ownership.get("compose_project_name")
    if isinstance(app_id, str) and isinstance(project_name, str) and project_name != app_id:
        add(
            "$.ownership.compose_project_name",
            f"compose project name must equal app_id '{app_id}' (fixed mapping); got '{project_name}'",
            "identity.project-name-mismatch",
        )

    labels = ownership.get("labels") if isinstance(ownership.get("labels"), dict) else {}
    expected_labels = {
        "io.dockroll.managed": "true",
        "io.dockroll.app-id": app_id,
        "io.dockroll.release-id": release_id,
    }
    for label, expected in expected_labels.items():
        actual = labels.get(label)
        if isinstance(expected, str) and actual != expected:
            add(
                f"$.ownership.labels.{label}",
                f"resource ownership label must be '{expected}', got {actual!r}",
                "identity.label-mismatch",
            )

    compatibility = manifest.get("compatibility") if isinstance(manifest.get("compatibility"), dict) else {}
    min_compose = compatibility.get("min_compose_version")
    if isinstance(min_compose, str):
        parsed = parse_semver(min_compose)
        if parsed is not None and parsed < MIN_COMPOSE_VERSION:
            add(
                "$.compatibility.min_compose_version",
                f"min_compose_version {min_compose} is below the supported floor "
                f"{'.'.join(map(str, MIN_COMPOSE_VERSION))}",
                "compatibility.compose-floor",
            )

    # Secret references and uniqueness.
    declared_secrets: set[str] = set()
    secrets = manifest.get("secrets")
    if isinstance(secrets, list):
        for index, entry in enumerate(secrets):
            if not isinstance(entry, dict):
                continue
            name = entry.get("name")
            if isinstance(name, str):
                if name in declared_secrets:
                    add(
                        f"$.secrets[{index}].name",
                        f"duplicate secret name '{name}'",
                        "secret.duplicate",
                    )
                declared_secrets.add(name)
            provider = entry.get("provider")
            reference = entry.get("ref")
            if isinstance(provider, str) and isinstance(reference, str):
                if provider == "file":
                    if not reference.startswith("/run/dockroll-secrets/"):
                        add(
                            f"$.secrets[{index}].ref",
                            "file secret ref must be under /run/dockroll-secrets/",
                            "secret.ref-invalid",
                        )
                    elif posixpath.normpath(reference) != reference or ".." in Path(reference).parts:
                        add(
                            f"$.secrets[{index}].ref",
                            "file secret ref must be normalized and must not contain '..'",
                            "secret.ref-invalid",
                        )
                elif provider == "env" and not re.match(r"^[A-Z_][A-Z0-9_]{0,127}$", reference):
                    add(
                        f"$.secrets[{index}].ref",
                        "env secret ref must be an uppercase environment variable name",
                        "secret.ref-invalid",
                    )
                elif provider == "docker_secret" and not re.match(
                    r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$", reference
                ):
                    add(
                        f"$.secrets[{index}].ref",
                        "docker_secret ref must be a valid Docker secret name",
                        "secret.ref-invalid",
                    )

    container = manifest.get("container") if isinstance(manifest.get("container"), dict) else {}
    env = container.get("env")
    if isinstance(env, list):
        env_names: set[str] = set()
        for index, entry in enumerate(env):
            if not isinstance(entry, dict):
                continue
            env_name = entry.get("name")
            if isinstance(env_name, str):
                if env_name in env_names:
                    add(
                        f"$.container.env[{index}].name",
                        f"duplicate environment variable name '{env_name}'; Docker last-wins semantics would silently drop an entry",
                        "env.duplicate-name",
                    )
                env_names.add(env_name)
            secret_ref = entry.get("secret_ref")
            if isinstance(secret_ref, str) and secret_ref not in declared_secrets:
                add(
                    f"$.container.env[{index}].secret_ref",
                    f"secret_ref '{secret_ref}' is not declared in secrets[]",
                    "secret.ref-unknown",
                )

    # Compose service set.
    compose = manifest.get("compose") if isinstance(manifest.get("compose"), dict) else {}
    service_names: list[str] = []
    services = compose.get("services")
    if isinstance(services, list):
        for index, service in enumerate(services):
            if not isinstance(service, dict):
                continue
            name = service.get("name")
            if isinstance(name, str):
                if name in service_names:
                    add(
                        f"$.compose.services[{index}].name",
                        f"duplicate compose service name '{name}'",
                        "compose.service-duplicate",
                    )
                service_names.append(name)
        if release_type == "compose" and not service_names:
            add("$.compose.services", "compose release must declare at least one managed service", "compose.services-empty")

    arch_values = compatibility.get("arch") if isinstance(compatibility.get("arch"), list) else []
    if arch_values:
        def check_image_platform(image: Any, path: str) -> None:
            if not isinstance(image, dict):
                return
            platform = image.get("platform")
            if not isinstance(platform, str):
                return
            platform_arch = platform.rsplit("/", 1)[-1]
            if platform_arch not in arch_values:
                add(
                    f"{path}.platform",
                    f"image platform '{platform}' is not covered by compatibility.arch {arch_values}",
                    "image.platform-arch-mismatch",
                )

        if isinstance(container.get("image"), dict):
            check_image_platform(container["image"], "$.container.image")
        if isinstance(services, list):
            for index, service in enumerate(services):
                if isinstance(service, dict):
                    check_image_platform(service.get("image"), f"$.compose.services[{index}].image")

    # Port conflicts inside the single-container spec.
    ports = container.get("ports")
    if isinstance(ports, list):
        seen_ports: set[tuple[str, int, str]] = set()
        for index, port in enumerate(ports):
            if not isinstance(port, dict):
                continue
            host_ip = port.get("host_ip", "127.0.0.1")
            host_port = port.get("host_port")
            protocol = port.get("protocol")
            if not isinstance(host_ip, str) or not isinstance(host_port, int) or not isinstance(
                protocol, str
            ):
                continue
            key = (host_ip, host_port, protocol)
            if key in seen_ports:
                add(
                    f"$.container.ports[{index}].host_port",
                    f"duplicate host binding {host_ip}:{host_port}/{protocol}",
                    "port.duplicate",
                )
            seen_ports.add(key)

    # Mounts must be normalized and must not escape the intended host/container
    # path. The container root is never a valid mount target.
    mounts = container.get("mounts")
    if isinstance(mounts, list):
        for index, mount in enumerate(mounts):
            if not isinstance(mount, dict):
                continue
            for key in ("source", "target"):
                value = mount.get(key)
                if not isinstance(value, str):
                    continue
                if posixpath.normpath(value) != value or ".." in Path(value).parts:
                    add(
                        f"$.container.mounts[{index}].{key}",
                        f"{key} must be normalized and must not contain '..'",
                        "mount.path-not-normalized",
                    )
                elif value == "/":
                    add(
                        f"$.container.mounts[{index}].{key}",
                        f"{key} must not be the host or container root",
                        "mount.root-forbidden",
                    )

    # Bind mount allowlist, app ownership and read-only rules.
    mounts = container.get("mounts")
    if isinstance(mounts, list):
        for index, mount in enumerate(mounts):
            if not isinstance(mount, dict) or mount.get("type") != "bind":
                continue
            source = mount.get("source")
            if not isinstance(source, str):
                continue
            parts = Path(source).parts
            app_segment: str | None = None
            if source.startswith("/etc/dockroll/apps/"):
                app_segment = parts[4] if len(parts) > 4 else None
                if isinstance(app_id, str) and app_segment != app_id:
                    add(
                        f"$.container.mounts[{index}].source",
                        f"bind source must be under the managed app root for '{app_id}'",
                        "mount.app-id-mismatch",
                    )
                if mount.get("read_only") is not True:
                    add(
                        f"$.container.mounts[{index}].read_only",
                        "configuration bind mounts under /etc/dockroll/apps/<app_id>/ must be read_only",
                        "mount.read-only-required",
                    )
            elif source.startswith("/var/lib/dockroll/apps/"):
                app_segment = parts[5] if len(parts) > 5 else None
                if isinstance(app_id, str) and app_segment != app_id:
                    add(
                        f"$.container.mounts[{index}].source",
                        f"bind source must be under the managed app root for '{app_id}'",
                        "mount.app-id-mismatch",
                    )
            elif source.startswith(("/srv/", "/opt/")):
                app_segment = parts[2] if len(parts) > 2 else None
                if isinstance(app_id, str) and app_segment != app_id:
                    add(
                        f"$.container.mounts[{index}].source",
                        f"bind source must be under the app-specific root for '{app_id}'",
                        "mount.app-id-mismatch",
                    )
            else:
                add(
                    f"$.container.mounts[{index}].source",
                    "bind source is outside the allowlist",
                    "mount.source-not-allowed",
                )

    # Managed configuration paths.
    config = manifest.get("config") if isinstance(manifest.get("config"), dict) else {}
    config_files = config.get("files")
    target_paths: set[str] = set()
    if isinstance(config_files, list):
        root = f"{CONFIG_ROOT_PREFIX}{app_id}/" if isinstance(app_id, str) else CONFIG_ROOT_PREFIX
        for index, entry in enumerate(config_files):
            if not isinstance(entry, dict):
                continue
            target = entry.get("target_path")
            mode = entry.get("mode")
            if isinstance(target, str):
                normalized = posixpath.normpath(target)
                if normalized != target or ".." in Path(target).parts:
                    add(
                        f"$.config.files[{index}].target_path",
                        "target_path must be normalized and must not contain '..'",
                        "config.target-not-normalized",
                    )
                elif not target.startswith(root) or target == root:
                    add(
                        f"$.config.files[{index}].target_path",
                        f"target_path must be a file under the managed app root '{root}'",
                        "config.target-outside-root",
                    )
                if target in target_paths:
                    add(
                        f"$.config.files[{index}].target_path",
                        f"duplicate target_path '{target}'",
                        "config.target-duplicate",
                    )
                target_paths.add(target)
            if isinstance(mode, str) and re.match(r"^0[0-7]{3}$", mode):
                if int(mode, 8) & 0o002:
                    add(
                        f"$.config.files[{index}].mode",
                        f"mode {mode} is world-writable; use 0640/0644 or stricter",
                        "config.mode-insecure",
                    )

    # Takeover and shared-resource protection.
    shared_resources = manifest.get("shared_resources")
    shared_names: set[str] = set()
    if isinstance(shared_resources, list):
        for index, resource in enumerate(shared_resources):
            if not isinstance(resource, dict):
                continue
            name = resource.get("name")
            if isinstance(name, str):
                if name in shared_names:
                    add(
                        f"$.shared_resources[{index}].name",
                        f"duplicate shared resource '{name}'",
                        "resource.duplicate",
                    )
                shared_names.add(name)
            if resource.get("kind") == "bind_path":
                path = resource.get("path")
                if isinstance(path, str):
                    normalized = posixpath.normpath(path)
                    if normalized != path or ".." in Path(path).parts or path == "/":
                        add(
                            f"$.shared_resources[{index}].path",
                            "bind_path path must be a normalized absolute host path, not '/' and not containing '..'",
                            "resource.bind-path-invalid",
                        )

    takeover = manifest.get("takeover") if isinstance(manifest.get("takeover"), dict) else {}
    takeover_mode = takeover.get("mode", "none")
    if takeover_mode != "none":
        if release_type != "compose":
            add(
                "$.takeover.mode",
                "takeover is only supported for compose releases",
                "takeover.release-type",
            )
        existing_project = takeover.get("existing_project_name")
        if isinstance(existing_project, str) and isinstance(app_id, str) and existing_project != app_id:
            add(
                "$.takeover.existing_project_name",
                f"existing project name must equal app_id '{app_id}'; rename the existing stack "
                "in a separate authorized operation before adoption",
                "takeover.project-name-mismatch",
            )
        # Existing services may be absent from the target set: that is an
        # explicit service removal, and rollback restores the previous set.
        preserve = takeover.get("preserve_shared_resources")
        if isinstance(preserve, list):
            for index, name in enumerate(preserve):
                if isinstance(name, str) and name not in shared_names:
                    add(
                        f"$.takeover.preserve_shared_resources[{index}]",
                        f"shared resource '{name}' is not declared in shared_resources[]",
                        "takeover.shared-resource-unknown",
                    )

    # Health-check service targeting.
    health = manifest.get("health") if isinstance(manifest.get("health"), dict) else {}
    check = health.get("check") if isinstance(health.get("check"), dict) else {}
    check_service = check.get("service")
    if isinstance(check_service, str):
        if release_type == "compose":
            if check_service not in service_names:
                add(
                    "$.health.check.service",
                    f"health check service '{check_service}' is not in compose.services[]",
                    "health.service-unknown",
                )
        else:
            add(
                "$.health.check.service",
                "health.check.service is only valid for compose releases",
                "health.service-forbidden",
            )
    elif (
        release_type == "compose"
        and health.get("success_criteria") == "primary_service_healthy"
        and len(service_names) > 1
    ):
        add(
            "$.health.check.service",
            "success_criteria 'primary_service_healthy' requires an explicit check.service",
            "health.primary-service-missing",
        )

    interval = health.get("interval_seconds")
    timeout = health.get("timeout_seconds")
    if isinstance(interval, int) and isinstance(timeout, int) and timeout >= interval:
        add(
            "$.health.timeout_seconds",
            f"timeout_seconds ({timeout}) must be less than interval_seconds ({interval})",
            "health.timeout-vs-interval",
        )

    # Reload targeting.
    apply_policy = manifest.get("apply_policy") if isinstance(manifest.get("apply_policy"), dict) else {}
    reload_block = apply_policy.get("reload") if isinstance(apply_policy.get("reload"), dict) else {}
    reload_service = reload_block.get("service")
    if isinstance(reload_service, str):
        if release_type == "compose":
            if reload_service not in service_names:
                add(
                    "$.apply_policy.reload.service",
                    f"reload service '{reload_service}' is not in compose.services[]",
                    "apply.reload-service-unknown",
                )
        else:
            add(
                "$.apply_policy.reload.service",
                "apply_policy.reload.service is only valid for compose releases",
                "apply.reload-service-forbidden",
            )

    # Rollback target.
    rollback = manifest.get("rollback") if isinstance(manifest.get("rollback"), dict) else {}
    target_release = rollback.get("target_release_id")
    if (
        rollback.get("strategy") == "explicit_release"
        and isinstance(target_release, str)
        and isinstance(release_id, str)
        and target_release == release_id
    ):
        add(
            "$.rollback.target_release_id",
            "rollback target must differ from the release being installed",
            "rollback.self-target",
        )

    # Artifact presence, size and hash.
    if isinstance(release_type, str):
        issues.extend(artifact_issues(manifest, manifest_dir, release_type))

    # Signature verification is opt-in: trust roots are defined by the
    # recovery/security design, not by this schema.
    digest: str | None = None
    try:
        digest = manifest_digest(manifest)
        signature = manifest.get("signature") if isinstance(manifest.get("signature"), dict) else {}
        encoded = signature.get("signature")
        algorithm = signature.get("algorithm")
        if isinstance(encoded, str):
            try:
                raw_signature = base64.b64decode(encoded, validate=True)
            except (ValueError, base64.binascii.Error):
                add(
                    "$.signature.signature",
                    "signature is not valid base64",
                    "signature.base64",
                )
                raw_signature = b""
            if algorithm == "ed25519" and raw_signature and len(raw_signature) != 64:
                add(
                    "$.signature.signature",
                    f"ed25519 signature must be 64 bytes, got {len(raw_signature)}",
                    "signature.length",
                )
            if trusted_key is not None and raw_signature:
                if not CRYPTO_AVAILABLE:
                    add(
                        "$.signature.signature",
                        "cannot verify signature: cryptography is not installed",
                        "signature.verify-unavailable",
                    )
                else:
                    try:
                        public_key = serialization.load_pem_public_key(trusted_key.read_bytes())
                    except (OSError, ValueError) as exc:
                        add(
                            "$.signature.signature",
                            f"cannot load trusted key: {exc}",
                            "signature.key-load",
                        )
                    else:
                        payload = canonical_bytes(manifest)
                        try:
                            if algorithm == "ed25519" and isinstance(public_key, ed25519.Ed25519PublicKey):
                                public_key.verify(raw_signature, payload)
                            elif algorithm == "ecdsa-p256-sha256" and isinstance(
                                public_key, ec.EllipticCurvePublicKey
                            ):
                                public_key.verify(raw_signature, payload, ec.ECDSA(hashes.SHA256()))
                            else:
                                add(
                                    "$.signature.algorithm",
                                    "trusted key type does not match signature.algorithm",
                                    "signature.key-mismatch",
                                )
                        except InvalidSignature:
                            add(
                                "$.signature.signature",
                                "signature verification failed for the canonical manifest bytes",
                                "signature.verify-failed",
                            )
    except ValueError as exc:
        add(
            "$.signature",
            f"cannot canonicalize manifest for signing: {exc}",
            "signature.canonicalization",
        )

    return issues, digest


def validate_manifest(
    manifest_path: Path,
    validator: jsonschema.Draft202012Validator,
    trusted_key: Path | None,
) -> ValidationResult:
    try:
        size = manifest_path.stat().st_size
        if size > MAX_MANIFEST_BYTES:
            return ValidationResult(
                manifest=str(manifest_path),
                ok=False,
                errors=[
                    ValidationIssue(
                        "$",
                        f"manifest is {size} bytes; limit is {MAX_MANIFEST_BYTES} bytes",
                        "manifest.too-large",
                    )
                ],
            )
        data = manifest_path.read_bytes()
        if len(data) > MAX_MANIFEST_BYTES:
            return ValidationResult(
                manifest=str(manifest_path),
                ok=False,
                errors=[
                    ValidationIssue(
                        "$",
                        f"manifest is {len(data)} bytes; limit is {MAX_MANIFEST_BYTES} bytes",
                        "manifest.too-large",
                    )
                ],
            )
        manifest = json.loads(data.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        return ValidationResult(
            manifest=str(manifest_path),
            ok=False,
            errors=[ValidationIssue("$", f"cannot read JSON manifest: {exc}", "manifest.read")],
        )

    if not isinstance(manifest, dict):
        return ValidationResult(
            manifest=str(manifest_path),
            ok=False,
            errors=[ValidationIssue("$", "manifest root must be a JSON object", "manifest.root-type")],
        )

    # Reject unsupported versions before any field validation: a future minor
    # manifest may contain fields this parser does not know, and reporting them
    # as unknown fields would hide the real incompatibility.
    schema_version = manifest.get("schema_version")
    if (
        isinstance(schema_version, str)
        and re.match(r"^[0-9]+\.[0-9]+$", schema_version)
        and schema_version not in SUPPORTED_SCHEMA_VERSIONS
    ):
        return ValidationResult(
            manifest=str(manifest_path),
            ok=False,
            errors=[
                ValidationIssue(
                    "$.schema_version",
                    f"unsupported schema_version '{schema_version}'; supported "
                    f"{', '.join(SUPPORTED_SCHEMA_VERSIONS)} (major must match and newer "
                    "minor versions are rejected before field validation)",
                    "schema-version.unsupported",
                )
            ],
            release_id=manifest.get("release_id") if isinstance(manifest.get("release_id"), str) else None,
            app_id=manifest.get("app_id") if isinstance(manifest.get("app_id"), str) else None,
            release_type=manifest.get("release_type")
            if isinstance(manifest.get("release_type"), str)
            else None,
            schema_version=schema_version,
        )

    issues: list[ValidationIssue] = []
    try:
        schema_errors = sorted(
            validator.iter_errors(manifest),
            key=lambda error: (tuple(str(part) for part in error.absolute_path), error.message),
        )
    except RecursionError:
        return ValidationResult(
            manifest=str(manifest_path),
            ok=False,
            errors=[ValidationIssue("$", "manifest nesting is too deep to validate safely", "manifest.too-deep")],
        )
    for error in schema_errors:
        issues.extend(json_schema_issues(error))
    issues.extend(prescan_issues(manifest))

    digest = None
    if not schema_errors:
        semantic, digest = semantic_issues(manifest, manifest_path.parent, trusted_key)
        issues.extend(semantic)

    # Stable, deduplicated output.
    unique: dict[tuple[str, str, str], ValidationIssue] = {}
    for issue in issues:
        unique[(issue.path, issue.reason, issue.rule)] = issue
    ordered = sorted(unique.values(), key=lambda issue: (issue.path, issue.rule, issue.reason))

    return ValidationResult(
        manifest=str(manifest_path),
        ok=not ordered,
        errors=ordered,
        release_id=manifest.get("release_id") if isinstance(manifest.get("release_id"), str) else None,
        app_id=manifest.get("app_id") if isinstance(manifest.get("app_id"), str) else None,
        release_type=manifest.get("release_type")
        if isinstance(manifest.get("release_type"), str)
        else None,
        schema_version=manifest.get("schema_version")
        if isinstance(manifest.get("schema_version"), str)
        else None,
        manifest_digest=digest,
    )


def expand_paths(raw_paths: list[str]) -> list[Path]:
    expanded: list[Path] = []
    for raw in raw_paths:
        path = Path(raw)
        if path.is_dir():
            expanded.extend(sorted(path.rglob("manifest.json")))
        elif path.is_file():
            expanded.append(path)
        else:
            raise FileNotFoundError(raw)
    return expanded


def print_text(result: ValidationResult) -> None:
    status = "PASS" if result.ok else "FAIL"
    print(f"{status} {result.manifest}")
    if result.ok:
        print(
            f"  release_id={result.release_id} app_id={result.app_id} "
            f"release_type={result.release_type} schema_version={result.schema_version}"
        )
        print(f"  manifest_digest={result.manifest_digest}")
    else:
        for issue in result.errors:
            print(f"  - {issue.path}: {issue.reason} [{issue.rule}]")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate DockRoll release manifest v1.0 with field-path errors."
    )
    parser.add_argument("paths", nargs="+", help="manifest.json files or directories to scan")
    parser.add_argument(
        "--schema",
        default=str(SCHEMA_PATH),
        help=f"JSON Schema path (default: {SCHEMA_PATH})",
    )
    parser.add_argument(
        "--trusted-key",
        help="PEM public key used to verify signature (optional; trust roots are defined outside this schema)",
    )
    parser.add_argument("--json", action="store_true", help="emit machine-readable results")
    args = parser.parse_args(argv)

    try:
        schema = json.loads(Path(args.schema).read_text(encoding="utf-8"))
        jsonschema.Draft202012Validator.check_schema(schema)
        validator = jsonschema.Draft202012Validator(schema)
    except (OSError, json.JSONDecodeError, jsonschema.SchemaError) as exc:
        print(f"ERROR: invalid JSON Schema: {exc}", file=sys.stderr)
        return 2

    trusted_key = Path(args.trusted_key) if args.trusted_key else None
    if trusted_key is not None and not trusted_key.is_file():
        print(f"ERROR: trusted key not found: {trusted_key}", file=sys.stderr)
        return 2

    try:
        manifest_paths = expand_paths(args.paths)
    except FileNotFoundError as exc:
        print(f"ERROR: path not found: {exc}", file=sys.stderr)
        return 2
    if not manifest_paths:
        print("ERROR: no manifest.json files found", file=sys.stderr)
        return 2

    results = [validate_manifest(path, validator, trusted_key) for path in manifest_paths]

    if args.json:
        payload = {
            "results": [
                {
                    "manifest": result.manifest,
                    "ok": result.ok,
                    "release_id": result.release_id,
                    "app_id": result.app_id,
                    "release_type": result.release_type,
                    "schema_version": result.schema_version,
                    "manifest_digest": result.manifest_digest,
                    "errors": [
                        {"path": issue.path, "reason": issue.reason, "rule": issue.rule}
                        for issue in result.errors
                    ],
                }
                for result in results
            ],
            "summary": {
                "total": len(results),
                "passed": sum(1 for result in results if result.ok),
                "failed": sum(1 for result in results if not result.ok),
            },
        }
        print(json.dumps(payload, indent=2, ensure_ascii=False))
    else:
        for result in results:
            print_text(result)
        passed = sum(1 for result in results if result.ok)
        failed = len(results) - passed
        print(f"summary: {passed} passed, {failed} failed, {len(results)} total")

    return 0 if all(result.ok for result in results) else 1


if __name__ == "__main__":
    sys.exit(main())
