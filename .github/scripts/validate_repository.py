"""Validate published rule sets, the artifact manifest and README links."""

from __future__ import annotations

import hashlib
import json
import re
import sys
import zlib
from pathlib import Path
from typing import Any

import yaml


ROOT = Path(__file__).resolve().parents[2]
REPOSITORY = "Ethan2258/rules"
MANIFEST_PATH = ROOT / ".github" / "rule-artifacts.json"
README_PATH = ROOT / "README.md"
SRS_MAGIC = b"SRS"
EXPECTED_RULE_SETS = {
    "NodeSeek": ("domain", {"Nodeseek.yaml", "Nodeseek.srs"}),
    "WebRTC": ("domain", {"Webrtc_domain.srs"}),
    "TelegramSG": ("ipcidr", {"TelegramSG.srs"}),
    "TelegramNL": ("ipcidr", {"TelegramNL.srs"}),
}
EGERN_RULE_SET_KEYS = {
    "domain_suffix_set",
    "domain_set",
    "domain_keyword_set",
    "domain_regex_set",
}
REPOSITORY_FILE_URL = re.compile(
    r"https://(?:raw\.githubusercontent\.com/" + re.escape(REPOSITORY) + r"/main"
    r"|(?:cdn|fastly|gcore)\.jsdelivr\.net/gh/" + re.escape(REPOSITORY) + r"@main)"
    r"/(?P<path>[^\s\"'`<>)]+)"
)
WORKFLOW_URL = re.compile(
    r"https://github\.com/" + re.escape(REPOSITORY) + r"/actions/workflows/(?P<file>[\w.-]+)"
)
RELATIVE_LINK = re.compile(r"\]\((?!https?://|#)(?P<path>[^)\s]+)\)")


class UniqueKeyLoader(yaml.SafeLoader):
    """Safe YAML loader that rejects duplicate mapping keys."""


def construct_unique_mapping(
    loader: UniqueKeyLoader, node: yaml.MappingNode, deep: bool = False
) -> dict[Any, Any]:
    keys: set[Any] = set()
    for key_node, _ in node.value:
        if key_node.tag == "tag:yaml.org,2002:merge":
            continue
        key = loader.construct_object(key_node, deep=deep)
        if key in keys:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                f"found duplicate key {key!r}",
                key_node.start_mark,
            )
        keys.add(key)
    return yaml.SafeLoader.construct_mapping(loader, node, deep=deep)


UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, construct_unique_mapping
)


def relative(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def load_yaml(path: Path, errors: list[str]) -> Any:
    try:
        with path.open(encoding="utf-8") as stream:
            return yaml.load(stream, Loader=UniqueKeyLoader)
    except (OSError, yaml.YAMLError) as error:
        errors.append(f"{relative(path)}: {error}")
        return None


def validate_egern_rule_set(path: Path, config: Any, errors: list[str]) -> None:
    if not isinstance(config, dict) or not config or not set(config) <= EGERN_RULE_SET_KEYS:
        errors.append(
            f"{relative(path)}: expected only Egern domain set keys "
            f"({', '.join(sorted(EGERN_RULE_SET_KEYS))})"
        )
        return

    for key, items in config.items():
        if not isinstance(items, list) or not items:
            errors.append(f"{relative(path)}: {key} must be a non-empty list")
        elif not all(isinstance(entry, str) and entry for entry in items):
            errors.append(f"{relative(path)}: {key} entries must be non-empty strings")
        elif len(items) != len(set(items)):
            errors.append(f"{relative(path)}: {key} contains duplicate entries")


def validate_srs_files(errors: list[str]) -> int:
    paths = sorted(ROOT.glob("*.srs"))
    for path in paths:
        data = path.read_bytes()
        if len(data) <= len(SRS_MAGIC) + 1:
            errors.append(f"{relative(path)}: file is empty or truncated")
            continue
        if data[:3] != SRS_MAGIC:
            errors.append(f"{relative(path)}: invalid sing-box SRS header")
            continue
        if data[3] == 0:
            errors.append(f"{relative(path)}: invalid sing-box SRS version")
            continue
        try:
            payload = zlib.decompress(data[4:])
        except zlib.error as error:
            errors.append(f"{relative(path)}: invalid sing-box SRS stream: {error}")
            continue
        if not payload:
            errors.append(f"{relative(path)}: empty sing-box SRS payload")
    return len(paths)


def validate_artifact_manifest(errors: list[str]) -> set[str]:
    """Check the manifest against the published files and return the files it lists."""
    try:
        manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        errors.append(f"{relative(MANIFEST_PATH)}: {error}")
        return set()
    if not isinstance(manifest, dict) or manifest.get("schema") != 1:
        errors.append(f"{relative(MANIFEST_PATH)}: expected manifest schema 1")
        return set()
    tools = manifest.get("tools")
    if not isinstance(tools, dict) or not isinstance(tools.get("sing_box"), str) or not tools["sing_box"]:
        errors.append(f"{relative(MANIFEST_PATH)}: missing sing-box compiler version")
    rule_sets = manifest.get("rule_sets")
    if not isinstance(rule_sets, dict) or set(rule_sets) != set(EXPECTED_RULE_SETS):
        errors.append(f"{relative(MANIFEST_PATH)}: unexpected rule-set inventory")
        return set()

    manifest_files: set[str] = set()
    for name, (expected_kind, expected_files) in EXPECTED_RULE_SETS.items():
        entry = rule_sets[name]
        if (
            not isinstance(entry, dict)
            or type(entry.get("rules")) is not int
            or entry["rules"] <= 0
        ):
            errors.append(f"{relative(MANIFEST_PATH)}: invalid rule count for {name}")
            continue
        if entry.get("kind") != expected_kind:
            errors.append(f"{relative(MANIFEST_PATH)}: invalid rule kind for {name}")
        files = entry.get("files")
        if not isinstance(files, dict) or set(files) != expected_files:
            errors.append(f"{relative(MANIFEST_PATH)}: invalid file inventory for {name}")
            continue
        manifest_files.update(files)
        for filename, metadata in files.items():
            artifact = ROOT / filename
            if not artifact.is_file():
                errors.append(f"{filename}: missing artifact")
                continue
            data = artifact.read_bytes()
            expected_size = metadata.get("size") if isinstance(metadata, dict) else None
            expected_hash = metadata.get("sha256") if isinstance(metadata, dict) else None
            if expected_size != len(data):
                errors.append(f"{filename}: size does not match artifact manifest")
            if expected_hash != hashlib.sha256(data).hexdigest():
                errors.append(f"{filename}: SHA-256 does not match artifact manifest")

    published = {path.name for pattern in ("*.srs", "*.yaml") for path in ROOT.glob(pattern)}
    unlisted = sorted(published - manifest_files)
    if unlisted:
        errors.append(
            f"{relative(MANIFEST_PATH)}: unlisted rule-set files: {', '.join(unlisted)}"
        )
    return manifest_files


def validate_readme(manifest_files: set[str], errors: list[str]) -> None:
    try:
        text = README_PATH.read_text(encoding="utf-8")
    except OSError as error:
        errors.append(f"README.md: {error}")
        return

    linked = {match.group("path") for match in REPOSITORY_FILE_URL.finditer(text)}
    for path in sorted(linked):
        if not (ROOT / path).is_file():
            errors.append(f"README.md: link points to missing file {path}")
    workflows = {match.group("file") for match in WORKFLOW_URL.finditer(text)}
    for workflow in sorted(workflows):
        if not (ROOT / ".github" / "workflows" / workflow).is_file():
            errors.append(f"README.md: link points to missing workflow {workflow}")
    relative_paths = {match.group("path").split("#", 1)[0] for match in RELATIVE_LINK.finditer(text)}
    for path in sorted(relative_paths - {""}):
        if not (ROOT / path).exists():
            errors.append(f"README.md: relative link points to missing path {path}")

    # Keeping every published file in the README catches download tables that drift.
    unlinked = sorted(manifest_files - linked)
    if unlinked:
        errors.append(f"README.md: missing download links for {', '.join(unlinked)}")


def main() -> int:
    errors: list[str] = []
    rule_set_files = sorted(ROOT.glob("*.yaml"))
    workflow_files = sorted((ROOT / ".github" / "workflows").glob("*.yml"))

    for path in rule_set_files:
        loaded_errors = len(errors)
        config = load_yaml(path, errors)
        if len(errors) == loaded_errors:
            validate_egern_rule_set(path, config, errors)
    for path in workflow_files:
        load_yaml(path, errors)
    srs_count = validate_srs_files(errors)
    manifest_files = validate_artifact_manifest(errors)
    validate_readme(manifest_files, errors)

    if errors:
        print("Repository validation failed:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1

    print(
        f"Validated {len(rule_set_files)} Egern rule sets, {srs_count} SRS files, "
        f"{len(workflow_files)} workflows, the artifact manifest and README links."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
