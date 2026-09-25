"""Validate published rule sets, the artifact manifest and README links."""

from __future__ import annotations

import hashlib
import ipaddress
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
UPDATE_WORKFLOW_PATH = ROOT / ".github" / "workflows" / "update-rules.yml"
SRS_MAGIC = b"SRS"
EXPECTED_RULE_SETS = {
    "NodeSeek": ("domain", {"Nodeseek.yaml", "Nodeseek.srs"}),
    "WebRTC": ("domain", {"Webrtc_domain.yaml", "Webrtc_domain.srs"}),
    "TelegramSG": ("ipcidr", {"TelegramSG.yaml", "TelegramSG.srs"}),
    "TelegramNL": ("ipcidr", {"TelegramNL.yaml", "TelegramNL.srs"}),
}
EGERN_RULE_SET_KEYS = {
    "domain": {
        "domain_suffix_set",
        "domain_set",
        "domain_keyword_set",
        "domain_regex_set",
    },
    "ipcidr": {"ip_cidr_set", "ip_cidr6_set"},
}
EGERN_IP_VERSIONS = {"ip_cidr_set": 4, "ip_cidr6_set": 6}
EGERN_FILE_KINDS = {
    filename: kind
    for kind, files in EXPECTED_RULE_SETS.values()
    for filename in files
    if filename.endswith(".yaml")
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
HOURLY_CRON = re.compile(r"^\d{1,2} (?P<hours>\*|\*/(?P<step>\d+)) \* \* \*$")


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


def validate_egern_rule_set(path: Path, config: Any, errors: list[str]) -> int:
    """Check an Egern rule set against its manifest kind and return its rule count."""
    kind = EGERN_FILE_KINDS.get(path.name)
    allowed = EGERN_RULE_SET_KEYS.get(kind, set().union(*EGERN_RULE_SET_KEYS.values()))
    if isinstance(config, dict) and kind == "ipcidr":
        # sing-box ip_cidr rule sets never resolve domains, so the Egern files must not either.
        if config.get("no_resolve") is not True:
            errors.append(f"{relative(path)}: IP rule sets must set no_resolve: true")
        config = {key: value for key, value in config.items() if key != "no_resolve"}
    if not isinstance(config, dict) or not config or not set(config) <= allowed:
        errors.append(
            f"{relative(path)}: expected only Egern {kind or 'rule'} set keys "
            f"({', '.join(sorted(allowed))})"
        )
        return 0

    count = 0
    for key, items in config.items():
        if not isinstance(items, list) or not items:
            errors.append(f"{relative(path)}: {key} must be a non-empty list")
        elif not all(isinstance(entry, str) and entry for entry in items):
            errors.append(f"{relative(path)}: {key} entries must be non-empty strings")
        elif len(items) != len(set(items)):
            errors.append(f"{relative(path)}: {key} contains duplicate entries")
        else:
            count += len(items)
            version = EGERN_IP_VERSIONS.get(key)
            for entry in items if version else ():
                try:
                    network = ipaddress.ip_network(entry, strict=True)
                except ValueError:
                    network = None
                if network is None or network.version != version:
                    errors.append(f"{relative(path)}: {key} contains invalid network {entry!r}")
    return count


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


def validate_artifact_manifest(egern_counts: dict[str, int], errors: list[str]) -> set[str]:
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
        for filename in sorted(files):
            if filename in egern_counts and egern_counts[filename] != entry["rules"]:
                errors.append(
                    f"{filename}: {egern_counts[filename]} rules, but the artifact manifest "
                    f"lists {entry['rules']} for {name}"
                )
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


def update_schedule_phrase(errors: list[str]) -> str | None:
    """Return how README.md must describe the update workflow's schedule."""
    workflow = load_yaml(UPDATE_WORKFLOW_PATH, errors)
    if not isinstance(workflow, dict):
        return None
    # PyYAML reads the bare `on` key as the boolean True.
    triggers = workflow.get("on", workflow.get(True))
    schedule = triggers.get("schedule") if isinstance(triggers, dict) else None
    crons = [entry.get("cron") for entry in schedule or [] if isinstance(entry, dict)]
    match = HOURLY_CRON.fullmatch(crons[0]) if len(crons) == 1 and isinstance(crons[0], str) else None
    if not match:
        errors.append(
            f"{relative(UPDATE_WORKFLOW_PATH)}: expected one hourly or every-N-hours cron "
            "so README.md can state the update frequency"
        )
        return None
    step = int(match.group("step") or 1)
    return "每小时" if step == 1 else f"每 {step} 小时"


def validate_readme(manifest_files: set[str], errors: list[str]) -> None:
    try:
        text = README_PATH.read_text(encoding="utf-8")
    except OSError as error:
        errors.append(f"README.md: {error}")
        return

    schedule = update_schedule_phrase(errors)
    if schedule and f"{schedule}自动检查上游" not in text:
        errors.append(
            f"README.md: update frequency must read “{schedule}自动检查上游” "
            "to match the workflow cron"
        )

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

    egern_counts: dict[str, int] = {}
    for path in rule_set_files:
        loaded_errors = len(errors)
        config = load_yaml(path, errors)
        if len(errors) == loaded_errors:
            count = validate_egern_rule_set(path, config, errors)
            if len(errors) == loaded_errors:
                egern_counts[path.name] = count
    for path in workflow_files:
        load_yaml(path, errors)
    srs_count = validate_srs_files(errors)
    manifest_files = validate_artifact_manifest(egern_counts, errors)
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
