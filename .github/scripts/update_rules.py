"""Download upstream rules and publish them as verified sing-box and Egern rule sets."""

from __future__ import annotations

import hashlib
import http.client
import ipaddress
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
import zipfile
from collections.abc import Callable
from pathlib import Path
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parents[2]
USER_AGENT = "Ethan2258-rules-updater/1.0"
SINGBOX_RELEASE_API = "https://api.github.com/repos/SagerNet/sing-box/releases/latest"
SRS_MAGIC = b"SRS"
# Version 1 used a legacy domain matcher; every later version shares one payload layout.
SRS_MIN_PAYLOAD_VERSION = 2
MIRROR_BRANCH = "Loon"
FETCH_ATTEMPTS = 3
DOMAIN_ENTRY = re.compile(r"^(?:[A-Za-z0-9_*-]+\.)+[A-Za-z0-9_*-]+$")
NODESEEK_SOURCES = (
    "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/nodeseek.json",
    "https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/nodeseek.json",
)
WEBRTC_SOURCES = (
    "https://raw.githubusercontent.com/MeALiYeYe/ProxyConfigFiles/main/Surge/rule/WebRTC/WebRTC.list",
    "https://cdn.jsdelivr.net/gh/MeALiYeYe/ProxyConfigFiles@main/Surge/rule/WebRTC/WebRTC.list",
)
TELEGRAM_OFFICIAL_CIDR_SOURCES = (
    "https://core.telegram.org/resources/cidr.txt",
)
TELEGRAM_SOURCES = {
    "TelegramSG": (
        "https://rule.kelee.one/Loon/TelegramSG.lsr",
        f"https://raw.githubusercontent.com/mihoyo-typ/KeleeOne/{MIRROR_BRANCH}/Rule/TelegramSG.lsr",
        "https://raw.githubusercontent.com/Qmxn/Tool/X/Loon/Rule/TelegramSG/TelegramSG.lsr",
    ),
    "TelegramNL": (
        "https://rule.kelee.one/Loon/TelegramNL.lsr",
        f"https://raw.githubusercontent.com/mihoyo-typ/KeleeOne/{MIRROR_BRANCH}/Rule/TelegramNL.lsr",
        "https://raw.githubusercontent.com/Qmxn/Tool/X/Loon/Rule/TelegramNL/TelegramNL.lsr",
    ),
}
MIN_NODESEEK_RULES = 3
MIN_WEBRTC_RULES = 20
RULE_ARTIFACTS = {
    "NodeSeek": {
        "kind": "domain",
        "files": ("Nodeseek.yaml", "Nodeseek.srs"),
    },
    "WebRTC": {
        "kind": "domain",
        "files": ("Webrtc_domain.yaml", "Webrtc_domain.srs"),
    },
    "TelegramSG": {
        "kind": "ipcidr",
        "files": ("TelegramSG.yaml", "TelegramSG.srs"),
    },
    "TelegramNL": {
        "kind": "ipcidr",
        "files": ("TelegramNL.yaml", "TelegramNL.srs"),
    },
}

Records = list[tuple[str, str]]
Networks = list[ipaddress.IPv4Network | ipaddress.IPv6Network]


def fetch(url: str, accept: str = "text/plain,*/*") -> bytes:
    headers = {"User-Agent": USER_AGENT, "Accept": accept}
    token = os.environ.get("GITHUB_TOKEN")
    if token and urlsplit(url).hostname == "api.github.com":
        # Authenticated API calls are not throttled by the shared runner IP limit.
        headers["Authorization"] = f"Bearer {token}"
    last_error: Exception | None = None
    for attempt in range(FETCH_ATTEMPTS):
        try:
            request = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(request, timeout=60) as response:
                data = response.read()
            sample = data[:512].lower()
            if b"attention required" in sample or b"cf-chl-" in sample:
                raise RuntimeError("Cloudflare challenge page returned")
            return data
        except (
            OSError,
            RuntimeError,
            http.client.HTTPException,
            urllib.error.URLError,
        ) as error:
            last_error = error
            if attempt + 1 < FETCH_ATTEMPTS:
                time.sleep(2**attempt)
    raise RuntimeError(f"download failed after {FETCH_ATTEMPTS} attempts: {last_error}")


def download_first(urls: tuple[str, ...]) -> tuple[bytes, str]:
    failures: list[str] = []
    for url in urls:
        try:
            return fetch(url), url
        except (OSError, urllib.error.URLError, RuntimeError) as error:
            failures.append(f"{url}: {error}")
    raise RuntimeError("; ".join(failures))


def download_records(
    urls: tuple[str, ...],
    parse: Callable[[bytes], Records],
    minimum: int = 1,
) -> tuple[Records, str]:
    failures: list[str] = []
    for url in urls:
        try:
            records = parse(fetch(url))
            if len(records) < minimum:
                raise ValueError(f"expected at least {minimum} rules, received {len(records)}")
            return records, url
        except (OSError, RuntimeError, ValueError, urllib.error.URLError) as error:
            failures.append(f"{url}: {error}")
    raise RuntimeError("; ".join(failures))


def parse_lsr_records(data: bytes, kind: str) -> Records:
    text = data.decode("utf-8-sig")
    entries: Records = []
    seen: set[tuple[str, str]] = set()
    domain_types = {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "HOST", "HOST-SUFFIX"}
    ip_types = {"IP-CIDR", "IP-CIDR6", "IP-ASN"}
    known_types = domain_types | ip_types
    accepted = domain_types if kind == "domain" else ip_types

    for line_number, raw_line in enumerate(text.splitlines(), 1):
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        fields = [field.strip() for field in line.split(",")]
        if len(fields) < 2:
            raise ValueError(f"line {line_number}: expected a rule with a value")
        rule_type, value = fields[0].upper(), fields[1]
        # HOST is Loon's name for DOMAIN; folding it keeps duplicates out of every output.
        rule_type = {"HOST": "DOMAIN", "HOST-SUFFIX": "DOMAIN-SUFFIX"}.get(rule_type, rule_type)
        if rule_type not in known_types:
            raise ValueError(f"line {line_number}: unsupported rule type {rule_type}")
        if rule_type not in accepted:
            continue
        if not value:
            raise ValueError(f"line {line_number}: empty rule value")
        if rule_type == "IP-ASN":
            raise ValueError(
                f"line {line_number}: IP-ASN cannot be represented losslessly by a sing-box rule set"
            )
        value = value.removeprefix("*.").removeprefix(".").strip()
        if rule_type in {"DOMAIN", "DOMAIN-SUFFIX", "HOST", "HOST-SUFFIX"}:
            value = value.lower().rstrip(".")
            if not DOMAIN_ENTRY.fullmatch(value):
                raise ValueError(f"line {line_number}: invalid domain value {value!r}")
        elif rule_type == "DOMAIN-KEYWORD":
            value = value.lower()
        else:
            try:
                network = ipaddress.ip_network(value, strict=False)
            except ValueError as error:
                raise ValueError(
                    f"line {line_number}: invalid network {value!r}"
                ) from error
            expected_version = 6 if rule_type == "IP-CIDR6" else 4
            if network.version != expected_version:
                raise ValueError(
                    f"line {line_number}: {rule_type} contains IPv{network.version}"
                )
            value = network.with_prefixlen
        entry = (rule_type, value)
        if entry not in seen:
            entries.append(entry)
            seen.add(entry)

    if not entries:
        raise ValueError(f"source contains no {kind} rules")
    return entries


def singbox_source_records(data: bytes, source_name: str) -> Records:
    """Read a sing-box rule-set source that only matches domains and domain suffixes."""
    try:
        source = json.loads(data.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"{source_name}: invalid rule-set JSON: {error}") from error
    rules = source.get("rules") if isinstance(source, dict) else None
    if not isinstance(rules, list) or not rules:
        raise ValueError(f"{source_name}: rule-set contains no rules")
    records: Records = []
    for rule in rules:
        if not isinstance(rule, dict) or not rule or not set(rule) <= {"domain", "domain_suffix"}:
            raise ValueError(f"{source_name}: unsupported rule {rule!r}")
        for field, rule_type in (("domain", "DOMAIN"), ("domain_suffix", "DOMAIN-SUFFIX")):
            values = rule.get(field, [])
            for value in [values] if isinstance(values, str) else values:
                if not isinstance(value, str):
                    raise ValueError(f"{source_name}: invalid {field} value {value!r}")
                # A leading dot changes suffix semantics, so it is rejected by the pattern.
                value = value.lower().rstrip(".")
                if not DOMAIN_ENTRY.fullmatch(value):
                    raise ValueError(f"{source_name}: invalid {field} value {value!r}")
                records.append((rule_type, value))
    return list(dict.fromkeys(records))


def singbox_binary(directory: Path) -> Path:
    release = json.loads(fetch(SINGBOX_RELEASE_API, "application/vnd.github+json"))

    windows = platform.system() == "Windows"
    archive_suffix = ".zip" if windows else ".tar.gz"
    assets = [
        asset
        for asset in release.get("assets", [])
        if asset.get("name", "").startswith("sing-box-")
        and asset.get("name", "").endswith(archive_suffix)
    ]
    candidates = []
    suffixes = (
        ("-windows-amd64.zip",)
        if windows
        else (
            "-linux-amd64.tar.gz",
            "-linux-amd64-glibc.tar.gz",
            "-linux-amd64-musl.tar.gz",
        )
    )
    for suffix in suffixes:
        candidates = [asset for asset in assets if asset["name"].endswith(suffix)]
        if candidates:
            break
    if not candidates:
        raise RuntimeError(
            f"no {platform.system()} amd64 sing-box release asset found"
        )

    archive = directory / f"sing-box{archive_suffix}"
    extract_directory = directory / "sing-box"
    archive.write_bytes(fetch(candidates[0]["browser_download_url"]))
    extract_directory.mkdir()
    if windows:
        with zipfile.ZipFile(archive) as compressed:
            compressed.extractall(extract_directory)
    else:
        with tarfile.open(archive, "r:gz") as compressed:
            compressed.extractall(extract_directory, filter="data")
    binary_name = "sing-box.exe" if windows else "sing-box"
    binaries = list(extract_directory.rglob(binary_name))
    if not binaries:
        raise RuntimeError("sing-box archive did not contain a binary")
    binary = binaries[0]
    if not windows:
        binary.chmod(binary.stat().st_mode | stat.S_IXUSR)
    return binary


def singbox_version(binary: Path) -> str:
    result = subprocess.run([str(binary), "version"], capture_output=True, text=True)
    if result.returncode:
        detail = (result.stderr or result.stdout).strip()
        raise RuntimeError(f"unable to query sing-box version: {detail}")
    return (result.stdout or result.stderr).strip().splitlines()[0]


def telegram_official_networks() -> tuple[Networks, str]:
    data, used_url = download_first(TELEGRAM_OFFICIAL_CIDR_SOURCES)
    try:
        lines = data.decode("utf-8-sig").splitlines()
    except UnicodeDecodeError as error:
        raise RuntimeError(f"Telegram official CIDR list is not UTF-8: {error}") from error
    networks: Networks = []
    for line_number, raw_line in enumerate(lines, 1):
        value = raw_line.strip()
        if not value:
            continue
        try:
            networks.append(ipaddress.ip_network(value, strict=True))
        except ValueError as error:
            raise RuntimeError(
                f"Telegram official CIDR line {line_number} is invalid: {value!r}"
            ) from error
    if len(networks) < 10 or not {network.version for network in networks} == {4, 6}:
        raise RuntimeError("Telegram official CIDR list is unexpectedly small or not dual-stack")
    return networks, used_url


def validate_telegram_records(
    name: str,
    records: Records,
    official_networks: Networks,
) -> Networks:
    networks = [ipaddress.ip_network(value, strict=True) for _, value in records]
    outside = [
        network
        for network in networks
        if not any(
            network.version == official.version and network.subnet_of(official)
            for official in official_networks
        )
    ]
    if outside:
        raise RuntimeError(f"{name}: CIDRs outside Telegram official ranges: {outside}")
    return networks


def write_artifact_manifest(counts: dict[str, int], singbox: str, srs_version: int) -> None:
    rule_sets = {}
    for name, specification in RULE_ARTIFACTS.items():
        if name not in counts:
            raise RuntimeError(f"missing generated rule count for {name}")
        files = {}
        for filename in specification["files"]:
            artifact = ROOT / filename
            if not artifact.is_file():
                raise RuntimeError(f"missing generated artifact: {filename}")
            data = artifact.read_bytes()
            files[filename] = {
                "size": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
            }
        rule_sets[name] = {
            "kind": specification["kind"],
            "rules": counts[name],
            "files": files,
        }
    manifest = {
        "schema": 1,
        "tools": {"sing_box": singbox},
        "srs_version": srs_version,
        "rule_sets": rule_sets,
    }
    (ROOT / ".github/rule-artifacts.json").write_text(
        json.dumps(manifest, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def decompile_srs(binary: Path, input_path: Path, output_path: Path) -> list[dict]:
    command = [
        str(binary),
        "rule-set",
        "decompile",
        str(input_path),
        "-o",
        str(output_path),
    ]
    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode:
        detail = (result.stderr or result.stdout).strip()
        raise RuntimeError(f"sing-box SRS decompilation failed: {detail}")
    try:
        source = json.loads(output_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise RuntimeError(f"{input_path.name}: invalid decompiled rule-set: {error}") from error
    rules = source.get("rules") if isinstance(source, dict) else None
    if not isinstance(rules, list) or not rules or not all(isinstance(rule, dict) for rule in rules):
        raise RuntimeError(f"{input_path.name}: decompiled rule-set contains no rules")
    return rules


def rule_values(values: object) -> object:
    # sing-box renders a single-item list as a bare string when decompiling.
    if isinstance(values, str):
        return [values]
    return sorted(values) if isinstance(values, list) else values


def rule_count(rules: list[dict]) -> int:
    return sum(
        len(values)
        for rule in rules
        for values in map(rule_values, rule.values())
        if isinstance(values, list)
    )


def verify_srs(
    binary: Path,
    input_path: Path,
    expected_rules: list[dict[str, list[str]]],
    workspace: Path,
) -> None:
    actual_rules = decompile_srs(
        binary,
        input_path,
        workspace / f"{input_path.name}.verified.json",
    )
    normalize = lambda rules: [
        {key: rule_values(values) for key, values in sorted(rule.items())}
        for rule in rules
    ]
    if normalize(actual_rules) != normalize(expected_rules):
        raise RuntimeError(f"{input_path.name}: generated SRS differs from its source")


def singbox_rule(domain: list[str] | None = None, domain_suffix: list[str] | None = None,
                 domain_keyword: list[str] | None = None, ip_cidr: list[str] | None = None) -> dict[str, list[str]]:
    rule: dict[str, list[str]] = {}
    for key, values in (
        ("domain", domain),
        ("domain_suffix", domain_suffix),
        ("domain_keyword", domain_keyword),
        ("ip_cidr", ip_cidr),
    ):
        if values:
            rule[key] = values
    return rule


def current_srs_source_version(binary: Path) -> int:
    result = subprocess.run(
        [str(binary), "rule-set", "upgrade", "stdin"],
        input=json.dumps({"version": 1, "rules": []}),
        capture_output=True,
        text=True,
    )
    if result.returncode:
        detail = (result.stderr or result.stdout).strip()
        raise RuntimeError(f"sing-box rule-set version detection failed: {detail}")
    upgraded = json.loads(result.stdout)
    version = upgraded.get("version")
    if type(version) is not int or version < 1 or upgraded.get("rules", []) != []:
        raise RuntimeError("sing-box returned an invalid upgraded rule-set version")
    return version


def compile_srs(binary: Path, rules: list[dict[str, list[str]]], output_path: Path) -> None:
    source_version = current_srs_source_version(binary)
    source_path = output_path.with_suffix(".json")
    source_path.write_text(
        json.dumps({"version": source_version, "rules": rules}, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    command = [str(binary), "rule-set", "compile", str(source_path), "-o", str(output_path)]
    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode:
        detail = (result.stderr or result.stdout).strip()
        raise RuntimeError(f"sing-box SRS compilation failed: {detail}")
    if not output_path.is_file() or output_path.read_bytes()[:3] != SRS_MAGIC:
        raise RuntimeError(f"{output_path.name}: compiler did not produce a valid SRS file")
    data = output_path.read_bytes()
    if len(data) <= 4 or not SRS_MIN_PAYLOAD_VERSION <= data[3] <= source_version:
        raise RuntimeError(f"{output_path.name}: compiler produced an invalid SRS version")
    compiled_version = data[3]
    # The compiler lowers the header to the oldest version the rules need, but the
    # payload is encoded the same way from v2 on (newer versions only add rule items,
    # which the compiler rejects below their version). Stamping the latest version
    # therefore yields the file a non-downgrading compiler would write.
    output_path.write_bytes(data[:3] + bytes([source_version]) + data[4:])
    print(
        f"{output_path.name}: SRS format v{source_version} "
        f"(compiler selected v{compiled_version})"
    )


def records_to_srs_rules(records: Records, kind: str) -> list[dict[str, list[str]]]:
    domains: list[str] = []
    suffixes: list[str] = []
    keywords: list[str] = []
    cidrs: list[str] = []
    for rule_type, value in records:
        if rule_type in {"DOMAIN", "HOST"}:
            domains.append(value)
        elif rule_type in {"DOMAIN-SUFFIX", "HOST-SUFFIX"}:
            suffixes.append(value)
        elif rule_type == "DOMAIN-KEYWORD":
            keywords.append(value)
        elif rule_type in {"IP-CIDR", "IP-CIDR6"}:
            cidrs.append(value)
        else:
            raise ValueError(f"{rule_type} cannot be represented by a sing-box rule set")
    if kind == "domain" and cidrs:
        raise ValueError("domain SRS cannot contain IP-CIDR rules")
    if kind == "ipcidr" and (domains or suffixes or keywords):
        raise ValueError("ipcidr SRS cannot contain domain rules")
    rule = singbox_rule(
        domain=domains,
        domain_suffix=suffixes,
        domain_keyword=keywords,
        ip_cidr=cidrs,
    )
    if not rule:
        raise ValueError("source contains no rules for a sing-box rule set")
    return [rule]


EGERN_KEYS = (
    ("domain_suffix_set", {"DOMAIN-SUFFIX", "HOST-SUFFIX"}),
    ("domain_set", {"DOMAIN", "HOST"}),
    ("domain_keyword_set", {"DOMAIN-KEYWORD"}),
    ("ip_cidr_set", {"IP-CIDR"}),
    ("ip_cidr6_set", {"IP-CIDR6"}),
)


def records_to_egern_yaml(records: Records, kind: str) -> str:
    known_types = set().union(*(types for _, types in EGERN_KEYS))
    unsupported = sorted({rule_type for rule_type, _ in records} - known_types)
    if unsupported:
        raise ValueError(f"{', '.join(unsupported)} cannot be represented by an Egern rule set")
    # Like sing-box ip_cidr rule sets, IP rule sets never trigger a DNS lookup.
    lines: list[str] = ["no_resolve: true"] if kind == "ipcidr" else []
    for key, types in EGERN_KEYS:
        values = sorted({value for rule_type, value in records if rule_type in types})
        if values:
            lines.append(f"{key}:")
            lines.extend(f"  - {value}" for value in values)
    if len(lines) == (1 if kind == "ipcidr" else 0):
        raise ValueError("source contains no rules for an Egern rule set")
    return "\n".join(lines) + "\n"


def build_egern(records: Records, kind: str, output: str, workspace: Path) -> Path:
    path = workspace / output
    # Bytes keep LF line endings on every platform, which keeps the SHA-256 stable.
    path.write_bytes(records_to_egern_yaml(records, kind).encode("utf-8"))
    return path


def build_srs(singbox: Path, records: Records, kind: str, output: str, workspace: Path) -> Path:
    rules = records_to_srs_rules(records, kind)
    compiled = workspace / output
    compile_srs(singbox, rules, compiled)
    verify_srs(singbox, compiled, rules, workspace)
    return compiled


def build_nodeseek(singbox: Path, workspace: Path) -> tuple[int, list[Path]]:
    records, used_url = download_records(
        NODESEEK_SOURCES,
        lambda data: singbox_source_records(data, "NodeSeek"),
        MIN_NODESEEK_RULES,
    )
    srs_output = build_srs(singbox, records, "domain", "Nodeseek.srs", workspace)
    yaml_output = build_egern(records, "domain", "Nodeseek.yaml", workspace)
    print(f"NodeSeek: {len(records)} rules from {used_url}")
    return len(records), [yaml_output, srs_output]


def preserve_existing_srs(
    singbox: Path,
    filename: str,
    workspace: Path,
    download_error: RuntimeError,
) -> tuple[int, list[Path]]:
    existing = ROOT / filename
    if not existing.is_file() or existing.read_bytes()[:3] != SRS_MAGIC:
        raise RuntimeError(
            f"{filename}: sources are unavailable and no valid existing SRS is present: "
            f"{download_error}"
        )
    companion = existing.with_suffix(".yaml")
    if not companion.is_file():
        raise RuntimeError(
            f"{companion.name}: sources are unavailable and no existing Egern rule set "
            f"is present: {download_error}"
        )
    rules = decompile_srs(singbox, existing, workspace / f"{filename}.existing.json")
    count = rule_count(rules)
    print(
        f"WARNING: {filename}: sources are unavailable; preserving {count} validated "
        f"existing rules: {download_error}"
    )
    data = existing.read_bytes()
    if data[3] == current_srs_source_version(singbox):
        return count, []
    # Keep every published SRS on the latest format even while its source is down.
    recompiled = workspace / filename
    compile_srs(singbox, rules, recompiled)
    verify_srs(singbox, recompiled, rules, workspace)
    return count, [recompiled]


def build_webrtc(singbox: Path, workspace: Path) -> tuple[int, list[Path]]:
    try:
        records, used_url = download_records(
            WEBRTC_SOURCES,
            lambda data: parse_lsr_records(data, "domain"),
            MIN_WEBRTC_RULES,
        )
    except RuntimeError as error:
        return preserve_existing_srs(singbox, "Webrtc_domain.srs", workspace, error)
    srs_output = build_srs(singbox, records, "domain", "Webrtc_domain.srs", workspace)
    yaml_output = build_egern(records, "domain", "Webrtc_domain.yaml", workspace)
    print(f"WebRTC: {len(records)} rules from {used_url}")
    return len(records), [yaml_output, srs_output]


def build_telegram(singbox: Path, workspace: Path) -> dict[str, tuple[int, list[Path]]]:
    official, official_url = telegram_official_networks()
    print(
        f"Telegram official CIDR audit: {len(official)} dual-stack ranges; "
        f"{official_url}"
    )
    networks: dict[str, Networks] = {}
    results: dict[str, tuple[int, list[Path]]] = {}
    for name, urls in TELEGRAM_SOURCES.items():
        records, used_url = download_records(urls, lambda data: parse_lsr_records(data, "ipcidr"))
        networks[name] = validate_telegram_records(name, records, official)
        srs_output = build_srs(singbox, records, "ipcidr", f"{name}.srs", workspace)
        yaml_output = build_egern(records, "ipcidr", f"{name}.yaml", workspace)
        print(f"{name}: {len(records)} rules from {used_url}")
        results[name] = (len(records), [yaml_output, srs_output])
    overlap = [
        (left, right)
        for left in networks["TelegramSG"]
        for right in networks["TelegramNL"]
        if left.version == right.version and left.overlaps(right)
    ]
    if overlap:
        raise RuntimeError(f"Telegram SG/NL ranges overlap: {overlap}")
    return results


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="rule-update-") as temporary:
        workspace = Path(temporary)
        singbox = singbox_binary(workspace)
        version = singbox_version(singbox)
        print(f"Using {version}")
        results = {
            "NodeSeek": build_nodeseek(singbox, workspace),
            "WebRTC": build_webrtc(singbox, workspace),
            **build_telegram(singbox, workspace),
        }
        # Every rule set is built and verified before any tracked file changes.
        for _, artifacts in results.values():
            for artifact in artifacts:
                # The temporary directory can sit on another filesystem.
                shutil.move(artifact, ROOT / artifact.name)
        write_artifact_manifest(
            {name: count for name, (count, _) in results.items()},
            version,
            current_srs_source_version(singbox),
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
