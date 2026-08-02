from __future__ import annotations

import argparse
import ctypes
import ipaddress
import math
import os
import re
import shlex
import shutil
import subprocess
import sys
import threading
import time
import types
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterable, Sequence

from . import data_root

if __name__ not in sys.modules:
    sys.modules[__name__] = types.ModuleType(__name__)

if sys.stdout is None:
    sys.stdout = open(os.devnull, "w", encoding="utf-8")
if sys.stderr is None:
    sys.stderr = open(os.devnull, "w", encoding="utf-8")


DOMAIN_RE = re.compile(
    r"(?<![@A-Za-z0-9_-])((?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63})(?![A-Za-z0-9_-])"
)
XML_HOST_RE = re.compile(r"<host>([^<]+)</host>", re.IGNORECASE)
XML_PORT_RE = re.compile(r"<port>(\d{2,5})</port>", re.IGNORECASE)
LABELED_HOST_RE = re.compile(r"[`'\"]?host[`'\"]?\s*[:=]\s*[`'\"]?([0-9.; ]{7,})", re.IGNORECASE)
LABELED_PORT_RE = re.compile(r"[`'\"]?port[`'\"]?\s*[:=]\s*[`'\"]?(\d{2,5})", re.IGNORECASE)
URL_RE = re.compile(r"\b(https?)://([A-Za-z0-9.-]+)(?::(\d{2,5}))?(?:[/?#]|$)", re.IGNORECASE)
DOMAIN_PORT_RE = re.compile(r"\b((?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}):(\d{2,5})\b")
IP_PORT_RE = re.compile(r"\b((?:\d{1,3}\.){3}\d{1,3}):(\d{2,5})\b")
LOGON_XML_RE = re.compile(r"(?is)<logon\b[^>]*>.*?</logon>")

HOSTS_BLOCK_BEGIN = "# >>> RF4 MONITOR BEGIN"
HOSTS_BLOCK_END = "# <<< RF4 MONITOR END"
LEGACY_HOSTS_BLOCK_BEGIN = "# >>> RF4 MITM CHAT BEGIN"
LEGACY_HOSTS_BLOCK_END = "# <<< RF4 MITM CHAT END"
HOSTS_BLOCK_BEGIN_MARKERS = {HOSTS_BLOCK_BEGIN, LEGACY_HOSTS_BLOCK_BEGIN}
HOSTS_BLOCK_END_MARKERS = {HOSTS_BLOCK_END, LEGACY_HOSTS_BLOCK_END}
TEXT_SUFFIXES = {
    ".cfg",
    ".csv",
    ".ini",
    ".json",
    ".jsonl",
    ".log",
    ".md",
    ".txt",
    ".xml",
    ".yaml",
    ".yml",
}
DEFAULT_DOMAIN_SUFFIXES = ("rf4game.ru", "rf4game.com")
PREFERRED_REVERSE_HOSTS = ("api.rf4game.ru",)


@dataclass(frozen=True)
class ReferenceTrafficInfo:
    domains: tuple[str, ...]
    realtime_hosts: tuple[str, ...]
    realtime_port: int | None
    reverse_targets: tuple["ReverseProxyTarget", ...]
    https_upstream_overrides: tuple["HttpsUpstreamOverride", ...]
    source_files: tuple[Path, ...]


@dataclass(frozen=True)
class HostsUpdateResult:
    path: Path
    backup_path: Path | None
    entries: tuple[str, ...]
    updated: bool


@dataclass(frozen=True)
class GeneratedCertificate:
    cert_path: Path
    key_path: Path
    pem_path: Path
    common_name: str
    domains: tuple[str, ...]


@dataclass(frozen=True, order=True)
class ReverseProxyTarget:
    scheme: str
    host: str
    upstream_port: int
    listen_port: int

    def mode_spec(self) -> str:
        return f"reverse:{self.scheme}://{self.host}:{self.upstream_port}@{self.listen_port}"


@dataclass(frozen=True, order=True)
class HttpsUpstreamOverride:
    domain: str
    connect_host: str
    port: int = 443


@dataclass(frozen=True)
class LoginLogonInfo:
    hosts: tuple[str, ...]
    port: int
    region: str | None
    server: str | None
    userid: str | None
    token: str | None


@dataclass(frozen=True)
class LoginRewriteResult:
    text: str
    original: LoginLogonInfo
    redirected_hosts: tuple[str, ...]
    redirected_port: int


THIS_DIR = data_root()
REPO_ROOT = THIS_DIR.parents[1]
BUNDLED_REFERENCE_PATH = THIS_DIR / "reference_defaults.txt"


def default_reference_paths(repo_root: Path) -> list[Path]:
    return [repo_root / "数据包"]


def default_hosts_path() -> Path:
    if os.name == "nt":
        system_root = Path(os.environ.get("SystemRoot", r"C:\Windows"))
        return system_root / "System32" / "drivers" / "etc" / "hosts"
    return Path("/etc/hosts")


def extract_reference_info(
    paths: Sequence[Path],
    *,
    include_all_domains: bool = False,
    allowed_domain_suffixes: Sequence[str] = DEFAULT_DOMAIN_SUFFIXES,
    max_scan_bytes: int = 2_000_000,
) -> ReferenceTrafficInfo:
    domains: set[str] = set()
    realtime_hosts: list[str] = []
    reverse_targets: set[ReverseProxyTarget] = set()
    https_upstream_overrides: set[HttpsUpstreamOverride] = set()
    realtime_port: int | None = None
    source_files: list[Path] = []

    for file_path in iter_reference_text_files(paths):
        text = safe_read_text(file_path, max_scan_bytes=max_scan_bytes)
        if text is None:
            continue
        source_files.append(file_path)
        domains.update(extract_domains_from_text(text))
        extend_unique(realtime_hosts, extract_realtime_hosts_from_text(text))
        reverse_targets.update(extract_reverse_targets_from_text(text))
        https_upstream_overrides.update(extract_https_upstream_overrides_from_text(text))
        if realtime_port is None:
            realtime_port = extract_realtime_port_from_text(text)

    filtered_domains = sorted(
        domain
        for domain in domains
        if include_all_domains or domain_matches_suffixes(domain, allowed_domain_suffixes)
    )
    filtered_reverse_target_set = {
        target
        for target in reverse_targets
        if include_all_domains or domain_matches_suffixes(target.host, allowed_domain_suffixes)
    }
    filtered_reverse_target_set.update(infer_default_reverse_targets(filtered_domains))
    filtered_reverse_targets = tuple(sorted(filtered_reverse_target_set))
    filtered_https_upstream_overrides = tuple(
        sorted(
            override
            for override in https_upstream_overrides
            if include_all_domains or domain_matches_suffixes(override.domain, allowed_domain_suffixes)
        )
    )

    return ReferenceTrafficInfo(
        domains=tuple(filtered_domains),
        realtime_hosts=tuple(realtime_hosts),
        realtime_port=realtime_port,
        reverse_targets=filtered_reverse_targets,
        https_upstream_overrides=filtered_https_upstream_overrides,
        source_files=tuple(source_files),
    )


def iter_reference_text_files(paths: Sequence[Path]) -> Iterable[Path]:
    seen: set[Path] = set()
    for path in paths:
        resolved = Path(path).expanduser().resolve()
        if not resolved.exists():
            continue
        if resolved.is_file():
            if resolved not in seen and should_scan_file(resolved):
                seen.add(resolved)
                yield resolved
            continue
        for file_path in sorted(resolved.rglob("*")):
            if not file_path.is_file():
                continue
            if file_path in seen or not should_scan_file(file_path):
                continue
            seen.add(file_path)
            yield file_path


def should_scan_file(path: Path) -> bool:
    return path.suffix.lower() in TEXT_SUFFIXES


def safe_read_text(path: Path, *, max_scan_bytes: int) -> str | None:
    try:
        with path.open("rb") as handle:
            raw = handle.read(max_scan_bytes)
    except OSError:
        return None
    return raw.decode("utf-8", errors="ignore")


def extract_domains_from_text(text: str) -> set[str]:
    domains = {match.group(1).strip(".").lower() for match in DOMAIN_RE.finditer(text)}
    return {domain for domain in domains if "." in domain}


def extract_realtime_hosts_from_text(text: str) -> tuple[str, ...]:
    hosts: list[str] = []
    for match in XML_HOST_RE.finditer(text):
        extend_unique(hosts, split_ip_list(match.group(1)))
    for match in LABELED_HOST_RE.finditer(text):
        extend_unique(hosts, split_ip_list(match.group(1)))
    return tuple(hosts)


def extract_realtime_port_from_text(text: str) -> int | None:
    for regex in (XML_PORT_RE, LABELED_PORT_RE):
        match = regex.search(text)
        if not match:
            continue
        port = int(match.group(1))
        if 1 <= port <= 65535:
            return port
    return None


def extract_reverse_targets_from_text(text: str) -> set[ReverseProxyTarget]:
    targets: set[ReverseProxyTarget] = set()
    for match in URL_RE.finditer(text):
        scheme = match.group(1).lower()
        host = match.group(2).lower()
        port = int(match.group(3)) if match.group(3) else (443 if scheme == "https" else 80)
        if scheme == "https" and port == 443:
            targets.add(ReverseProxyTarget(scheme=scheme, host=host, upstream_port=port, listen_port=port))

    for match in DOMAIN_PORT_RE.finditer(text):
        host = match.group(1).lower()
        port = int(match.group(2))
        if port == 443:
            targets.add(ReverseProxyTarget(scheme="https", host=host, upstream_port=443, listen_port=443))

    return targets


def extract_https_upstream_overrides_from_text(text: str) -> set[HttpsUpstreamOverride]:
    overrides: set[HttpsUpstreamOverride] = set()
    for raw_line in text.splitlines():
        if "<->" not in raw_line:
            continue
        domain_match = DOMAIN_PORT_RE.search(raw_line)
        if not domain_match:
            continue
        domain = domain_match.group(1).lower()
        port = int(domain_match.group(2))
        if port != 443:
            continue

        connect_host = ""
        for candidate_host, candidate_port in IP_PORT_RE.findall(raw_line):
            if candidate_port != "443":
                continue
            try:
                ipaddress.ip_address(candidate_host)
            except ValueError:
                continue
            connect_host = candidate_host

        if connect_host:
            overrides.add(HttpsUpstreamOverride(domain=domain, connect_host=connect_host, port=443))
    return overrides


def infer_default_reverse_targets(domains: Sequence[str]) -> list[ReverseProxyTarget]:
    return [ReverseProxyTarget(scheme="https", host=domain, upstream_port=443, listen_port=443) for domain in domains]


def select_reverse_targets(targets: Sequence[ReverseProxyTarget]) -> tuple[ReverseProxyTarget, ...]:
    selected_by_port: dict[int, ReverseProxyTarget] = {}
    for target in sorted(targets, key=_reverse_target_priority):
        if target.listen_port in selected_by_port:
            continue
        selected_by_port[target.listen_port] = target
    return tuple(sorted(selected_by_port.values()))


def managed_proxy_domains(domains: Sequence[str], reverse_targets: Sequence[ReverseProxyTarget]) -> tuple[str, ...]:
    selected_hosts = tuple(sorted({target.host for target in select_reverse_targets(reverse_targets)}))
    if selected_hosts:
        return selected_hosts
    return tuple(sorted({domain.lower() for domain in domains if domain.strip()}))


def _reverse_target_priority(target: ReverseProxyTarget) -> tuple[int, int, str, int]:
    if target.host in PREFERRED_REVERSE_HOSTS:
        host_rank = 0
    elif target.host.endswith(".rf4game.ru"):
        host_rank = 1
    elif target.host.endswith(".rf4game.com"):
        host_rank = 2
    else:
        host_rank = 3
    scheme_rank = 0 if target.scheme == "https" else 1
    return (host_rank, scheme_rank, target.host, target.upstream_port)


def select_https_upstream_overrides(
    overrides: Sequence[HttpsUpstreamOverride],
    reverse_targets: Sequence[ReverseProxyTarget],
) -> tuple[HttpsUpstreamOverride, ...]:
    selected_hosts = {
        target.host
        for target in select_reverse_targets(reverse_targets)
        if target.scheme in ("https", "tls")
    }
    selected_by_domain: dict[str, HttpsUpstreamOverride] = {}
    for override in sorted(overrides):
        if selected_hosts and override.domain not in selected_hosts:
            continue
        selected_by_domain.setdefault(override.domain, override)
    return tuple(sorted(selected_by_domain.values()))


def build_https_upstream_map_option(overrides: Sequence[HttpsUpstreamOverride]) -> str:
    return ";".join(f"{override.domain}={override.connect_host}" for override in overrides)


def parse_https_upstream_map(raw_value: str) -> dict[str, str]:
    mapping: dict[str, str] = {}
    for chunk in re.split(r"[;,]", raw_value):
        entry = chunk.strip()
        if not entry or "=" not in entry:
            continue
        domain, connect_host = entry.split("=", 1)
        normalized_domain = domain.strip().lower()
        normalized_host = connect_host.strip()
        if not normalized_domain or not normalized_host:
            continue
        try:
            ipaddress.ip_address(normalized_host)
        except ValueError:
            continue
        mapping[normalized_domain] = normalized_host
    return mapping


def split_ip_list(raw: str) -> tuple[str, ...]:
    out: list[str] = []
    for candidate in split_host_list(raw):
        if not candidate:
            continue
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            continue
        if candidate not in out:
            out.append(candidate)
    return tuple(out)


def extend_unique(target: list[str], values: Iterable[str]) -> None:
    seen = set(target)
    for value in values:
        if value in seen:
            continue
        target.append(value)
        seen.add(value)


def split_host_list(raw: str) -> tuple[str, ...]:
    hosts = []
    for value in raw.split(";"):
        candidate = value.strip().strip("`'\"")
        if candidate:
            hosts.append(candidate)
    return tuple(hosts)


def parse_login_logon_info(text: str) -> LoginLogonInfo | None:
    fragment = extract_logon_xml_fragment(text)
    if fragment is None:
        return None
    try:
        root = ET.fromstring(fragment)
    except ET.ParseError:
        return None

    host_text = (root.findtext("host") or "").strip()
    port_text = (root.findtext("port") or "").strip()
    if not host_text or not port_text:
        return None

    try:
        port = int(port_text)
    except ValueError:
        return None
    if not (1 <= port <= 65535):
        return None

    hosts = split_host_list(host_text)
    if not hosts:
        return None

    return LoginLogonInfo(
        hosts=hosts,
        port=port,
        region=_optional_xml_text(root, "region"),
        server=_optional_xml_text(root, "server"),
        userid=_optional_xml_text(root, "userid"),
        token=_optional_xml_text(root, "token"),
    )


def rewrite_login_logon_info(
    text: str,
    *,
    redirect_host: str,
    redirect_port: int,
    repeat_host_count: bool = True,
) -> LoginRewriteResult | None:
    if not redirect_host.strip():
        raise ValueError("redirect_host must not be empty")
    if not (1 <= redirect_port <= 65535):
        raise ValueError("redirect_port must be between 1 and 65535")

    fragment_match = LOGON_XML_RE.search(text)
    if not fragment_match:
        return None
    original = parse_login_logon_info(fragment_match.group(0))
    if original is None:
        return None

    try:
        root = ET.fromstring(fragment_match.group(0))
    except ET.ParseError:
        return None

    host_element = root.find("host")
    port_element = root.find("port")
    if host_element is None or port_element is None:
        return None

    redirected_hosts = build_redirect_host_list(
        redirect_host,
        original_count=len(original.hosts),
        repeat_host_count=repeat_host_count,
    )
    host_element.text = ";".join(redirected_hosts)
    port_element.text = str(redirect_port)
    rewritten_fragment = ET.tostring(root, encoding="unicode", method="xml")
    rewritten_text = text[:fragment_match.start()] + rewritten_fragment + text[fragment_match.end():]

    return LoginRewriteResult(
        text=rewritten_text,
        original=original,
        redirected_hosts=redirected_hosts,
        redirected_port=redirect_port,
    )


def build_redirect_host_list(
    redirect_host: str,
    *,
    original_count: int,
    repeat_host_count: bool,
) -> tuple[str, ...]:
    count = max(1, original_count if repeat_host_count else 1)
    return tuple(redirect_host for _ in range(count))


def extract_logon_xml_fragment(text: str) -> str | None:
    match = LOGON_XML_RE.search(text)
    if not match:
        return None
    return match.group(0)


def _optional_xml_text(root: ET.Element, tag: str) -> str | None:
    value = root.findtext(tag)
    if value is None:
        return None
    value = value.strip()
    return value or None


def domain_matches_suffixes(domain: str, suffixes: Sequence[str]) -> bool:
    normalized = domain.lower()
    return any(normalized == suffix or normalized.endswith(f".{suffix}") for suffix in suffixes)


def build_tcp_hosts_regex(hosts: Sequence[str], port: int | None) -> str | None:
    normalized = [host.strip() for host in hosts if host.strip()]
    if not normalized:
        return None
    host_group = "|".join(re.escape(host) for host in normalized)
    if port is not None:
        return rf"^(?:{host_group})(?::{port})?$"
    return rf"^(?:{host_group})(?::\d+)?$"


def update_hosts_file(
    path: Path,
    target_ip: str,
    domains: Sequence[str],
    *,
    dry_run: bool = False,
) -> HostsUpdateResult:
    ordered_domains = tuple(sorted({domain.lower() for domain in domains if domain.strip()}))
    entries = tuple(f"{target_ip} {domain}" for domain in ordered_domains)
    block = render_hosts_block(entries)

    existing = ""
    if path.exists():
        existing = path.read_text(encoding="utf-8", errors="ignore")
    updated_text = replace_hosts_block(existing, block)
    changed = updated_text != existing
    backup_path: Path | None = None

    if changed and not dry_run:
        if path.exists():
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_path = path.with_name(f"{path.name}.rf4_monitor.{timestamp}.bak")
            shutil.copy2(path, backup_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(updated_text, encoding="utf-8")

    return HostsUpdateResult(
        path=path,
        backup_path=backup_path,
        entries=entries,
        updated=changed,
    )


def render_hosts_block(entries: Sequence[str]) -> str:
    return "\n".join([HOSTS_BLOCK_BEGIN, *entries, HOSTS_BLOCK_END])


def replace_hosts_block(existing_text: str, block: str) -> str:
    normalized = existing_text.rstrip("\n")
    lines = normalized.splitlines() if normalized else []

    output: list[str] = []
    in_block = False
    for line in lines:
        stripped = line.strip()
        if stripped in HOSTS_BLOCK_BEGIN_MARKERS:
            in_block = True
            continue
        if stripped in HOSTS_BLOCK_END_MARKERS:
            in_block = False
            continue
        if not in_block:
            output.append(line)

    while output and output[-1] == "":
        output.pop()
    if output:
        output.append("")
    output.extend(block.splitlines())
    return "\n".join(output) + "\n"


def remove_hosts_block(path: Path) -> bool:
    if not path.exists():
        return False
    existing = path.read_text(encoding="utf-8", errors="ignore")
    normalized = existing.rstrip("\n")
    lines = normalized.splitlines() if normalized else []

    output: list[str] = []
    in_block = False
    found = False
    for line in lines:
        stripped = line.strip()
        if stripped in HOSTS_BLOCK_BEGIN_MARKERS:
            in_block = True
            found = True
            continue
        if stripped in HOSTS_BLOCK_END_MARKERS:
            in_block = False
            continue
        if not in_block:
            output.append(line)

    while output and output[-1] == "":
        output.pop()
    updated_text = "\n".join(output) + "\n" if output else ""
    if not found or updated_text == existing:
        return False
    path.write_text(updated_text, encoding="utf-8")
    return True


def restore_hosts_on_exit(hosts_result) -> None:
    if hosts_result is None:
        return
    if not getattr(hosts_result, "updated", False):
        return
    try:
        removed = remove_hosts_block(hosts_result.path)
    except OSError:
        print(
            f"[rf4-monitor-runner] warning: failed to restore hosts file {hosts_result.path}. "
            f"Original backup is at {hosts_result.backup_path}",
            file=sys.stderr,
        )
    else:
        if removed:
            print(f"[rf4-monitor-runner] restored hosts file {hosts_result.path}")


def generate_self_signed_certificate(
    cert_dir: Path,
    domains: Sequence[str],
    *,
    common_name: str | None = None,
    days: int = 3650,
    force: bool = False,
) -> GeneratedCertificate:
    normalized_domains = tuple(sorted({domain for domain in domains if domain.strip()}))
    if not normalized_domains:
        raise ValueError("cannot generate a certificate without at least one domain")

    cert_dir.mkdir(parents=True, exist_ok=True)
    key_path = cert_dir / "rf4_monitor.key"
    cert_path = cert_dir / "rf4_monitor.crt"
    pem_path = cert_dir / "rf4_monitor.pem"
    final_common_name = common_name or normalized_domains[0]

    if force or not (key_path.exists() and cert_path.exists() and pem_path.exists()):
        openssl = shutil.which("openssl")
        if not openssl:
            raise FileNotFoundError("openssl executable not found in PATH")
        san_value = ",".join(f"DNS:{domain}" for domain in normalized_domains)
        command = [
            openssl,
            "req",
            "-x509",
            "-sha256",
            "-nodes",
            "-newkey",
            "rsa:2048",
            "-days",
            str(days),
            "-subj",
            f"/CN={final_common_name}",
            "-addext",
            f"subjectAltName={san_value}",
            "-keyout",
            str(key_path),
            "-out",
            str(cert_path),
        ]
        result = subprocess.run(command, capture_output=True, text=True)
        if result.returncode != 0:
            stderr = result.stderr.strip() or result.stdout.strip()
            raise RuntimeError(f"openssl certificate generation failed: {stderr}")
        pem_path.write_text(
            key_path.read_text(encoding="utf-8") + cert_path.read_text(encoding="utf-8"),
            encoding="utf-8",
        )

    return GeneratedCertificate(
        cert_path=cert_path,
        key_path=key_path,
        pem_path=pem_path,
        common_name=final_common_name,
        domains=normalized_domains,
    )


def quote_command(args: Sequence[str]) -> str:
    if os.name == "nt":
        return subprocess.list2cmdline(list(args))
    return shlex.join(list(args))


def parse_args(argv: list[str]) -> tuple[argparse.Namespace, list[str]]:
    parser = argparse.ArgumentParser(
        description="Run RF4 Monitor as a single entrypoint. By default the launcher auto-updates hosts, prepares certs, rewrites login realtime targets, and starts mitmdump."
    )
    parser.add_argument(
        "--reference-path",
        action="append",
        dest="reference_paths",
        help="File or directory used to extract RF4 domains and realtime hosts. Defaults to the repo 数据包 directory.",
    )
    parser.add_argument(
        "--include-all-domains",
        action="store_true",
        help="Do not filter extracted domains to RF4-owned suffixes.",
    )
    parser.add_argument(
        "--apply-hosts",
        action="store_true",
        help="Compatibility flag. Hosts update is enabled by default; use --skip-hosts to disable it.",
    )
    parser.add_argument(
        "--hosts-file",
        default=str(default_hosts_path()),
        help="Hosts file path to update. Defaults to the current OS hosts path.",
    )
    parser.add_argument(
        "--hosts-target",
        default="127.0.0.1",
        help="IP address written for each extracted domain when --apply-hosts is enabled.",
    )
    parser.add_argument(
        "--hosts-dry-run",
        action="store_true",
        help="Preview the hosts block without writing it to disk.",
    )
    parser.add_argument(
        "--update-hosts-only",
        action="store_true",
        help="Only update the managed hosts block and exit without preparing certs or starting mitmdump.",
    )
    parser.add_argument(
        "--generate-cert",
        action="store_true",
        help="Compatibility flag. Certificate preparation is enabled by default; use --skip-cert to disable it.",
    )
    parser.add_argument(
        "--cert-dir",
        default=str(THIS_DIR / "certs"),
        help="Output directory for the generated certificate bundle.",
    )
    parser.add_argument(
        "--cert-common-name",
        default="",
        help="Override the certificate common name. Defaults to the first extracted domain.",
    )
    parser.add_argument(
        "--cert-days",
        type=int,
        default=3650,
        help="Certificate validity period in days.",
    )
    parser.add_argument(
        "--force-cert",
        action="store_true",
        help="Regenerate the certificate even if the files already exist.",
    )
    parser.add_argument(
        "--skip-hosts",
        action="store_true",
        help="Do not update the hosts file automatically.",
    )
    parser.add_argument(
        "--skip-cert",
        action="store_true",
        help="Do not prepare the self-signed certificate automatically.",
    )
    parser.add_argument(
        "--prepare-only",
        action="store_true",
        help="Prepare hosts/certs and print the mitmdump command without starting it.",
    )
    parser.add_argument(
        "--print-command-only",
        action="store_true",
        help="Alias for --prepare-only that only prints the final command and exits.",
    )
    parser.add_argument(
        "--no-auto-tcp-hosts",
        action="store_true",
        help="Do not derive --tcp-hosts from the reference realtime server list.",
    )
    parser.add_argument(
        "--no-auto-reverse-modes",
        action="store_true",
        help="Do not derive reverse listener modes from extracted RF4 domains.",
    )
    parser.add_argument(
        "--no-auto-realtime-mode",
        action="store_true",
        help="Do not derive a reverse TCP listener for the realtime game socket.",
    )
    parser.add_argument(
        "--no-auto-login-rewrite",
        action="store_true",
        help="Do not inject realtime host/port rewrite options into the mitm addon.",
    )
    parser.add_argument(
        "--realtime-listen-host",
        default="127.0.0.1",
        help="Host value written back into the login logon response for the realtime socket.",
    )
    parser.add_argument(
        "--realtime-listen-port",
        type=int,
        default=0,
        help="Local port written back into the login logon response. Defaults to the extracted realtime port.",
    )
    parser.add_argument(
        "--realtime-upstream-host",
        default="",
        help="Override the realtime upstream host used by the reverse TCP listener.",
    )
    parser.add_argument(
        "--realtime-upstream-port",
        type=int,
        default=0,
        help="Override the realtime upstream port used by the reverse TCP listener.",
    )
    parser.add_argument(
        "--no-auto-verbose",
        action="store_true",
        help="Do not append the default parser-visible logging options.",
    )
    parser.add_argument(
        "--mitmdump-bin",
        default="",
        help="Path to the mitmdump executable. Defaults to tools/rf4_monitor/.venv/bin/mitmdump when available, otherwise PATH.",
    )
    parser.add_argument(
        "--mode",
        choices=("proxy", "passive"),
        default="proxy",
        help="proxy=MITM 代理(默认，可改包注入)；passive=旁路抓包监听(纯只读，不改 hosts/证书)。",
    )
    return parser.parse_known_args(argv)


def _run_passive_mode(reference: ReferenceTrafficInfo, passthrough: list[str]) -> int:
    """旁路监听模式：启动 RF4Sniffer 引擎（纯只读抓包）。

    不写 hosts、不伪造证书、不启动 mitmdump。打包态下以 RF4_SNIFFER_MODE=1
    复用同一个 exe；源码态直接 import 运行 passive_engine。
    """
    print("[rf4-monitor-runner] 旁路监听模式：纯只读抓包，不劫持不注入。")
    print(f"[rf4-monitor-runner] realtime 参考: {', '.join(reference.realtime_hosts)}:{reference.realtime_port}")

    # 透传 --set 选项给 passive_engine
    option_args: list[str] = []
    index = 0
    while index < len(passthrough):
        arg = passthrough[index]
        if arg == "--set" and index + 1 < len(passthrough):
            option_args.extend(["--set", passthrough[index + 1]])
            index += 2
        else:
            index += 1

    if getattr(sys, "frozen", False):
        command = [sys.executable, *option_args]
        process_env = dict(os.environ)
        process_env["PYTHONUNBUFFERED"] = "1"
        process_env["RF4_SNIFFER_MODE"] = "1"
    else:
        command = [sys.executable, "-m", "rf4_core.passive_engine", *option_args]
        process_env = dict(os.environ)
        # 源码态下 python 默认块缓冲，日志积压不落盘；强制 unbuffered。
        process_env["PYTHONUNBUFFERED"] = "1"

    creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    log_file = None
    if creationflags:
        log_dir = THIS_DIR / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        log_path = log_dir / "rf4_sniffer.log"
        log_file = log_path.open("w", encoding="utf-8")
        print(f"[rf4-monitor-runner] sniffer output is written to {log_file.name}")

    print(f"[rf4-monitor-runner] command: {quote_command(command)}")
    try:
        process = subprocess.Popen(
            command,
            creationflags=creationflags,
            stdout=log_file,
            stderr=log_file if log_file is not None else None,
            env=process_env,
        )
    except OSError as exc:
        print(f"[rf4-monitor-runner] error: failed to start sniffer: {exc}", file=sys.stderr)
        return 2
    try:
        process.wait()
    except KeyboardInterrupt:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
    return process.returncode if process.returncode is not None else 0


def main(argv: list[str] | None = None) -> int:
    args, passthrough = parse_args(list(sys.argv[1:] if argv is None else argv))
    reference_paths = resolve_reference_paths(args.reference_paths)
    reference = extract_reference_info(reference_paths, include_all_domains=args.include_all_domains)
    selected_reverse_targets = select_reverse_targets(reference.reverse_targets)
    managed_domains = managed_proxy_domains(reference.domains, reference.reverse_targets)
    if args.update_hosts_only and not managed_domains:
        print("[rf4-monitor-runner] error: no RF4 domains were found in the reference paths.", file=sys.stderr)
        return 2
    auto_apply_hosts = not args.skip_hosts
    auto_generate_cert = not args.skip_cert
    hosts_result = None

    selected_https_upstream_overrides = select_https_upstream_overrides(
        reference.https_upstream_overrides,
        selected_reverse_targets,
    )
    print_reference_summary(
        reference,
        selected_reverse_targets=selected_reverse_targets,
        selected_https_upstream_overrides=selected_https_upstream_overrides,
    )

    # 旁路监听模式：纯只读抓包，不写 hosts、不伪造证书、不启动 mitmdump。
    if args.mode == "passive":
        return _run_passive_mode(reference, passthrough)

    if auto_apply_hosts or args.apply_hosts or args.hosts_dry_run:
        try:
            hosts_result = update_hosts_file(
                Path(args.hosts_file).expanduser(),
                args.hosts_target,
                managed_domains,
                dry_run=args.hosts_dry_run,
            )
        except OSError as exc:
            if args.apply_hosts:
                print(
                    f"[rf4-monitor-runner] error: failed to update hosts file {args.hosts_file}: {exc}",
                    file=sys.stderr,
                )
                return 2
            print(
                f"[rf4-monitor-runner] warning: failed to auto-update hosts file {args.hosts_file}: {exc}. "
                "Continue only if the RF4 domains are already mapped to the local machine, or rerun with elevated privileges.",
                file=sys.stderr,
            )
        else:
            print_hosts_summary(hosts_result, dry_run=args.hosts_dry_run)
            if args.update_hosts_only:
                return 0

    certificate = None
    if auto_generate_cert or args.generate_cert:
        try:
            certificate = generate_self_signed_certificate(
                Path(args.cert_dir).expanduser(),
                managed_domains,
                common_name=args.cert_common_name or None,
                days=args.cert_days,
                force=args.force_cert,
            )
        except (FileNotFoundError, OSError, RuntimeError, ValueError) as exc:
            if args.generate_cert:
                print(f"[rf4-monitor-runner] error: failed to prepare certificate: {exc}", file=sys.stderr)
                return 2
            print(
                f"[rf4-monitor-runner] warning: failed to auto-prepare certificate: {exc}. "
                "HTTPS login interception may fail unless a usable certificate is already configured.",
                file=sys.stderr,
            )
        else:
            print_certificate_summary(certificate)

    command = build_mitmdump_command(
        reference,
        passthrough,
        certificate,
        auto_verbose=not args.no_auto_verbose,
        auto_tcp_hosts=not args.no_auto_tcp_hosts,
        auto_reverse_modes=not args.no_auto_reverse_modes,
        auto_realtime_mode=not args.no_auto_realtime_mode,
        auto_login_rewrite=not args.no_auto_login_rewrite,
        realtime_listen_host=args.realtime_listen_host,
        realtime_listen_port=args.realtime_listen_port,
        realtime_upstream_host=args.realtime_upstream_host,
        realtime_upstream_port=args.realtime_upstream_port,
    )
    command[0] = resolve_mitmdump_binary(args.mitmdump_bin)
    print(f"[rf4-monitor-runner] command: {quote_command(command)}")

    if args.prepare_only or args.print_command_only:
        return 0

    if not mitmdump_binary_exists(command[0]):
        print(
            f"[rf4-monitor-runner] error: '{command[0]}' was not found in PATH. "
            "Install mitmproxy first, or use the bundled tools/rf4_monitor/.venv environment.",
            file=sys.stderr,
        )
        return 2

    log_file = None
    creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    if creationflags:
        log_dir = THIS_DIR / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        log_path = log_dir / "rf4_monitor.log"
        log_file = log_path.open("w", encoding="utf-8")
        print(f"[rf4-monitor-runner] mitmdump output is written to {log_file.name}")

    try:
        try:
            process_env = dict(os.environ)
            # mitmproxy 10 在非 TTY(无窗口)环境下 stdout 会块缓冲，日志积压在缓冲区
            # 不落盘；设置 PYTHONUNBUFFERED 让 mitmdump 的每行日志即时写入文件。
            process_env["PYTHONUNBUFFERED"] = "1"
            # 打包态下：由同一个 exe 扮演 mitmdump 引擎（见打包入口 frozen_entry），
            # 用它自身吸收 --rf4-engine 标志后来到 DumpMaster 引擎分支。
            if getattr(sys, "frozen", False):
                process_env["RF4_ENGINE_MODE"] = "1"
            process = subprocess.Popen(
                command,
                creationflags=creationflags,
                stdout=log_file,
                stderr=log_file if log_file is not None else None,
                env=process_env,
            )
        except OSError:
            if log_file is not None:
                log_file.close()
                log_file = None
            raise

        # 若由 RF4Tray 启动，托盘退出时自动终止本进程链，避免残留 RF4Monitor/Overlay。
        parent_pid = _watchdog_parent_pid()
        watchdog = None
        if parent_pid is not None:
            watchdog = _spawn_parent_watchdog(parent_pid, process)

        try:
            return process.wait()
        except KeyboardInterrupt:
            if watchdog is not None:
                _stop_watchdog(watchdog)
            process.terminate()
            try:
                return process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                return process.wait()
    finally:
        if log_file is not None:
            log_file.close()
            log_file = None
        restore_hosts_on_exit(hosts_result)


RF4_WATCHDOG_PARENT_ENV = "RF4_TRAY_PARENT_PID"


def _watchdog_parent_pid() -> int | None:
    """读取由托盘传入的父进程(托盘) PID；未设置则返回 None(不启用守护)。"""
    raw = os.environ.get(RF4_WATCHDOG_PARENT_ENV, "").strip()
    return int(raw) if raw.isdigit() else None


def _pid_alive(pid: int) -> bool:
    """探测指定 PID 进程是否存活(只读，无需提权)。"""
    kernel32 = ctypes.windll.kernel32
    process = kernel32.OpenProcess(0x1000, False, int(pid))  # PROCESS_QUERY_LIMITED_INFORMATION
    if not process:
        return False
    try:
        status = ctypes.c_ulong()
        kernel32.GetExitCodeProcess(process, ctypes.byref(status))
        return status.value == 259  # STILL_ACTIVE
    finally:
        kernel32.CloseHandle(process)


def _spawn_parent_watchdog(parent_pid: int, engine: subprocess.Popen) -> threading.Thread:
    """启动守护线程：轮询父托盘进程，若其已退出则终止引擎进程链。"""
    stop_event = threading.Event()

    def watch() -> None:
        interval = 1.0
        while not stop_event.wait(interval):
            if not _pid_alive(parent_pid):
                _terminate_engine_tree(engine)
                break

    thread = threading.Thread(target=watch, name="rf4-parent-watchdog", daemon=True)
    thread.start()
    thread.stop_event = stop_event  # type: ignore[attr-defined]
    return thread


def _terminate_engine_tree(engine: subprocess.Popen) -> None:
    try:
        children = _find_children(engine.pid)
        for child in children:
            _terminate_pid_tree(child)
        try:
            engine.kill()
        except Exception:
            pass
    except Exception:
        pass


def _stop_watchdog(thread: threading.Thread) -> None:
    stop_event = getattr(thread, "stop_event", None)
    if stop_event is not None:
        stop_event.set()


def _find_children(parent_pid: int) -> list[int]:
    pids: list[int] = []
    try:
        out = subprocess.check_output(
            [
                "wmic",
                "process",
                "where",
                f"(ParentProcessId={parent_pid})",
                "get",
                "ProcessId",
            ],
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            text=True,
        )
        for line in out.splitlines():
            line = line.strip()
            if line.isdigit() and int(line) != parent_pid:
                pids.append(int(line))
    except Exception:
        pass
    return pids


def _terminate_pid_tree(pid: int) -> None:
    children = _find_children(pid)
    for child in children:
        _terminate_pid_tree(child)
    try:
        subprocess.run(
            ["taskkill", "/PID", str(pid), "/T", "/F"],
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            capture_output=True,
            timeout=10,
        )
    except Exception:
        pass


def resolve_reference_paths(raw_paths: list[str] | None) -> list[Path]:
    if raw_paths:
        return [Path(value).expanduser() for value in raw_paths]
    default_paths = default_reference_paths(REPO_ROOT)
    if any(path.expanduser().exists() for path in default_paths):
        return default_paths
    if BUNDLED_REFERENCE_PATH.exists():
        return [BUNDLED_REFERENCE_PATH]
    return default_paths


def resolve_mitmdump_binary(raw_value: str, *, base_dir: Path = THIS_DIR) -> str:
    if raw_value.strip():
        return str(Path(raw_value).expanduser())

    # 打包态：同一个 exe 就是 mitmdump 引擎（frozen_entry 通过 RF4_ENGINE_MODE 区分）。
    if getattr(sys, "frozen", False):
        return str(Path(sys.executable).resolve())

    bundled_candidates = (
        base_dir / ".venv" / "bin" / "mitmdump",
        base_dir / ".venv" / "Scripts" / "mitmdump.exe",
        base_dir / ".venv" / "Scripts" / "mitmdump",
    )
    for candidate in bundled_candidates:
        if candidate.exists():
            return str(candidate)

    try:
        import sysconfig

        scripts_dir = sysconfig.get_path("scripts")
        if scripts_dir:
            for candidate in (
                Path(scripts_dir) / "mitmdump.exe",
                Path(scripts_dir) / "mitmdump",
            ):
                if candidate.exists():
                    return str(candidate)
    except Exception:
        pass

    detected = shutil.which("mitmdump")
    return detected or "mitmdump"


def mitmdump_binary_exists(raw_value: str) -> bool:
    candidate = Path(raw_value).expanduser()
    if candidate.exists():
        return True
    return shutil.which(raw_value) is not None


def print_reference_summary(
    reference: ReferenceTrafficInfo,
    *,
    selected_reverse_targets: Sequence[ReverseProxyTarget],
    selected_https_upstream_overrides: Sequence[HttpsUpstreamOverride],
) -> None:
    print(f"[rf4-monitor-runner] scanned {len(reference.source_files)} reference file(s)")
    if reference.domains:
        print(f"[rf4-monitor-runner] extracted domains: {', '.join(reference.domains)}")
    else:
        print("[rf4-monitor-runner] extracted domains: <none>")
    if reference.realtime_hosts:
        port_text = reference.realtime_port if reference.realtime_port is not None else "unknown"
        print(
            f"[rf4-monitor-runner] extracted realtime hosts: {', '.join(reference.realtime_hosts)} "
            f"(port={port_text})"
        )
    else:
        print("[rf4-monitor-runner] extracted realtime hosts: <none>")
    if reference.reverse_targets:
        print(
            "[rf4-monitor-runner] extracted reverse targets: "
            + ", ".join(target.mode_spec() for target in reference.reverse_targets)
        )
    else:
        print("[rf4-monitor-runner] extracted reverse targets: <none>")
    if reference.https_upstream_overrides:
        print(
            "[rf4-monitor-runner] extracted https upstreams: "
            + ", ".join(
                f"{override.domain}:{override.port} -> {override.connect_host}:{override.port}"
                for override in reference.https_upstream_overrides
            )
        )
    else:
        print("[rf4-monitor-runner] extracted https upstreams: <none>")
    if selected_reverse_targets:
        print(
            "[rf4-monitor-runner] active reverse targets: "
            + ", ".join(target.mode_spec() for target in selected_reverse_targets)
        )
    else:
        print("[rf4-monitor-runner] active reverse targets: <none>")
    if selected_https_upstream_overrides:
        print(
            "[rf4-monitor-runner] active https upstreams: "
            + ", ".join(
                f"{override.domain}:{override.port} -> {override.connect_host}:{override.port}"
                for override in selected_https_upstream_overrides
            )
        )
    else:
        print("[rf4-monitor-runner] active https upstreams: <none>")
    dropped_targets = [target for target in reference.reverse_targets if target not in selected_reverse_targets]
    for target in dropped_targets:
        print(
            "[rf4-monitor-runner] skipped reverse target due to listen-port conflict: "
            f"{target.mode_spec()}"
        )


def print_hosts_summary(result: HostsUpdateResult, *, dry_run: bool) -> None:
    mode = "preview" if dry_run else "updated"
    print(f"[rf4-monitor-runner] hosts {mode}: {result.path}")
    if result.backup_path is not None:
        print(f"[rf4-monitor-runner] hosts backup: {result.backup_path}")
    if result.entries:
        print(f"[rf4-monitor-runner] hosts entries: {', '.join(result.entries)}")
    else:
        print("[rf4-monitor-runner] hosts entries: <none>")


def print_certificate_summary(certificate: GeneratedCertificate) -> None:
    print(
        f"[rf4-monitor-runner] certificate ready: cn={certificate.common_name} "
        f"pem={certificate.pem_path} domains={', '.join(certificate.domains)}"
    )


def build_mitmdump_command(
    reference: ReferenceTrafficInfo,
    passthrough: list[str],
    certificate: GeneratedCertificate | None,
    *,
    auto_verbose: bool,
    auto_tcp_hosts: bool,
    auto_reverse_modes: bool,
    auto_realtime_mode: bool,
    auto_login_rewrite: bool,
    realtime_listen_host: str,
    realtime_listen_port: int,
    realtime_upstream_host: str,
    realtime_upstream_port: int,
) -> list[str]:
    script = THIS_DIR / "rf4_monitor.py"
    command: list[str] = ["mitmdump", "-s", str(script)]
    command.extend(passthrough)
    selected_reverse_targets = select_reverse_targets(reference.reverse_targets)
    selected_https_upstream_overrides = select_https_upstream_overrides(
        reference.https_upstream_overrides,
        selected_reverse_targets,
    )

    if auto_reverse_modes and not has_flag(command, "--mode"):
        for target in selected_reverse_targets:
            command.extend(["--mode", target.mode_spec()])

    selected_realtime_host = realtime_upstream_host.strip() or (reference.realtime_hosts[0] if reference.realtime_hosts else "")
    selected_realtime_port = realtime_upstream_port or reference.realtime_port or 0
    selected_listen_port = realtime_listen_port or selected_realtime_port

    if (
        auto_realtime_mode
        and selected_realtime_host
        and selected_realtime_port
        and selected_listen_port
        and not has_mode_prefix(command, "reverse:tcp://")
    ):
        command.extend(
            [
                "--mode",
                f"reverse:tcp://{selected_realtime_host}:{selected_realtime_port}@{selected_listen_port}",
            ]
        )

    if auto_verbose:
        command = ensure_option_set(command, "flow_detail=0")
        command = ensure_option_set(command, "rf4_log_parsed_events=true")
        command = ensure_option_set(command, "rf4_verbose_logging=true")

    if selected_https_upstream_overrides:
        command = ensure_option_set(command, "keep_host_header=true")
        command = ensure_option_set(
            command,
            f"rf4_https_upstream_map={build_https_upstream_map_option(selected_https_upstream_overrides)}",
        )

    if auto_login_rewrite and selected_listen_port:
        command = ensure_option_set(command, "rf4_enable_login_rewrite=true")
        command = ensure_option_set(command, f"rf4_realtime_redirect_host={realtime_listen_host}")
        command = ensure_option_set(command, f"rf4_realtime_redirect_port={selected_listen_port}")

    if auto_tcp_hosts and not has_flag(command, "--tcp-hosts"):
        tcp_hosts = None if reference.realtime_hosts == () else build_tcp_hosts_regex(reference.realtime_hosts, reference.realtime_port)
        if tcp_hosts:
            command.extend(["--tcp-hosts", tcp_hosts])

    if certificate is not None and not has_flag(command, "--certs"):
        for domain in certificate.domains:
            command.extend(["--certs", f"{domain}={certificate.pem_path}"])

    return command


def has_flag(args: list[str], flag: str) -> bool:
    return any(value == flag or value.startswith(f"{flag}=") for value in args)


def has_mode_prefix(args: list[str], mode_prefix: str) -> bool:
    for index, value in enumerate(args):
        if value != "--mode" or index + 1 >= len(args):
            continue
        if args[index + 1].startswith(mode_prefix):
            return True
    return False


def ensure_option_set(args: list[str], option_value: str) -> list[str]:
    target_key = option_value.split("=", 1)[0]
    for index, value in enumerate(args):
        if value != "--set" or index + 1 >= len(args):
            continue
        if args[index + 1].split("=", 1)[0] == target_key:
            return args
    return [*args, "--set", option_value]

# --- Protocol profile ---
