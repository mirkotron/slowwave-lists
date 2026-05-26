#!/usr/bin/env python3
"""
SlowWave blocklist builder.

Reads policy.yaml. For each age tier, fetches the union of category sources,
parses them into a normalized domain set, collapses redundant subdomains,
and writes a per-tier dnsmasq-format blocklist.

Usage:
    python3 build_blocklist.py                  # build all tiers
    python3 build_blocklist.py --tier tier3_10_to_12
    python3 build_blocklist.py --dry-run        # report only, no write
    python3 build_blocklist.py --force          # ignore cache, refetch all
    python3 build_blocklist.py --verify         # check upstream availability

Cron suggestion:
    7 */6 * * * /usr/bin/python3 /etc/slowwave/build_blocklist.py >> /var/log/slowwave/build.log 2>&1

Requires: Python 3.9+, requests, pyyaml
    pip install --break-system-packages requests pyyaml
"""

import argparse
import hashlib
import json
import logging
import os
import re
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable
from urllib.parse import urlparse

try:
    import requests
    import yaml
except ImportError as exc:
    sys.stderr.write(f"missing dependency: {exc}. Install with:\n")
    sys.stderr.write("  pip install --break-system-packages requests pyyaml\n")
    sys.exit(1)


# ---------------------------------------------------------------------------
# Config + logging
# ---------------------------------------------------------------------------

SCRIPT_DIR = Path(__file__).resolve().parent
POLICY_FILE = SCRIPT_DIR / "policy.yaml"
DEFAULT_USER_AGENT = "SlowWave-BlocklistBuilder/1.0 (+https://slowwave.example/contact)"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("slowwave-blocklist")


# ---------------------------------------------------------------------------
# Domain validation
# ---------------------------------------------------------------------------

# RFC 1035 + practical: lowercased, length <= 253, labels <= 63, alnum + hyphen
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)


def normalize_domain(d: str) -> str | None:
    """Lowercase, strip, validate. Returns None for invalid entries."""
    d = d.strip().lower().rstrip(".")
    if not d:
        return None
    # Strip common prefixes that show up in lists but mean the same domain
    for prefix in ("www.", "m.", "mobile."):
        if d.startswith(prefix):
            d = d[len(prefix):]
            break
    if not _DOMAIN_RE.match(d):
        return None
    # Common junk
    if d in {"localhost", "broadcasthost", "local"}:
        return None
    return d


# ---------------------------------------------------------------------------
# Source format parsers
# ---------------------------------------------------------------------------

def _strip_comment(line: str) -> str:
    """Remove inline # comments while preserving the leading text."""
    for marker in ("#", "!"):
        idx = line.find(marker)
        if idx >= 0:
            line = line[:idx]
    return line.strip()


def parse_domains(text: str) -> set[str]:
    """One bare domain per line. Comments via # or !."""
    out: set[str] = set()
    for raw in text.splitlines():
        line = _strip_comment(raw)
        if not line:
            continue
        # Some "domain" lists actually contain wildcards or hosts entries
        # (e.g. OISD domainswild2). Best-effort tolerate.
        if line.startswith("*."):
            line = line[2:]
        if " " in line or "\t" in line:
            # Probably hosts format
            parts = line.split()
            line = parts[-1]
        d = normalize_domain(line)
        if d:
            out.add(d)
    return out


def parse_hosts(text: str) -> set[str]:
    """Hosts file format: `0.0.0.0 domain.com` or `127.0.0.1 domain.com`."""
    out: set[str] = set()
    for raw in text.splitlines():
        line = _strip_comment(raw)
        if not line:
            continue
        parts = line.split()
        if len(parts) < 2:
            # Tolerate plain-domain lines mixed in
            d = normalize_domain(parts[0]) if parts else None
            if d:
                out.add(d)
            continue
        # First field is the IP, take everything after
        for field_ in parts[1:]:
            d = normalize_domain(field_)
            if d:
                out.add(d)
    return out


_ABP_RULE_RE = re.compile(r"^\|\|([a-z0-9.-]+)\^")


def parse_adblock(text: str) -> set[str]:
    """ABP / EasyList format. Extracts ||domain^ rules; ignores cosmetic/CSS."""
    out: set[str] = set()
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("!", "[")):
            continue
        # Skip element-hiding rules (## and #@#) and exception rules (@@)
        if "##" in line or line.startswith("@@"):
            continue
        m = _ABP_RULE_RE.match(line.lower())
        if not m:
            continue
        # Strip $third-party, $domain= modifiers - we don't honor them at DNS
        domain_part = m.group(1)
        d = normalize_domain(domain_part)
        if d:
            out.add(d)
    return out


def parse_safesearch_rewrites(text: str) -> list[tuple[str, str]]:
    """
    Parse HaGeZi safesearch list - returns (from_domain, to_domain) pairs
    for dnsmasq cname= lines.
    """
    rewrites: list[tuple[str, str]] = []
    # HaGeZi format example:
    #   www.google.com forcesafesearch.google.com
    # Or in some lists: hosts-style with the rewrite target as the "IP"
    for raw in text.splitlines():
        line = _strip_comment(raw)
        if not line:
            continue
        parts = line.split()
        if len(parts) != 2:
            continue
        src = normalize_domain(parts[0])
        dst = normalize_domain(parts[1])
        if src and dst:
            rewrites.append((src, dst))
    return rewrites


PARSERS = {
    "domains": parse_domains,
    "hosts": parse_hosts,
    "adblock": parse_adblock,
    "safesearch_rewrites": parse_safesearch_rewrites,
}


# ---------------------------------------------------------------------------
# Fetcher with cache (Etag + Last-Modified conditional GET)
# ---------------------------------------------------------------------------

@dataclass
class CachedFetch:
    cache_dir: Path
    timeout: int = 30
    user_agent: str = DEFAULT_USER_AGENT

    def _cache_path(self, url: str) -> tuple[Path, Path]:
        key = hashlib.sha256(url.encode()).hexdigest()[:24]
        return (
            self.cache_dir / f"{key}.body",
            self.cache_dir / f"{key}.meta.json",
        )

    def fetch(self, url: str, force: bool = False) -> tuple[str, bool]:
        """
        Returns (body_text, was_modified). Uses Etag/Last-Modified.
        """
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        body_path, meta_path = self._cache_path(url)

        headers = {"User-Agent": self.user_agent}
        if not force and meta_path.exists() and body_path.exists():
            try:
                meta = json.loads(meta_path.read_text())
                if meta.get("etag"):
                    headers["If-None-Match"] = meta["etag"]
                if meta.get("last_modified"):
                    headers["If-Modified-Since"] = meta["last_modified"]
            except (json.JSONDecodeError, OSError):
                pass

        log.debug("fetching %s", url)
        try:
            resp = requests.get(url, headers=headers, timeout=self.timeout)
        except requests.RequestException as exc:
            log.warning("fetch failed %s: %s", url, exc)
            if body_path.exists():
                log.info("  using cached copy")
                return body_path.read_text(errors="replace"), False
            return "", False

        if resp.status_code == 304:
            log.info("not modified: %s", url)
            return body_path.read_text(errors="replace"), False

        if resp.status_code != 200:
            log.warning("HTTP %d from %s", resp.status_code, url)
            if body_path.exists():
                return body_path.read_text(errors="replace"), False
            return "", False

        body = resp.text
        body_path.write_text(body)
        meta = {
            "url": url,
            "etag": resp.headers.get("ETag"),
            "last_modified": resp.headers.get("Last-Modified"),
            "fetched_at": time.time(),
            "bytes": len(body),
        }
        meta_path.write_text(json.dumps(meta))
        log.info("fetched %s (%d bytes)", url, len(body))
        return body, True


# ---------------------------------------------------------------------------
# Source resolution
# ---------------------------------------------------------------------------

@dataclass
class Source:
    url: str | None
    file: str | None
    format: str
    raw_text: str = ""

    def load(self, fetcher: CachedFetch, force: bool) -> str:
        if self.file:
            p = SCRIPT_DIR / self.file
            if not p.exists():
                log.warning("missing local file: %s", p)
                return ""
            return p.read_text()
        if self.url:
            body, _ = fetcher.fetch(self.url, force=force)
            return body
        return ""


def load_category(cat_def: dict, fetcher: CachedFetch, force: bool):
    """
    Returns either set[str] of domains, or list[tuple[str,str]] of rewrites
    for the special safesearch case.
    """
    domains: set[str] = set()
    rewrites: list[tuple[str, str]] = []

    for src_def in cat_def.get("sources", []):
        src = Source(
            url=src_def.get("url"),
            file=src_def.get("file"),
            format=src_def.get("format", "domains"),
        )
        text = src.load(fetcher, force)
        if not text:
            continue

        parser = PARSERS.get(src.format)
        if not parser:
            log.warning("unknown format '%s' (skipping)", src.format)
            continue

        parsed = parser(text)
        if src.format == "safesearch_rewrites":
            rewrites.extend(parsed)
        else:
            domains.update(parsed)

    if rewrites:
        return rewrites
    return domains


# ---------------------------------------------------------------------------
# Subdomain collapse
# ---------------------------------------------------------------------------

def collapse_subdomains(domains: set[str]) -> set[str]:
    """
    If example.com is in the set, drop foo.example.com and a.b.example.com.
    Big space savings for dnsmasq. Operates in O(n log n) via sort.
    """
    if not domains:
        return domains
    # Sort by label count then lexicographic - parents come before children
    sorted_doms = sorted(domains, key=lambda d: (d.count("."), d))
    kept: set[str] = set()
    for d in sorted_doms:
        # If any suffix-match parent is already kept, skip
        labels = d.split(".")
        is_covered = False
        for i in range(1, len(labels) - 1):  # skip the bare TLD
            parent = ".".join(labels[i:])
            if parent in kept:
                is_covered = True
                break
        if not is_covered:
            kept.add(d)
    return kept


# ---------------------------------------------------------------------------
# Allowlist
# ---------------------------------------------------------------------------

def load_allowlist(paths: list[Path]) -> set[str]:
    out: set[str] = set()
    for p in paths:
        if not p or not p.exists():
            continue
        try:
            for raw in p.read_text().splitlines():
                d = normalize_domain(_strip_comment(raw))
                if d:
                    out.add(d)
        except OSError as exc:
            log.warning("could not read allowlist %s: %s", p, exc)
    return out


def apply_allowlist(domains: set[str], allow: set[str]) -> set[str]:
    """Remove any domain that is in the allowlist or is a subdomain thereof."""
    if not allow:
        return domains
    out: set[str] = set()
    for d in domains:
        skip = False
        labels = d.split(".")
        for i in range(len(labels) - 1):
            if ".".join(labels[i:]) in allow:
                skip = True
                break
        if not skip:
            out.add(d)
    return out


# ---------------------------------------------------------------------------
# Output writers
# ---------------------------------------------------------------------------

def write_dnsmasq(
    out_path: Path,
    domains: set[str],
    rewrites: list[tuple[str, str]],
    sinkhole: str,
    tier_name: str,
):
    """Atomic write: .tmp then rename."""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = out_path.with_suffix(out_path.suffix + ".tmp")
    with tmp.open("w") as f:
        f.write(f"# SlowWave blocklist - tier: {tier_name}\n")
        f.write(f"# Generated: {time.strftime('%Y-%m-%d %H:%M:%S %Z')}\n")
        f.write(f"# Domains: {len(domains)}\n")
        f.write(f"# Rewrites: {len(rewrites)}\n")
        f.write("# DO NOT EDIT - regenerate with build_blocklist.py\n\n")

        if sinkhole == "#":
            sink_directive = "address=/{}/#\n"
        else:
            sink_directive = f"address=/{{}}/{sinkhole}\n"

        for d in sorted(domains):
            f.write(sink_directive.format(d))

        if rewrites:
            f.write("\n# SafeSearch rewrites\n")
            for src, dst in sorted(rewrites):
                f.write(f"cname={src},{dst}\n")
    tmp.replace(out_path)
    log.info(
        "wrote %s (%d domains, %d rewrites)",
        out_path, len(domains), len(rewrites)
    )


def write_hosts(out_path: Path, domains: set[str], tier_name: str):
    out_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = out_path.with_suffix(out_path.suffix + ".tmp")
    with tmp.open("w") as f:
        f.write(f"# SlowWave blocklist (hosts format) - tier: {tier_name}\n")
        f.write(f"# Generated: {time.strftime('%Y-%m-%d %H:%M:%S %Z')}\n\n")
        for d in sorted(domains):
            f.write(f"0.0.0.0 {d}\n")
    tmp.replace(out_path)
    log.info("wrote %s (%d domains)", out_path, len(domains))


def write_plain(out_path: Path, domains: set[str], tier_name: str):
    out_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = out_path.with_suffix(out_path.suffix + ".tmp")
    with tmp.open("w") as f:
        f.write(f"# SlowWave blocklist - tier: {tier_name}\n")
        for d in sorted(domains):
            f.write(f"{d}\n")
    tmp.replace(out_path)
    log.info("wrote %s (%d domains)", out_path, len(domains))


# ---------------------------------------------------------------------------
# Build orchestration
# ---------------------------------------------------------------------------

def build(policy: dict, target_tier: str | None, force: bool, dry_run: bool):
    settings = policy.get("settings", {})
    output_dir = Path(settings.get("output_dir", "./output"))
    cache_dir = Path(settings.get("cache_dir", "./cache"))
    output_format = settings.get("output_format", "dnsmasq")
    sinkhole = settings.get("sinkhole", "#")
    collapse = bool(settings.get("collapse_subdomains", True))
    timeout = int(settings.get("fetch_timeout_seconds", 30))

    fetcher = CachedFetch(cache_dir=cache_dir, timeout=timeout)

    # Load all categories once - many tiers reuse them
    log.info("loading %d categories", len(policy.get("categories", {})))
    category_cache: dict[str, set | list] = {}
    for cat_name, cat_def in policy.get("categories", {}).items():
        log.info("category: %s", cat_name)
        category_cache[cat_name] = load_category(cat_def, fetcher, force)

    # Allowlist
    allow_paths = [
        SCRIPT_DIR / settings.get("allowlist_file", "allowlist.txt"),
    ]
    parent_allow = settings.get("parent_allowlist_file")
    if parent_allow:
        allow_paths.append(Path(parent_allow))
    allowlist = load_allowlist(allow_paths)
    if allowlist:
        log.info("allowlist: %d domains", len(allowlist))

    # Per-tier build
    for tier_name, tier_def in policy.get("tiers", {}).items():
        if target_tier and tier_name != target_tier:
            continue

        log.info("=" * 60)
        log.info("building tier: %s", tier_name)
        log.info("  %s", tier_def.get("description", ""))

        tier_domains: set[str] = set()
        tier_rewrites: list[tuple[str, str]] = []

        for cat_name in tier_def.get("categories", []):
            data = category_cache.get(cat_name)
            if data is None:
                log.warning("  unknown category in tier: %s", cat_name)
                continue
            if isinstance(data, list):
                tier_rewrites.extend(data)
                log.info("  + %-30s %5d rewrites", cat_name, len(data))
            else:
                before = len(tier_domains)
                tier_domains.update(data)
                added = len(tier_domains) - before
                log.info(
                    "  + %-30s %7d domains (+%d)",
                    cat_name, len(data), added
                )

        # Allowlist + collapse
        tier_domains = apply_allowlist(tier_domains, allowlist)
        pre_collapse = len(tier_domains)
        if collapse:
            tier_domains = collapse_subdomains(tier_domains)
            log.info(
                "  collapse: %d -> %d (saved %d entries)",
                pre_collapse, len(tier_domains),
                pre_collapse - len(tier_domains)
            )

        # Dedupe rewrites (multiple sources may normalize to same pair)
        tier_rewrites = sorted(set(tier_rewrites))

        log.info("  TOTAL: %d domains, %d rewrites",
                 len(tier_domains), len(tier_rewrites))

        if dry_run:
            log.info("  [dry-run] skipping write")
            continue

        ext = {"dnsmasq": "conf", "hosts": "hosts", "plain": "txt"}.get(
            output_format, "txt"
        )
        out_path = output_dir / f"{tier_name}.{ext}"

        if output_format == "dnsmasq":
            write_dnsmasq(out_path, tier_domains, tier_rewrites, sinkhole, tier_name)
        elif output_format == "hosts":
            write_hosts(out_path, tier_domains, tier_name)
        else:
            write_plain(out_path, tier_domains, tier_name)


def verify_sources(policy: dict, timeout: int = 10) -> int:
    """HEAD-check every URL in the policy. Returns count of failures."""
    failures = 0
    seen: set[str] = set()
    for cat_name, cat_def in policy.get("categories", {}).items():
        for src in cat_def.get("sources", []):
            url = src.get("url")
            if not url or url in seen:
                continue
            seen.add(url)
            try:
                r = requests.head(url, timeout=timeout, allow_redirects=True,
                                  headers={"User-Agent": DEFAULT_USER_AGENT})
                # Many CDNs reject HEAD; fall back to GET with stream
                if r.status_code in (405, 403):
                    r = requests.get(
                        url, timeout=timeout, stream=True,
                        headers={"User-Agent": DEFAULT_USER_AGENT}
                    )
                    r.close()
                status = "OK" if r.status_code == 200 else f"HTTP {r.status_code}"
                if r.status_code != 200:
                    failures += 1
            except requests.RequestException as exc:
                status = f"ERROR: {exc}"
                failures += 1
            host = urlparse(url).netloc
            log.info("%-40s %s", f"[{cat_name}]", f"{host} -> {status}")
    return failures


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    parser.add_argument("--policy", type=Path, default=POLICY_FILE,
                        help="path to policy.yaml")
    parser.add_argument("--tier", help="build only this tier (default: all)")
    parser.add_argument("--force", action="store_true",
                        help="ignore cache, refetch everything")
    parser.add_argument("--dry-run", action="store_true",
                        help="report only, don't write outputs")
    parser.add_argument("--verify", action="store_true",
                        help="HEAD-check all upstream URLs and exit")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args(argv)

    if args.verbose:
        log.setLevel(logging.DEBUG)

    if not args.policy.exists():
        log.error("policy file not found: %s", args.policy)
        return 2

    try:
        policy = yaml.safe_load(args.policy.read_text())
    except yaml.YAMLError as exc:
        log.error("policy parse error: %s", exc)
        return 2

    if args.verify:
        n = verify_sources(policy)
        log.info("verification complete; %d failures", n)
        return 0 if n == 0 else 1

    build(policy, args.tier, args.force, args.dry_run)
    return 0


if __name__ == "__main__":
    sys.exit(main())
