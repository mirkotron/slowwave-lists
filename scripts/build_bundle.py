#!/usr/bin/env python3
"""SlowWave lists bundle builder.

Reads policy.yaml + supplemental/, produces a versioned tarball, signs
it with the curator's Ed25519 key, emits latest.json. Run from the repo
root:

    python3 scripts/build_bundle.py 2026.06.01

Outputs:
    dist/slowwave-lists-<version>/        (extracted bundle for inspection)
    dist/slowwave-lists-<version>.tar.gz  (the bundle)
    dist/slowwave-lists-<version>.tar.gz.sig (Ed25519 detached signature)
    dist/latest.json                       (channel pointer for the daemon)
    dist/RELEASE_NOTES.md                  (skeleton for gh release create)
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path

try:
    import yaml
except ImportError:
    sys.exit("missing pyyaml — `pip install --break-system-packages pyyaml`")

ROOT = Path(__file__).resolve().parent.parent
SUPP = ROOT / "supplemental"
ALLOWLIST = ROOT / "allowlist.txt"
POLICY = ROOT / "policy.yaml"
KEY = Path.home() / ".slowwave" / "lists-signing.key"
DIST = ROOT / "dist"
MIN_SLOWWAVE = "0.8.0"
RELEASE_BASE = "https://github.com/mirkotron/slowwave-lists/releases/download"

# Category metadata not present in policy.yaml: which intent-group it
# belongs to in the parent UI, what its default action should be, and
# whether it's a blocklist or allowlist. The daemon uses this to slot
# categories into the UI groups defined in PROJECT_STATE §7.3.
CATEGORY_META: dict[str, tuple[str, str, str]] = {
    "malware_security":         ("safety",    "block",    "blocklist"),
    "trackers":                 ("privacy",   "block",    "blocklist"),
    "native_device_trackers":   ("privacy",   "block",    "blocklist"),
    "nsfw":                     ("safety",    "block",    "blocklist"),
    "gambling":                 ("safety",    "block",    "blocklist"),
    "shock_gore":               ("safety",    "block",    "blocklist"),
    "dating":                   ("wellbeing", "block",    "blocklist"),
    "crypto":                   ("wellbeing", "block",    "blocklist"),
    "ai_companions":            ("safety",    "block",    "blocklist"),
    "social_broad":             ("social",    "throttle", "blocklist"),
    "social_major":             ("social",    "throttle", "blocklist"),
    "social_meta":              ("social",    "throttle", "blocklist"),
    "chat_anonymous":           ("wellbeing", "block",    "blocklist"),
    "location_broadcasting":    ("wellbeing", "block",    "blocklist"),
    "url_shorteners":           ("privacy",   "block",    "blocklist"),
    "dynamic_dns_free_hosting": ("integrity", "block",    "blocklist"),
    "bypass_dns_vpn":           ("integrity", "block",    "blocklist"),
    "piracy":                   ("wellbeing", "block",    "blocklist"),
    "nosafesearch_engines":     ("integrity", "block",    "blocklist"),
    # safesearch_force outputs CNAME rewrites — kind=blocklist preserves
    # the existing schema; the compiler routes safesearch_rewrites-format
    # sources into the category_rewrites table.
    "safesearch_force":         ("integrity", "block",    "blocklist"),
    "whitelist_education":      ("whitelist", "pass",     "allowlist"),
}

TIER_DISPLAY = {
    "tier1_0_to_5":   "Young child (0–5)",
    "tier2_6_to_9":   "Child (6–9)",
    "tier3_10_to_12": "Tween (10–12)",
    "tier4_13_to_15": "Young teen (13–15)",
    "tier5_16_to_17": "Older teen (16–17)",
    "adult":          "Adult (18+)",
}

# Age band each preset targets, surfaced in the preset JSON so the M7
# setup wizard can recommend one from a child's age. age_max=None = no
# upper bound (adult).
TIER_AUDIENCE = {
    "tier1_0_to_5":   {"age_min": 0,  "age_max": 5},
    "tier2_6_to_9":   {"age_min": 6,  "age_max": 9},
    "tier3_10_to_12": {"age_min": 10, "age_max": 12},
    "tier4_13_to_15": {"age_min": 13, "age_max": 15},
    "tier5_16_to_17": {"age_min": 16, "age_max": 17},
    "adult":          {"age_min": 18, "age_max": None},
}

SOCIAL_FAMILY = {
    "social_meta", "social_major", "social_broad", "short_form_video",
}


def policy_rows_for_tier(tier_def: dict) -> list[dict]:
    rows: list[dict] = []
    for cat in tier_def.get("categories", []):
        meta = CATEGORY_META.get(cat)
        if cat in SOCIAL_FAMILY:
            # friction-first per Phase 0.8 plan §1
            rows.append({"category": cat, "window": "bedtime",
                         "action": "block",         "priority": 900})
            rows.append({"category": cat, "window": "school_hours",
                         "action": "hard_throttle", "priority": 800})
            rows.append({"category": cat, "window": "always",
                         "action": "throttle",      "priority": 100})
        elif meta is None:
            rows.append({"category": cat, "window": "always",
                         "action": "block", "priority": 100})
        else:
            _, default_action, _ = meta
            rows.append({"category": cat, "window": "always",
                         "action": default_action, "priority": 100})
    # Every tier gets the educational allowlist as pass.
    rows.append({"category": "whitelist_education",
                 "window": "always", "action": "pass", "priority": 100})
    return rows


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _count_list_domains(filename: str) -> int | None:
    """Approximate domain count of a shipped supplemental list: non-empty,
    non-comment lines. Returns None for sources we can't count at build
    time (upstream URLs)."""
    p = SUPP / Path(filename).name
    if not p.exists():
        return None
    n = 0
    for line in p.read_text(errors="replace").splitlines():
        s = line.strip()
        if not s or s.startswith(("#", "!")):
            continue
        n += 1
    return n


def _count_allowlist_domains() -> int:
    """Non-empty, non-comment lines in the curator allowlist."""
    n = 0
    for line in ALLOWLIST.read_text(errors="replace").splitlines():
        s = line.strip()
        if s and not s.startswith(("#", "!")):
            n += 1
    return n


def build_categories_json(cats_def: dict) -> dict:
    out = []
    for name, defn in cats_def.items():
        group, default_action, kind = CATEGORY_META.get(
            name, ("manual", "block", "blocklist"))
        sources = []
        cat_count = 0
        cat_countable = False  # at least one source we could count
        for s in defn.get("sources", []):
            if "url" in s:
                # Can't count an upstream list without fetching it.
                sources.append({
                    "kind": "upstream_url",
                    "location": s["url"],
                    "format": s.get("format", "domains"),
                    "domain_count": None,
                })
            elif "file" in s:
                c = _count_list_domains(s["file"])
                if c is not None:
                    cat_count += c
                    cat_countable = True
                sources.append({
                    "kind": "slowwave_file",
                    "location": f"lists/{Path(s['file']).name}",
                    "format": s.get("format", "domains"),
                    "domain_count": c,
                })
        out.append({
            "name": name,
            "display_name": defn.get("display_name",
                                      name.replace("_", " ").title()),
            "description": defn.get("description", ""),
            "managed_by": "slowwave",
            "default_action": default_action,
            "kind": kind,
            "group": group,
            # Sum over countable sources; null when nothing is countable
            # (e.g. all upstream) so the chooser can show "—" rather than 0.
            "domain_count": cat_count if cat_countable else None,
            "sources": sources,
        })
    # The two categories the 0.7.3 → 0.8 migration creates from the
    # existing 14 Meta blocks and 10 educational whitelist domains.
    # Sources empty here — daemon's M1 migration populates them from
    # the live DB.
    out.append({
        "name": "social_meta",
        "display_name": "Social media — Meta apps",
        "description": "Facebook, Instagram, WhatsApp, Threads, Messenger and related Meta surfaces.",
        "managed_by": "slowwave",
        "default_action": "throttle",
        "kind": "blocklist",
        "group": "social",
        "sources": [],
    })
    out.append({
        "name": "whitelist_education",
        "display_name": "Educational sites",
        "description": "A short curated list of learning sites that are never "
                       "blocked and skip the slow lane.",
        "managed_by": "slowwave",
        "default_action": "pass",
        "kind": "allowlist",
        "group": "whitelist",
        # Ships the curator allowlist as a real source. The daemon's M1
        # migration ALSO seeds this category from the live DB (the parent's
        # manual edu entries) — that's a `manual` source and survives; this
        # bundle source is additive (slowwave_file, replaced on each update).
        "sources": [{
            "kind": "slowwave_file",
            "location": f"lists/{ALLOWLIST.name}",
            "format": "domains",
            "domain_count": _count_allowlist_domains(),
        }],
    })
    return {"categories": out}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("version", help="calendar version e.g. 2026.06.01")
    ap.add_argument("--channel", default="stable")
    ap.add_argument(
        "--skip-sign", action="store_true",
        help="build everything except the .sig (sign the tarball on the "
             "curator's machine afterwards; see RELEASING.md)",
    )
    args = ap.parse_args()
    version = args.version

    if not args.skip_sign and not KEY.exists():
        sys.exit(f"private signing key missing at {KEY}")

    policy = yaml.safe_load(POLICY.read_text())
    tiers = policy["tiers"]
    cats_def = policy["categories"]

    DIST.mkdir(exist_ok=True)
    work = DIST / f"slowwave-lists-{version}"
    if work.exists():
        shutil.rmtree(work)
    (work / "lists").mkdir(parents=True)
    (work / "presets").mkdir()

    for f in sorted(SUPP.glob("*.txt")):
        shutil.copy2(f, work / "lists" / f.name)

    # Ship the curator allowlist INSIDE the bundle so the daemon actually
    # receives it. Without this, whitelist_education arrives with empty
    # sources and the device has zero allowlist domains — an NSFW/malware
    # false positive can then NXDOMAIN google/youtube with nothing to
    # override it (2026-06-18 integrated run). The daemon subtracts these
    # from the compiled block set (see build_categories_json below).
    shutil.copy2(ALLOWLIST, work / "lists" / ALLOWLIST.name)

    (work / "categories.json").write_text(
        json.dumps(build_categories_json(cats_def), indent=2) + "\n"
    )

    for tier_name, tier_def in tiers.items():
        spec = {
            "name": tier_name,
            "display_name": TIER_DISPLAY.get(tier_name, tier_name),
            "description": tier_def.get("description", ""),
            "audience": TIER_AUDIENCE.get(tier_name),
            "version": version,
            "policy_rows": policy_rows_for_tier(tier_def),
        }
        (work / "presets" / f"{tier_name}.json").write_text(
            json.dumps(spec, indent=2) + "\n"
        )

    files = []
    for p in sorted(work.rglob("*")):
        if p.is_file():
            files.append({
                "path": p.relative_to(work).as_posix(),
                "size": p.stat().st_size,
                "sha256": sha256_file(p),
            })
    manifest = {
        "version": version,
        "channel": args.channel,
        "min_slowwave_version": MIN_SLOWWAVE,
        "created_at": datetime.datetime.now(
            datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "files": files,
        "notes": (
            "The curated allowlist is now learning sites only, and the "
            "category is called Educational sites. Removed from it: the "
            "Google/Apple/Microsoft account infrastructure, the YouTube "
            "delivery CDNs (youtube.com, googlevideo.com, ytimg.com, ...) "
            "and the regulator-exempt apps (Discord, Roblox, Steam, "
            "WhatsApp, Messenger, Pinterest, GitHub, YouTube Kids). An "
            "allowlist entry means full speed and reachable through a "
            "scheduled Off, which those never deserved. Pairs with slowwave "
            ">= 0.8.0~m7.60, where the parent's own lists live in their own "
            "categories (ADR-028). Six age-tier presets and the 21 other "
            "categories unchanged."
        ),
    }
    (work / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")

    tar_path = DIST / f"slowwave-lists-{version}.tar.gz"
    with tarfile.open(tar_path, "w:gz") as tf:
        tf.add(work, arcname=work.name)
    tar_sha = sha256_file(tar_path)

    sig_path = Path(str(tar_path) + ".sig")
    if args.skip_sign:
        sig_path.unlink(missing_ok=True)
    else:
        subprocess.run(
            ["openssl", "pkeyutl", "-sign",
             "-inkey", str(KEY), "-rawin",
             "-in", str(tar_path), "-out", str(sig_path)],
            check=True,
        )

    latest = {
        "version": version,
        "channel": args.channel,
        "min_slowwave_version": MIN_SLOWWAVE,
        "bundle_url": f"{RELEASE_BASE}/{version}/slowwave-lists-{version}.tar.gz",
        "signature_url": f"{RELEASE_BASE}/{version}/slowwave-lists-{version}.tar.gz.sig",
        "sha256": tar_sha,
        "notes": manifest["notes"],
    }
    (DIST / "latest.json").write_text(json.dumps(latest, indent=2) + "\n")

    notes_path = DIST / "RELEASE_NOTES.md"
    notes_path.write_text(
        f"# slowwave-lists {version}\n\n"
        f"{manifest['notes']}\n\n"
        f"**Bundle:** `slowwave-lists-{version}.tar.gz`  ({tar_path.stat().st_size:,} bytes)\n"
        f"**sha256:** `{tar_sha}`\n"
        f"**min slowwave:** `{MIN_SLOWWAVE}`\n\n"
        "## How to verify\n\n"
        "```\n"
        "openssl pkeyutl -verify -pubin \\\n"
        "    -inkey /usr/share/slowwave/keys/lists-signing.pub \\\n"
        f"    -rawin -in slowwave-lists-{version}.tar.gz \\\n"
        f"    -sigfile slowwave-lists-{version}.tar.gz.sig\n"
        "```\n"
    )

    print(f"  bundle   : {tar_path}  ({tar_path.stat().st_size:,} bytes)")
    if args.skip_sign:
        print("  signature: SKIPPED — on the curator's machine run:")
        print(f"             openssl pkeyutl -sign -inkey ~/.slowwave/lists-signing.key "
              f"-rawin -in {tar_path.name} -out {sig_path.name}")
    else:
        print(f"  signature: {sig_path}")
    print(f"  sha256   : {tar_sha}")
    print(f"  latest   : {DIST / 'latest.json'}")
    print(f"  notes    : {notes_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
