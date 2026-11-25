#!/usr/bin/env python3
"""Refresh the supplemental lists that are snapshots of an outside source.

Some official lists are not plain text the daemon can fetch (an XML
register, an HTML table), and some need cleaning before they are safe to
block from. Those are fetched here, cleaned, and written into
supplemental/ so they ship inside the bundle. Run before a release:

    python3 scripts/fetch_external_lists.py

Each output carries a header naming its source and the day it was taken.
Entries listed in scripts/external_exclusions.txt are always left out, as
are education and government hosts and anything on the allowlist or the
protect list. A source that fails to fetch, or comes
back less than half its previous size, leaves the existing file untouched
and the run exits non-zero.
"""
from __future__ import annotations

import datetime
import html
import re
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SUPP = ROOT / "supplemental"
EXCLUSIONS = Path(__file__).resolve().parent / "external_exclusions.txt"
UA = "Mozilla/5.0 (slowwave-lists build)"

PL_REGISTER = "https://hazard.mf.gov.pl/api/Register"
BE_LIST = ("https://www.gamingcommission.be/en/gaming-commission/"
           "illegal-games-of-chance/list-of-illegal-gambling-sites")
UT1_MIRROR = "https://raw.githubusercontent.com/cbuijs/ut1/master/{cat}/domains"

HOST_RE = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}$")
INSTITUTIONAL_RE = re.compile(
    r"(?:\.edu|\.gov|\.mil|\.gouv\.fr|\.gc\.ca|\.europa\.eu|\.ac\.[a-z]{2})$"
    r"|\.edu\.[a-z]{2}$|\.gov\.[a-z]{2}$|\.gob\.[a-z]{2}$"
)


def fetch(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=90) as r:
        return r.read().decode("utf-8", errors="replace")


def clean_host(raw: str) -> str | None:
    h = html.unescape(raw).strip().lower()
    h = re.sub(r"^[a-z]+://", "", h).split("/")[0].split(":")[0].rstrip(".")
    if h.startswith("www."):
        h = h[4:]
    return h if HOST_RE.match(h) else None


def load_exclusions() -> set[str]:
    """The hand-kept exclusions, plus everything on the allowlist and the
    protect list: a name we promise to keep working is never taken in."""
    out = set()
    for f in (EXCLUSIONS, ROOT / "allowlist.txt", ROOT / "infrastructure.txt"):
        for line in f.read_text().splitlines():
            s = line.split("#", 1)[0].strip().lower()
            if s:
                out.add(s)
    return out


def excluded(host: str, excl: set[str]) -> bool:
    if INSTITUTIONAL_RE.search(host):
        return True
    parts = host.split(".")
    return any(".".join(parts[i:]) in excl for i in range(len(parts) - 1))


def poland() -> set[str]:
    xml = fetch(PL_REGISTER)
    return {h for h in map(clean_host, re.findall(r"<AdresDomeny>([^<]+)", xml)) if h}


def belgium() -> set[str]:
    page = fetch(BE_LIST)
    table = page[page.find("<table"):page.find("</table>")]
    out = set()
    for row in re.findall(r"<tr>(.*?)</tr>", table, flags=re.S):
        cells = re.findall(r"<td[^>]*>(.*?)</td>", row, flags=re.S)
        if len(cells) >= 2:
            h = clean_host(re.sub(r"<[^>]+>", "", cells[1]))
            if h:
                out.add(h)
    return out


def ut1(*cats: str) -> set[str]:
    out: set[str] = set()
    for cat in cats:
        body = fetch(UT1_MIRROR.format(cat=cat))
        got = {h for h in map(clean_host, body.splitlines()) if h}
        if not got:
            raise RuntimeError(f"UT1 category {cat} came back empty")
        out |= got
    return out


UT1_NOTE = (
    "Source: the UT1 blacklists kept by Université Toulouse Capitole\n"
    "#   (https://dsi.ut-capitole.fr/blacklists/), category {cats},\n"
    "#   taken from the mirror at https://github.com/cbuijs/ut1.\n"
    "# UT1 publishes its lists under a Creative Commons licence; this file is a\n"
    "#   derived copy and stays under that licence, not this repository's."
)

OUTPUTS = {
    "gambling_regulators.txt": (
        "Gambling sites named by national regulators as operating without a licence",
        "Sources: Poland, Ministry of Finance, register of domains used to offer\n"
        "#   gambling contrary to the Gambling Act (https://hazard.mf.gov.pl/);\n"
        "#   Belgium, Gaming Commission, list of illegal gambling sites\n"
        "#   (https://www.gamingcommission.be/).\n"
        "# A site is here because it has no licence in that country. Some are\n"
        "#   licensed elsewhere.",
        lambda: poland() | belgium(),
    ),
    "dating_ut1.txt": (
        "Dating sites",
        UT1_NOTE.format(cats="dating"),
        lambda: ut1("dating"),
    ),
    "drugs_ut1.txt": (
        "Drug sites",
        UT1_NOTE.format(cats="drogue"),
        lambda: ut1("drogue"),
    ),
    "hate_violence_ut1.txt": (
        "Hate, violence, cults and weapons",
        UT1_NOTE.format(cats="agressif, sect, dangerous_material"),
        lambda: ut1("agressif", "sect", "dangerous_material"),
    ),
}


def previous_count(path: Path) -> int:
    if not path.exists():
        return 0
    return sum(1 for l in path.read_text().splitlines() if l and not l.startswith("#"))


def main() -> int:
    excl = load_exclusions()
    today = datetime.date.today().isoformat()
    failed = False
    for name, (title, note, getter) in OUTPUTS.items():
        path = SUPP / name
        try:
            raw = getter()
        except Exception as e:  # noqa: BLE001 - report and keep the old file
            print(f"  {name}: FETCH FAILED ({e}); kept the existing file")
            failed = True
            continue
        kept = sorted(h for h in raw if not excluded(h, excl))
        before = previous_count(path)
        if before and len(kept) < before / 2:
            print(f"  {name}: {len(kept)} entries against {before} before; "
                  "kept the existing file")
            failed = True
            continue
        path.write_text(
            f"# SlowWave supplemental list: {title}\n#\n# {note}\n#\n"
            f"# Snapshot taken {today} by scripts/fetch_external_lists.py.\n"
            f"# {len(kept)} entries; {len(raw) - len(kept)} left out "
            "(exclusions, allow and protect lists, education and government hosts).\n"
            "# Do not edit by hand: the next refresh overwrites it.\n#\n"
            + "\n".join(kept) + "\n"
        )
        print(f"  {name}: {len(kept)} entries ({len(raw) - len(kept)} left out; was {before})")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
