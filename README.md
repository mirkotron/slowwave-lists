# slowwave-lists

The curated content bundle for [SlowWave](https://github.com/mirkotron/slowwave-pi).

A SlowWave Pi pulls a signed bundle from this repo's GitHub Releases on a
monthly cadence. The bundle holds:

- **Curated supplemental lists** (`supplemental/`) that fill gaps the
  public blocklists don't cover well — AI companion apps, the Aussie 10
  social list, location/stalkerware, the DoH/VPN bypass set, SafeSearch
  CNAME rewrites.
- **Snapshots of official and academic lists** (also in `supplemental/`,
  since 2026.11.24) that are not plain text a device can fetch, or need
  cleaning first: the gambling regulators' lists of unlicensed sites
  (Poland, Belgium) and the UT1 lists of Université Toulouse Capitole for
  dating, drugs, and hate, violence and weapons. `scripts/fetch_external_lists.py`
  refreshes them; `scripts/external_exclusions.txt` holds what is always
  left out, with the reason for each.
- **Preset definitions** (`presets/<tier>.json`) — six age-tier
  starting points that map categories to actions on a friction-first
  spectrum (pass / throttle / hard_throttle / block).
- **Category index** (`categories.json`) — names, default actions,
  groupings, and source URLs for every category SlowWave can enforce.
- **`policy.yaml`** — the source of truth from which the bundle is
  built. Edit this to change what each category covers or what each
  tier includes; rerun `scripts/build_bundle.py` to produce a new
  release.

Public blocklists (HaGeZi, StevenBlack, OISD, EasyPrivacy,
ShadowWhisperer) are NOT in the bundle; the SlowWave daemon fetches
them live every 6 hours from the URLs declared in `categories.json`.

## Verifying a bundle

```
openssl pkeyutl -verify -pubin \
    -inkey /usr/share/slowwave/keys/lists-signing.pub \
    -rawin -in slowwave-lists-<version>.tar.gz \
    -sigfile slowwave-lists-<version>.tar.gz.sig
```

## Layout

```
policy.yaml            source of truth (tiers × categories × sources)
allowlist.txt          Educational sites (learning sites only since 2026.11.13)
infrastructure.txt     Keeps things working: sign-in and delivery hosts a
                       curated list must never sinkhole (protect, 2026.11.17)
build_blocklist.py     standalone compiler (parents/developers can
                       run locally; SlowWave daemon ships its own port)
supplemental/          curated text files included in every release
keys/lists-signing.pub public verification key (PEM, Ed25519)
scripts/build_bundle.py builder that emits release tarballs
scripts/fetch_external_lists.py  refreshes the snapshot lists before a release
scripts/external_exclusions.txt  hosts never taken into a snapshot, and why
```

See `RELEASING.md` for how to cut a new release.
