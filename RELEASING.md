# Releasing slowwave-lists

Bundles follow calendar versioning: `YYYY.MM.DD`. Monthly cadence
(first of the month, ideally), but ad-hoc releases for urgent updates
are fine.

## Prerequisites

- Ed25519 private signing key at `~/.slowwave/lists-signing.key`
  (mode 600). Generated once, kept offline on the curator's machine.
  The matching public key lives at `keys/lists-signing.pub` and is
  shipped in the `slowwave-pi` `.deb`.
- Python 3.11+ with `pyyaml` (`pip install --break-system-packages pyyaml`).
- `gh` CLI authenticated against `github.com`.

## Cutting a release

```
# 1. Edit policy.yaml / supplemental/ as needed.
# 2. Build the bundle and sign it.
python3 scripts/build_bundle.py 2026.06.01

# 3. Inspect the dist/ output.
ls -la dist/
#   slowwave-lists-2026.06.01.tar.gz
#   slowwave-lists-2026.06.01.tar.gz.sig
#   latest.json
#   slowwave-lists-2026.06.01/         (extracted, for inspection)

# 4. Tag and create a GitHub Release with the three assets attached.
git tag 2026.06.01
git push origin main 2026.06.01
gh release create 2026.06.01 \
    dist/slowwave-lists-2026.06.01.tar.gz \
    dist/slowwave-lists-2026.06.01.tar.gz.sig \
    dist/latest.json \
    --title "slowwave-lists 2026.06.01" \
    --notes-file dist/RELEASE_NOTES.md
```

### Building where the key isn't

The key lives on the curator's machine, which may not have `pyyaml`. Build
anywhere with `--skip-sign`, sign the tarball where the key is, and bring
the `.sig` back next to it:

```
python3 scripts/build_bundle.py 2026.11.13 --skip-sign
scp dist/slowwave-lists-2026.11.13.tar.gz curator:/tmp/
ssh curator '/opt/homebrew/bin/openssl pkeyutl -sign -inkey ~/.slowwave/lists-signing.key -rawin \
    -in /tmp/slowwave-lists-2026.11.13.tar.gz -out /tmp/slowwave-lists-2026.11.13.tar.gz.sig'
scp curator:/tmp/slowwave-lists-2026.11.13.tar.gz.sig dist/
openssl pkeyutl -verify -pubin -inkey keys/lists-signing.pub -rawin \
    -in dist/slowwave-lists-2026.11.13.tar.gz -sigfile dist/slowwave-lists-2026.11.13.tar.gz.sig
```

On macOS use Homebrew's OpenSSL 3 for the signing step: the system
`/usr/bin/openssl` is LibreSSL and cannot load an Ed25519 key.

`latest.json` only carries the tarball's sha256, so it does not change when
the signature is added afterwards.

After the release, the SlowWave daemon's update client will see the new
version via `https://github.com/mirkotron/slowwave-lists/releases/latest/download/latest.json`
on its next check (default every 6 hours).

## Key custody

The Ed25519 private key never leaves the curator's offline machine. If
the key is compromised or lost, generate a new keypair, ship the new
public key in a `slowwave-pi` release, and reference the new key as
`next_key` in the manifest of the last bundle signed with the old key
(so daemons can migrate cleanly).

## Sanity tripwires

`build_bundle.py` refuses to emit a bundle if any supplemental file
shrinks by >50% or grows by >500% vs. the previously-built version
(state stored in `dist/.previous-sizes.json`). Override with
`--force-resize`.
