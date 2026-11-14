#!/usr/bin/env python3
"""Writes latest.json, the manifest that Veil's in-app updater reads from the latest GitHub release.

    python3 app/tools/make-latest-json.py --version 1.0.0-beta.2 \
        --sig dist/Veil.app.tar.gz.sig [--notes-file notes.md | --notes "text"] [--out dist/latest.json]

Only the darwin-aarch64 platform (Apple Silicon); the Windows build does not update itself.
The signature must be the .sig that `cargo tauri signer sign --app-version <version>` wrote for
Veil.app.tar.gz: the app requires the signed version to match the announced one.
`--self-test` checks this script on sample data in a temporary folder.
"""

import argparse
import base64
import binascii
import datetime
import json
import os
import re
import sys
import tempfile

REPO = "orioshavfx/Veil"
ASSET = "Veil.app.tar.gz"
PLATFORM = "darwin-aarch64"
# semver 2.0 (no leading "v"); build metadata is not allowed in a release version here.
SEMVER = re.compile(
    r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?$"
)


class InputError(Exception):
    pass


def normalize_version(raw):
    v = raw.strip()
    if v.startswith("v"):
        v = v[1:]
    if not SEMVER.match(v):
        raise InputError(f"not a release version (semver, like 1.0.0 or 1.0.0-beta.2): {raw!r}")
    return v


def check_signature(sig, version):
    """`sig` is the .sig file content: base64 of a minisign signature box."""
    sig = sig.strip()
    if not sig:
        raise InputError("the signature file is empty")
    try:
        box = base64.b64decode(sig, validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError) as e:
        raise InputError(f"the signature is not the base64 text of a .sig file: {e}") from None
    lines = box.splitlines()
    if len(lines) < 4 or not lines[0].startswith("untrusted comment:") or not lines[2].startswith("trusted comment:"):
        raise InputError("the signature is not a minisign signature box")
    fields = dict(f.split(":", 1) for f in lines[2][len("trusted comment:"):].strip().split("\t") if ":" in f)
    if fields.get("file") not in (None, ASSET):
        raise InputError(f"the signature is for {fields['file']!r}, not {ASSET}")
    signed = fields.get("version")
    if signed is None:
        raise InputError("the signature carries no version: sign with `cargo tauri signer sign --app-version <version>`")
    if signed.lstrip("v") != version:
        raise InputError(f"the signature is for version {signed}, not {version}")
    return sig


def build(version, sig, notes, pub_date=None):
    version = normalize_version(version)
    sig = check_signature(sig, version)
    if pub_date is None:
        pub_date = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
    return {
        "version": version,
        "notes": notes.strip(),
        "pub_date": pub_date.isoformat().replace("+00:00", "Z"),
        "platforms": {
            PLATFORM: {
                "signature": sig,
                "url": f"https://github.com/{REPO}/releases/download/v{version}/{ASSET}",
            }
        },
    }


def main(argv):
    p = argparse.ArgumentParser(description="Write latest.json for Veil's in-app updater.")
    p.add_argument("--version")
    p.add_argument("--sig", help="path of Veil.app.tar.gz.sig")
    g = p.add_mutually_exclusive_group()
    g.add_argument("--notes", default="")
    g.add_argument("--notes-file")
    p.add_argument("--out", default="dist/latest.json")
    p.add_argument("--self-test", action="store_true")
    a = p.parse_args(argv)
    if a.self_test:
        return self_test()
    if not a.version or not a.sig:
        p.error("--version and --sig are required")
    try:
        with open(a.sig, encoding="utf-8") as f:
            sig = f.read()
        notes = a.notes
        if a.notes_file:
            with open(a.notes_file, encoding="utf-8") as f:
                notes = f.read()
        doc = build(a.version, sig, notes)
    except (InputError, OSError) as e:
        print(f"make-latest-json: {e}", file=sys.stderr)
        return 1
    os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
    with open(a.out, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2)
        f.write("\n")
    print(f"{a.out}: version {doc['version']}, {PLATFORM}")
    return 0


def _sample_sig(version, file=ASSET):
    """A signature box of the right shape (not a real signature: only the format is checked here)."""
    trusted = f"timestamp:1794600000\tfile:{file}" + (f"\tversion:{version}" if version else "")
    box = (
        "untrusted comment: signature from tauri secret key\n"
        "RUTest0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000=\n"
        f"trusted comment: {trusted}\n"
        "GlobalTest000000000000000000000000000000000000000000000000000000000000000000000000000000000==\n"
    )
    return base64.b64encode(box.encode()).decode()


def self_test():
    def fails(fn, *args):
        try:
            fn(*args)
        except InputError:
            return True
        return False

    when = datetime.datetime(2026, 11, 14, 12, 0, 0, tzinfo=datetime.timezone.utc)
    d = build("v1.0.0-beta.2", _sample_sig("1.0.0-beta.2"), " Fixes\n", when)
    assert d["version"] == "1.0.0-beta.2", d
    assert d["notes"] == "Fixes"
    assert d["pub_date"] == "2026-11-14T12:00:00Z"
    plat = d["platforms"][PLATFORM]
    assert plat["url"] == "https://github.com/orioshavfx/Veil/releases/download/v1.0.0-beta.2/Veil.app.tar.gz", plat
    assert plat["signature"] == _sample_sig("1.0.0-beta.2")
    assert list(d["platforms"]) == [PLATFORM]
    # Input checks.
    assert fails(normalize_version, "1.0")
    assert fails(normalize_version, "1.0.0+build")
    assert fails(normalize_version, "01.0.0")
    assert normalize_version("1.0.0") == "1.0.0"
    assert fails(build, "1.0.0", "", "")
    assert fails(build, "1.0.0", "not base64!", "")
    assert fails(build, "1.0.0", base64.b64encode(b"hello").decode(), "")
    assert fails(build, "1.0.0", _sample_sig("0.9.0"), ""), "version mismatch"
    assert fails(build, "1.0.0", _sample_sig(None), ""), "unversioned signature"
    assert fails(build, "1.0.0", _sample_sig("1.0.0", file="Other.tar.gz"), "")
    # The file round trip through main().
    with tempfile.TemporaryDirectory() as tmp:
        sig = os.path.join(tmp, "Veil.app.tar.gz.sig")
        with open(sig, "w") as f:
            f.write(_sample_sig("1.2.3") + "\n")
        out = os.path.join(tmp, "dist", "latest.json")
        assert main(["--version", "1.2.3", "--sig", sig, "--notes", "n", "--out", out]) == 0
        with open(out) as f:
            back = json.load(f)
        assert back["platforms"][PLATFORM]["signature"] == _sample_sig("1.2.3")
        assert back["version"] == "1.2.3"
        datetime.datetime.fromisoformat(back["pub_date"].replace("Z", "+00:00"))
        assert main(["--version", "1.2.4", "--sig", sig, "--out", out]) == 1
        assert main(["--version", "1.2.3", "--sig", os.path.join(tmp, "missing.sig"), "--out", out]) == 1
    print("make-latest-json: self-test passed")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
