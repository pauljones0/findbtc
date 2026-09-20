#!/usr/bin/env python3
"""verify-packaging-pins.py — every packaging entry binds the right URL
to the right SHA-256 for the right architecture.

Each manifest entry is parsed structurally (not grepped): the asset
name in its URL must match the release checksums.txt row whose hash
equals the entry's pinned hash, so swapped or repeated hashes fail.
Live mode fetches checksums.txt for TAG (default v0.2.0) and checks
packaging/; --self-test runs the same binding checks over in-repo
fixtures with a synthetic checksum map and no network, so the
regression coverage cannot hide behind a fetch failure.
"""
import json
import re
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SELFTEST = Path(__file__).resolve().parent / "testdata" / "pins"

BASE = "https://github.com/pauljones0/findbtc/releases/download"


class PinError(Exception):
    pass


def fetch_checksums(tag):
    url = f"{BASE}/{tag}/checksums.txt"
    try:
        with urllib.request.urlopen(url, timeout=60) as r:
            body = r.read().decode()
    except Exception as e:
        raise PinError(f"cannot fetch {url}: {e}")
    sums = {}
    for line in body.splitlines():
        parts = line.split()
        if len(parts) == 2:
            sums[parts[1]] = parts[0].lower()
    return sums


def head_ok(url):
    req = urllib.request.Request(url, method="HEAD")
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return 200 <= r.status < 400
    except Exception:
        return False


def check_url_head(url):
    if not head_ok(url):
        raise PinError(f"pinned URL does not resolve: {url}")


def check_cask(path, ver, sums):
    text = Path(path).read_text()
    m = re.search(r'^\s*version\s+"([^"]+)"', text, re.M)
    if not m or m.group(1) != ver:
        raise PinError(f"{path}: version is not {ver}")
    # (os, arch) blocks each bind one url to one sha256. Split OS
    # sections on their two-space `end` first (inner ends use four
    # spaces), then take arch blocks inside each section.
    want = {("macos", "intel"): f"findbtc_{ver}_darwin_amd64.tar.gz",
            ("macos", "arm"): f"findbtc_{ver}_darwin_arm64.tar.gz",
            ("linux", "intel"): f"findbtc_{ver}_linux_amd64.tar.gz",
            ("linux", "arm"): f"findbtc_{ver}_linux_arm64.tar.gz"}
    seen = set()
    sections = re.findall(r"on_(macos|linux)\s+do\s+(.*?)\n  end", text, re.S)
    blocks = [(osname, arch, inner)
              for osname, body in sections
              for arch, inner in re.findall(r"on_(arm|intel)\s+do\s+(.*?)\n\s+end", body, re.S)]
    for osname, arch, inner in blocks:
        key = (osname, arch)
        if key in seen:
            raise PinError(f"{path}: duplicate {(osname, arch)} block")
        seen.add(key)
        asset = want.get(key)
        if asset is None:
            raise PinError(f"{path}: unexpected block {(osname, arch)}")
        urls = re.findall(r'url\s+"([^"]+)"', inner)
        shas = re.findall(r'sha256\s+"([^"]+)"', inner)
        if len(urls) != 1 or len(shas) != 1:
            raise PinError(f"{path}: {(osname, arch)} must bind one url to one sha256")
        url, sha = urls[0], shas[0].lower()
        if url != f"{BASE}/v{ver}/{asset}":
            raise PinError(f"{path}: {(osname, arch)} url {url} is not the v{ver} {asset} URL")
        if sums.get(asset) is None:
            raise PinError(f"{path}: {asset} missing from checksums.txt")
        if sha != sums[asset]:
            raise PinError(f"{path}: {(osname, arch)} sha {sha} != {asset} {sums[asset]}")
        check_url_head(url)
    if seen != set(want):
        raise PinError(f"{path}: blocks {sorted(seen)} != {sorted(want)}")


def check_scoop(path, ver, sums, key="findbtc"):
    d = json.loads(Path(path).read_text())
    if d.get("version") != ver:
        raise PinError(f"{path}: version is not {ver}")
    arch = d.get("architecture")
    if not isinstance(arch, dict) or set(arch) != {"64bit", "arm64"}:
        raise PinError(f"{path}: architecture keys must be exactly 64bit+arm64")
    want = {"64bit": f"findbtc_{ver}_windows_amd64.zip",
            "arm64": f"findbtc_{ver}_windows_arm64.zip"}
    hashes = set()
    for name, entry in arch.items():
        asset = want[name]
        url = entry.get("url", "")
        h = entry.get("hash", "")
        if url != f"{BASE}/v{ver}/{asset}":
            raise PinError(f"{path}: {name} url {url} is not the v{ver} {asset} URL")
        if sums.get(asset) is None:
            raise PinError(f"{path}: {asset} missing from checksums.txt")
        if h.lower() != "sha256:" + sums[asset]:
            raise PinError(f"{path}: {name} hash {h} != {asset} {sums[asset]}")
        hashes.add(h.lower())
        check_url_head(url)
    if len(hashes) != 2:
        raise PinError(f"{path}: duplicate hash across architectures")
    # Autoupdate templates must render to the pinned URLs ($version,
    # never the digits-only $cleanVersion).
    raw = Path(path).read_text()
    if "$cleanVersion" in raw:
        raise PinError(f"{path}: template uses digits-only $cleanVersion")
    try:
        tmpl = d["autoupdate"]["architecture"]
    except KeyError:
        raise PinError(f"{path}: missing autoupdate.architecture")
    for name in ("64bit", "arm64"):
        t = tmpl.get(name, {}).get("url", "")
        rendered = t.replace("$version", ver)
        if "$" in rendered:
            raise PinError(f"{path}: unexpanded variable in autoupdate {name}: {t}")
        if rendered != arch[name]["url"]:
            raise PinError(f"{path}: autoupdate {name} renders to {rendered}, pinned {arch[name]['url']}")


def parse_simple_yaml(path):
    """Strict subset parser for the winget manifests: top-level
    `Key: value` lines, `Key:` list openers, `- scalar` items, and
    `- Key: value` mapping items with indented `Key: value`
    continuations. Returns (scalars, lists); mapping items come
    back as dicts. Anything else fails."""
    scalars, lists = {}, {}
    current, item, folded = None, None, None
    for lineno, line in enumerate(Path(path).read_text().splitlines(), 1):
        if not line.strip() or line.startswith("#"):
            continue
        m = re.match(r"^\s*-\s+(.*)$", line)
        if m:
            if current is None:
                raise PinError(f"{path}:{lineno}: list item outside a list: {line}")
            rest = m.group(1)
            kv = re.match(r"^([A-Za-z0-9]+):\s*(.*)$", rest)
            if kv and kv.group(2):
                item = {kv.group(1): kv.group(2)}
                lists[current].append(item)
            elif kv:
                raise PinError(f"{path}:{lineno}: empty mapping value: {line}")
            else:
                lists[current].append(rest)
                item = None
            folded = None
            continue
        m = re.match(r"^\s*([A-Za-z0-9]+):\s*(.*)$", line)
        if not m:
            # Folded plain-scalar continuation ("Description: ...\n  more").
            if folded is not None and line.startswith((" ", "\t")):
                scalars[folded] += " " + line.strip()
                continue
            raise PinError(f"{path}:{lineno}: bad line: {line}")
        key, val = m.group(1), m.group(2)
        if line.startswith((" ", "\t")):
            if not val:
                raise PinError(f"{path}:{lineno}: bad line: {line}")
            if not isinstance(item, dict):
                raise PinError(f"{path}:{lineno}: continuation outside a mapping item: {line}")
            if key in item:
                raise PinError(f"{path}:{lineno}: duplicate key {key}")
            item[key] = val
            folded = None
        elif val:
            if key in scalars or key in lists:
                raise PinError(f"{path}:{lineno}: duplicate key {key}")
            scalars[key] = val
            current, item, folded = None, None, key
        else:
            if key in scalars or key in lists:
                raise PinError(f"{path}:{lineno}: duplicate key {key}")
            lists[key] = []
            current, item, folded = key, None, None
    return scalars, lists


def check_winget(path, ver, sums):
    want_id = "pauljones0.findbtc"
    want_files = ["pauljones0.findbtc.yaml",
                  "pauljones0.findbtc.installer.yaml",
                  "pauljones0.findbtc.locale.en-US.yaml"]
    for f in want_files:
        if not (Path(path) / f).exists():
            raise PinError(f"{path}: missing {f}")
    for f in want_files:
        scalars, _ = parse_simple_yaml(Path(path) / f)
        if scalars.get("PackageIdentifier") != want_id:
            raise PinError(f"{path}/{f}: identifier is not {want_id}")
        if scalars.get("PackageVersion") != ver:
            raise PinError(f"{path}/{f}: version is not {ver}")
    scalars, lists = parse_simple_yaml(Path(path) / "pauljones0.findbtc.installer.yaml")
    if scalars.get("InstallerType") != "zip":
        raise PinError(f"{path}: InstallerType is not zip")
    if scalars.get("NestedInstallerType") != "portable":
        raise PinError(f"{path}: NestedInstallerType is not portable")
    # Each installer entry binds Architecture -> Url -> Sha256.
    items = lists.get("Installers", [])
    if not items or any(not isinstance(i, dict) for i in items):
        raise PinError(f"{path}: Installers must hold Architecture/Url/Sha entries")
    want = {"x64": f"findbtc_{ver}_windows_amd64.zip",
            "arm64": f"findbtc_{ver}_windows_arm64.zip"}
    seen = set()
    for inst in items:
        arch, url, sha = (inst.get("Architecture", ""), inst.get("InstallerUrl", ""),
                          inst.get("InstallerSha256", "").lower())
        if arch in seen:
            raise PinError(f"{path}: duplicate installer {arch}")
        seen.add(arch)
        asset = want.get(arch)
        if asset is None:
            raise PinError(f"{path}: unexpected installer {arch}")
        if url != f"{BASE}/v{ver}/{asset}":
            raise PinError(f"{path}: {arch} url {url} is not the v{ver} {asset} URL")
        if sums.get(asset) is None:
            raise PinError(f"{path}: {asset} missing from checksums.txt")
        if sha != sums[asset]:
            raise PinError(f"{path}: {arch} sha {sha} != {asset} {sums[asset]}")
        check_url_head(url)
    if seen != set(want):
        raise PinError(f"{path}: installers {sorted(seen)} != {sorted(want)}")
    nested = lists.get("NestedInstallerFiles", [])
    if len(nested) != 1 or not isinstance(nested[0], dict):
        raise PinError(f"{path}: want one NestedInstallerFiles entry")
    if nested[0].get("RelativeFilePath") != "findbtc.exe":
        raise PinError(f"{path}: NestedInstallerFiles must point at findbtc.exe")
    if nested[0].get("PortableCommandAlias") != "findbtc":
        raise PinError(f"{path}: PortableCommandAlias must be findbtc")


def verify(packaging, ver, sums):
    check_cask(packaging / "homebrew" / "Casks" / "findbtc.rb", ver, sums)
    check_scoop(packaging / "scoop" / "findbtc.json", ver, sums)
    check_winget(packaging / "winget", ver, sums)


def self_test():
    """Offline regression proof: the good fixture passes, every
    mutant (swapped/repeated/missing/drifted bindings) fails."""
    import shutil
    import tempfile
    tmp = Path(tempfile.mkdtemp(prefix="pins-selftest-"))
    try:
        good = SELFTEST / "good"
        sums = json.loads((SELFTEST / "sums.json").read_text())
        save_head = globals()["check_url_head"]
        globals()["check_url_head"] = lambda url: None  # offline: no fetches
        try:
            verify(good, "9.9.9", sums)
        finally:
            globals()["check_url_head"] = save_head
        print("self-test: good fixture passes")
        mutants = sorted(p.name for p in SELFTEST.iterdir()
                         if p.is_dir() and p.name != "good")
        if not mutants:
            raise PinError("self-test: no mutant fixtures found")
        for m in mutants:
            case = tmp / m
            shutil.copytree(good, case)
            for src in (SELFTEST / m).rglob("*"):
                if src.is_file():
                    dst = case / src.relative_to(SELFTEST / m)
                    dst.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy(src, dst)
            save_head = globals()["check_url_head"]
            globals()["check_url_head"] = lambda url: None
            try:
                failed = False
                try:
                    verify(case, "9.9.9", sums)
                except PinError as e:
                    failed = True
                    print(f"self-test: mutant {m} rejected ({e})")
            finally:
                globals()["check_url_head"] = save_head
            if not failed:
                raise PinError(f"self-test: mutant {m} ACCEPTED")
        print(f"self-test: all {len(mutants)} mutants rejected")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main(argv):
    if "--self-test" in argv:
        try:
            self_test()
        except PinError as e:
            print(f"SELF-TEST FAIL: {e}", file=sys.stderr)
            return 1
        print("SELF-TEST OK")
        return 0
    tag = argv[1] if len(argv) > 1 and not argv[1].startswith("-") else "v0.2.0"
    ver = tag[1:] if tag.startswith("v") else tag
    try:
        sums = fetch_checksums(tag)
        verify(ROOT / "packaging", ver, sums)
    except PinError as e:
        print(f"FAIL: {e}", file=sys.stderr)
        return 1
    print(f"OK: all packaging entries bind v{ver} URLs to checksums.txt SHAs")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
