#!/usr/bin/env python3
"""Generate the Goal 41 owner-rehearsal media (deterministic, synthetic).

Writes into OUT/media/: owner.img (marker + public testnet tprv +
public abandon-about test mnemonic), hostile-named marker copies,
a benign decoy, an unreadable-candidate file, and a truncated file.
Also writes OUT/media/secrets.env holding the embedded secret
strings for the harness's no-leak assertions (sourced, never
printed). Prints only the manifest (filenames) to stdout.

All key material is public test vectors (BIP32-style testnet tprv,
BIP39 zero-entropy mnemonic); nothing real, nothing fund-bearing.
"""
import os
import random
import sys

TPRV = "tprv8ZgxMBicQKsPdGnGVznT7VGLJ7LC4FEUy8qx6fLYEV7ReyaS47XcTSH8nEqYxwayjp9heARX8gKnEuSiXanXVXM82B4MguxSRJceAzecMUR"
MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
MARKER = b"bestblock"

SEED = 0x4131


def fill(rng, n):
    return bytes(rng.randrange(256) for _ in range(n))


def place(buf, off, payload):
    buf[off:off + len(payload)] = payload


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "."
    media = os.path.join(out, "media")
    os.makedirs(media, exist_ok=True)
    rng = random.Random(SEED)

    owner = bytearray(fill(rng, 64 * 1024))
    place(owner, 4096, MARKER)
    place(owner, 12288, b" " + TPRV.encode() + b" ")
    place(owner, 20480, b"\n" + MNEMONIC.encode() + b"\n")
    with open(os.path.join(media, "owner.img"), "wb") as f:
        f.write(owner)

    hostile = bytearray(fill(rng, 8 * 1024))
    place(hostile, 4096, MARKER)
    for name in ("spaced name.img", "dollar$'quote.img",
                 "line\nbreak.img", "café.img"):
        with open(os.path.join(media, name), "wb") as f:
            f.write(hostile)

    decoy = (b"The quick brown fox jumps over the lazy dog. " * 200)[:8192]
    with open(os.path.join(media, "decoy.bin"), "wb") as f:
        f.write(decoy)

    locked = bytearray(fill(rng, 8 * 1024))
    place(locked, 4096, MARKER)
    with open(os.path.join(media, "locked.bin"), "wb") as f:
        f.write(locked)

    with open(os.path.join(media, "cut.img"), "wb") as f:
        f.write(MARKER + fill(rng, 100))

    with open(os.path.join(media, "secrets.env"), "w") as f:
        f.write('REH_TPRV="%s"\n' % TPRV)
        f.write('REH_MNEMONIC="%s"\n' % MNEMONIC)

    for name in sorted(os.listdir(media)):
        print(name)


if __name__ == "__main__":
    main()
