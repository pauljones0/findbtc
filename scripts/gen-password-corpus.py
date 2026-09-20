#!/usr/bin/env python3
"""Generate the Goal 33 password-handoff corpus (deterministic, tiny KDFs).

Outputs land in testdata/password-handoff/:
  core-bdb-mkey.bin     real Bitcoin Core mkey value (BTCRecover's
  core-sqlite-mkey.bin  bitcoincore-*.dat test wallets; public test password)
  eth-pbkdf2.json       generated Web3 keystore, PBKDF2 c=4096,
                        password RiverStone2019 (3 hit-context tokens)
  eth-scrypt.json       generated Web3 keystore, scrypt N=262144/r=8/p=1
                        (geth defaults: real-world cost), password tide-harbor-42
  wallet-context.bin    fake carve: owner notes holding the password parts
                        (lowercase river/stone so findbtc mutations are
                        required) plus distractor words
  passwords.txt         tiny crack list holding every corpus password

All passwords here are public test vectors (btcr-test-password is
BTCRecover's own published test password; the rest are invented for
this corpus). Nothing real, nothing fund-bearing.

Usage:
  gen-password-corpus.py [--check]   # --check: regen to temp and diff
"""
import argparse
import hashlib
import json
import os
import random
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

OUT_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "testdata", "password-handoff")

SEED = 0x5533  # fixed, deterministic

# Real CMasterKey values from BTCRecover's test wallets (the same bytes
# detector/mkey_test.go pins as oracles). Public fixtures; the wallets'
# password is BTCRecover's published test password "btcr-test-password".
# Trailing 00 on the SQLite value is the empty otherParams newer wallets
# append; the parser ignores it.
REAL_MKEY_BDB_HEX = (
    "302e2c3b9b58e9b33c9799b4472e83c136e6246120c45e390daa6a57476e7fbe4f57d8"
    "3f79d75f9b4c1db680fe5a846cb8084593aff5639179c70000000044090100")
REAL_MKEY_SQLITE_HEX = (
    "30fd43fb19505f4d200ee82c0c196520dad57eb66f53d15a0b95cb3514518ef83ce87b7"
    "43ccafef31e1953a7fef0f88f420811a9673bb6d7542800000000e014040000")

PBKDF2_PASSWORD = "RiverStone2019"   # tokens: River + Stone + 2019
PBKDF2_ITERS = 4096                  # tiny KDF: CI-crackable, still real PBKDF2
SCRYPT_PASSWORD = "tide-harbor-42"
SCRYPT_N, SCRYPT_R, SCRYPT_P = 262144, 8, 1  # geth defaults: real-world cost

# Owner-notes prose. river/stone appear lowercase only, so the Capitalized
# mutation in findbtc -tokenlist is load-bearing: without it no BTCRecover
# combination can rebuild RiverStone2019. 2019 appears verbatim. Ten words
# here plus the "hint" wrapper word keep the --max-tokens 3 search near
# 23k guesses (~1 min); every added line multiplies combinations, which
# is why the runbook says to trim.
CONTEXT_WORDS = ("laptop river backup stone valley 2019 harbor pilot "
                 "retry notes").split()

PASSWORDS_TXT = "\n".join([
    "wrong-password-one",
    "btcr-test-password",   # both core mkey records
    PBKDF2_PASSWORD,        # eth-pbkdf2.json (also the tokenlist target)
    SCRYPT_PASSWORD,        # eth-scrypt.json
    "wrong-password-two",
]) + "\n"


def make_keystore(password, kdf, kdfparams, rng):
    from Crypto.Cipher import AES
    from Crypto.Hash import keccak
    # Salts avoid 0x00 bytes: John 1.9.0-jumbo-1 sizes the scrypt salt with
    # strlen (ethereum_fmt_plug.c), so a zero byte truncates it and the hash
    # can never crack there. PBKDF2-side John/hashcat handle 0x00 fine; the
    # corpus keeps both salts clean so one rule covers every tool.
    while True:
        salt = bytes(rng.randrange(256) for _ in range(32))
        if b"\x00" not in salt:
            break
    iv = bytes(rng.randrange(256) for _ in range(16))
    privkey = bytes(rng.randrange(256) for _ in range(32))
    if kdf == "pbkdf2":
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(),
                                 salt, kdfparams["c"], 32)
    else:
        dk = hashlib.scrypt(password.encode(), salt=salt,
                            n=kdfparams["n"], r=kdfparams["r"],
                            p=kdfparams["p"], dklen=32,
                            maxmem=512 << 20)  # N=262144 needs ~256 MiB
    ct = AES.new(dk[:16], AES.MODE_CTR, nonce=b"", initial_value=int.from_bytes(iv, "big")).encrypt(privkey)
    mac = keccak.new(digest_bits=256, data=dk[16:32] + ct).hexdigest()
    addr = "".join("%02x" % rng.randrange(256) for _ in range(20))
    return {
        "address": addr,
        "crypto": {
            "cipher": "aes-128-ctr",
            "ciphertext": ct.hex(),
            "cipherparams": {"iv": iv.hex()},
            "kdf": kdf,
            "kdfparams": dict(kdfparams, salt=salt.hex()),
            "mac": mac,
        },
        "id": "00000000-0000-4000-8000-%012x" % rng.randrange(1 << 48),
        "version": 3,
    }


def build(out_dir):
    rng = random.Random(SEED)
    os.makedirs(out_dir, exist_ok=True)
    files = {}
    files["core-bdb-mkey.bin"] = bytes.fromhex(REAL_MKEY_BDB_HEX)
    files["core-sqlite-mkey.bin"] = bytes.fromhex(REAL_MKEY_SQLITE_HEX)
    files["eth-pbkdf2.json"] = (json.dumps(make_keystore(
        PBKDF2_PASSWORD, "pbkdf2",
        {"dklen": 32, "c": PBKDF2_ITERS, "prf": "hmac-sha256"}, rng),
        indent=2) + "\n").encode()
    files["eth-scrypt.json"] = (json.dumps(make_keystore(
        SCRYPT_PASSWORD, "scrypt",
        {"dklen": 32, "n": SCRYPT_N, "r": SCRYPT_R, "p": SCRYPT_P}, rng),
        indent=2) + "\n").encode()
    # A carve-like blob: binary padding around owner notes, so the
    # tokenlist generator must pick words out of binary context like the
    # real thing. The wrapper adds exactly one word ("hint").
    notes = ("pw hint: %s !!\n" % " ".join(CONTEXT_WORDS)).encode()
    files["wallet-context.bin"] = (b"\x00" * 64 + b"\xff\xfe\x00"
                                   + notes + b"\x00" * 32)
    files["passwords.txt"] = PASSWORDS_TXT.encode()
    for name, data in files.items():
        with open(os.path.join(out_dir, name), "wb") as f:
            f.write(data)
    return sorted(files)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()
    if not args.check:
        for name in build(OUT_DIR):
            print("wrote testdata/password-handoff/" + name)
        return
    with tempfile.TemporaryDirectory() as tmp:
        names = build(tmp)
        bad = 0
        for name in names:
            with open(os.path.join(tmp, name), "rb") as f:
                fresh = f.read()
            committed = os.path.join(OUT_DIR, name)
            try:
                with open(committed, "rb") as f:
                    old = f.read()
            except FileNotFoundError:
                print("missing committed file: " + name)
                bad += 1
                continue
            if fresh != old:
                print("corpus drift: %s differs from committed copy" % name)
                bad += 1
        if bad:
            sys.exit(1)
        print("corpus matches committed files (%d files)" % len(names))


if __name__ == "__main__":
    main()
