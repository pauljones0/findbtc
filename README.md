# FindBTC

Scans devices for remnants of bitcoin wallet files. 

The tool can find wallets even if;

- The wallet was deleted, but not overwritten
- The file system is corrupted and inaccessible
- The device has been reformatted
- The wallet has been partially overwritten
- The wallet is inside a .zip or .tar.gz file, including 
  nested in multiple levels of compressed files
- The zip's central directory is lost: single entries are still carved from
  local file headers

It looks for byte traces of legacy wallets (`bestblock`, `defaultkey`,
`keymeta`, `hdseed`, `crypted_key`, ...), modern descriptor wallets
(`walletdescriptor`, `activeblock`), checksum-validated BIP39 seed phrases
(12/15/18/21/24 words), WIF and extended (`xprv`/`xpub`/...) keys with
base58check validation, Ethereum keystore files (validated by structure),
and the `wallet.dat` file name. Only key and phrase
types are ever printed; the secrets themselves stay out of logs and output.

## Installing

Download a ready-made binary for linux, macOS or Windows (x86-64 and ARM64)
from the [releases page](https://github.com/jakewins/findbtc/releases), then
verify its checksum:

    sha256sum -c checksums.txt

Release artifacts also carry Sigstore build-provenance attestations, verifiable
with `gh attestation verify`. On macOS and Linux with Homebrew:

    brew tap jakewins/findbtc
    brew install --cask findbtc

Since this is potentially sensitive software, you are encouraged to build it
from source instead. That requires Go 1.24 or later, see
https://golang.org/doc/install

    go install github.com/jakewins/findbtc@latest
    sudo findbtc /dev/sda


## Usage

    findbtc [-s start-offset] [-json] [-extract-dir DIR [-context BYTES]] DEVICE

    # Eg. scan a disk, printing human-readable hits:

    findbtc /dev/sda

    # Eg. machine-readable hits with exact byte offsets:

    findbtc -json /dev/sda > hits.jsonl

    # Eg. carve 1MB around every hit into ./carve/ for forensic follow-up:

    findbtc -extract-dir ./carve /dev/sda

Detections print to stdout; logs, progress and the final `[COMPLETE]` line go
to stderr, so `-json` output stays parseable. Each carved hit lands in
`hit-NNNNNN.bin` with a `hit-NNNNNN.json` sidecar holding the same detection
plus a classification of the carved bytes (`sqlite`, `bdb`, `gzip`, `zip`,
`text`, `high-entropy`, ...).
Never carve onto the device being scanned.

Unreadable sectors are retried, then skipped and logged with their byte
ranges, so one bad spot never aborts a scan. For long scans, `-checkpoint
FILE` journals progress every 1MB; if the run is interrupted, `-resume`
continues from the journal instead of starting over.

## License

GPL
