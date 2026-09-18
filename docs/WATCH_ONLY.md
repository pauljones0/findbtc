# Watch-only balance triage

You found an extended public key (`xpub`/`ypub`/`zpub`, or testnet
`tpub`/`upub`/`vpub`). It cannot spend funds, but it derives every address
in the wallet — so it answers "is there anything here worth pursuing?"
without touching private material. The instinctive move — pasting the key
into a block-explorer website — hands your entire wallet history to a
stranger and is the #1 phishing pattern in recovery. Do this instead:

1. Derive the addresses **locally** with `findbtc -watch` (offline).
2. Check the exported address list anywhere: your own node, a Tor-routed
   client, or — least private — a public explorer, one address at a time.

## Derive addresses

From a carve, a pasted key file, or a scan's `hits.jsonl` (whose carves are
searched automatically):

    findbtc -watch ./carve/hit-000003.bin -watch-out addrs.csv
    findbtc -watch hits.jsonl -watch-out addrs.csv
    findbtc -watch key.txt -watch-format json -watch-count 50 > addrs.json

Each run derives `-watch-count` addresses (default 20, the BIP44 gap limit)
on both the external (`0/i`) and change (`1/i`) chains. The script type
follows the key version per SLIP132:

| Version | Network | Addresses |
|---------|---------|-----------|
| xpub | mainnet | P2PKH (`1...`) |
| ypub | mainnet | P2SH-P2WPKH (`3...`) |
| zpub | mainnet | P2WPKH (`bc1q...`) |
| tpub | testnet | P2PKH (`m...`/`n...`) |
| upub | testnet | P2SH-P2WPKH (`2...`) |
| vpub | testnet | P2WPKH (`tb1q...`) |

The export carries addresses plus provenance (fingerprint, version,
chain/index/path, script) — never the extended key itself. The
fingerprint is `HASH160(pubkey)[:4]` in hex, the descriptor convention,
so you can match an export back to its source key.

Private extended keys (`xprv`, ...) are refused outright: findbtc never
derives from, stores, or prints private material. If your carve holds one,
move it to an offline machine and sweep to a fresh wallet.

## Optional balance lookup

`-balance-endpoint` queries an **Esplora-compatible** server
(`GET {endpoint}/address/:addr`) and fills the `balance_sats` column
(confirmed plus mempool). It is strictly opt-in: without the flag the
tool makes zero network calls (enforced by test).

    findbtc -watch key.txt -balance-endpoint http://localhost:50001 -watch-out addrs.csv

Consent warning: the endpoint operator learns every address you query,
which is your full wallet footprint. Prefer, in order:

1. **Your own node.** [Esplora](https://github.com/Blockstream/esplora)
   or a [mempool.space](https://github.com/mempool/mempool) backend
   against your own Bitcoin Core over `localhost` leaks nothing.
2. **Your node over Tor.** Point the endpoint at the daemon's onion
   address so network observers see only Tor traffic. findbtc honors the
   standard `HTTP_PROXY`/`HTTPS_PROXY` environment variables, so
   `HTTPS_PROXY=socks5://127.0.0.1:9050` routes lookups through Tor —
   but the endpoint server itself still sees the addresses.
3. **Someone else's server.** A public Esplora instance works with the
   same flag, at the cost of telling that operator your wallet. Never
   send an extended public key to any server — only individual
   addresses, and only as many as you need.

Lookups are sequential and best-effort: per-address failures print to
stderr, successes are still written, and unknown balances stay empty
rather than reading as zero.

## Limits

- Gap limit 20 covers standard wallets; heavily used wallets (exchanges,
  merchants) may need a higher `-watch-count` (max 10000).
- Only single-signature BIP32/44/49/84 layouts derive: multisig and
  script-path wallets need their full descriptors.
- An address list proves funds exist, not that you can spend them —
  spending still needs the seed or private keys the scan was hunting.
