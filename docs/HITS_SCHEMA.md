# Hits JSON schema

`findbtc -json` prints one JSON object per line (JSONL). Every downstream
mode (`-report`, `-dfxml`, `-watch`, carves) consumes this interchange,
so its shape is a compatibility contract, not an implementation detail.

The versioned contract lives at [schema/hits-v1.json](../schema/hits-v1.json)
(JSON Schema draft 2020-12). One schema covers every output variant:
variant-only fields are optional, and a missing optional field always
means "this variant does not produce it", never "unknown".

## Variant matrix

| Field | Raw scan | `-fs` scan | `--reveal` | `-extract-dir` |
|---|---|---|---|---|
| `description`, `needle`, `offset`, `target`, `block_offset`, `match_length` | always | always | always | always |
| `file_name` | never | when known | as per scan | as per scan |
| `words` | never | never | BIP39 hits only | as per scan |
| `carve_path`, `carve` | never | never | never | when carving succeeds |
| `hashes` | never | never | never | when mkey/keystore records found |
| `salvage` | never | never | never | when a `.salvage.db` is written |
| `fingerprint` | on `-patch` scans (history key); `-walk` sweeps carry the walk key when fingerprintable | never | as per scan | as per scan |
| `commit`, `path`, `line` | on `-patch` scans, when inside a commit/diff/added-or-context line | never | as per scan | as per scan |

Privacy notes: `words` appears only under the owner `--reveal` opt-in;
`hashes` carries cracker inputs, never wallet ciphertext.

## Stability policy (ties to Goal 19)

- Within `hits-vN`, only additive, backwards-compatible changes are
  allowed: new optional properties, new `carve.class` labels, new enum
  values where the schema marks the set extensible.
- Removing or renaming a property, changing a type, or turning an
  optional field required is a breaking change and requires `hits-v(N+1)`.
- The committed conformance test (`detector/hits_schema_test.go`)
  validates genuine scanner output plus every variant against the
  published schema file, with a negative control: a `Detection` change
  that drifts from the schema fails the suite.

## Validating your own output

Any draft 2020-12 validator works, e.g. Python:

    python3 -c "
    import json, sys
    from jsonschema import Draft202012Validator
    v = Draft202012Validator(json.load(open('schema/hits-v1.json')))
    for i, line in enumerate(open(sys.argv[1])):
        v.validate(json.loads(line))
    " hits.jsonl
