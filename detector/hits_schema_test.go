package detector_test

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/pauljones0/findbtc/detector"
)

// Conformance of `-json` output against the published versioned schema
// (schema/hits-v1.json, Goal 11). The test reads the schema file itself,
// so a Detection struct change that drifts from the schema fails here.
//
// The validator below implements only the JSON Schema subset the published
// schema uses ($ref, type, required, properties, items, enum, minimum,
// additionalProperties); checkSchemaKeywords fails the test if the schema
// ever grows a keyword the validator does not understand, instead of
// silently skipping it.

const hitsSchemaPath = "../schema/hits-v1.json"

// schemaKeywords is the full set of keywords the validator implements.
// Metadata keywords are accepted and ignored; all others must be understood.
var schemaKeywords = map[string]bool{
	"$schema": true, "$id": true, "$comment": true,
	"title": true, "description": true, "$defs": true,
	"$ref": true, "type": true, "required": true,
	"properties": true, "items": true, "enum": true,
	"minimum": true, "additionalProperties": true,
}

type schemaValidator struct {
	root map[string]any
}

func loadHitsSchema(t *testing.T) *schemaValidator {
	t.Helper()
	raw, err := os.ReadFile(hitsSchemaPath)
	if err != nil {
		t.Fatalf("read schema: %v", err)
	}
	var root map[string]any
	if err := json.Unmarshal(raw, &root); err != nil {
		t.Fatalf("parse schema: %v", err)
	}
	v := &schemaValidator{root: root}
	v.checkKeywords(t, root, "#")
	return v
}

// checkKeywords walks the schema and fails on any keyword outside the
// implemented subset, so silent validator gaps become test failures.
func (v *schemaValidator) checkKeywords(t *testing.T, schema map[string]any, path string) {
	t.Helper()
	for kw := range schema {
		if !schemaKeywords[kw] {
			t.Fatalf("schema %s uses keyword %q the test validator does not implement", path, kw)
		}
	}
	if ref, ok := schema["$ref"].(string); ok && ref != "" {
		return // referenced schema is checked via $defs walk below
	}
	if props, ok := schema["properties"].(map[string]any); ok {
		for name, sub := range props {
			subMap, ok := sub.(map[string]any)
			if !ok {
				t.Fatalf("schema %s property %q is not an object", path, name)
			}
			v.checkKeywords(t, subMap, path+"/properties/"+name)
		}
	}
	if items, ok := schema["items"].(map[string]any); ok {
		v.checkKeywords(t, items, path+"/items")
	}
	if ap, ok := schema["additionalProperties"].(map[string]any); ok {
		v.checkKeywords(t, ap, path+"/additionalProperties")
	}
	if defs, ok := schema["$defs"].(map[string]any); ok {
		for name, sub := range defs {
			subMap, ok := sub.(map[string]any)
			if !ok {
				t.Fatalf("schema $defs %q is not an object", name)
			}
			v.checkKeywords(t, subMap, "#/$defs/"+name)
		}
	}
}

func (v *schemaValidator) validateLine(t *testing.T, line []byte) error {
	t.Helper()
	var val any
	if err := json.Unmarshal(line, &val); err != nil {
		return fmt.Errorf("line is not valid JSON: %v", err)
	}
	return v.validate(val, v.root, "$")
}

func (v *schemaValidator) resolve(ref string) (map[string]any, error) {
	const prefix = "#/$defs/"
	if !strings.HasPrefix(ref, prefix) {
		return nil, fmt.Errorf("unsupported $ref %q (only %s* resolvable)", ref, prefix)
	}
	defs, _ := v.root["$defs"].(map[string]any)
	sub, _ := defs[strings.TrimPrefix(ref, prefix)].(map[string]any)
	if sub == nil {
		return nil, fmt.Errorf("unresolvable $ref %q", ref)
	}
	return sub, nil
}

func (v *schemaValidator) validate(val any, schema map[string]any, path string) error {
	if ref, ok := schema["$ref"].(string); ok && ref != "" {
		sub, err := v.resolve(ref)
		if err != nil {
			return err
		}
		return v.validate(val, sub, path)
	}
	if typ, ok := schema["type"].(string); ok && typ != "" {
		if err := checkJSONType(val, typ, path); err != nil {
			return err
		}
	}
	if enum, ok := schema["enum"].([]any); ok {
		matched := false
		for _, allowed := range enum {
			if reflect.DeepEqual(val, allowed) {
				matched = true
				break
			}
		}
		if !matched {
			return fmt.Errorf("%s: %v is not one of %v", path, val, enum)
		}
	}
	if min, ok := schema["minimum"].(float64); ok {
		num, ok := val.(float64)
		if !ok {
			return fmt.Errorf("%s: minimum applies to numbers, got %T", path, val)
		}
		if num < min {
			return fmt.Errorf("%s: %v is below minimum %v", path, num, min)
		}
	}
	if obj, ok := val.(map[string]any); ok {
		if req, ok := schema["required"].([]any); ok {
			for _, r := range req {
				name, _ := r.(string)
				if _, present := obj[name]; !present {
					return fmt.Errorf("%s: required property %q missing", path, name)
				}
			}
		}
		props, _ := schema["properties"].(map[string]any)
		for name, subVal := range obj {
			sub, known := props[name].(map[string]any)
			if !known {
				switch ap := schema["additionalProperties"].(type) {
				case nil:
					continue
				case bool:
					if !ap {
						return fmt.Errorf("%s: unknown property %q", path, name)
					}
				case map[string]any:
					if err := v.validate(subVal, ap, path+"."+name); err != nil {
						return err
					}
				default:
					return fmt.Errorf("%s: bad additionalProperties for %q", path, name)
				}
				continue
			}
			if err := v.validate(subVal, sub, path+"."+name); err != nil {
				return err
			}
		}
	}
	if arr, ok := val.([]any); ok {
		if items, ok := schema["items"].(map[string]any); ok {
			for i, elem := range arr {
				if err := v.validate(elem, items, fmt.Sprintf("%s[%d]", path, i)); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func checkJSONType(val any, typ, path string) error {
	switch typ {
	case "string":
		if _, ok := val.(string); !ok {
			return fmt.Errorf("%s: expected string, got %T", path, val)
		}
	case "boolean":
		if _, ok := val.(bool); !ok {
			return fmt.Errorf("%s: expected boolean, got %T", path, val)
		}
	case "number":
		if _, ok := val.(float64); !ok {
			return fmt.Errorf("%s: expected number, got %T", path, val)
		}
	case "integer":
		num, ok := val.(float64)
		if !ok || num != math.Trunc(num) {
			return fmt.Errorf("%s: expected integer, got %v", path, val)
		}
	case "array":
		if _, ok := val.([]any); !ok {
			return fmt.Errorf("%s: expected array, got %T", path, val)
		}
	case "object":
		if _, ok := val.(map[string]any); !ok {
			return fmt.Errorf("%s: expected object, got %T", path, val)
		}
	default:
		return fmt.Errorf("%s: validator does not implement type %q", path, typ)
	}
	return nil
}

// validateDetections marshals each detection exactly as `-json` does and
// validates every line against the schema.
func (v *schemaValidator) validateDetections(t *testing.T, dts []detector.Detection) {
	t.Helper()
	if len(dts) == 0 {
		t.Fatal("no detections to validate: fixture or scan produced nothing")
	}
	for i, d := range dts {
		line, err := json.Marshal(d)
		if err != nil {
			t.Fatalf("detection %d: marshal: %v", i, err)
		}
		if err := v.validateLine(t, line); err != nil {
			t.Errorf("detection %d fails schema: %v\nline: %s", i, err, line)
		}
	}
}

func scanFixture(t *testing.T, path string) []detector.Detection {
	t.Helper()
	recorder := &detectionRecorder{}
	if err := detector.Scan(0, path, recorder.OnDetection, recorder.OnProgress); err != nil {
		t.Fatalf("scan %s: %v", path, err)
	}
	return recorder.detections
}

// TestHitsSchemaLiveScans validates genuine scanner output: every detection
// from the existing raw and archive fixtures must conform.
func TestHitsSchemaLiveScans(t *testing.T) {
	v := loadHitsSchema(t)
	v.validateDetections(t, scanFixture(t, "./testdata/test_wallet.dat"))
	v.validateDetections(t, scanFixture(t, "./testdata/test_wallet.dat.zip"))
}

// TestHitsSchemaVariants covers one schema over all output variants: raw,
// carve (+hashes, +salvage), filesystem-guided (file_name), and
// owner-reveal (words). Each variant must validate.
func TestHitsSchemaVariants(t *testing.T) {
	v := loadHitsSchema(t)
	magicOff := int64(512)
	base := detector.Detection{
		Description: "Found 'wif' at ./evidence.img in 4kB block at byte offset 0",
		Needle:      "wif",
		Offset:      100,
		Target:      "./evidence.img",
		BlockOffset: 0,
		MatchLen:    51,
	}
	raw := base
	carved := base
	carved.CarvePath = "./carve/hit-000000.bin"
	carved.Carve = &detector.CarveInfo{Class: "bdb", MagicOffset: &magicOff, Size: 1048576, Entropy: 7.42}
	carvedNoMagic := carved
	carvedNoMagic.Carve = &detector.CarveInfo{Class: "high-entropy", Size: 4096, Entropy: 7.99}
	withHashes := carved
	withHashes.Hashes = []detector.CrackHash{
		{
			Format: "bitcoin-core-mkey", Hash: "$bitcoin$96$deadbeef$16$0102030405060708090a0b0c0d0e0f$2$1$1",
			KDF: "pbkdf2-hmac-sha512", Iterations: 25000, SaltHex: "0102030405060708", Method: 0, Offset: 2048,
		},
		{
			Format: "ethereum-keystore", KDF: "scrypt",
			Params: map[string]string{"n": "262144", "r": "8", "p": "1", "cipher": "aes-128-ctr"},
			Offset: 8192,
		},
	}
	fs := base
	fs.FileName = "wallets/wallet.dat"
	reveal := base
	reveal.Needle = "bip39-12"
	reveal.Words = []string{"abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract", "absurd", "abuse", "access", "accident"}
	salvageBDB := carved
	salvageBDB.CarvePath = "./carve/hit-000001.bin"
	salvageBDB.Salvage = &detector.SalvageInfo{
		Path: "./carve/hit-000001.salvage.db", Kind: "bdb", PageSize: 4096,
		Pages: []detector.SalvagePage{
			{PgNo: 0, Offset: 4096, Size: 4096, Kind: "bdb-meta"},
			{PgNo: 1, Offset: 8192, Size: 4096, Kind: "bdb-page"},
		},
		Runs:     []detector.SalvageRun{{StartOffset: 4096, Pages: 2}},
		Complete: true, Ordered: true,
	}
	salvageSQLite := base
	salvageSQLite.CarvePath = "./carve/hit-000002.bin"
	salvageSQLite.Salvage = &detector.SalvageInfo{
		Kind: "sqlite", PageSize: 4096,
		Pages: []detector.SalvagePage{
			{Offset: 0, Size: 4096, Kind: "sqlite-master"},
			{Offset: 12288, Size: 4096, Kind: "sqlite-btree"},
		},
		Runs:     []detector.SalvageRun{{StartOffset: 0, Pages: 1}, {StartOffset: 12288, Pages: 1}},
		Complete: false, Ordered: false,
	}
	v.validateDetections(t, []detector.Detection{
		raw, carved, carvedNoMagic, withHashes, fs, reveal, salvageBDB, salvageSQLite,
	})
}

// TestHitsSchemaNegativeControl mutates valid hits; every mutation must be
// rejected. If a mutation ever validates, the schema (or validator) is too
// loose to catch drift.
func TestHitsSchemaNegativeControl(t *testing.T) {
	v := loadHitsSchema(t)
	good := map[string]any{
		"description":  "Found 'wif' at ./evidence.img in 4kB block at byte offset 0",
		"needle":       "wif",
		"offset":       float64(100),
		"target":       "./evidence.img",
		"block_offset": float64(0),
		"match_length": float64(51),
	}
	line, err := json.Marshal(good)
	if err != nil {
		t.Fatalf("marshal control: %v", err)
	}
	if err := v.validateLine(t, line); err != nil {
		t.Fatalf("control line must validate, got: %v", err)
	}
	mutate := func(f func(m map[string]any)) []byte {
		m := map[string]any{}
		for k, val := range good {
			m[k] = val
		}
		f(m)
		out, err := json.Marshal(m)
		if err != nil {
			t.Fatalf("marshal mutation: %v", err)
		}
		return out
	}
	cases := map[string][]byte{
		"missing required offset": mutate(func(m map[string]any) { delete(m, "offset") }),
		"wrong type for offset":   mutate(func(m map[string]any) { m["offset"] = "100" }),
		"fractional integer":      mutate(func(m map[string]any) { m["offset"] = 100.5 }),
		"negative offset":         mutate(func(m map[string]any) { m["offset"] = float64(-1) }),
		"unknown top-level field": mutate(func(m map[string]any) { m["secret_material"] = "x" }),
		"bad carve shape": mutate(func(m map[string]any) {
			m["carve"] = map[string]any{"size": float64(10), "entropy_bits": 7.0}
		}),
		"bad hash enum": mutate(func(m map[string]any) {
			m["hashes"] = []any{map[string]any{"format": "md5", "kdf": "none", "offset": float64(0)}}
		}),
		"bad salvage page kind": mutate(func(m map[string]any) {
			m["salvage"] = map[string]any{
				"kind": "bdb", "page_size": float64(4096),
				"pages": []any{map[string]any{"offset": float64(0), "size": float64(4096), "kind": "bdb-table"}},
				"runs":  []any{}, "complete": false, "ordered": true,
			}
		}),
		"words not strings": mutate(func(m map[string]any) { m["words"] = []any{float64(1)} }),
	}
	for name, bad := range cases {
		if err := v.validateLine(t, bad); err == nil {
			t.Errorf("negative control %q validated but must be rejected: %s", name, bad)
		}
	}
}
