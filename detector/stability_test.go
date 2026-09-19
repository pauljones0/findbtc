package detector_test

import (
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/pauljones0/findbtc/detector"
)

// The Detection JSON wire format is frozen per schema/hits-v1.json (Tier
// 1 stability): struct tags must equal the schema's property names, and
// required schema keys must equal the tags without `omitempty`. A change
// here means a wire break — bump the schema version and update this
// mapping instead of editing tags in place.
func TestDetectionJSONTagsFrozen(t *testing.T) {
	v := loadHitsSchema(t)
	defs, ok := v.root["$defs"].(map[string]any)
	if !ok {
		t.Fatal("schema has no $defs")
	}
	frozen := []struct {
		name string
		typ  reflect.Type
		node map[string]any
	}{
		{"Detection", reflect.TypeOf(detector.Detection{}), v.root},
		{"CarveInfo", reflect.TypeOf(detector.CarveInfo{}), defNode(t, defs, "carveInfo")},
		{"CrackHash", reflect.TypeOf(detector.CrackHash{}), defNode(t, defs, "crackHash")},
		{"SalvageInfo", reflect.TypeOf(detector.SalvageInfo{}), defNode(t, defs, "salvageInfo")},
		{"SalvagePage", reflect.TypeOf(detector.SalvagePage{}), defNode(t, defs, "salvagePage")},
		{"SalvageRun", reflect.TypeOf(detector.SalvageRun{}), defNode(t, defs, "salvageRun")},
	}
	for _, f := range frozen {
		props, ok := f.node["properties"].(map[string]any)
		if !ok {
			t.Errorf("%s: schema node has no properties", f.name)
			continue
		}
		var wantProps []string
		for name := range props {
			wantProps = append(wantProps, name)
		}
		var wantRequired []string
		if req, ok := f.node["required"].([]any); ok {
			for _, r := range req {
				wantRequired = append(wantRequired, r.(string))
			}
		}
		var gotProps, gotRequired []string
		for i := 0; i < f.typ.NumField(); i++ {
			field := f.typ.Field(i)
			if !field.IsExported() {
				continue
			}
			tag := field.Tag.Get("json")
			name, opt, _ := strings.Cut(tag, ",")
			if name == "" || name == "-" {
				t.Errorf("%s.%s: exported field without a json name is not allowed on the frozen wire format", f.name, field.Name)
				continue
			}
			gotProps = append(gotProps, name)
			if !strings.Contains(opt, "omitempty") {
				gotRequired = append(gotRequired, name)
			}
		}
		sort.Strings(wantProps)
		sort.Strings(gotProps)
		sort.Strings(wantRequired)
		sort.Strings(gotRequired)
		if !reflect.DeepEqual(gotProps, wantProps) {
			t.Errorf("%s: json tags %v do not match schema properties %v (wire format frozen: bump the schema version instead)", f.name, gotProps, wantProps)
		}
		if !reflect.DeepEqual(gotRequired, wantRequired) {
			t.Errorf("%s: non-omitempty tags %v do not match schema required %v", f.name, gotRequired, wantRequired)
		}
	}
}

func defNode(t *testing.T, defs map[string]any, name string) map[string]any {
	t.Helper()
	node, ok := defs[name].(map[string]any)
	if !ok {
		t.Fatalf("schema $defs has no %q", name)
	}
	return node
}
