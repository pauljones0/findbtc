package detector

import (
	"bytes"
	"encoding/xml"
	"strings"
	"testing"
)

type dfxmlProbe struct {
	Version string `xml:"version,attr"`
	Files   []struct {
		Filename string `xml:"filename"`
		Runs     struct {
			Runs []struct {
				ImgOffset int64 `xml:"img_offset,attr"`
				Len       int   `xml:"len,attr"`
			} `xml:"byte_run"`
		} `xml:"byte_runs"`
		Hit struct {
			Needle      string `xml:"needle,attr"`
			BlockOffset int64  `xml:"block_offset,attr"`
			Target      string `xml:"target,attr"`
			File        string `xml:"file,attr"`
			Carve       string `xml:"carve,attr"`
			Description string `xml:"description,attr"`
		} `xml:"detection"`
	} `xml:"fileobject"`
}

func writeDFXMLProbe(t *testing.T, dets []Detection) dfxmlProbe {
	t.Helper()
	var buf bytes.Buffer
	if err := WriteDFXML(&buf, "test", dets); err != nil {
		t.Fatal(err)
	}
	var p dfxmlProbe
	if err := xml.Unmarshal(buf.Bytes(), &p); err != nil {
		t.Fatalf("output is not well-formed XML: %s\n%s", err, buf.String())
	}
	return p
}

func TestDFXMLRoundTrip(t *testing.T) {
	dets := []Detection{
		{Description: "bip39-12 at img.E01", Needle: "bip39-12",
			Offset: 50001, Target: "img.E01", BlockOffset: 49152, MatchLen: 93},
		{Description: "descriptor <segwit> & more", Needle: "descriptor",
			Offset: 200, Target: "vol.img", BlockOffset: 0, MatchLen: 64,
			FileName: "wallet.dat", CarvePath: "carves/hit-000001.bin"},
	}
	p := writeDFXMLProbe(t, dets)
	if p.Version != DFXMLSchemaVersion {
		t.Fatalf("schema version %q", p.Version)
	}
	if len(p.Files) != 2 {
		t.Fatalf("got %d fileobjects, want 2", len(p.Files))
	}
	f0, f1 := p.Files[0], p.Files[1]
	if f0.Filename != "img.E01" || len(f0.Runs.Runs) != 1 ||
		f0.Runs.Runs[0].ImgOffset != 50001 || f0.Runs.Runs[0].Len != 93 {
		t.Fatalf("hit 0 location %+v", f0)
	}
	if f0.Hit.Needle != "bip39-12" || f0.Hit.Description != dets[0].Description ||
		f0.Hit.BlockOffset != 49152 {
		t.Fatalf("hit 0 detail %+v", f0.Hit)
	}
	// XML-special characters survive the round trip.
	if f1.Hit.Description != "descriptor <segwit> & more" {
		t.Fatalf("hit 1 description %q", f1.Hit.Description)
	}
	if f1.Hit.File != "wallet.dat" || f1.Hit.Carve != "carves/hit-000001.bin" {
		t.Fatalf("hit 1 detail %+v", f1.Hit)
	}
}

func TestDFXMLEmpty(t *testing.T) {
	p := writeDFXMLProbe(t, nil)
	if len(p.Files) != 0 {
		t.Fatalf("got %d fileobjects, want 0", len(p.Files))
	}
}

// Seed words never leave in DFXML, even when the input came from --reveal.
func TestDFXMLNeverExportsWords(t *testing.T) {
	var buf bytes.Buffer
	dets := []Detection{{Description: "x", Needle: "bip39-12", Offset: 1,
		Target: "t", MatchLen: 10, Words: []string{"abandon", "about"}}}
	if err := WriteDFXML(&buf, "test", dets); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "abandon") {
		t.Fatal("DFXML contains seed words")
	}
}
