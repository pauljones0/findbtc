// DFXML export: detections as Digital Forensics XML so case tools that
// speak DFXML (fiwalk-style pipelines, feature-file annotators) can
// consume findbtc hits with byte-precise locations.
package detector

import (
	"encoding/xml"
	"io"
	"time"
)

// DFXMLSchemaVersion is the dfxml_schema version the output adheres to.
const DFXMLSchemaVersion = "1.1.1"

// FindbtcDFXMLNS carries findbtc-specific hit detail that DFXML's
// fileobject has no native element for. The schema allows foreign
// namespaces after hashdigest (lax), so validators skip it cleanly.
const FindbtcDFXMLNS = "https://github.com/jakewins/findbtc/ns/dfxml#"

type dfxmlDoc struct {
	XMLName      xml.Name          `xml:"dfxml"`
	Xmlns        string            `xml:"xmlns,attr"`
	XmlnsFindbtc string            `xml:"xmlns:findbtc,attr"`
	Version      string            `xml:"version,attr"`
	Metadata     dfxmlMetadata     `xml:"metadata"`
	Files        []dfxmlFileObject `xml:"fileobject"`
}

type dfxmlMetadata struct {
	Tool     string `xml:"findbtc:tool"`
	Version  string `xml:"findbtc:version"`
	Exported string `xml:"findbtc:exported"`
}

type dfxmlFileObject struct {
	Filename string         `xml:"filename"`
	Runs     dfxmlByteRuns  `xml:"byte_runs"`
	Hit      dfxmlHitDetail `xml:"findbtc:detection"`
}

type dfxmlByteRuns struct {
	Runs []dfxmlByteRun `xml:"byte_run"`
}

type dfxmlByteRun struct {
	ImgOffset int64 `xml:"img_offset,attr"`
	Len       int   `xml:"len,attr"`
}

type dfxmlHitDetail struct {
	Needle      string `xml:"needle,attr"`
	BlockOffset int64  `xml:"block_offset,attr"`
	Target      string `xml:"target,attr"`
	File        string `xml:"file,attr,omitempty"`
	Carve       string `xml:"carve,attr,omitempty"`
	Description string `xml:"description,attr"`
}

// WriteDFXML emits dets as a DFXML 1.1.1 document: one fileobject per
// hit, naming the source image with a byte_run at the hit offset.
// Seed words are never exported: Words stay out even for --reveal input.
func WriteDFXML(w io.Writer, toolVersion string, dets []Detection) error {
	doc := dfxmlDoc{
		Xmlns:        "http://www.forensicswiki.org/wiki/Category:Digital_Forensics_XML",
		XmlnsFindbtc: FindbtcDFXMLNS,
		Version:      DFXMLSchemaVersion,
		Metadata: dfxmlMetadata{
			Tool:     "findbtc",
			Version:  toolVersion,
			Exported: time.Now().UTC().Format(time.RFC3339),
		},
	}
	for _, d := range dets {
		doc.Files = append(doc.Files, dfxmlFileObject{
			Filename: d.Target,
			Runs:     dfxmlByteRuns{Runs: []dfxmlByteRun{{ImgOffset: d.Offset, Len: d.MatchLen}}},
			Hit: dfxmlHitDetail{
				Needle:      d.Needle,
				BlockOffset: d.BlockOffset,
				Target:      d.Target,
				File:        d.FileName,
				Carve:       d.CarvePath,
				Description: d.Description,
			},
		})
	}
	if _, err := io.WriteString(w, xml.Header); err != nil {
		return err
	}
	enc := xml.NewEncoder(w)
	enc.Indent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return err
	}
	_, err := io.WriteString(w, "\n")
	return err
}
