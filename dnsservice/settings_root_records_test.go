package dnsservice

import (
	"errors"
	"strings"
	"testing"
)

// dns.yml with the three numbers §12.6 leaves open set, and more appended.
func rootRecordsTestYaml(more string) string {
	return `
roots: [zone.example]
signatures_per_second: 1
tcp: {connections_per_source: 1}
rrl: {responses_per_second: 1}
` + more
}

// root_records keys by canonical root and holds each root's own records.
func TestDnsSettingsReadRootRecords(t *testing.T) {
	settings, err := LoadDnsSettings([]byte(rootRecordsTestYaml(`
root_records:
  Zone.Example:
    report_mx: rpt.report.example
    glue: {ns1: [192.0.2.53, "2001:db8::53"]}
`)))
	if err != nil {
		t.Fatal(err)
	}
	records := settings.RootRecords["zone.example."]
	if records == nil || records.ReportMx != "rpt.report.example" || len(records.Glue["ns1"]) != 2 {
		t.Fatalf("root records %+v", settings.RootRecords)
	}
}

// A root no roots entry names, glue for an NS ns does not list, an address that is none, and an empty
// root's block are refused.
func TestDnsSettingsRefuseBadRootRecords(t *testing.T) {
	for _, more := range []string{
		"root_records:\n  other.example: {}\n",
		"root_records:\n  zone.example: {glue: {ns9: [192.0.2.1]}}\n",
		"root_records:\n  zone.example: {glue: {ns1: [not-an-address]}}\n",
		"root_records:\n  zone.example:\n",
	} {
		if _, err := LoadDnsSettings([]byte(rootRecordsTestYaml(more))); !errors.Is(err, ErrDnsSettingsRefused) {
			t.Errorf("%s: %v", strings.TrimSpace(more), err)
		}
	}
}
