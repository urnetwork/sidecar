package dnsservice

import (
	"errors"
	"strings"
	"testing"

	"github.com/miekg/dns"
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

// A fresh P-256 DNSKEY for zone.example. with flags, as dns.yml writes it: its RDATA alone.
func trustAnchorTestRdata(t *testing.T, flags uint16) string {
	t.Helper()
	key := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: "zone.example.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
		Flags:     flags,
		Protocol:  3,
		Algorithm: dns.ECDSAP256SHA256,
	}
	if _, err := key.Generate(256); err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(strings.TrimPrefix(key.String(), key.Hdr.String()))
}

// trust_anchors keys by canonical root and holds only key-signing keys of a root dns.yml serves.
func TestDnsSettingsReadTrustAnchors(t *testing.T) {
	ksk := trustAnchorTestRdata(t, dns.ZONE|dns.SEP)
	settings, err := LoadDnsSettings([]byte(rootRecordsTestYaml("trust_anchors:\n  Zone.Example: ['" + ksk + "']\n")))
	if err != nil {
		t.Fatal(err)
	}
	if anchors := settings.TrustAnchors["zone.example."]; len(anchors) != 1 {
		t.Fatalf("anchors %+v", settings.TrustAnchors)
	}
	zsk := trustAnchorTestRdata(t, dns.ZONE)
	for _, more := range []string{
		"trust_anchors:\n  other.example: ['" + ksk + "']\n",
		"trust_anchors:\n  zone.example: ['" + zsk + "']\n",
		"trust_anchors:\n  zone.example: ['not a key']\n",
	} {
		if _, err := LoadDnsSettings([]byte(rootRecordsTestYaml(more))); !errors.Is(err, ErrDnsSettingsRefused) {
			t.Errorf("%.60s: %v", strings.TrimSpace(more), err)
		}
	}
}
