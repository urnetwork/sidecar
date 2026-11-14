package dnsservice

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// ds_published (DNS-M7-04; D-DNS-5): empty by default, canonical once loaded, and only a root that has trust
// anchors, listed once.
func TestDnsSettingsReadDsPublished(t *testing.T) {
	if settings := DefaultDnsSettings(); len(settings.DsPublished) != 0 {
		t.Fatalf("a DS published by default: %v", settings.DsPublished)
	}
	ksk := trustAnchorTestRdata(t, dns.ZONE|dns.SEP)
	anchored := "trust_anchors:\n  zone.example: ['" + ksk + "']\n"
	settings, err := LoadDnsSettings([]byte(rootRecordsTestYaml(anchored + "ds_published: [Zone.Example]\n")))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(settings.DsPublished, []string{"zone.example."}) || !settings.DsPublishedFor("zone.example.") {
		t.Fatalf("ds_published %v", settings.DsPublished)
	}
	if settings.DsPublishedFor("other.example.") {
		t.Errorf("a root the file does not list reads as published")
	}
	unpublished, err := LoadDnsSettings([]byte(rootRecordsTestYaml(anchored + "ds_published: []\n")))
	if err != nil || unpublished.DsPublishedFor("zone.example.") {
		t.Fatalf("an empty list: %v %v", unpublished, err)
	}
	for _, more := range []string{
		anchored + "ds_published: [other.example]\n",
		anchored + "ds_published: [zone.example, ZONE.example]\n",
		"ds_published: [zone.example]\n",
		anchored + "ds_published: true\n",
	} {
		if _, err := LoadDnsSettings([]byte(rootRecordsTestYaml(more))); !errors.Is(err, ErrDnsSettingsRefused) {
			t.Errorf("%.70s: %v", strings.TrimSpace(more), err)
		}
	}
}
