package dnsservice

// QD-807: the record write (server's model.WriteDnsRecords) runs §12.7's validator on each upsert and then the host
// screen, sidecar.ScreenHost, on each new owner's host labels. The two keep the same owners from users: a TXT at each
// of §12.7's system hosts, the zone's scope label and a word-number label is refused by both, and at each word of
// §12.5's block that is neither those nor a brand, www, api, status and login among them, by neither.

import (
	"errors"
	"slices"
	"testing"

	"github.com/miekg/dns"

	"github.com/urnetwork/sidecar"
)

func TestValidatorAndHostScreenKeepTheSameOwners(t *testing.T) {
	vectors := readTestUserRecordVectors(t)
	context := vectors.context()
	if len(vectors.ScopeLabels) == 0 {
		t.Fatal("the vectors' zone has no scope label")
	}
	facts := &sidecar.ScreenFacts{ScopeLabels: vectors.ScopeLabels}
	kept := slices.Concat([]string{"b", "mx", "mail", "mta-sts", "otter-4821"}, vectors.ScopeLabels)
	for _, host := range kept {
		set := testUserRecordSet(vectors.Apex, host, dns.TypeTXT, vectors.TtlRange[0], `"x"`)
		if err := ValidateUserRecordSet(context, set); !errors.Is(err, ErrDnsUserRecordRefused) {
			t.Errorf("the validator answered %v at %s", err, host)
		}
		if verdict := sidecar.ScreenHost(host, facts); verdict != sidecar.ScreenVerdictDeny {
			t.Errorf("ScreenHost(%s) = %s", host, verdict)
		}
	}

	brands := []string{}
	for _, brand := range sidecar.ScreenBrands() {
		brands = append(brands, brand.Brand)
	}
	allowedHosts := []string{}
	for _, host := range sidecar.ReservedDnsLabels() {
		if slices.Contains(kept, host) || slices.Contains(brands, host) {
			continue
		}
		set := testUserRecordSet(vectors.Apex, host, dns.TypeTXT, vectors.TtlRange[0], `"x"`)
		if err := ValidateUserRecordSet(context, set); err != nil {
			t.Errorf("the validator refused a TXT at %s: %v", host, err)
		}
		if verdict := sidecar.ScreenHost(host, facts); verdict != sidecar.ScreenVerdictAllow {
			t.Errorf("ScreenHost(%s) = %s", host, verdict)
		}
		allowedHosts = append(allowedHosts, host)
	}
	for _, host := range []string{"www", "api", "status", "login"} {
		if !slices.Contains(allowedHosts, host) {
			t.Errorf("%s is not among the hosts both allow", host)
		}
	}
}
