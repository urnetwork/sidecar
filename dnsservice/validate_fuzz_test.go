package dnsservice

import (
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/miekg/dns"
	"github.com/urnetwork/connect"
	"github.com/urnetwork/sidecar"
)

// FuzzValidateUserRecordSet (§22.6): nothing non-public or refused passes. Whatever the validator
// accepts is held again here by rules written apart from it: one of §12.7's six types at an owner it
// allows, a TTL in range, public unicast addresses, printable text within its bound, and caps kept.

// Ranges no public address is in, written apart from zone.go's list.
var fuzzNonPublicPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("169.254.0.0/16"), netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/3"), netip.MustParsePrefix("2001:db8::/32"), netip.MustParsePrefix("3fff::/20"),
}

// Why an accepted set breaks §12.7, or empty.
func checkAcceptedUserRecordSet(context *DnsUserRecordContext, set *DnsRecordSet) string {
	if !slices.Contains([]uint16{dns.TypeA, dns.TypeAAAA, dns.TypeCNAME, dns.TypeTXT, dns.TypeMX, dns.TypeSRV}, set.Type) {
		return "a type outside the user table"
	}
	if set.Ttl < context.TtlRange[0] || context.TtlRange[1] < set.Ttl {
		return "a ttl outside user_range"
	}
	if set.Owner != context.Apex && !strings.HasSuffix(set.Owner, "."+context.Apex) {
		return "an owner outside the zone"
	}
	relative := []string{}
	if set.Owner != context.Apex {
		relative = strings.Split(strings.TrimSuffix(set.Owner, "."+context.Apex), ".")
	}
	if 3 < len(relative) {
		return "an owner deeper than §12.7's"
	}
	for _, label := range relative {
		if slices.Contains([]string{"b", "mx", "mail", "mta-sts", "_acme-challenge", "_dmarc", "_domainkey", "_mta-sts", "_smtp"}, label) ||
			slices.Contains(context.ScopeLabels, label) || sidecar.IsWordNumberDnsLabel(label) {
			return "a refused owner label " + label
		}
	}
	if len(relative) == 1 && relative[0] == "*" {
		return "the system's *"
	}
	if 0 < len(relative) && relative[0] == "*" && set.Type != dns.TypeA && set.Type != dns.TypeAAAA {
		return "a wildcard with a type other than A and AAAA"
	}
	if set.Owner == context.Apex && (set.Type == dns.TypeCNAME || set.Type == dns.TypeMX) {
		return "a CNAME or MX at the apex"
	}
	records, err := set.Records()
	if err != nil {
		return "rdata that does not parse"
	}
	switch set.Type {
	case dns.TypeA, dns.TypeAAAA:
		if 8 < len(records) {
			return "more than 8 addresses"
		}
		for _, record := range records {
			text := strings.Fields(record.String())
			address, err := netip.ParseAddr(text[len(text)-1])
			if err != nil {
				return "an address that does not parse"
			}
			address = address.Unmap()
			if address.Is6() && !netip.MustParsePrefix("2000::/3").Contains(address) {
				return "an IPv6 address outside global unicast"
			}
			for _, prefix := range fuzzNonPublicPrefixes {
				if prefix.Contains(address) {
					return "a non-public address " + address.String()
				}
			}
			if address.String() == connect.DefaultDnsUpgradeMaskAddress || address == netip.MustParseAddr(connect.DefaultDnsUpgradeMaskAddressIpv6) {
				return "a DNS stand-in"
			}
		}
	case dns.TypeTXT:
		byteCount := 0
		for _, record := range records {
			text, err := dnsTxtText(record.(*dns.TXT))
			if err != nil {
				return "text with a broken escape"
			}
			byteCount += len(text)
			for index := range len(text) {
				if text[index] < 0x20 || 0x7e < text[index] {
					return "a byte that is not printable ASCII"
				}
			}
			if set.Owner == context.Apex && strings.HasPrefix(strings.ToLower(text), "v=spf1") {
				return "SPF at the apex"
			}
		}
		if 1024 < byteCount {
			return "more than 1024 bytes of text"
		}
	case dns.TypeMX:
		if 4 < len(records) {
			return "more than 4 exchanges"
		}
	case dns.TypeCNAME:
		if dns.CanonicalName(records[0].(*dns.CNAME).Target) == set.Owner {
			return "a CNAME to itself"
		}
	}
	return ""
}

// The seeds under the repository's testdata/fuzz/FuzzValidateUserRecordSet, kept with §12's other
// vectors. go test reads a corpus only from beside the package, so this reads it here.
func addFuzzUserRecordSeeds(f *testing.F) {
	paths, err := filepath.Glob(filepath.Join("..", "testdata", "fuzz", "FuzzValidateUserRecordSet", "*"))
	if err != nil {
		f.Fatal(err)
	}
	if len(paths) < 10 {
		f.Fatalf("%d seeds", len(paths))
	}
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			f.Fatal(err)
		}
		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		if len(lines) != 5 || lines[0] != "go test fuzz v1" {
			f.Fatalf("%s is not a corpus file of four values", path)
		}
		value := func(line string, prefix string) string {
			inner, ok := strings.CutPrefix(line, prefix+"(")
			if !ok || !strings.HasSuffix(inner, ")") {
				f.Fatalf("%s: %q", path, line)
			}
			return strings.TrimSuffix(inner, ")")
		}
		owner, err := strconv.Unquote(value(lines[1], "string"))
		if err != nil {
			f.Fatalf("%s: %v", path, err)
		}
		rrType, err := strconv.ParseUint(value(lines[2], "uint16"), 10, 16)
		if err != nil {
			f.Fatalf("%s: %v", path, err)
		}
		ttl, err := strconv.ParseUint(value(lines[3], "uint32"), 10, 32)
		if err != nil {
			f.Fatalf("%s: %v", path, err)
		}
		rdata, err := strconv.Unquote(value(lines[4], "string"))
		if err != nil {
			f.Fatalf("%s: %v", path, err)
		}
		f.Add(owner, uint16(rrType), uint32(ttl), rdata)
	}
}

// owner is relative to the zone, @ for its apex; rdata's records are split at |.
func FuzzValidateUserRecordSet(f *testing.F) {
	addFuzzUserRecordSeeds(f)
	context := &DnsUserRecordContext{
		Root:        testRoot,
		Apex:        "net1." + testRoot,
		TtlRange:    [2]uint32{60, 3600},
		ScopeLabels: []string{"team"},
		Tombstoned:  func(label string) bool { return label == "deadlabel1" },
	}
	f.Fuzz(func(t *testing.T, owner string, rrType uint16, ttl uint32, rdata string) {
		set := testUserRecordSet(context.Apex, owner, rrType, ttl, strings.Split(rdata, "|")...)
		if ValidateUserRecordSet(context, set) != nil {
			return
		}
		if failure := checkAcceptedUserRecordSet(context, set); failure != "" {
			t.Fatalf("accepted %s %d %d %q: %s", set.Owner, rrType, ttl, rdata, failure)
		}
	})
}
