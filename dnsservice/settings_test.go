package dnsservice

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

// §12.6's sketch, with an .example root and numbers where it leaves <cap> placeholders.
const dnsSettingsSketch = `# config/<env>/dns.yml (sketch)
roots: [zone.example]
reverse: from smtpedge.yml's sending addresses   # M9; HE's classless delegation; unsigned
delegated: Team customers' _domainkey.<domain> zones   # v1 (§14.6); not roots
ns: [ns1, ns2]                  # two hosts at the site; IPv4 and IPv6 from different gateway blocks
ttl: {challenge: 60, edge: 60, mx: 300, mx_host: 300, tlsa: 300, mail_policy: 3600, caa: 3600,
      user: 300, user_range: [60, 3600], soa_minimum: 60, ns: 86400, ptr: 3600}   # edge: A, AAAA at *, @
rrl: {ipv4_prefix: 24, ipv6_prefix: 56, slip: 2, classes: [answer, denial, error], responses_per_second: 20}
signatures_per_second: 500      # cached answers first
edns_udp_size: 1232
any: minimal                    # RFC 8482
client_subnet: ignore           # RFC 7871; never echoed or stored
tcp: {connections_per_source: 8, idle_timeout_s: 10}
`

// The sketch with one line's text replaced.
func sketchWith(t *testing.T, old string, replacement string) []byte {
	t.Helper()
	if !strings.Contains(dnsSettingsSketch, old) {
		t.Fatalf("the sketch holds no %q", old)
	}
	return []byte(strings.Replace(dnsSettingsSketch, old, replacement, 1))
}

func TestDnsSettingsSketchParses(t *testing.T) {
	settings, err := LoadDnsSettings([]byte(dnsSettingsSketch))
	if err != nil {
		t.Fatal(err)
	}
	want := DefaultDnsSettings()
	want.Roots = []string{"zone.example."}
	want.Reverse = "from smtpedge.yml's sending addresses"
	want.Delegated = "Team customers' _domainkey.<domain> zones"
	want.SignaturesPerSecond = 500
	want.Tcp.ConnectionsPerSource = 8
	want.Rrl.ResponsesPerSecond = 20
	if !reflect.DeepEqual(settings, want) {
		t.Errorf("settings %+v, want %+v", settings, want)
	}
}

// Each default against §12.6's sketch, written out again so a change to either side shows here.
func TestDnsSettingsDefaultsAreTheDesigns(t *testing.T) {
	settings := DefaultDnsSettings()
	ttls := []struct {
		name string
		ttl  uint32
		want uint32
	}{
		{name: "challenge", ttl: settings.Ttl.Challenge, want: 60},
		{name: "edge", ttl: settings.Ttl.Edge, want: 60},
		{name: "mx", ttl: settings.Ttl.Mx, want: 300},
		{name: "mx_host", ttl: settings.Ttl.MxHost, want: 300},
		{name: "tlsa", ttl: settings.Ttl.Tlsa, want: 300},
		{name: "mail_policy", ttl: settings.Ttl.MailPolicy, want: 3600},
		{name: "caa", ttl: settings.Ttl.Caa, want: 3600},
		{name: "user", ttl: settings.Ttl.User, want: 300},
		{name: "user_range low", ttl: settings.Ttl.UserRange[0], want: 60},
		{name: "user_range high", ttl: settings.Ttl.UserRange[1], want: 3600},
		{name: "soa_minimum", ttl: settings.Ttl.SoaMinimum, want: 60},
		{name: "ns", ttl: settings.Ttl.Ns, want: 86400},
		{name: "ptr", ttl: settings.Ttl.Ptr, want: 3600},
	}
	for _, c := range ttls {
		if c.ttl != c.want {
			t.Errorf("ttl.%s %d, want %d", c.name, c.ttl, c.want)
		}
	}
	if settings.EdnsUdpSize != 1232 {
		t.Errorf("edns_udp_size %d", settings.EdnsUdpSize)
	}
	if settings.Any != "minimal" || settings.ClientSubnet != "ignore" {
		t.Errorf("any %q, client_subnet %q", settings.Any, settings.ClientSubnet)
	}
	if settings.Rrl.Ipv4Prefix != 24 || settings.Rrl.Ipv6Prefix != 56 || settings.Rrl.Slip != 2 {
		t.Errorf("rrl %+v", settings.Rrl)
	}
	if !reflect.DeepEqual(settings.Rrl.Classes, []string{"answer", "denial", "error"}) {
		t.Errorf("rrl.classes %v", settings.Rrl.Classes)
	}
	if !reflect.DeepEqual(settings.Ns, []string{"ns1", "ns2"}) || settings.Tcp.IdleTimeoutSeconds != 10 {
		t.Errorf("ns %v, tcp %+v", settings.Ns, settings.Tcp)
	}
	if settings.SignaturesPerSecond != 0 || settings.Tcp.ConnectionsPerSource != 0 || settings.Rrl.ResponsesPerSecond != 0 {
		t.Errorf("a number §12.6 leaves open has a default: %+v", settings)
	}
	if len(settings.Roots) != 0 {
		t.Errorf("a root in code: %v", settings.Roots)
	}
}

func TestDnsSettingsRefusals(t *testing.T) {
	cases := []struct {
		name string
		data []byte
		// the refusal's text must hold this
		want string
	}{
		{
			name: "signatures_per_second left out",
			data: sketchWith(t, "signatures_per_second: 500      # cached answers first\n", ""),
			want: "signatures_per_second",
		},
		{
			name: "signatures_per_second zero",
			data: sketchWith(t, "signatures_per_second: 500", "signatures_per_second: 0"),
			want: "signatures_per_second",
		},
		{
			name: "signatures_per_second still the sketch's placeholder",
			data: sketchWith(t, "signatures_per_second: 500", "signatures_per_second: <cap per host>"),
			want: "cannot unmarshal",
		},
		{
			name: "connections_per_source left out",
			data: sketchWith(t, "connections_per_source: 8, ", ""),
			want: "connections_per_source",
		},
		{
			name: "connections_per_source still the sketch's placeholder",
			data: sketchWith(t, "connections_per_source: 8", "connections_per_source: <cap>"),
			want: "cannot unmarshal",
		},
		{
			name: "rrl rate left out",
			data: sketchWith(t, ", responses_per_second: 20", ""),
			want: "responses_per_second",
		},
		{name: "no roots", data: sketchWith(t, "roots: [zone.example]\n", ""), want: "roots"},
		{name: "an empty root list", data: sketchWith(t, "[zone.example]", "[]"), want: "roots"},
		{name: "a root that is a tld", data: sketchWith(t, "[zone.example]", "[example]"), want: "top-level"},
		{name: "a root that is no name", data: sketchWith(t, "[zone.example]", "[\"bad_root.example\"]"), want: "host label"},
		{name: "a root inside another", data: sketchWith(t, "[zone.example]", "[zone.example, a.zone.example]"), want: "overlap"},
		{name: "a root twice", data: sketchWith(t, "[zone.example]", "[zone.example, ZONE.example]"), want: "overlap"},
		{name: "an empty ns", data: sketchWith(t, "[ns1, ns2]", "[]"), want: "ns"},
		{name: "an ns twice", data: sketchWith(t, "[ns1, ns2]", "[ns1, ns1]"), want: "twice"},
		{name: "an ns with a dot", data: sketchWith(t, "[ns1, ns2]", "[ns1.zone.example]"), want: "host label"},
		{name: "a zero ttl", data: sketchWith(t, "challenge: 60", "challenge: 0"), want: "challenge"},
		{name: "a ttl past RFC 2181's", data: sketchWith(t, "ptr: 3600", "ptr: 4000000000"), want: "ptr"},
		{name: "a denial past R-DNS-7's 60 s", data: sketchWith(t, "soa_minimum: 60", "soa_minimum: 61"), want: "R-DNS-7"},
		{name: "a backward user range", data: sketchWith(t, "user_range: [60, 3600]", "user_range: [3600, 60]"), want: "user_range"},
		{name: "a user range of one value", data: sketchWith(t, "user_range: [60, 3600]", "user_range: [60]"), want: "array"},
		{name: "a user ttl outside its range", data: sketchWith(t, "user: 300", "user: 30"), want: "outside"},
		{name: "an ipv4 prefix past 32", data: sketchWith(t, "ipv4_prefix: 24", "ipv4_prefix: 33"), want: "ipv4_prefix"},
		{name: "an ipv6 prefix past 128", data: sketchWith(t, "ipv6_prefix: 56", "ipv6_prefix: 129"), want: "ipv6_prefix"},
		{name: "a negative slip", data: sketchWith(t, "slip: 2", "slip: -1"), want: "slip"},
		{name: "an empty rrl class list", data: sketchWith(t, "classes: [answer, denial, error]", "classes: []"), want: "classes"},
		{name: "an rrl class that is none", data: sketchWith(t, "[answer, denial, error]", "[answer, query]"), want: "query"},
		{name: "a udp size below 512", data: sketchWith(t, "edns_udp_size: 1232", "edns_udp_size: 511"), want: "edns_udp_size"},
		{name: "any answered in full", data: sketchWith(t, "any: minimal", "any: full"), want: "any"},
		{name: "a client subnet kept", data: sketchWith(t, "client_subnet: ignore", "client_subnet: echo"), want: "client_subnet"},
		{name: "no idle timeout", data: sketchWith(t, "idle_timeout_s: 10", "idle_timeout_s: 0"), want: "idle_timeout_s"},
		{name: "a mistyped key", data: sketchWith(t, "edns_udp_size:", "edns_udp_sise:"), want: "edns_udp_sise"},
		{name: "a key given twice", data: []byte(dnsSettingsSketch + "any: minimal\n"), want: "already"},
		{name: "a second document", data: []byte(dnsSettingsSketch + "---\nany: minimal\n"), want: "document"},
		{name: "nothing", data: []byte(""), want: "EOF"},
		{name: "not yaml", data: []byte("roots: [unclosed"), want: "yaml"},
	}
	for _, c := range cases {
		settings, err := LoadDnsSettings(c.data)
		if !errors.Is(err, ErrDnsSettingsRefused) {
			t.Errorf("%s: settings %v, err %v", c.name, settings, err)
			continue
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %q does not name %q", c.name, err, c.want)
		}
	}
}

func TestDnsSettingsRootIsCanonicalOnceLoaded(t *testing.T) {
	settings, err := LoadDnsSettings(sketchWith(t, "[zone.example]", "[Zone.Example., other.example]"))
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"zone.example.", "other.example."}; !reflect.DeepEqual(settings.Roots, want) {
		t.Errorf("roots %v", settings.Roots)
	}
}

// A file naming only the three open numbers and a root takes every other default.
func TestDnsSettingsKeepDefaultsAFileLeavesOut(t *testing.T) {
	settings, err := LoadDnsSettings([]byte(`roots: [zone.example]
signatures_per_second: 1
tcp: {connections_per_source: 1}
rrl: {responses_per_second: 1}
ttl: {challenge: 30}
`))
	if err != nil {
		t.Fatal(err)
	}
	if settings.Ttl.Challenge != 30 || settings.Ttl.Edge != 60 || settings.Tcp.IdleTimeoutSeconds != 10 || settings.Rrl.Slip != 2 {
		t.Errorf("settings %+v", settings)
	}
}

// The signing block's defaults hold together, and a file can only tighten them into something that
// still does.
func TestDnsSigningSettings(t *testing.T) {
	signing := DefaultDnsSettings().Signing
	if signing.LifetimeSeconds <= signing.RefreshSeconds+signing.JitterSeconds {
		t.Errorf("defaults %+v", signing)
	}
	if signing.RefreshSeconds < int(DefaultDnsSettings().Ttl.Ns) {
		t.Errorf("refresh_s %d is below the longest TTL", signing.RefreshSeconds)
	}
	settings, err := LoadDnsSettings([]byte(dnsSettingsSketch + "signing: {lifetime_s: 7200, refresh_s: 3600, jitter_s: 0}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if settings.Signing.LifetimeSeconds != 7200 || settings.Signing.CacheEntryCount != signing.CacheEntryCount {
		t.Errorf("signing %+v", settings.Signing)
	}
	for _, block := range []string{
		"signing: {lifetime_s: 3600, refresh_s: 3600, jitter_s: 0}",
		"signing: {lifetime_s: 7200, refresh_s: 3600, jitter_s: 3600}",
		"signing: {refresh_s: 0}",
		"signing: {jitter_s: -1}",
		"signing: {inception_offset_s: -1}",
		"signing: {cache_entries: 0}",
		"signing: {lifetime: 7200}",
	} {
		_, err := LoadDnsSettings([]byte(dnsSettingsSketch + block + "\n"))
		if !errors.Is(err, ErrDnsSettingsRefused) {
			t.Errorf("%s: %v", block, err)
		}
	}
}
