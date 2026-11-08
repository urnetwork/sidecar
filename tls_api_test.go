// §13.15's bodies on the wire: the names bringyour.yml documents, round trips, unset values left out, and the one kill
// rule tlsedge and Find share. sidecartest/tls_api_rows_test.go holds their stored fields to §2.8's rows.

package sidecar

import (
	"encoding/json"
	"maps"
	"reflect"
	"slices"
	"testing"
	"time"
)

// A time with no monotonic reading and no sub-millisecond part, as one comes back from JSON.
func testTlsTime(unixMilli int64) time.Time {
	return time.UnixMilli(unixMilli).UTC()
}

// Every body with every field set, as a server or device would send it.
func testTlsBodies() []any {
	certId := Id{0x01, 0x93, 0x00, 0x01}
	return []any{
		&TlsCertOrderArgs{Csr: []byte{0x30, 0x01}, Attestation: []byte{0x0a, 0x01}, Replaces: "aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE"},
		&TlsCertOrderResult{CertId: certId, State: TlsCertStateQueued, RetryAfterMs: 5000},
		&TlsCertOrderStatus{
			State:          TlsCertStateIssued,
			RetryAfterMs:   1000,
			Chain:          [][]byte{{0x30, 0x02}, {0x30, 0x03}},
			AriWindowStart: testTlsTime(1767225600000),
			AriWindowEnd:   testTlsTime(1767312000000),
		},
		&TlsCertsResult{
			Certs: []*TlsCertRecord{{
				CertId:              certId,
				NetworkId:           Id{0x02},
				ClientId:            Id{0x03},
				SidecarId:           Id{0x04},
				IdentifierSetSha256: make([]byte, 32),
				SpkiSha256:          make([]byte, 32),
				Attestation:         []byte{0x0a, 0x01},
				Csr:                 []byte{0x30, 0x04},
				Ca:                  "letsencrypt",
				AccountUri:          "https://acme.letsencrypt.example/acme/acct/1001",
				Profile:             "tlsserver",
				Serial:              "04a1",
				NotBefore:           testTlsTime(1767225600000),
				NotAfter:            testTlsTime(1771113600000),
				AriWindowStart:      testTlsTime(1769817600000),
				AriWindowEnd:        testTlsTime(1769904000000),
				State:               TlsCertStateRevoked,
				SuccessorCertId:     Id{0x05},
				Chain:               [][]byte{{0x30, 0x05}},
			}},
			QueuedCsrs: []*TlsCertRecord{{CertId: Id{0x06}, State: TlsCertStateQueued, Csr: []byte{0x30, 0x06}}},
		},
		&TlsCertRegisterArgs{CertId: certId, Attestation: []byte{0x0a}, Chain: [][]byte{{0x30}}, AccountUri: "https://acme.letsencrypt.example/acme/acct/2002"},
		&TlsCertRevokeArgs{CertId: certId, KeyCompromise: true},
		&TlsSuspendArgs{NetworkId: Id{0x02}, Host: "blog", Reason: "abuse:case", Until: testTlsTime(1767225600000)},
		&TlsKillEntry{Host: TlsKillAllHosts, Reason: "abuse:case", Until: testTlsTime(1767225600000)},
	}
}

func TestTlsBodiesRoundTrip(t *testing.T) {
	for _, body := range testTlsBodies() {
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		decoded := reflect.New(reflect.TypeOf(body).Elem()).Interface()
		if err := json.Unmarshal(encoded, decoded); err != nil {
			t.Fatalf("%T: %v", body, err)
		}
		if !reflect.DeepEqual(decoded, body) {
			t.Errorf("%T came back as %+v", body, decoded)
		}
	}
}

// The JSON names, which bringyour.yml's schemas repeat, so a renamed field shows here first.
func TestTlsBodiesKeepTheirWireNames(t *testing.T) {
	want := map[string][]string{
		"TlsCertOrderArgs":    {"attestation", "csr", "replaces"},
		"TlsCertOrderResult":  {"cert_id", "retry_after_ms", "state"},
		"TlsCertOrderStatus":  {"ari_window_end", "ari_window_start", "chain", "retry_after_ms", "state"},
		"TlsCertsResult":      {"certs", "queued_csrs"},
		"TlsCertRegisterArgs": {"account_uri", "attestation", "cert_id", "chain"},
		"TlsCertRevokeArgs":   {"cert_id", "key_compromise"},
		"TlsSuspendArgs":      {"host", "network_id", "reason", "until"},
		"TlsKillEntry":        {"host", "reason", "until"},
	}
	for _, body := range testTlsBodies() {
		name := reflect.TypeOf(body).Elem().Name()
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		fields := map[string]json.RawMessage{}
		if err := json.Unmarshal(encoded, &fields); err != nil {
			t.Fatal(err)
		}
		if got := slices.Sorted(maps.Keys(fields)); !slices.Equal(got, want[name]) {
			t.Errorf("%s: %q", name, got)
		}
	}
	record, err := json.Marshal(testTlsBodies()[3].(*TlsCertsResult).Certs[0])
	if err != nil {
		t.Fatal(err)
	}
	fields := map[string]json.RawMessage{}
	if err := json.Unmarshal(record, &fields); err != nil {
		t.Fatal(err)
	}
	wantRecord := []string{
		"account_uri", "ari_window_end", "ari_window_start", "attestation", "ca", "cert_id", "chain", "client_id", "csr",
		"identifier_set_sha256", "network_id", "not_after", "not_before", "profile", "serial", "sidecar_id",
		"spki_sha256", "state", "successor_cert_id",
	}
	if got := slices.Sorted(maps.Keys(fields)); !slices.Equal(got, wantRecord) {
		t.Errorf("TlsCertRecord: %q", got)
	}
}

// An unset time, successor or chain is left out rather than sent as a zero a reader could take for a value.
func TestTlsBodiesLeaveUnsetValuesOut(t *testing.T) {
	cases := []struct {
		body   any
		absent []string
	}{
		{body: &TlsCertOrderStatus{State: TlsCertStateOrdering}, absent: []string{"ari_window_start", "ari_window_end", "chain", "retry_after_ms"}},
		{body: &TlsCertRecord{CertId: Id{0x01}, State: TlsCertStateQueued}, absent: []string{"not_before", "not_after", "ari_window_start", "successor_cert_id", "chain", "csr", "serial"}},
		{body: &TlsKillEntry{Host: "blog", Reason: "abuse:case"}, absent: []string{"until"}},
		{body: &TlsCertRegisterArgs{Chain: [][]byte{{0x30}}}, absent: []string{"cert_id", "attestation"}},
	}
	for _, c := range cases {
		encoded, err := json.Marshal(c.body)
		if err != nil {
			t.Fatal(err)
		}
		fields := map[string]json.RawMessage{}
		if err := json.Unmarshal(encoded, &fields); err != nil {
			t.Fatal(err)
		}
		for _, name := range c.absent {
			if _, present := fields[name]; present {
				t.Errorf("%T sends %s unset: %s", c.body, name, encoded)
			}
		}
	}
}

func TestTlsKillEntryKills(t *testing.T) {
	now := testTlsTime(1767225600000)
	cases := []struct {
		entry TlsKillEntry
		host  string
		kills bool
	}{
		{entry: TlsKillEntry{Host: "blog"}, host: "blog", kills: true},
		{entry: TlsKillEntry{Host: "blog"}, host: "shop", kills: false},
		{entry: TlsKillEntry{Host: TlsKillAllHosts}, host: "shop", kills: true},
		{entry: TlsKillEntry{Host: TlsKillAllHosts}, host: "@", kills: true},
		// a kill that cannot say whom it spares spares no one
		{entry: TlsKillEntry{}, host: "shop", kills: true},
		{entry: TlsKillEntry{Host: "blog", Until: now.Add(time.Millisecond)}, host: "blog", kills: true},
		{entry: TlsKillEntry{Host: "blog", Until: now}, host: "blog", kills: false},
		{entry: TlsKillEntry{Host: TlsKillAllHosts, Until: now.Add(-time.Hour)}, host: "blog", kills: false},
	}
	for _, c := range cases {
		if kills := c.entry.Kills(c.host, now); kills != c.kills {
			t.Errorf("%+v on %q: %t", c.entry, c.host, kills)
		}
	}
}
