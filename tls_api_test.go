// §13.15's bodies on the wire: the names bringyour.yml documents, round trips, unset values left out, and the one kill
// rule tlsedge and Find share. sidecartest/tls_api_rows_test.go holds their stored fields to §2.8's rows.

package sidecar

import (
	"encoding/json"
	"maps"
	"reflect"
	"slices"
	"strings"
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
		&TlsCertRegisterArgs{
			CertId:         certId,
			ClaimSeq:       7,
			Chain:          [][]byte{{0x30}},
			AccountUri:     "https://acme.letsencrypt.example/acme/acct/2002",
			AriWindowStart: testTlsTime(1769817600000),
			AriWindowEnd:   testTlsTime(1769904000000),
		},
		&TlsCertRevokeArgs{CertId: certId, KeyCompromise: true},
		&TlsSuspendArgs{NetworkId: Id{0x02}, Host: "blog", Reason: "abuse:case", Until: testTlsTime(1767225600000)},
		&TlsKillEntry{Host: TlsKillAllHosts, Reason: "abuse:case", Until: testTlsTime(1767225600000)},
		&TlsCustomRefusal{Reason: TlsCustomRefusalInFlight, RetryAfterMs: 1500, CertId: certId, KeySeq: 3},
		&TlsCustomAccount{
			Domain:            "customer.example",
			Ca:                "letsencrypt",
			AccountUri:        "https://acme.letsencrypt.example/acme/acct/3003",
			KeySeq:            3,
			KeyThumbprint:     []byte{0x0b},
			KeyRepoId:         Id{0x07},
			NextKeyThumbprint: []byte{0x0c},
			NextKeyRepoId:     Id{0x08},
			LockSidecarId:     Id{0x09},
			LockRetryAfterMs:  2000,
			HoldNewMs:         3000,
			HoldAllMs:         4000,
			AcmeName:          "token1.acme.root.example",
		},
		&TlsCustomClaimArgs{Domain: "customer.example", Purpose: TlsCustomPurposeOrder, CertId: certId, KeySeq: 3},
		&TlsCustomClaimResult{
			ClaimSeq:     12,
			LeaseMs:      120000,
			Record:       &TlsCertRecord{CertId: certId, State: TlsCertStateCustomOrdering, CustomHost: "app.customer.example", CustomDomain: "customer.example"},
			OrderUrl:     "https://acme.letsencrypt.example/acme/order/1/2",
			MayOrder:     true,
			ReplacesLeaf: []byte{0x30, 0x07},
		},
		&TlsCustomProgressArgs{
			Domain:       "customer.example",
			ClaimSeq:     12,
			CertId:       certId,
			Event:        TlsCustomEventRateLimited,
			OrderUrl:     "https://acme.letsencrypt.example/acme/order/1/2",
			RetryAfterMs: 60000,
			Reason:       "caa",
			Ari:          []*TlsCustomAri{{CertId: certId, AriWindowStart: testTlsTime(1769817600000), AriWindowEnd: testTlsTime(1769904000000)}},
		},
		&TlsCustomAccountArgs{
			Domain:        "customer.example",
			Op:            TlsCustomAccountRollBegin,
			AccountUri:    "https://acme.letsencrypt.example/acme/acct/3003",
			KeySeq:        3,
			KeyThumbprint: []byte{0x0d},
			KeyRepoId:     Id{0x0a},
			ClaimSeq:      12,
		},
		&TlsCustomChallengeArgs{Domain: "customer.example", Value: "abcdefghijklmnopqrstuvwxyz0123456789-_ABCDE"},
		&TlsCustomChallengeResult{ChallengeId: 41, Readiness: "ready"},
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
		"TlsCertRegisterArgs": {"account_uri", "ari_window_end", "ari_window_start", "cert_id", "chain", "claim_seq"},
		"TlsCertRevokeArgs":   {"cert_id", "key_compromise"},
		"TlsSuspendArgs":      {"host", "network_id", "reason", "until"},
		"TlsKillEntry":        {"host", "reason", "until"},
		"TlsCustomRefusal":    {"cert_id", "key_seq", "reason", "retry_after_ms"},
		"TlsCustomAccount": {
			"account_uri", "acme_name", "ca", "domain", "hold_all_ms", "hold_new_ms", "key_repo_id", "key_seq",
			"key_thumbprint", "lock_retry_after_ms", "lock_sidecar_id", "next_key_repo_id", "next_key_thumbprint",
		},
		"TlsCustomClaimArgs":       {"cert_id", "domain", "key_seq", "purpose"},
		"TlsCustomClaimResult":     {"claim_seq", "lease_ms", "may_order", "order_url", "record", "replaces_leaf"},
		"TlsCustomProgressArgs":    {"ari", "cert_id", "claim_seq", "domain", "event", "order_url", "reason", "retry_after_ms"},
		"TlsCustomAccountArgs":     {"account_uri", "claim_seq", "domain", "key_repo_id", "key_seq", "key_thumbprint", "op"},
		"TlsCustomChallengeArgs":   {"domain", "value"},
		"TlsCustomChallengeResult": {"challenge_id", "readiness"},
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
		{body: &TlsCertRegisterArgs{Chain: [][]byte{{0x30}}}, absent: []string{"ari_window_start", "ari_window_end"}},
		{body: &TlsCustomRefusal{Reason: TlsCustomRefusalLocked}, absent: []string{"retry_after_ms", "cert_id", "key_seq"}},
		{body: &TlsCustomClaimArgs{Domain: "customer.example", Purpose: TlsCustomPurposeRollover}, absent: []string{"cert_id"}},
		{body: &TlsCertRecord{CertId: Id{0x01}, State: TlsCertStateIssued}, absent: []string{"custom_host", "custom_domain", "custom_reason", "wait_ms", "host_ready", "owner"}},
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

// {tes_<network_id>} and its trigger share one hash tag, the trigger parses back to its network, and no
// other key parses.
func TestTlsKillKeys(t *testing.T) {
	networkId := NewId()
	key := TlsKillKey(networkId)
	trigger := TlsKillTriggerKey(networkId)
	if key != "{tes_"+networkId.String()+"}" || trigger != key+"n" {
		t.Fatalf("keys %q, %q", key, trigger)
	}
	// one hash tag, the whole of the hash's key, so both land on one slot
	if !strings.HasPrefix(key, "{") || !strings.HasSuffix(key, "}") || strings.Count(trigger, "}") != 1 {
		t.Fatal("the hash and its trigger do not share one tag")
	}
	parsed, ok := ParseTlsKillTriggerKey(trigger)
	if !ok || parsed != networkId {
		t.Fatalf("parsed %v, %v", parsed, ok)
	}
	for _, other := range []string{key, "{tes_}n", "{tes_not-an-id}n", "{acl_" + networkId.String() + "}v", "tes_" + networkId.String() + "n"} {
		if _, ok := ParseTlsKillTriggerKey(other); ok {
			t.Errorf("%q parsed", other)
		}
	}
}
