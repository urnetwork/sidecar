//go:build !sidecar_http

// §9's route bodies as they cross the wire: every field survives JSON under its design name, a ticket and
// a claim pass through untouched, and what §2.8 does not list stays off the wire (I-18).

package sidecar

import (
	"bytes"
	"encoding/json"
	"maps"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/urnetwork/connect"
	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

var (
	testSocketApiId      = connect.Id{1: 1, 15: 1}
	testSocketApiOtherId = connect.Id{1: 2, 15: 2}
)

// A registration with every field set.
func testSocketApiRegistration() *SocketRegistration {
	return &SocketRegistration{
		Name:       "tls/443/blog",
		NameToken:  bytes.Repeat([]byte{0x01}, socketTokenByteCount),
		SealedName: bytes.Repeat([]byte{0x02}, socketSealByteCount),
		ListenId:   &testSocketApiId,
		Protocol:   "tls",
		Version:    2,
		Alpn:       []string{"h2", "http/1.1"},
		AppMode:    "raw",
		Weight:     100,
		MaxStreams: 256,
		Exclusive:  true,
		Affinity:   true,
		Serving:    true,
		Draining:   true,
		Inflight:   3,
		Claim:      []byte{0x03},
		// 17.2.10's two lists
		CertifiedNames: []string{"app.customer.example"},
		AcmeNames:      []*SocketAcmeName{{Name: "app.customer.example", ClaimSeq: 4}},
	}
}

// One value of every route body, with every field set but those the wire must not carry.
func testSocketApiBodies() []any {
	key := &SocketTicketKey{KeyId: "synthetic-key", PublicKey: []byte{0x01}, ExpireTimeMillis: 2}
	failure := &SocketError{Code: SocketErrorCodeUnavailable, RetryAfterMs: 100}
	findTicket := &SocketFindTicket{Ticket: []byte{0x04}, Claim: []byte{0x05}}
	return []any{
		&SocketRegistrationsArgs{
			SetVersion:    7,
			KeyStart:      []byte{0x01},
			KeyEnd:        []byte{0x02},
			Registrations: []*SocketRegistration{testSocketApiRegistration()},
		},
		&SocketRegistrationsResult{
			Statuses:         []SocketRegistrationStatus{SocketRegistrationStatusOk, SocketRegistrationStatusRevoked},
			SetVersion:       7,
			ServerTimeMillis: 1,
			TicketKeys:       []*SocketTicketKey{key},
			UrnetworkEdge:    &testSocketApiOtherId,
			StreamsStopped:   true,
			Error:            failure,
		},
		&SocketFindArgs{
			Name:          "tls/443/blog",
			NameToken:     []byte{0x01},
			NetworkId:     &testSocketApiId,
			Protocol:      "tls",
			MinVersion:    1,
			Alpn:          []string{"h2"},
			ServerName:    "app.customer.example",
			AffinityKey:   []byte{0x02},
			FailedTickets: []*SocketFailedTicket{{Ticket: []byte{0x03}, Reason: SocketFailedReasonTimeout}},
			ClientIds:     []*connect.Id{&testSocketApiId, &testSocketApiOtherId},
		},
		&SocketFindResult{Primary: findTicket, Backup: findTicket, Error: failure},
		&SocketListResult{
			Names:      []*SocketListName{{Name: "tls/443/blog", NameToken: []byte{0x01}, SealedName: []byte{0x02}}},
			NextCursor: "cursor",
			Error:      failure,
		},
		&SocketKeysResult{Keys: []*SocketTicketKey{key}},
	}
}

// Whether every field of value that the wire carries is set, however deep, so a body above that left one
// out proves nothing about it.
func testSocketApiUnsetFields(value reflect.Value, path string) []string {
	unset := []string{}
	switch value.Kind() {
	case reflect.Pointer:
		if value.IsNil() {
			return []string{path}
		}
		if value.Type().Elem().Kind() == reflect.Struct && value.Type() != reflect.TypeFor[*connect.Id]() {
			return testSocketApiUnsetFields(value.Elem(), path)
		}
	case reflect.Slice:
		if value.Len() == 0 {
			return []string{path}
		}
		if value.Type().Elem().Kind() == reflect.Pointer {
			return testSocketApiUnsetFields(value.Index(0), path)
		}
	case reflect.Struct:
		for index := range value.NumField() {
			field := value.Type().Field(index)
			if field.Tag.Get("json") != "-" {
				unset = append(unset, testSocketApiUnsetFields(value.Field(index), path+"."+field.Name)...)
			}
		}
	default:
		if value.IsZero() {
			return []string{path}
		}
	}
	return unset
}

// Every field of every body comes back as it went, and none was left unset to pass.
func TestSocketRouteBodiesRoundTrip(t *testing.T) {
	for _, body := range testSocketApiBodies() {
		bodyType := reflect.TypeOf(body).Elem()
		if unset := testSocketApiUnsetFields(reflect.ValueOf(body), bodyType.Name()); len(unset) != 0 {
			t.Errorf("unset, so unproved: %v", unset)
		}
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		decoded := reflect.New(bodyType).Interface()
		if err := json.Unmarshal(encoded, decoded); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(decoded, body) {
			t.Errorf("%s: %s came back as %+v", bodyType.Name(), encoded, decoded)
		}
	}
}

// The keys a body shows, sorted.
func testSocketApiKeys(t *testing.T, body any) []string {
	t.Helper()
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	keyValues := map[string]json.RawMessage{}
	if err := json.Unmarshal(encoded, &keyValues); err != nil {
		t.Fatal(err)
	}
	return slices.Sorted(maps.Keys(keyValues))
}

// Wire names are §9.5's and §9.15's as written, and this is where a rename would show.
func TestSocketRouteBodyNames(t *testing.T) {
	cases := []struct {
		body any
		keys []string
	}{
		{
			body: testSocketApiRegistration(),
			keys: []string{
				"acme_names", "affinity", "alpn", "app_mode", "certified_names", "claim", "draining", "exclusive", "inflight",
				"listen_id", "max_streams", "name", "name_token", "protocol", "sealed_name", "serving", "version", "weight",
			},
		},
		// a registration with neither of 17.2.10's lists shows neither
		{
			body: func() *SocketRegistration {
				registration := testSocketApiRegistration()
				registration.CertifiedNames = nil
				registration.AcmeNames = nil
				return registration
			}(),
			keys: []string{
				"affinity", "alpn", "app_mode", "claim", "draining", "exclusive", "inflight", "listen_id", "max_streams",
				"name", "name_token", "protocol", "sealed_name", "serving", "version", "weight",
			},
		},
		{body: &SocketAcmeName{}, keys: []string{"claim_seq", "name"}},
		{body: &SocketRegistrationsArgs{}, keys: []string{"key_end", "key_start", "registrations", "set_version"}},
		{
			body: &SocketRegistrationsResult{Error: &SocketError{}},
			keys: []string{
				"error", "server_time", "set_version", "statuses", "streams_stopped", "ticket_keys", "urnetwork_edge",
			},
		},
		{body: &SocketTicketKey{}, keys: []string{"expire_time_millis", "key_id", "public_key"}},
		{body: &SocketError{Code: SocketErrorCodeBusy, RetryAfterMs: 1}, keys: []string{"code", "retry_after_ms"}},
		{body: &SocketFindTicket{}, keys: []string{"claim", "ticket"}},
		{body: &SocketFailedTicket{}, keys: []string{"reason", "ticket"}},
		{body: &SocketKeysResult{}, keys: []string{"keys"}},
		{body: &SocketListResult{}, keys: []string{"names", "next_cursor"}},
		// a Find shows only what the call holds, so a refusal holds no ticket
		{body: &SocketFindResult{Error: &SocketError{}}, keys: []string{"error"}},
		{body: &SocketFindArgs{}, keys: []string{"network_id"}},
	}
	for _, c := range cases {
		if keys := testSocketApiKeys(t, c.body); !slices.Equal(keys, c.keys) {
			t.Errorf("%T shows %v, want %v", c.body, keys, c.keys)
		}
	}
}

// §9.9's codes, §9.5's statuses and the reasons are what a client and the metrics read.
func TestSocketRouteValues(t *testing.T) {
	cases := []struct {
		got  string
		want string
	}{
		{got: string(SocketRegistrationStatusOk), want: "ok"},
		{got: string(SocketRegistrationStatusRevoked), want: "revoked"},
		{got: string(SocketRegistrationStatusDenied), want: "denied"},
		{got: string(SocketRegistrationStatusTaken), want: "taken"},
		{got: string(SocketRegistrationStatusInvalid), want: "invalid"},
		{got: string(SocketErrorCodeNoListener), want: "no_listener"},
		{got: string(SocketErrorCodeBusy), want: "busy"},
		{got: string(SocketErrorCodeDenied), want: "denied"},
		{got: string(SocketErrorCodeQuota), want: "quota"},
		{got: string(SocketErrorCodeUnavailable), want: "unavailable"},
		{got: string(SocketErrorCodeStale), want: "stale"},
		{got: string(SocketErrorCodeInvalid), want: "invalid"},
		{got: string(SocketFailedReasonTimeout), want: "timeout"},
		{got: string(SocketFailedReasonRefused), want: "refused"},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%q, want %q", c.got, c.want)
		}
	}
}

// Find's filter rides the wire under sock-2's names, and a custom host's server name with it (17.2.10): each field
// crosses JSON as it was set, and a Find that asks nothing carries none of them.
func TestSocketFindArgsCarriesItsFilterOnTheWire(t *testing.T) {
	args := &SocketFindArgs{
		NameToken:  []byte{0x01},
		NetworkId:  &testSocketApiId,
		Protocol:   "tls",
		MinVersion: 3,
		Alpn:       []string{"h2"},
		ServerName: "app.customer.example",
	}
	encoded, err := json.Marshal(args)
	if err != nil {
		t.Fatal(err)
	}
	decoded := &SocketFindArgs{}
	if err := json.Unmarshal(encoded, decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Protocol != "tls" || decoded.MinVersion != 3 || len(decoded.Alpn) != 1 || decoded.Alpn[0] != "h2" ||
		decoded.ServerName != "app.customer.example" {
		t.Errorf("read from the wire: %+v", decoded)
	}
	plain, err := json.Marshal(&SocketFindArgs{NameToken: []byte{0x01}, NetworkId: &testSocketApiId})
	if err != nil {
		t.Fatal(err)
	}
	for _, text := range []string{"protocol", "min_version", "alpn", "server_name"} {
		if strings.Contains(string(plain), text) {
			t.Errorf("%q in a Find that asks nothing: %s", text, plain)
		}
	}
}

// A ticket and its claim cross JSON as the bytes they arrived as: a Find's answer is what a dialer
// presents, and what the service takes back as a failed ticket, with no decoding between.
func TestSocketFindTicketCarriesTheBytesThatVerify(t *testing.T) {
	vectors := testReadSocketTicketVectors(t)
	keys := vectors.ticketKeys(t)
	for _, vector := range vectors.Tickets {
		received := testSocketHex(t, vector.Received)
		encoded, err := json.Marshal(&SocketFindResult{Primary: &SocketFindTicket{Ticket: received, Claim: []byte{0x01}}})
		if err != nil {
			t.Fatal(err)
		}
		result := &SocketFindResult{}
		if err := json.Unmarshal(encoded, result); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(result.Primary.Ticket, received) {
			t.Errorf("%s: the bytes changed", vector.Name)
		}
		if _, err := VerifySocketTicket(result.Primary.Ticket, keys, vectors.NowMillis); err != nil {
			t.Errorf("%s: %v", vector.Name, err)
		}
		stream := &protocol.StreamOpen{Ticket: result.Primary.Ticket}
		streamBytes, err := proto.Marshal(stream)
		if err != nil {
			t.Fatal(err)
		}
		opened := &protocol.StreamOpen{}
		if err := proto.Unmarshal(streamBytes, opened); err != nil {
			t.Fatal(err)
		}
		if _, err := VerifySocketTicket(opened.GetTicket(), keys, vectors.NowMillis); err != nil {
			t.Errorf("%s through StreamOpen: %v", vector.Name, err)
		}
	}
}
