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
				"affinity", "alpn", "app_mode", "claim", "draining", "exclusive", "inflight", "listen_id", "max_streams",
				"name", "name_token", "protocol", "sealed_name", "serving", "version", "weight",
			},
		},
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

// §9.7's filter fields stay off the wire in both directions until §2.8's sock-2 lists them (I-18,
// plan-SOCK-metadata-rows). Changing a tag here is a change to what the service sees, which starts with
// the row.
func TestSocketFindArgsKeepsItsFilterOffTheWire(t *testing.T) {
	args := &SocketFindArgs{
		NameToken:  []byte{0x01},
		NetworkId:  &testSocketApiId,
		Protocol:   "canary-protocol",
		MinVersion: 12345,
		Alpn:       []string{"canary-alpn"},
	}
	encoded, err := json.Marshal(args)
	if err != nil {
		t.Fatal(err)
	}
	for _, text := range []string{"protocol", "min_version", "alpn", "canary", "12345"} {
		if strings.Contains(string(encoded), text) {
			t.Errorf("%q in %s", text, encoded)
		}
	}

	decoded := &SocketFindArgs{}
	body := `{"name":"tls/443/blog","protocol":"tcp","min_version":3,"alpn":["h2"],"Protocol":"tcp","MinVersion":3,"Alpn":["h2"]}`
	if err := json.Unmarshal([]byte(body), decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Protocol != "" || decoded.MinVersion != 0 || decoded.Alpn != nil {
		t.Errorf("read from the wire: %+v", decoded)
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
