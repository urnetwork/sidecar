// §9.6's tickets and §6.11's rule for §9's two signed types. testdata/socket/tickets.json came from §9.6's
// text by a separate implementation, with Ed25519 from RFC 8032 and protobuf written by hand, so a
// mistake in how this code composes them fails here rather than being written into the file.
//
// The file is built into the test binary, because this runs on the sidecar_http leg too, whose Worker has
// no file system (TestHttpLegPassesInAWorker names these).

package sidecar

import (
	"bytes"
	"crypto/ed25519"
	_ "embed"
	"encoding/json"
	"errors"
	"math"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

//go:embed testdata/socket/tickets.json
var socketTicketVectorFile []byte

// A service key: its seed signs here, and a verifier holds the rest.
type testSocketTicketKeyVector struct {
	Name             string `json:"name"`
	KeyId            string `json:"key_id"`
	Seed             string `json:"seed"`
	PublicKey        string `json:"public_key"`
	ExpireTimeMillis uint64 `json:"expire_time_millis"`
}

// A ticket's fields as the file writes them, bytes in hex.
type testSocketTicketFields struct {
	TicketId              string `json:"ticket_id"`
	NetworkId             string `json:"network_id"`
	Name                  string `json:"name"`
	ListenerClientId      string `json:"listener_client_id"`
	ListenId              string `json:"listen_id"`
	DialerClientId        string `json:"dialer_client_id"`
	DialerNetworkId       string `json:"dialer_network_id"`
	IssueTimeMillis       uint64 `json:"issue_time_millis"`
	ExpireTimeMillis      uint64 `json:"expire_time_millis"`
	PolicyVersion         uint64 `json:"policy_version"`
	GrantId               string `json:"grant_id"`
	Backup                bool   `json:"backup"`
	GrantExpireTimeMillis uint64 `json:"grant_expire_time_millis"`
	NameToken             string `json:"name_token"`
}

// A ticket that verifies, with each stage of its encoding.
type testSocketTicketVector struct {
	Name        string                  `json:"name"`
	Fields      *testSocketTicketFields `json:"fields"`
	Ticket      string                  `json:"ticket"`
	SignedBytes string                  `json:"signed_bytes"`
	Signature   string                  `json:"signature"`
	Received    string                  `json:"received"`
	// No marshal writes this encoding.
	ReencodesApart bool `json:"reencodes_apart"`
}

// Bytes a verifier refuses, and the error that says why.
type testSocketTicketRefusal struct {
	Name     string `json:"name"`
	Received string `json:"received"`
	Refusal  string `json:"refusal"`
}

type testSocketTicketVectors struct {
	NowMillis uint64                       `json:"now_millis"`
	Keys      []*testSocketTicketKeyVector `json:"keys"`
	Tickets   []*testSocketTicketVector    `json:"tickets"`
	Refusals  []*testSocketTicketRefusal   `json:"refusals"`
}

// The file, parsed.
func testReadSocketTicketVectors(t testing.TB) *testSocketTicketVectors {
	t.Helper()
	vectors := &testSocketTicketVectors{}
	if err := json.Unmarshal(socketTicketVectorFile, vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors.Tickets) == 0 || len(vectors.Refusals) == 0 || len(vectors.Keys) == 0 {
		t.Fatal("the vector file is empty, so this would prove nothing")
	}
	return vectors
}

// What a holder of the file's keys verifies under.
func (self *testSocketTicketVectors) ticketKeys(t testing.TB) []*SocketTicketKey {
	t.Helper()
	keys := []*SocketTicketKey{}
	for _, key := range self.Keys {
		keys = append(keys, &SocketTicketKey{
			KeyId:            key.KeyId,
			PublicKey:        testSocketHex(t, key.PublicKey),
			ExpireTimeMillis: key.ExpireTimeMillis,
		})
	}
	return keys
}

// The file's key by its name.
func (self *testSocketTicketVectors) key(t testing.TB, name string) *testSocketTicketKeyVector {
	t.Helper()
	for _, key := range self.Keys {
		if key.Name == name {
			return key
		}
	}
	t.Fatalf("no key %q", name)
	return nil
}

func (self *testSocketTicketKeyVector) privateKey(t testing.TB) ed25519.PrivateKey {
	t.Helper()
	return ed25519.NewKeyFromSeed(testSocketHex(t, self.Seed))
}

func (self *testSocketTicketFields) ticket(t testing.TB) *protocol.SocketTicket {
	t.Helper()
	return &protocol.SocketTicket{
		TicketId:              testSocketHex(t, self.TicketId),
		NetworkId:             testSocketHex(t, self.NetworkId),
		Name:                  self.Name,
		ListenerClientId:      testSocketHex(t, self.ListenerClientId),
		ListenId:              testSocketHex(t, self.ListenId),
		DialerClientId:        testSocketHex(t, self.DialerClientId),
		DialerNetworkId:       testSocketHex(t, self.DialerNetworkId),
		IssueTimeMillis:       self.IssueTimeMillis,
		ExpireTimeMillis:      self.ExpireTimeMillis,
		PolicyVersion:         self.PolicyVersion,
		GrantId:               testSocketHex(t, self.GrantId),
		Backup:                self.Backup,
		GrantExpireTimeMillis: self.GrantExpireTimeMillis,
		NameToken:             testSocketHex(t, self.NameToken),
	}
}

// The sentinel a refusal names.
func testSocketTicketRefusalError(t testing.TB, refusal string) error {
	t.Helper()
	switch refusal {
	case "malformed":
		return ErrSocketTicketMalformed
	case "key_unknown":
		return ErrSocketTicketKeyUnknown
	case "key_expired":
		return ErrSocketTicketKeyExpired
	case "signature":
		return bridge.ErrSignedSignature
	}
	t.Fatalf("no refusal %q", refusal)
	return nil
}

// A fixed key of the kind a service holds, apart from the file's.
var testSocketTicketPrivateKey = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x33}, ed25519.SeedSize))

const (
	testSocketTicketKeyId   = "synthetic-key"
	testSocketTicketNow     = uint64(1_000_000)
	testSocketTicketExpires = testSocketTicketNow + 1_000_000
)

// What verifies testSocketTicketPrivateKey's tickets.
func testSocketTicketPublicKeys() []*SocketTicketKey {
	return []*SocketTicketKey{{
		KeyId:            testSocketTicketKeyId,
		PublicKey:        testSocketTicketPrivateKey.Public().(ed25519.PublicKey),
		ExpireTimeMillis: testSocketTicketExpires,
	}}
}

// A ticket with every field but the name set, at its widest where that has a limit: §8.8's grant_id is a
// SHA-256, and a time here takes all a varint holds.
func testSocketTicket() *protocol.SocketTicket {
	id := func(fill byte) []byte {
		return bytes.Repeat([]byte{fill}, socketTicketIdByteCount)
	}
	return &protocol.SocketTicket{
		TicketId:              id(0x01),
		NetworkId:             id(0x02),
		ListenerClientId:      id(0x03),
		ListenId:              id(0x04),
		DialerClientId:        id(0x05),
		DialerNetworkId:       id(0x06),
		IssueTimeMillis:       math.MaxUint64 - 1,
		ExpireTimeMillis:      math.MaxUint64,
		PolicyVersion:         math.MaxUint64,
		GrantId:               bytes.Repeat([]byte{0x07}, 32),
		Backup:                true,
		GrantExpireTimeMillis: math.MaxUint64,
	}
}

// As testSocketTicket, naming a tls/ host.
func testNamedSocketTicket() *protocol.SocketTicket {
	ticket := testSocketTicket()
	ticket.Name = "tls/443/blog"
	return ticket
}

// As testSocketTicket, naming a token path of segmentCount segments.
func testTokenSocketTicket(segmentCount int) *protocol.SocketTicket {
	ticket := testSocketTicket()
	ticket.NameToken = bytes.Repeat([]byte{0x08}, segmentCount*socketTokenByteCount)
	return ticket
}

// A plaintext name of exactly byteCount bytes, in the widest shape the grammar allows.
func testLongEdgeName(byteCount int) string {
	prefix := "tls/443/" + strings.Repeat("a", socketSegmentMaxByteCount) + "/"
	return prefix + strings.Repeat("b", byteCount-len(prefix))
}

// What a Find hands a dialer for ticket: the bytes StreamOpen.ticket carries.
func testSignedSocketTicketBytes(t testing.TB, ticket *protocol.SocketTicket) []byte {
	t.Helper()
	signedTicket, err := SignSocketTicket(testSocketTicketKeyId, testSocketTicketPrivateKey, ticket)
	if err != nil {
		t.Fatal(err)
	}
	received, err := proto.Marshal(signedTicket)
	if err != nil {
		t.Fatal(err)
	}
	return received
}

// A SignedSocketTicket of raw ticket bytes, signed under purpose and signedType by key, with no check
// on what those bytes hold, as a service gone wrong might write.
func testSignRawSocketTicket(t testing.TB, key ed25519.PrivateKey, purpose string, signedType bridge.SignedType, ticketBytes []byte) []byte {
	t.Helper()
	received, err := proto.Marshal(&protocol.SignedSocketTicket{
		KeyId:     testSocketTicketKeyId,
		Ticket:    ticketBytes,
		Signature: ed25519.Sign(key, bridge.SignedBytes(purpose, signedType, ticketBytes)),
	})
	if err != nil {
		t.Fatal(err)
	}
	return received
}

// Signing reproduces every encoding a marshal can write, byte for byte, stage by stage.
func TestSocketTicketVectorsSign(t *testing.T) {
	vectors := testReadSocketTicketVectors(t)
	key := vectors.key(t, "current")
	signedCount := 0
	for _, vector := range vectors.Tickets {
		if vector.ReencodesApart {
			continue
		}
		signedCount += 1
		signedTicket, err := SignSocketTicket(key.KeyId, key.privateKey(t), vector.Fields.ticket(t))
		if err != nil {
			t.Errorf("%s: %v", vector.Name, err)
			continue
		}
		if want := testSocketHex(t, vector.Ticket); !bytes.Equal(signedTicket.GetTicket(), want) {
			t.Errorf("%s: ticket bytes %x, want %x", vector.Name, signedTicket.GetTicket(), want)
		}
		signedBytes := bridge.SignedBytes(SocketTicketPurpose, bridge.SignedType_SIGNED_SOCKET_TICKET, signedTicket.GetTicket())
		if want := testSocketHex(t, vector.SignedBytes); !bytes.Equal(signedBytes, want) {
			t.Errorf("%s: signed bytes %x, want %x", vector.Name, signedBytes, want)
		}
		if want := testSocketHex(t, vector.Signature); !bytes.Equal(signedTicket.GetSignature(), want) {
			t.Errorf("%s: signature %x, want %x", vector.Name, signedTicket.GetSignature(), want)
		}
		received, err := proto.MarshalOptions{Deterministic: true}.Marshal(signedTicket)
		if err != nil {
			t.Fatal(err)
		}
		if want := testSocketHex(t, vector.Received); !bytes.Equal(received, want) {
			t.Errorf("%s: received %x, want %x", vector.Name, received, want)
		}
	}
	if signedCount == 0 {
		t.Fatal("no vector was signed")
	}
}

// Each vector verifies from the bytes alone, to the fields the file states.
func TestSocketTicketVectorsVerify(t *testing.T) {
	vectors := testReadSocketTicketVectors(t)
	keys := vectors.ticketKeys(t)
	for _, vector := range vectors.Tickets {
		received := testSocketHex(t, vector.Received)
		ticket, err := VerifySocketTicket(received, keys, vectors.NowMillis)
		if err != nil {
			t.Errorf("%s: %v", vector.Name, err)
			continue
		}
		if vector.ReencodesApart {
			if len(ticket.ProtoReflect().GetUnknown()) == 0 {
				t.Errorf("%s: its unknown fields are gone", vector.Name)
			}
			ticket.ProtoReflect().SetUnknown(nil)
		}
		if want := vector.Fields.ticket(t); !proto.Equal(ticket, want) {
			t.Errorf("%s: %v, want %v", vector.Name, ticket, want)
		}
	}
}

// §22.6: only the bytes received verify. The vector's encoding is one no marshal writes, so the same
// signature over its re-encoding has to fail, which a verifier that re-marshals would get backward.
func TestSocketTicketVerifiesOverReceivedBytes(t *testing.T) {
	vectors := testReadSocketTicketVectors(t)
	keys := vectors.ticketKeys(t)
	checkedCount := 0
	for _, vector := range vectors.Tickets {
		if !vector.ReencodesApart {
			continue
		}
		checkedCount += 1
		ticket, err := VerifySocketTicket(testSocketHex(t, vector.Received), keys, vectors.NowMillis)
		if err != nil {
			t.Fatalf("%s: %v", vector.Name, err)
		}
		reencoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(ticket)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(reencoded, testSocketHex(t, vector.Ticket)) {
			t.Fatalf("%s: a marshal wrote this encoding, so this proves nothing", vector.Name)
		}
		received, err := proto.Marshal(&protocol.SignedSocketTicket{
			KeyId:     vectors.key(t, "current").KeyId,
			Ticket:    reencoded,
			Signature: testSocketHex(t, vector.Signature),
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := VerifySocketTicket(received, keys, vectors.NowMillis); !errors.Is(err, bridge.ErrSignedSignature) {
			t.Errorf("%s re-encoded: %v", vector.Name, err)
		}
	}
	if checkedCount == 0 {
		t.Fatal("no vector re-encodes apart")
	}
}

func TestSocketTicketVectorRefusals(t *testing.T) {
	vectors := testReadSocketTicketVectors(t)
	keys := vectors.ticketKeys(t)
	for _, vector := range vectors.Refusals {
		ticket, err := VerifySocketTicket(testSocketHex(t, vector.Received), keys, vectors.NowMillis)
		if ticket != nil {
			t.Errorf("%s: a ticket came back with %v", vector.Name, err)
		}
		if want := testSocketTicketRefusalError(t, vector.Refusal); !errors.Is(err, want) {
			t.Errorf("%s: %v, want %v", vector.Name, err, want)
		}
	}
}

// A ticket fits within §9.6's bounds at both of its limits, and the next step past either is refused.
func TestSocketTicketSizeBoundsAtBothLimits(t *testing.T) {
	longest := testSocketTicket()
	longest.Name = testLongEdgeName(socketNameMaxByteCount)
	if len(longest.GetName()) != socketNameMaxByteCount {
		t.Fatalf("a %d-byte name", len(longest.GetName()))
	}
	for _, ticket := range []*protocol.SocketTicket{longest, testTokenSocketTicket(socketNameMaxSegmentCount)} {
		signedTicket, err := SignSocketTicket(strings.Repeat("k", 64), testSocketTicketPrivateKey, ticket)
		if err != nil {
			t.Fatal(err)
		}
		if size := len(signedTicket.GetTicket()); socketTicketMaxByteCount < size {
			t.Errorf("a ticket of %d bytes", size)
		}
		if size := proto.Size(signedTicket); signedSocketTicketMaxByteCount < size {
			t.Errorf("a signed ticket of %d bytes", size)
		}
	}

	tooLong := testSocketTicket()
	tooLong.Name = testLongEdgeName(socketNameMaxByteCount + 1)
	for _, ticket := range []*protocol.SocketTicket{tooLong, testTokenSocketTicket(socketNameMaxSegmentCount + 1)} {
		if _, err := SignSocketTicket(testSocketTicketKeyId, testSocketTicketPrivateKey, ticket); !errors.Is(err, ErrSocketTicketMalformed) {
			t.Errorf("past a limit: %v", err)
		}
	}
}

// What rides beside a ticket counts toward StreamOpen.ticket too, so a key_id past what fits is refused at
// signing, and the verifier takes exactly 512 bytes and not one more.
func TestSocketTicketSignedBoundIsExact(t *testing.T) {
	ticket := testNamedSocketTicket()
	overhead := proto.Size(&protocol.SignedSocketTicket{
		KeyId:     "k",
		Ticket:    testSignedTicketBody(t, ticket),
		Signature: make([]byte, ed25519.SignatureSize),
	}) - 1

	fitting := strings.Repeat("k", signedSocketTicketMaxByteCount-overhead-2)
	signedTicket, err := SignSocketTicket(fitting, testSocketTicketPrivateKey, ticket)
	if err != nil {
		t.Fatal(err)
	}
	received, err := proto.Marshal(signedTicket)
	if err != nil {
		t.Fatal(err)
	}
	if len(received) != signedSocketTicketMaxByteCount {
		t.Fatalf("%d bytes, and this needs exactly the bound", len(received))
	}
	keys := []*SocketTicketKey{{
		KeyId:            fitting,
		PublicKey:        testSocketTicketPrivateKey.Public().(ed25519.PublicKey),
		ExpireTimeMillis: testSocketTicketExpires,
	}}
	if _, err := VerifySocketTicket(received, keys, testSocketTicketNow); err != nil {
		t.Errorf("at the bound: %v", err)
	}

	if _, err := SignSocketTicket(fitting+"k", testSocketTicketPrivateKey, ticket); !errors.Is(err, ErrSocketTicketMalformed) {
		t.Errorf("signing past the bound: %v", err)
	}
	if _, err := VerifySocketTicket(append(received, 0x00), keys, testSocketTicketNow); !errors.Is(err, ErrSocketTicketMalformed) {
		t.Errorf("verifying past the bound: %v", err)
	}
}

// A ticket's own bytes, as signing would write them.
func testSignedTicketBody(t testing.TB, ticket *protocol.SocketTicket) []byte {
	t.Helper()
	body, err := proto.MarshalOptions{Deterministic: true}.Marshal(ticket)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

// Each byte of what is signed is covered, and a flip anywhere in a ticket or its signature refuses it.
func TestSocketTicketTamperingRefused(t *testing.T) {
	keys := testSocketTicketPublicKeys()
	signedTicket, err := SignSocketTicket(testSocketTicketKeyId, testSocketTicketPrivateKey, testNamedSocketTicket())
	if err != nil {
		t.Fatal(err)
	}
	verify := func(tampered *protocol.SignedSocketTicket) error {
		received, err := proto.Marshal(tampered)
		if err != nil {
			t.Fatal(err)
		}
		_, err = VerifySocketTicket(received, keys, testSocketTicketNow)
		return err
	}
	if err := verify(signedTicket); err != nil {
		t.Fatal(err)
	}
	for index := range signedTicket.GetTicket() {
		tampered := proto.CloneOf(signedTicket)
		tampered.Ticket[index] ^= 0x01
		if err := verify(tampered); !errors.Is(err, bridge.ErrSignedSignature) {
			t.Errorf("ticket byte %d: %v", index, err)
		}
	}
	for index := range signedTicket.GetSignature() {
		tampered := proto.CloneOf(signedTicket)
		tampered.Signature[index] ^= 0x01
		if err := verify(tampered); !errors.Is(err, bridge.ErrSignedSignature) {
			t.Errorf("signature byte %d: %v", index, err)
		}
	}
}

func TestVerifySocketTicketRefusesAnUnknownKeyId(t *testing.T) {
	received := testSignedSocketTicketBytes(t, testNamedSocketTicket())
	keys := testSocketTicketPublicKeys()
	keys[0].KeyId = "another-key"
	if _, err := VerifySocketTicket(received, keys, testSocketTicketNow); !errors.Is(err, ErrSocketTicketKeyUnknown) {
		t.Errorf("another key's id: %v", err)
	}
	if _, err := VerifySocketTicket(received, nil, testSocketTicketNow); !errors.Is(err, ErrSocketTicketKeyUnknown) {
		t.Errorf("no keys: %v", err)
	}
	if _, err := VerifySocketTicket(received, []*SocketTicketKey{nil}, testSocketTicketNow); !errors.Is(err, ErrSocketTicketKeyUnknown) {
		t.Errorf("a nil key: %v", err)
	}
}

// A key holds up to its expiry and not at it, and a key with none has already expired.
func TestVerifySocketTicketRefusesAnExpiredKey(t *testing.T) {
	received := testSignedSocketTicketBytes(t, testNamedSocketTicket())
	keys := testSocketTicketPublicKeys()
	if _, err := VerifySocketTicket(received, keys, testSocketTicketExpires-1); err != nil {
		t.Errorf("before its expiry: %v", err)
	}
	if _, err := VerifySocketTicket(received, keys, testSocketTicketExpires); !errors.Is(err, ErrSocketTicketKeyExpired) {
		t.Errorf("at its expiry: %v", err)
	}
	keys[0].ExpireTimeMillis = 0
	if _, err := VerifySocketTicket(received, keys, 0); !errors.Is(err, ErrSocketTicketKeyExpired) {
		t.Errorf("no expiry: %v", err)
	}
}

// §9.8's rotation overlap: whichever listed key a ticket names is the one it verifies under, and a key
// another ticket's id does not name is never tried.
func TestVerifySocketTicketTakesTheKeyItNames(t *testing.T) {
	received := testSignedSocketTicketBytes(t, testNamedSocketTicket())
	otherKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x44}, ed25519.SeedSize))
	keys := append([]*SocketTicketKey{{
		KeyId:            "newer-key",
		PublicKey:        otherKey.Public().(ed25519.PublicKey),
		ExpireTimeMillis: testSocketTicketExpires,
	}}, testSocketTicketPublicKeys()...)
	if _, err := VerifySocketTicket(received, keys, testSocketTicketNow); err != nil {
		t.Errorf("an older listed key: %v", err)
	}

	keys[1].PublicKey = otherKey.Public().(ed25519.PublicKey)
	if _, err := VerifySocketTicket(received, keys, testSocketTicketNow); !errors.Is(err, bridge.ErrSignedSignature) {
		t.Errorf("the named key changed: %v", err)
	}
	keys[1].PublicKey = []byte{0x01}
	if _, err := VerifySocketTicket(received, keys, testSocketTicketNow); !errors.Is(err, bridge.ErrSignedKey) {
		t.Errorf("a key of no length: %v", err)
	}
}

// A ticket's expiry is admission step 4's, after steps whose refusals differ, so an expired ticket still
// verifies here and comes back for the caller to refuse in order.
func TestVerifySocketTicketLeavesTheTicketsExpiryToItsCaller(t *testing.T) {
	ticket := testNamedSocketTicket()
	ticket.IssueTimeMillis = 1
	ticket.ExpireTimeMillis = 2
	verified, err := VerifySocketTicket(testSignedSocketTicketBytes(t, ticket), testSocketTicketPublicKeys(), testSocketTicketNow)
	if err != nil {
		t.Fatal(err)
	}
	if verified.GetExpireTimeMillis() != 2 {
		t.Errorf("expiry %d", verified.GetExpireTimeMillis())
	}
}

// Between a named and a tokened ticket every field of the message is set, and each comes back whole.
func TestSocketTicketEveryFieldRoundTrips(t *testing.T) {
	seenNumbers := map[protoreflect.FieldNumber]bool{}
	for _, ticket := range []*protocol.SocketTicket{testNamedSocketTicket(), testTokenSocketTicket(2)} {
		verified, err := VerifySocketTicket(testSignedSocketTicketBytes(t, ticket), testSocketTicketPublicKeys(), testSocketTicketNow)
		if err != nil {
			t.Fatal(err)
		}
		if !proto.Equal(verified, ticket) {
			t.Errorf("%v came back as %v", ticket, verified)
		}
		ticket.ProtoReflect().Range(func(field protoreflect.FieldDescriptor, value protoreflect.Value) bool {
			seenNumbers[field.Number()] = true
			return true
		})
	}
	fields := (&protocol.SocketTicket{}).ProtoReflect().Descriptor().Fields()
	for index := range fields.Len() {
		if field := fields.Get(index); !seenNumbers[field.Number()] {
			t.Errorf("%s never reached the wire", field.Name())
		}
	}
}

// Field 15 was policy_delta_seq, and no field may take its number. A signer that still wrote one
// would verify, and nothing reads it.
func TestSocketTicketFieldFifteenStaysReserved(t *testing.T) {
	descriptor := (&protocol.SocketTicket{}).ProtoReflect().Descriptor()
	const withdrawnNumber = protoreflect.FieldNumber(15)
	if !descriptor.ReservedRanges().Has(withdrawnNumber) {
		t.Error("15 is not reserved")
	}
	if descriptor.Fields().ByNumber(withdrawnNumber) != nil {
		t.Error("a field took 15")
	}

	body := testSignedTicketBody(t, testNamedSocketTicket())
	body = protowire.AppendTag(body, protowire.Number(withdrawnNumber), protowire.VarintType)
	body = protowire.AppendVarint(body, 3)
	received := testSignRawSocketTicket(t, testSocketTicketPrivateKey, SocketTicketPurpose, bridge.SignedType_SIGNED_SOCKET_TICKET, body)
	ticket, err := VerifySocketTicket(received, testSocketTicketPublicKeys(), testSocketTicketNow)
	if err != nil {
		t.Fatal(err)
	}
	ticket.ProtoReflect().SetUnknown(nil)
	if !proto.Equal(ticket, testNamedSocketTicket()) {
		t.Errorf("%v", ticket)
	}
}

// Everything §9.6 refuses of a ticket, at the signer. The verifier refuses each of these too, as a
// signature from a service gone wrong, and neither says what the name was (I-13).
func TestSocketTicketShapeRefusals(t *testing.T) {
	cases := []struct {
		name   string
		change func(ticket *protocol.SocketTicket)
	}{
		{name: "both a name and a token path", change: func(ticket *protocol.SocketTicket) {
			ticket.NameToken = bytes.Repeat([]byte{0x08}, socketTokenByteCount)
		}},
		{name: "neither a name nor a token path", change: func(ticket *protocol.SocketTicket) { ticket.Name = "" }},
		{name: "an application name", change: func(ticket *protocol.SocketTicket) { ticket.Name = "secretdb/primary" }},
		{name: "a share name", change: func(ticket *protocol.SocketTicket) {
			ticket.Name = "share/" + testSocketShareToken
		}},
		{name: "a reserved name", change: func(ticket *protocol.SocketTicket) { ticket.Name = "sys/secret" }},
		{name: "an uppercase name", change: func(ticket *protocol.SocketTicket) { ticket.Name = "tls/443/Secret" }},
		{name: "a name outside the grammar", change: func(ticket *protocol.SocketTicket) { ticket.Name = "tls/443/se cret" }},
		{name: "a token path of half a segment", change: func(ticket *protocol.SocketTicket) {
			ticket.Name = ""
			ticket.NameToken = make([]byte, socketTokenByteCount/2)
		}},
		{name: "a short ticket_id", change: func(ticket *protocol.SocketTicket) { ticket.TicketId = ticket.TicketId[1:] }},
		{name: "a short network_id", change: func(ticket *protocol.SocketTicket) { ticket.NetworkId = ticket.NetworkId[1:] }},
		{name: "a long listener_client_id", change: func(ticket *protocol.SocketTicket) {
			ticket.ListenerClientId = append(ticket.ListenerClientId, 0x00)
		}},
		{name: "no listen_id", change: func(ticket *protocol.SocketTicket) { ticket.ListenId = nil }},
		{name: "no dialer_client_id", change: func(ticket *protocol.SocketTicket) { ticket.DialerClientId = nil }},
		{name: "no dialer_network_id", change: func(ticket *protocol.SocketTicket) { ticket.DialerNetworkId = nil }},
		{name: "an expiry at its issue time", change: func(ticket *protocol.SocketTicket) {
			ticket.ExpireTimeMillis = ticket.GetIssueTimeMillis()
		}},
		{name: "an expiry before its issue time", change: func(ticket *protocol.SocketTicket) {
			ticket.ExpireTimeMillis = ticket.GetIssueTimeMillis() - 1
		}},
	}
	for _, c := range cases {
		ticket := testNamedSocketTicket()
		c.change(ticket)
		signedTicket, err := SignSocketTicket(testSocketTicketKeyId, testSocketTicketPrivateKey, ticket)
		if !errors.Is(err, ErrSocketTicketMalformed) || signedTicket != nil {
			t.Errorf("%s signed: %v", c.name, err)
		} else if strings.Contains(err.Error(), "ecret") {
			t.Errorf("%s: the name is in %q", c.name, err)
		}

		received := testSignRawSocketTicket(
			t,
			testSocketTicketPrivateKey,
			SocketTicketPurpose,
			bridge.SignedType_SIGNED_SOCKET_TICKET,
			testSignedTicketBody(t, ticket),
		)
		verified, err := VerifySocketTicket(received, testSocketTicketPublicKeys(), testSocketTicketNow)
		if !errors.Is(err, ErrSocketTicketMalformed) || verified != nil {
			t.Errorf("%s verified: %v", c.name, err)
		} else if strings.Contains(err.Error(), "ecret") {
			t.Errorf("%s: the name is in %q", c.name, err)
		}
	}
}

// Each edge namespace reaches a ticket in the clear (§9.4's table).
func TestSocketTicketTakesEachEdgeNamespace(t *testing.T) {
	for _, name := range []string{"tls/443/blog", "tls/8443/@", "smtp/25/mx", "ur/smtpedge"} {
		ticket := testSocketTicket()
		ticket.Name = name
		verified, err := VerifySocketTicket(testSignedSocketTicketBytes(t, ticket), testSocketTicketPublicKeys(), testSocketTicketNow)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if verified.GetName() != name {
			t.Errorf("%s came back as %s", name, verified.GetName())
		}
	}
}

func TestSignSocketTicketRefusesABadKey(t *testing.T) {
	if _, err := SignSocketTicket("", testSocketTicketPrivateKey, testNamedSocketTicket()); !errors.Is(err, ErrSocketTicketMalformed) {
		t.Errorf("no key id: %v", err)
	}
	if _, err := SignSocketTicket(testSocketTicketKeyId, testSocketTicketPrivateKey[:ed25519.SeedSize], testNamedSocketTicket()); !errors.Is(err, bridge.ErrSignedKey) {
		t.Errorf("a seed for a key: %v", err)
	}
	if _, err := SignSocketTicket(testSocketTicketKeyId, nil, testNamedSocketTicket()); !errors.Is(err, bridge.ErrSignedKey) {
		t.Errorf("no key: %v", err)
	}
	if _, err := SignSocketTicket(testSocketTicketKeyId, testSocketTicketPrivateKey, nil); !errors.Is(err, ErrSocketTicketMalformed) {
		t.Errorf("no ticket: %v", err)
	}
}

// One body that parses as both of §9's signed messages, with every id readable as text, since a claim's
// name and protocol are strings.
func testSocketDualBody(t testing.TB) []byte {
	t.Helper()
	ticket := testNamedSocketTicket()
	for _, id := range []*[]byte{&ticket.TicketId, &ticket.NetworkId, &ticket.ListenerClientId, &ticket.ListenId, &ticket.DialerClientId, &ticket.DialerNetworkId} {
		*id = bytes.Repeat([]byte{'a'}, socketTicketIdByteCount)
	}
	ticket.IssueTimeMillis = 1
	ticket.ExpireTimeMillis = 2
	ticket.PolicyVersion = 0
	ticket.GrantId = nil
	ticket.Backup = false
	ticket.GrantExpireTimeMillis = 0
	body := testSignedTicketBody(t, ticket)
	if err := proto.Unmarshal(body, &protocol.SocketRegistrationClaim{}); err != nil {
		t.Fatalf("the fixture must parse as a claim too, or this proves nothing: %v", err)
	}
	return body
}

// §6.11: a body parses only as its registered type. These two encode alike, so nothing in the body tells
// them apart, and each is refused as the other however a relay relabels it.
func TestSocketTicketAndClaimParseOnlyAsTheirRegisteredTypes(t *testing.T) {
	body := testSocketDualBody(t)
	publicKey := testSocketTicketPrivateKey.Public().(ed25519.PublicKey)
	ticketType := bridge.SignedType_SIGNED_SOCKET_TICKET
	claimType := bridge.SignedType_SIGNED_SOCKET_REGISTRATION

	// a ticket, shown as a claim
	received := testSignRawSocketTicket(t, testSocketTicketPrivateKey, SocketTicketPurpose, ticketType, body)
	if _, err := VerifySocketTicket(received, testSocketTicketPublicKeys(), testSocketTicketNow); err != nil {
		t.Fatal(err)
	}
	signed := &bridge.Signed{
		Body:      body,
		Signature: ed25519.Sign(testSocketTicketPrivateKey, bridge.SignedBytes(SocketTicketPurpose, ticketType, body)),
		Type:      uint32(ticketType),
	}
	err := bridge.VerifySigned(signed, SocketRegistrationPurpose, claimType, bridge.SignedKeyAlgEd25519, publicKey)
	if !errors.Is(err, bridge.ErrSignedTypeMismatch) {
		t.Errorf("a ticket as a claim: %v", err)
	}
	signed.Type = uint32(claimType)
	err = bridge.VerifySigned(signed, SocketRegistrationPurpose, claimType, bridge.SignedKeyAlgEd25519, publicKey)
	if !errors.Is(err, bridge.ErrSignedSignature) {
		t.Errorf("a ticket relabeled a claim: %v", err)
	}

	// a claim, shown as a ticket, under a key that signed both
	claim := &bridge.Signed{
		Body:      body,
		Signature: ed25519.Sign(testSocketTicketPrivateKey, bridge.SignedBytes(SocketRegistrationPurpose, claimType, body)),
		Type:      uint32(claimType),
	}
	if err := bridge.VerifySigned(claim, SocketRegistrationPurpose, claimType, bridge.SignedKeyAlgEd25519, publicKey); err != nil {
		t.Fatal(err)
	}
	received, err = proto.Marshal(&protocol.SignedSocketTicket{
		KeyId:     testSocketTicketKeyId,
		Ticket:    claim.GetBody(),
		Signature: claim.GetSignature(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySocketTicket(received, testSocketTicketPublicKeys(), testSocketTicketNow); !errors.Is(err, bridge.ErrSignedSignature) {
		t.Errorf("a claim as a ticket: %v", err)
	}
}

// §9.5's tuple, every field of it, through the Signed a claim rides in.
func TestSocketRegistrationClaimRoundTrips(t *testing.T) {
	claims := []*protocol.SocketRegistrationClaim{
		{
			NetworkId: bytes.Repeat([]byte{0x01}, socketTicketIdByteCount),
			Name:      "tls/443/blog",
			ListenId:  bytes.Repeat([]byte{0x02}, socketTicketIdByteCount),
			Protocol:  "tls",
			AppMode:   "raw",
		},
		{
			NetworkId: bytes.Repeat([]byte{0x01}, socketTicketIdByteCount),
			NameToken: bytes.Repeat([]byte{0x03}, 2*socketTokenByteCount),
			ListenId:  bytes.Repeat([]byte{0x02}, socketTicketIdByteCount),
			Protocol:  "tcp",
		},
	}
	seenNumbers := map[protoreflect.FieldNumber]bool{}
	publicKey := testSocketTicketPrivateKey.Public().(ed25519.PublicKey)
	claimType := bridge.SignedType_SIGNED_SOCKET_REGISTRATION
	for _, claim := range claims {
		body, err := proto.Marshal(claim)
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := proto.Marshal(&bridge.Signed{
			Body:      body,
			Signature: ed25519.Sign(testSocketTicketPrivateKey, bridge.SignedBytes(SocketRegistrationPurpose, claimType, body)),
			Type:      uint32(claimType),
		})
		if err != nil {
			t.Fatal(err)
		}

		signed := &bridge.Signed{}
		if err := proto.Unmarshal(encoded, signed); err != nil {
			t.Fatal(err)
		}
		if err := bridge.VerifySigned(signed, SocketRegistrationPurpose, claimType, bridge.SignedKeyAlgEd25519, publicKey); err != nil {
			t.Fatal(err)
		}
		parsed := &protocol.SocketRegistrationClaim{}
		if err := proto.Unmarshal(signed.GetBody(), parsed); err != nil {
			t.Fatal(err)
		}
		if !proto.Equal(parsed, claim) {
			t.Errorf("%v came back as %v", claim, parsed)
		}
		claim.ProtoReflect().Range(func(field protoreflect.FieldDescriptor, value protoreflect.Value) bool {
			seenNumbers[field.Number()] = true
			return true
		})
	}
	fields := (&protocol.SocketRegistrationClaim{}).ProtoReflect().Descriptor().Fields()
	for index := range fields.Len() {
		if field := fields.Get(index); !seenNumbers[field.Number()] {
			t.Errorf("%s never reached the wire", field.Name())
		}
	}
}

// §9.6's five codes one to one, and §6.11's zero, with anything else a sender may write, taken as
// invalid: a stream never reads an unknown code as retry or success.
func TestSocketRejectCode(t *testing.T) {
	cases := []struct {
		code uint32
		want protocol.StreamRejectCode
	}{
		{code: 0, want: protocol.StreamRejectCode_SR_INVALID},
		{code: 1, want: protocol.StreamRejectCode_SR_RETRY},
		{code: 2, want: protocol.StreamRejectCode_SR_BUSY},
		{code: 3, want: protocol.StreamRejectCode_SR_DENIED},
		{code: 4, want: protocol.StreamRejectCode_SR_INVALID},
		{code: 5, want: protocol.StreamRejectCode_SR_QUOTA},
		{code: 6, want: protocol.StreamRejectCode_SR_INVALID},
		{code: math.MaxInt32, want: protocol.StreamRejectCode_SR_INVALID},
		{code: math.MaxInt32 + 1, want: protocol.StreamRejectCode_SR_INVALID},
		{code: math.MaxUint32, want: protocol.StreamRejectCode_SR_INVALID},
	}
	for _, c := range cases {
		if got := SocketRejectCode(c.code); got != c.want {
			t.Errorf("%d is %s, want %s", c.code, got, c.want)
		}
	}
}
