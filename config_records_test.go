// §7.9's records as the log carries them: §22.6's typed Signed and body targets through the registry, the A_n vectors,
// and ids. Nothing here reads the source tree, so this runs on every leg, a Worker's included: the vectors are embedded.

package sidecar

import (
	"bytes"
	"cmp"
	"crypto/ed25519"
	"crypto/sha256"
	_ "embed"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"
	"unicode"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// Fixed bytes: the same file on every leg, with no file system to read it from in a Worker.
//
//go:embed testdata/config/chain.json
var testChainJson []byte

// The test key of testdata/config/chain.json.
var testConfigKey = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x5A}, ed25519.SeedSize))

// Above no real field number, so an encoding holding it is always unknown.
const testConfigUnknownField = protowire.Number(9999)

func testConfigPublicKey() ed25519.PublicKey {
	return testConfigKey.Public().(ed25519.PublicKey)
}

// The registered types in number order, so a failure reads the same on every run.
func testConfigTypes() []bridge.SignedType {
	return slices.Sorted(maps.Keys(configStatementTypes))
}

// A value no proto3 encoding omits, so a field filled here always reaches the wire.
func testConfigValue(field protoreflect.FieldDescriptor, seed int) protoreflect.Value {
	number := int(field.Number()) + seed
	switch field.Kind() {
	case protoreflect.BoolKind:
		return protoreflect.ValueOfBool(true)
	case protoreflect.Int32Kind, protoreflect.Sint32Kind, protoreflect.Sfixed32Kind:
		return protoreflect.ValueOfInt32(int32(number))
	case protoreflect.Uint32Kind, protoreflect.Fixed32Kind:
		return protoreflect.ValueOfUint32(uint32(number))
	case protoreflect.Int64Kind, protoreflect.Sint64Kind, protoreflect.Sfixed64Kind:
		return protoreflect.ValueOfInt64(int64(number))
	case protoreflect.Uint64Kind, protoreflect.Fixed64Kind:
		return protoreflect.ValueOfUint64(uint64(number))
	case protoreflect.EnumKind:
		values := field.Enum().Values()
		return protoreflect.ValueOfEnum(values.Get(values.Len() - 1).Number())
	case protoreflect.StringKind:
		return protoreflect.ValueOfString(fmt.Sprintf("value %d", number))
	case protoreflect.BytesKind:
		return protoreflect.ValueOfBytes(bytes.Repeat([]byte{byte(number)}, 16))
	}
	panic(fmt.Sprintf("%s has kind %s", field.FullName(), field.Kind()))
}

// Sets every field, with two elements in each list, so a body shows every field its message has.
func testConfigFill(message protoreflect.Message) {
	fields := message.Descriptor().Fields()
	for i := range fields.Len() {
		field := fields.Get(i)
		switch {
		case field.IsList():
			list := message.Mutable(field).List()
			for seed := range 2 {
				if field.Message() == nil {
					list.Append(testConfigValue(field, seed+1))
					continue
				}
				element := list.NewElement()
				testConfigFill(element.Message())
				list.Append(element)
			}
		case field.Message() != nil:
			testConfigFill(message.Mutable(field).Message())
		default:
			message.Set(field, testConfigValue(field, 1))
		}
	}
}

func testConfigEncode(t testing.TB, message proto.Message) []byte {
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(message)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

// A body of signedType with every field set.
func testConfigBody(t testing.TB, signedType bridge.SignedType) []byte {
	message := configStatementTypes[signedType].body.ProtoReflect().New()
	testConfigFill(message)
	return testConfigEncode(t, message.Interface())
}

// body as the signer signs it, under signedType's purpose.
func testConfigSign(signedType bridge.SignedType, body []byte) *bridge.Signed {
	signedBytes := bridge.SignedBytes(configStatementTypes[signedType].purpose, signedType, body)
	return &bridge.Signed{
		Body:      body,
		Signature: ed25519.Sign(testConfigKey, signedBytes),
		Type:      uint32(signedType),
	}
}

// A statement of signedType as it arrives, with every field of its body set.
func testConfigSignedBytes(t testing.TB, signedType bridge.SignedType) []byte {
	return testConfigEncode(t, testConfigSign(signedType, testConfigBody(t, signedType)))
}

func testConfigVerify(signed *bridge.Signed, purpose string, signedType bridge.SignedType) error {
	return bridge.VerifySigned(signed, purpose, signedType, bridge.SignedKeyAlgEd25519, testConfigPublicKey())
}

// An encoding's top-level fields, each a whole record: tag and value.
func testConfigSplitFields(t testing.TB, encoded []byte) [][]byte {
	fields := [][]byte{}
	for rest := encoded; len(rest) > 0; {
		_, _, length := protowire.ConsumeField(rest)
		if length < 0 {
			t.Fatalf("a field does not parse: %v", protowire.ParseError(length))
		}
		fields = append(fields, rest[:length])
		rest = rest[length:]
	}
	return fields
}

// Highest numbers first. Stable, so a repeated field keeps its order and the body still means the same.
func testConfigReordered(t testing.TB, encoded []byte) []byte {
	fields := testConfigSplitFields(t, encoded)
	slices.SortStableFunc(fields, func(a, b []byte) int {
		numberA, _, _ := protowire.ConsumeTag(a)
		numberB, _, _ := protowire.ConsumeTag(b)
		return cmp.Compare(numberB, numberA)
	})
	return bytes.Join(fields, nil)
}

// Each top-level varint one byte longer than it need be, a form every parser must accept and no encoder writes.
func testConfigNonMinimal(t testing.TB, encoded []byte) []byte {
	rewritten := []byte{}
	for _, field := range testConfigSplitFields(t, encoded) {
		number, wireType, tagLength := protowire.ConsumeTag(field)
		if wireType != protowire.VarintType {
			rewritten = append(rewritten, field...)
			continue
		}
		value, _ := protowire.ConsumeVarint(field[tagLength:])
		padded := protowire.AppendVarint(nil, value)
		padded[len(padded)-1] |= 0x80
		rewritten = protowire.AppendTag(rewritten, number, protowire.VarintType)
		rewritten = append(append(rewritten, padded...), 0x00)
	}
	return rewritten
}

// A whole field no message declares, tag and value.
func testConfigUnknown() []byte {
	return protowire.AppendVarint(protowire.AppendTag(nil, testConfigUnknownField, protowire.VarintType), 7)
}

// §6.11: exactly what §7.9, §8.8 and §17.8 put in the log or a head. A value added to one of those ranges fails here
// until it registers a body, and a type from outside them fails if it does.
func TestConfigTypesAreWhatTheLogCarries(t *testing.T) {
	want := []bridge.SignedType{}
	for number := range bridge.SignedType_name {
		if number>>8 == 0x11 || number>>8 == 0x12 || (number >= 0x1901 && number <= 0x1907) {
			want = append(want, bridge.SignedType(number))
		}
	}
	slices.Sort(want)
	if len(want) != 15+21+7 {
		t.Errorf("found %d types", len(want))
	}
	if got := testConfigTypes(); !slices.Equal(got, want) {
		t.Errorf("registered %v, want %v", got, want)
	}
}

// The purposes §7.9, §8.8 and §17.8 write, read through what a heterogeneous list uses.
func TestConfigStatementPurposeIsTheOneEachSectionWrites(t *testing.T) {
	for _, signedType := range testConfigTypes() {
		want := bridge.SignedPurposeAuthority
		switch {
		case signedType == bridge.SignedType_SIGNED_AUDIT_OPT_IN || signedType == bridge.SignedType_SIGNED_AUDIT_OPT_OUT:
		case signedType>>8 == 0x11:
			want = bridge.SignedPurposeAcl
		case signedType>>8 == 0x19:
			want = bridge.SignedPurposeBridge
		}
		got, ok := ConfigStatementPurpose(signedType)
		if !ok || got != want {
			t.Errorf("%s: %q, %t, want %q", signedType, got, ok, want)
		}
	}
	for _, signedType := range []bridge.SignedType{
		bridge.SignedType_SIGNED_TYPE_NONE,
		bridge.SignedType_SIGNED_EVS_PUSH,
		bridge.SignedType_SIGNED_WINDOW_DELEGATION,
		bridge.SignedType_SIGNED_SHARE_CERT,
		bridge.SignedType(0x12FF),
		bridge.SignedType(-1),
	} {
		if purpose, ok := ConfigStatementPurpose(signedType); ok {
			t.Errorf("%s registers %q", signedType, purpose)
		}
	}
}

// One body per value, each the message its SIGNED_<MESSAGE> name says (§6.11), which a table that paired two types
// the wrong way round would fail.
func TestEachConfigTypeRegistersTheBodyItNames(t *testing.T) {
	bodyTypes := map[protoreflect.FullName]bridge.SignedType{}
	for _, signedType := range testConfigTypes() {
		descriptor := configStatementTypes[signedType].body.ProtoReflect().Descriptor()
		if other, ok := bodyTypes[descriptor.FullName()]; ok {
			t.Errorf("%s and %s share %s", signedType, other, descriptor.Name())
		}
		bodyTypes[descriptor.FullName()] = signedType

		name := strings.Builder{}
		name.WriteString("SIGNED")
		for _, character := range string(descriptor.Name()) {
			if unicode.IsUpper(character) {
				name.WriteByte('_')
			}
			name.WriteRune(unicode.ToUpper(character))
		}
		if name.String() != signedType.String() {
			t.Errorf("%s registers %s", signedType, descriptor.Name())
		}
	}
}

// Every value of the enum under every purpose: only the registered pairs parse, and each to its own message.
func TestParseConfigStatementTakesOnlyItsPair(t *testing.T) {
	purposes := []string{
		bridge.SignedPurposeAuthority, bridge.SignedPurposeAcl, bridge.SignedPurposeBridge,
		"", "window-delegation", "evs-push", "authority\x00", "Authority",
	}
	signedTypes := []bridge.SignedType{bridge.SignedType(-1), bridge.SignedType(0x12FF), bridge.SignedType(0x1216)}
	for number := range bridge.SignedType_name {
		signedTypes = append(signedTypes, bridge.SignedType(number))
	}
	for _, signedType := range signedTypes {
		statementType, registered := configStatementTypes[signedType]
		body := []byte{}
		if registered {
			body = testConfigBody(t, signedType)
		}
		for _, purpose := range purposes {
			message, err := ParseConfigStatement(purpose, signedType, body)
			if !registered || purpose != statementType.purpose {
				if !errors.Is(err, ErrConfigStatementType) || message != nil {
					t.Errorf("%s under %q: %v, %v", signedType, purpose, message, err)
				}
				continue
			}
			if err != nil {
				t.Errorf("%s under %q: %v", signedType, purpose, err)
				continue
			}
			if message.ProtoReflect().Descriptor() != statementType.body.ProtoReflect().Descriptor() {
				t.Errorf("%s parsed as %s", signedType, message.ProtoReflect().Descriptor().Name())
			}
			if !bytes.Equal(testConfigEncode(t, message), body) {
				t.Errorf("%s lost something on the way in", signedType)
			}
		}
	}
}

func TestParseConfigStatementRefusesABodyThatDoesNotParse(t *testing.T) {
	purpose := bridge.SignedPurposeAuthority
	signedType := bridge.SignedType_SIGNED_GENESIS
	for _, body := range [][]byte{{0x0A}, {0x0A, 0xFF}, {0xFF}, {0x0A, 0x05, 0x00}} {
		message, err := ParseConfigStatement(purpose, signedType, body)
		if !errors.Is(err, ErrConfigStatementBody) || message != nil {
			t.Errorf("%x: %v, %v", body, message, err)
		}
	}
}

// A field a newer writer added stays with the body (§6.4).
func TestParseConfigStatementKeepsUnknownFields(t *testing.T) {
	signedType := bridge.SignedType_SIGNED_ADMISSION_CONFIRM
	body := append(testConfigBody(t, signedType), testConfigUnknown()...)
	message, err := ParseConfigStatement(bridge.SignedPurposeAuthority, signedType, body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(message.ProtoReflect().GetUnknown(), testConfigUnknown()) {
		t.Errorf("unknown bytes %x", message.ProtoReflect().GetUnknown())
	}
}

// §22.6's typed Signed target, every ordered pair of the types the log carries: a statement is refused as any other,
// whether a relay lies about its type or rewrites the field, and however the two parse.
func TestEveryConfigTypeIsRefusedAsEveryOther(t *testing.T) {
	signedTypes := testConfigTypes()
	for _, signedType := range signedTypes {
		purpose := configStatementTypes[signedType].purpose
		signed := testConfigSign(signedType, testConfigBody(t, signedType))
		if err := testConfigVerify(signed, purpose, signedType); err != nil {
			t.Fatalf("%s: %v", signedType, err)
		}
		for _, otherType := range signedTypes {
			if otherType == signedType {
				continue
			}
			otherPurpose := configStatementTypes[otherType].purpose
			if err := testConfigVerify(signed, otherPurpose, otherType); !errors.Is(err, bridge.ErrSignedTypeMismatch) {
				t.Errorf("%s presented as %s: %v", signedType, otherType, err)
			}
			rewritten := &bridge.Signed{Body: signed.GetBody(), Signature: signed.GetSignature(), Type: uint32(otherType)}
			if err := testConfigVerify(rewritten, otherPurpose, otherType); !errors.Is(err, bridge.ErrSignedSignature) {
				t.Errorf("%s rewritten to %s: %v", signedType, otherType, err)
			}
			if otherPurpose != purpose {
				_, err := ParseConfigStatement(purpose, otherType, signed.GetBody())
				if !errors.Is(err, ErrConfigStatementType) {
					t.Errorf("%s parsed as %s under its own purpose: %v", signedType, otherType, err)
				}
			}
		}
	}
}

// §22.6's named case through the whole path. The two bodies are the same bytes, so each parses as either statement,
// and only the signed type says which it is. It stands in for "equal field-1 bytes": the design's statements open
// with their header at field 1, so the whole of the two bodies is equal here, which asks more.
func TestGrantRevokeIsNeverAnOwnerConfirm(t *testing.T) {
	header := &bridge.StatementHeader{
		NetworkId:  bytes.Repeat([]byte{0x01}, 16),
		At:         &bridge.AuthPin{Version: 7, Chain: bytes.Repeat([]byte{0x02}, sha256.Size)},
		Nonce:      bytes.Repeat([]byte{0x03}, 16),
		NotAfterMs: 1,
	}
	id := bytes.Repeat([]byte{0x04}, 16)
	body := testConfigEncode(t, &bridge.GrantRevoke{Header: header, GrantId: id})
	if !bytes.Equal(body, testConfigEncode(t, &protocol.OwnerConfirm{Header: header, SidecarId: id})) {
		t.Fatal("the fixture must give one body for both statements, or this proves nothing")
	}

	purpose := bridge.SignedPurposeAcl
	grantRevokeType := bridge.SignedType_SIGNED_GRANT_REVOKE
	ownerConfirmType := bridge.SignedType_SIGNED_OWNER_CONFIRM
	message, err := ParseConfigStatement(purpose, grantRevokeType, body)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := message.(*bridge.GrantRevoke); !ok {
		t.Errorf("parsed as %T", message)
	}
	message, err = ParseConfigStatement(purpose, ownerConfirmType, body)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := message.(*protocol.OwnerConfirm); !ok {
		t.Errorf("parsed as %T", message)
	}

	signed := testConfigSign(grantRevokeType, body)
	if err := testConfigVerify(signed, purpose, grantRevokeType); err != nil {
		t.Fatal(err)
	}
	if err := testConfigVerify(signed, purpose, ownerConfirmType); !errors.Is(err, bridge.ErrSignedTypeMismatch) {
		t.Errorf("presented as OwnerConfirm: %v", err)
	}
	signed.Type = uint32(ownerConfirmType)
	if err := testConfigVerify(signed, purpose, ownerConfirmType); !errors.Is(err, bridge.ErrSignedSignature) {
		t.Errorf("rewritten to OwnerConfirm: %v", err)
	}
}

// §22.6's body target for each type the log carries, with the signature protocol's every-body tests leave out: a body
// however it was encoded verifies as received and parses to the same message, while the canonical encoding of what it
// parsed to is another body, which the signature refuses, so a layer that re-marshaled could not pass as one that kept.
func TestConfigBodiesVerifyAsReceivedHoweverEncoded(t *testing.T) {
	differed := map[string]int{}
	for _, signedType := range testConfigTypes() {
		purpose := configStatementTypes[signedType].purpose
		canonical := testConfigBody(t, signedType)
		want, err := ParseConfigStatement(purpose, signedType, canonical)
		if err != nil {
			t.Fatalf("%s: %v", signedType, err)
		}
		forms := map[string][]byte{
			"reordered":   testConfigReordered(t, canonical),
			"non-minimal": testConfigNonMinimal(t, canonical),
			"repeated":    append(slices.Clone(canonical), canonical...),
			"unknown":     append(slices.Clone(canonical), testConfigUnknown()...),
		}
		for form, body := range forms {
			received := &bridge.Signed{}
			if err := proto.Unmarshal(testConfigEncode(t, testConfigSign(signedType, body)), received); err != nil {
				t.Fatal(err)
			}
			if err := testConfigVerify(received, purpose, signedType); err != nil {
				t.Errorf("%s %s: %v", signedType, form, err)
			}
			message, err := ParseConfigStatement(purpose, signedType, received.GetBody())
			if err != nil {
				t.Errorf("%s %s: %v", signedType, form, err)
				continue
			}
			if form == "reordered" || form == "non-minimal" {
				if !proto.Equal(message, want) {
					t.Errorf("%s %s parsed differently", signedType, form)
				}
			}
			remarshaled := testConfigEncode(t, message)
			if bytes.Equal(remarshaled, body) {
				continue
			}
			differed[form]++
			received.Body = remarshaled
			if err := testConfigVerify(received, purpose, signedType); !errors.Is(err, bridge.ErrSignedSignature) {
				t.Errorf("%s %s verified over a re-marshal: %v", signedType, form, err)
			}
		}
	}
	// A form that never changed a byte would prove nothing about what a re-marshal does.
	for _, form := range []string{"reordered", "non-minimal", "repeated"} {
		if differed[form] == 0 {
			t.Errorf("no body's %s form differed from its re-marshal", form)
		}
	}
}

// §22.6's packed seeds: no statement holds a packed field of its own, so they reach one through a rule, which any
// parser takes either way.
func TestVersioningRulesParsePackedOrNot(t *testing.T) {
	signedType := bridge.SignedType_SIGNED_VERSIONING_RULES
	want := &protocol.VersioningRules{Rules: []*protocol.VersioningRule{{Kinds: []uint32{1, 2}}}}
	packed := testConfigEncode(t, want)

	rule := []byte{}
	rule = protowire.AppendVarint(protowire.AppendTag(rule, 1, protowire.VarintType), 1)
	rule = protowire.AppendVarint(protowire.AppendTag(rule, 1, protowire.VarintType), 2)
	unpacked := protowire.AppendBytes(protowire.AppendTag(nil, 1, protowire.BytesType), rule)
	if bytes.Equal(packed, unpacked) {
		t.Fatal("the two forms must differ, or this proves nothing")
	}
	for _, body := range [][]byte{packed, unpacked} {
		message, err := ParseConfigStatement(bridge.SignedPurposeAuthority, signedType, body)
		if err != nil {
			t.Fatal(err)
		}
		if !proto.Equal(message, want) {
			t.Errorf("%x parsed to %v", body, message)
		}
	}
}

// The design's definition, on bytes no encoder writes: a Signed's fields highest first and its type's varint padded.
// The id is of what arrived, so a layer that re-marshaled would name it differently, which is why bytes are kept.
// An id is the signed bytes' hash of the body as received (protos-bridge-statement-id-wrapper): a wrapper encoded
// another way keeps it, and a body encoded another way is another statement, whose signature would fail.
func TestStatementIdHashesTheSignedBytesAsReceived(t *testing.T) {
	signedType := bridge.SignedType_SIGNED_REPO_GRANT
	purpose := configStatementTypes[signedType].purpose
	canonical := testConfigSignedBytes(t, signedType)
	received := testConfigNonMinimal(t, testConfigReordered(t, canonical))
	if bytes.Equal(received, canonical) {
		t.Fatal("the fixture must differ from its re-marshal, or this proves nothing")
	}
	decoded := &bridge.Signed{}
	if err := proto.Unmarshal(received, decoded); err != nil {
		t.Fatal(err)
	}
	id, err := StatementId(received)
	if err != nil {
		t.Fatal(err)
	}
	if id != bridge.SignedBytesSha256(purpose, signedType, decoded.GetBody()) {
		t.Errorf("got %x", id)
	}
	remarshaledId, err := StatementId(testConfigEncode(t, decoded))
	if err != nil {
		t.Fatal(err)
	}
	if remarshaledId != id {
		t.Error("a re-marshaled wrapper changed the id")
	}

	reencoded := proto.Clone(decoded).(*bridge.Signed)
	reencoded.Body = testConfigNonMinimal(t, testConfigReordered(t, decoded.GetBody()))
	if bytes.Equal(reencoded.GetBody(), decoded.GetBody()) {
		t.Fatal("the body must differ from its re-encoding, or this proves nothing")
	}
	reencodedId, err := StatementId(testConfigEncode(t, reencoded))
	if err != nil {
		t.Fatal(err)
	}
	if reencodedId == id {
		t.Error("a body encoded another way kept its id")
	}
}

// One definition: a proposal's and a Delegation's ids are their statement ids, as §7.9's proposal row and §10.5's d each
// write. The three functions all stand on configSignedId, so what the wrapper question decides lands on all three.
func TestProposalAndDelegationIdsAreStatementIds(t *testing.T) {
	cases := []struct {
		signedType bridge.SignedType
		id         func(signedBytes []byte) ([sha256.Size]byte, error)
	}{
		{signedType: bridge.SignedType_SIGNED_AUTHORITY_PROPOSAL, id: ProposalId},
		{signedType: bridge.SignedType_SIGNED_DELEGATION, id: DelegationId},
	}
	for _, c := range cases {
		signedBytes := testConfigSignedBytes(t, c.signedType)
		want, err := StatementId(signedBytes)
		if err != nil {
			t.Fatalf("%s: %v", c.signedType, err)
		}
		got, err := c.id(signedBytes)
		if err != nil {
			t.Fatalf("%s: %v", c.signedType, err)
		}
		if got != want {
			t.Errorf("%s: got %x, want %x", c.signedType, got, want)
		}
	}
}

// An id names the statement it says it names, so a cosign cannot be pointed at a Delegation's id by way of a
// Delegation's bytes, nor the reverse.
func TestProposalAndDelegationIdsRefuseOtherStatements(t *testing.T) {
	for _, signedType := range testConfigTypes() {
		signedBytes := testConfigSignedBytes(t, signedType)
		if signedType != bridge.SignedType_SIGNED_AUTHORITY_PROPOSAL {
			if _, err := ProposalId(signedBytes); !errors.Is(err, ErrConfigStatementType) {
				t.Errorf("%s as a proposal: %v", signedType, err)
			}
		}
		if signedType != bridge.SignedType_SIGNED_DELEGATION {
			if _, err := DelegationId(signedBytes); !errors.Is(err, ErrConfigStatementType) {
				t.Errorf("%s as a Delegation: %v", signedType, err)
			}
		}
	}
}

// What is no Signed, or no statement the log carries, has no id, so nothing can sit in a ring or a row by accident.
func TestIdsRefuseWhatIsNoStatement(t *testing.T) {
	marshalType := func(signedType int32) []byte {
		return testConfigEncode(t, &bridge.Signed{Body: []byte("body"), Type: uint32(signedType)})
	}
	cases := []struct {
		name    string
		encoded []byte
		want    error
	}{
		{name: "no Signed", encoded: []byte{0x0A, 0xFF}, want: ErrConfigStatementBody},
		{name: "empty", encoded: nil, want: ErrConfigStatementType},
		{name: "type zero", encoded: marshalType(0), want: ErrConfigStatementType},
		{name: "another service's", encoded: marshalType(int32(bridge.SignedType_SIGNED_EVS_PUSH)), want: ErrConfigStatementType},
		{name: "a link's", encoded: marshalType(int32(bridge.SignedType_SIGNED_WINDOW_DELEGATION)), want: ErrConfigStatementType},
		{name: "unknown", encoded: marshalType(0x12FF), want: ErrConfigStatementType},
		{name: "above int32", encoded: marshalType(-1), want: ErrConfigStatementType},
	}
	functions := map[string]func(signedBytes []byte) ([sha256.Size]byte, error){
		"StatementId": StatementId, "ProposalId": ProposalId, "DelegationId": DelegationId,
	}
	for _, c := range cases {
		for name, function := range functions {
			if _, err := function(c.encoded); !errors.Is(err, c.want) {
				t.Errorf("%s of %s: %v", name, c.name, err)
			}
		}
	}
}

// No signature covers a Signed's wrapper, so a server can carry one statement as many Signeds that each verify and
// parse alike. protos-bridge-statement-id-wrapper's answer gives them one id, so §7.9's replay row, a RecoveryVeto and a
// DelegationRevoke see one statement whatever wrapper carries it.
func TestRewrappedStatementKeepsItsId(t *testing.T) {
	cases := []struct {
		signedType bridge.SignedType
		id         func(signedBytes []byte) ([sha256.Size]byte, error)
	}{
		{signedType: bridge.SignedType_SIGNED_REPO_GRANT, id: StatementId},
		{signedType: bridge.SignedType_SIGNED_AUTHORITY_PROPOSAL, id: ProposalId},
		{signedType: bridge.SignedType_SIGNED_DELEGATION, id: DelegationId},
	}
	for _, c := range cases {
		purpose := configStatementTypes[c.signedType].purpose
		body := testConfigBody(t, c.signedType)
		signed := testConfigSign(c.signedType, body)
		plain := testConfigEncode(t, signed)

		countersigned := testConfigSign(c.signedType, body)
		countersigned.Webauthn = &bridge.WebAuthnEvidence{KeyId: []byte("no key"), Signature: []byte("no signature")}
		otherIds := testConfigSign(c.signedType, body)
		otherIds.SignerId = []byte("another signer")
		otherIds.KeyId = []byte("another key")

		wrappers := map[string][]byte{
			"as signed":                          plain,
			"unknown field":                      append(slices.Clone(plain), testConfigUnknown()...),
			"body twice":                         protowire.AppendBytes(protowire.AppendTag(slices.Clone(plain), 1, protowire.BytesType), body),
			"a countersignature no row asks for": testConfigEncode(t, countersigned),
			"other signer_id and key_id":         testConfigEncode(t, otherIds),
		}
		wantId := bridge.SignedBytesSha256(purpose, c.signedType, body)
		for wrapper, encoded := range wrappers {
			received := &bridge.Signed{}
			if err := proto.Unmarshal(encoded, received); err != nil {
				t.Fatalf("%s: %v", wrapper, err)
			}
			if err := testConfigVerify(received, purpose, c.signedType); err != nil {
				t.Errorf("%s %s: %v", c.signedType, wrapper, err)
			}
			message, err := ParseConfigStatement(purpose, c.signedType, received.GetBody())
			if err != nil {
				t.Errorf("%s %s: %v", c.signedType, wrapper, err)
				continue
			}
			if !bytes.Equal(testConfigEncode(t, message), body) {
				t.Errorf("%s %s parsed to another statement", c.signedType, wrapper)
			}
			id, err := c.id(encoded)
			if err != nil {
				t.Errorf("%s %s: %v", c.signedType, wrapper, err)
				continue
			}
			if id != wantId {
				t.Errorf("%s %s has its own id", c.signedType, wrapper)
			}
		}
	}
}

func TestRetainedStatementIdIsTheFirst16Bytes(t *testing.T) {
	id, err := StatementId(testConfigSignedBytes(t, bridge.SignedType_SIGNED_SPONSOR_SET))
	if err != nil {
		t.Fatal(err)
	}
	retained := RetainedStatementId(id)
	if len(retained) != 16 || !bytes.Equal(retained[:], id[:16]) {
		t.Errorf("got %x of %x", retained, id)
	}
	// §7.9's 4,096 entries in 64 KiB, which a wider id would overrun.
	if 4096*len(retained) != 64*1024 {
		t.Errorf("%d B each", len(retained))
	}
}

type testChainRow struct {
	N          uint64 `json:"n"`
	Kind       uint32 `json:"kind"`
	TimeMs     int64  `json:"time_ms"`
	PrevChain  string `json:"prev_chain"`
	Body       string `json:"body"`
	BodySha256 string `json:"body_sha256"`
	Preimage   string `json:"preimage"`
	Chain      string `json:"chain"`
	Entry      string `json:"entry"`
}

type testChainVectors struct {
	PublicKey string `json:"public_key"`
	Genesis   struct {
		Signed string `json:"signed"`
		Chain  string `json:"chain"`
	} `json:"genesis"`
	Entries []testChainRow `json:"entries"`
	Edges   []testChainRow `json:"edges"`
}

func testChainHex(t *testing.T, value string) []byte {
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("%q: %v", value, err)
	}
	return decoded
}

// A row's digest, by §7.9's formula as this leg computes it and by hand, against the bytes the row holds.
func testCheckChainRow(t *testing.T, row testChainRow) {
	prevChain := testChainHex(t, row.PrevChain)
	body := testChainHex(t, row.Body)
	bodySha256 := sha256.Sum256(body)
	if hex.EncodeToString(bodySha256[:]) != row.BodySha256 {
		t.Errorf("n %d: the body hashes to %x", row.N, bodySha256)
	}

	preimage := []byte("urnetwork-sidecar-v1/auth-log")
	preimage = binary.BigEndian.AppendUint64(preimage, row.N)
	preimage = append(preimage, prevChain...)
	preimage = binary.BigEndian.AppendUint32(preimage, row.Kind)
	preimage = binary.BigEndian.AppendUint64(preimage, uint64(row.TimeMs))
	preimage = append(preimage, bodySha256[:]...)
	if hex.EncodeToString(preimage) != row.Preimage {
		t.Errorf("n %d: preimage %x", row.N, preimage)
	}

	got, err := bridge.AuthChainDigest(row.N, prevChain, row.Kind, row.TimeMs, body)
	if err != nil {
		t.Fatalf("n %d: %v", row.N, err)
	}
	if hex.EncodeToString(got[:]) != row.Chain || got != sha256.Sum256(preimage) {
		t.Errorf("n %d: got %x, want %s", row.N, got, row.Chain)
	}
}

// One small log from its genesis, byte-equal on every leg (§22.5), each entry's body read the way §7.9's apply row
// reads it: a base's and a statement's as a Signed of its registered type, a tick's as an unsigned ApiTick.
func TestAuthChainVectors(t *testing.T) {
	vectors := &testChainVectors{}
	if err := json.Unmarshal(testChainJson, vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors.Entries) != 5 || len(vectors.Edges) != 5 {
		t.Fatalf("%d entries, %d edges", len(vectors.Entries), len(vectors.Edges))
	}
	publicKey := testChainHex(t, vectors.PublicKey)
	if !bytes.Equal(publicKey, testConfigPublicKey()) {
		t.Fatalf("the vectors' key is %x", publicKey)
	}
	verify := func(signedBytes []byte) (bridge.SignedType, proto.Message) {
		signed := &bridge.Signed{}
		if err := proto.Unmarshal(signedBytes, signed); err != nil {
			t.Fatal(err)
		}
		signedType := bridge.SignedType(signed.GetType())
		purpose, ok := ConfigStatementPurpose(signedType)
		if !ok {
			t.Fatalf("%s is no config statement", signedType)
		}
		if err := testConfigVerify(signed, purpose, signedType); err != nil {
			t.Fatalf("%s: %v", signedType, err)
		}
		message, err := ParseConfigStatement(purpose, signedType, signed.GetBody())
		if err != nil {
			t.Fatalf("%s: %v", signedType, err)
		}
		return signedType, message
	}

	genesisBytes := testChainHex(t, vectors.Genesis.Signed)
	signedType, message := verify(genesisBytes)
	genesis, ok := message.(*bridge.Genesis)
	if !ok || signedType != bridge.SignedType_SIGNED_GENESIS {
		t.Fatalf("the genesis is a %s", signedType)
	}
	if !bytes.Equal(genesis.GetOwnerIdentityPublicKey(), publicKey) {
		t.Errorf("the genesis names key %x", genesis.GetOwnerIdentityPublicKey())
	}
	chain := bridge.GenesisChain(genesisBytes)
	if hex.EncodeToString(chain[:]) != vectors.Genesis.Chain {
		t.Fatalf("A_0 is %x, want %s", chain, vectors.Genesis.Chain)
	}

	pin := &bridge.AuthPin{Version: 0, Chain: chain[:]}
	for _, row := range vectors.Entries {
		if row.N != pin.GetVersion()+1 || row.PrevChain != hex.EncodeToString(pin.GetChain()) {
			t.Fatalf("n %d does not follow %d", row.N, pin.GetVersion())
		}
		testCheckChainRow(t, row)

		encoded := testChainHex(t, row.Entry)
		entry := &bridge.AuthEntry{}
		if err := proto.Unmarshal(encoded, entry); err != nil {
			t.Fatalf("n %d: %v", row.N, err)
		}
		if entry.GetN() != row.N || entry.GetKind() != row.Kind || entry.GetTimeMs() != row.TimeMs ||
			!bytes.Equal(entry.GetNetworkId(), genesis.GetNetworkId()) ||
			!bytes.Equal(entry.GetPrevChain(), pin.GetChain()) ||
			hex.EncodeToString(entry.GetBody()) != row.Body {
			t.Errorf("n %d decoded to %v", row.N, entry)
		}
		if !bytes.Equal(testConfigEncode(t, entry), encoded) {
			t.Errorf("n %d encoded differently", row.N)
		}

		switch row.Kind {
		case bridge.AuthEntryKindBase:
			signedType, message := verify(entry.GetBody())
			header, ok := message.(*bridge.ProjectionHeader)
			if !ok || signedType != bridge.SignedType_SIGNED_PROJECTION_HEADER {
				t.Fatalf("n %d: a base holds %s", row.N, signedType)
			}
			if header.GetVersion() != row.N || !bytes.Equal(header.GetPrevChain(), pin.GetChain()) {
				t.Errorf("n %d: the base names %d, %x", row.N, header.GetVersion(), header.GetPrevChain())
			}
		case bridge.AuthEntryKindStatement:
			signedType, message := verify(entry.GetBody())
			if _, err := StatementId(entry.GetBody()); err != nil {
				t.Errorf("n %d: %v", row.N, err)
			}
			statement, ok := message.(interface {
				GetHeader() *bridge.StatementHeader
			})
			if !ok {
				t.Fatalf("n %d: %s has no header", row.N, signedType)
			}
			at := statement.GetHeader().GetAt()
			if at.GetVersion() != pin.GetVersion() || !bytes.Equal(at.GetChain(), pin.GetChain()) {
				t.Errorf("n %d: signed at %d, %x", row.N, at.GetVersion(), at.GetChain())
			}
		case bridge.AuthEntryKindTick:
			tick := &bridge.ApiTick{}
			if err := proto.Unmarshal(entry.GetBody(), tick); err != nil {
				t.Fatalf("n %d: %v", row.N, err)
			}
			if len(tick.GetReapedSidecarIds()) != 1 {
				t.Errorf("n %d: reaped %d", row.N, len(tick.GetReapedSidecarIds()))
			}
		default:
			t.Errorf("n %d: kind %d", row.N, row.Kind)
		}
		pin = &bridge.AuthPin{Version: row.N, Chain: testChainHex(t, row.Chain)}
	}
	for _, row := range vectors.Edges {
		testCheckChainRow(t, row)
	}
}

// A forwarding Delegation's body in DESIGN-DETAILS 4.2.2's form: its keys and forward, and no tags, max_admits or
// not_after (§7.9's forwarding row; D-TEAM-33; owner decision 197).
func testForwardingDelegationBody() *protocol.Delegation {
	return &protocol.Delegation{
		Header: &bridge.StatementHeader{
			NetworkId:  bytes.Repeat([]byte{0x11}, 16),
			At:         &bridge.AuthPin{Version: 7, Chain: bytes.Repeat([]byte{0x22}, sha256.Size)},
			Nonce:      bytes.Repeat([]byte{0x33}, 16),
			NotAfterMs: 1_700_000_000_000,
		},
		Pubkey:               testConfigPublicKey(),
		ReaderXwingPublicKey: bytes.Repeat([]byte{0x5A}, configXwingPublicKeyByteCount),
		Forward: &bridge.ForwardScope{
			ForwardSidecarId:    bytes.Repeat([]byte{0x44}, 16),
			HostClientId:        bytes.Repeat([]byte{0x55}, 16),
			HostClientPublicKey: bytes.Repeat([]byte{0x66}, ed25519.PublicKeySize),
		},
	}
}

// One field DESIGN-DETAILS 4.2.2 adds, as its proto block writes it.
type testForwardingField struct {
	message  proto.Message
	name     string
	number   int32
	kind     protoreflect.Kind
	typeName string
}

// Every field TEAM-M2-20 adds before M2's freeze, each with 4.2.2's number and type.
func testForwardingFields() []testForwardingField {
	return []testForwardingField{
		{message: (*protocol.Delegation)(nil), name: "forward", number: 7, kind: protoreflect.MessageKind, typeName: "ForwardScope"},
		{message: (*bridge.ForwardScope)(nil), name: "forward_sidecar_id", number: 1, kind: protoreflect.BytesKind},
		{message: (*bridge.ForwardScope)(nil), name: "host_client_id", number: 2, kind: protoreflect.BytesKind},
		{message: (*bridge.ForwardScope)(nil), name: "host_client_public_key", number: 3, kind: protoreflect.BytesKind},
		{message: (*bridge.DelegationRow)(nil), name: "forward_sidecar_id", number: 12, kind: protoreflect.BytesKind},
		{message: (*bridge.DelegationRow)(nil), name: "host_client_id", number: 13, kind: protoreflect.BytesKind},
		{message: (*bridge.DelegationRow)(nil), name: "host_client_public_key", number: 14, kind: protoreflect.BytesKind},
		{message: (*bridge.DelegationRow)(nil), name: "superseded_at", number: 15, kind: protoreflect.Uint64Kind},
		{message: (*bridge.DelegationRow)(nil), name: "reader_key_sha256", number: 16, kind: protoreflect.BytesKind},
		{message: (*bridge.BridgeIdentity)(nil), name: "forward_delegation_id", number: 6, kind: protoreflect.BytesKind},
		{message: (*bridge.BridgeIdentity)(nil), name: "forward_public_key", number: 7, kind: protoreflect.BytesKind},
		{message: (*bridge.Pending)(nil), name: "forward_delegation_id", number: 5, kind: protoreflect.BytesKind},
		{message: (*bridge.ForwardingKeys)(nil), name: "key_set_id", number: 1, kind: protoreflect.BytesKind},
		{message: (*bridge.ForwardingKeys)(nil), name: "forward_public_key", number: 2, kind: protoreflect.BytesKind},
		{message: (*bridge.ForwardingKeys)(nil), name: "reader_xwing_public_key", number: 3, kind: protoreflect.BytesKind},
		{message: (*bridge.ForwardingKeys)(nil), name: "client_public_key", number: 4, kind: protoreflect.BytesKind},
		{message: (*bridge.ForwardingKeys)(nil), name: "host_client_id", number: 5, kind: protoreflect.BytesKind},
		{message: (*bridge.ForwardingKeys)(nil), name: "host_client_public_key", number: 6, kind: protoreflect.BytesKind},
		{message: (*bridge.ForwardingHandOff)(nil), name: "pending", number: 1, kind: protoreflect.MessageKind, typeName: "Pending"},
		{message: (*bridge.ForwardingHandOff)(nil), name: "key_set_id", number: 2, kind: protoreflect.BytesKind},
		{message: (*bridge.ForwardingHandOff)(nil), name: "forward_client_id", number: 3, kind: protoreflect.BytesKind},
		{message: (*bridge.ForwardingHandOff)(nil), name: "forward_client_jwt", number: 4, kind: protoreflect.StringKind},
		{message: (*bridge.ForwardingHandOff)(nil), name: "strict_exp_ms", number: 5, kind: protoreflect.Int64Kind},
		{message: (*bridge.ForwardingHandOff)(nil), name: "config_repo_id", number: 6, kind: protoreflect.BytesKind},
		{message: (*bridge.ForwardingHandOff)(nil), name: "config_group_id", number: 7, kind: protoreflect.BytesKind},
		{message: (*bridge.ForwardingHandOff)(nil), name: "signed_delegation", number: 8, kind: protoreflect.BytesKind},
		{message: (*bridge.ForwardingHandOff)(nil), name: "delegation_at", number: 9, kind: protoreflect.MessageKind, typeName: "AuthPin"},
	}
}

// DESIGN-DETAILS 4.2.2's formats, field by field: each new field has the number and type its proto block writes,
// none is repeated, the two setup messages hold nothing else, and each message that gained fields kept the ones it
// had at their numbers.
func TestForwardingFieldsAreDesignDetailsNumbers(t *testing.T) {
	for _, c := range testForwardingFields() {
		descriptor := c.message.ProtoReflect().Descriptor()
		field := descriptor.Fields().ByName(protoreflect.Name(c.name))
		if field == nil {
			t.Errorf("%s has no %s", descriptor.Name(), c.name)
			continue
		}
		if int32(field.Number()) != c.number || field.Kind() != c.kind || field.IsList() || field.IsMap() {
			t.Errorf("%s.%s is %d, %s", descriptor.Name(), c.name, field.Number(), field.Kind())
		}
		if c.typeName != "" && (field.Message() == nil || string(field.Message().Name()) != c.typeName) {
			t.Errorf("%s.%s is no %s", descriptor.Name(), c.name, c.typeName)
		}
	}
	fieldCounts := []struct {
		message proto.Message
		count   int
	}{
		{message: (*protocol.Delegation)(nil), count: 7},
		{message: (*bridge.ForwardScope)(nil), count: 3},
		{message: (*bridge.DelegationRow)(nil), count: 16},
		{message: (*bridge.BridgeIdentity)(nil), count: 7},
		{message: (*bridge.Pending)(nil), count: 5},
		{message: (*bridge.ForwardingKeys)(nil), count: 6},
		{message: (*bridge.ForwardingHandOff)(nil), count: 9},
	}
	for _, c := range fieldCounts {
		descriptor := c.message.ProtoReflect().Descriptor()
		if descriptor.Fields().Len() != c.count {
			t.Errorf("%s has %d fields, want %d", descriptor.Name(), descriptor.Fields().Len(), c.count)
		}
	}
	// what the device role parses lives in protocol/bridge (§4.4): it reads a Delegation's field 7 by wire
	for _, message := range []proto.Message{(*bridge.ForwardScope)(nil), (*bridge.ForwardingKeys)(nil), (*bridge.ForwardingHandOff)(nil)} {
		descriptor := message.ProtoReflect().Descriptor()
		if path := descriptor.ParentFile().Path(); !strings.HasPrefix(path, "protocol/bridge/") {
			t.Errorf("%s is declared in %s", descriptor.Name(), path)
		}
	}
	// the numbers each message had before, unmoved
	kept := []struct {
		message proto.Message
		name    string
		number  int32
	}{
		{message: (*protocol.Delegation)(nil), name: "reader_xwing_public_key", number: 3},
		{message: (*protocol.Delegation)(nil), name: "not_after", number: 6},
		{message: (*bridge.DelegationRow)(nil), name: "reader_xwing_public_key", number: 10},
		{message: (*bridge.DelegationRow)(nil), name: "max_admits", number: 11},
		{message: (*bridge.BridgeIdentity)(nil), name: "suspended", number: 5},
		{message: (*bridge.Pending)(nil), name: "identity_public_key", number: 4},
	}
	for _, c := range kept {
		descriptor := c.message.ProtoReflect().Descriptor()
		if field := descriptor.Fields().ByName(protoreflect.Name(c.name)); field == nil || int32(field.Number()) != c.number {
			t.Errorf("%s.%s moved", descriptor.Name(), c.name)
		}
	}
}

// Each message TEAM-M2-20 adds or extends round-trips with every field set: nothing is lost, nothing lands as
// unknown, and the deterministic bytes are stable.
func TestForwardingMessagesRoundTrip(t *testing.T) {
	messages := []proto.Message{
		&protocol.Delegation{}, &bridge.ForwardScope{}, &bridge.DelegationRow{}, &bridge.BridgeIdentity{},
		&bridge.Pending{}, &bridge.ForwardingKeys{}, &bridge.ForwardingHandOff{},
	}
	for _, message := range messages {
		name := message.ProtoReflect().Descriptor().Name()
		testConfigFill(message.ProtoReflect())
		encoded := testConfigEncode(t, message)
		decoded := message.ProtoReflect().New()
		if err := proto.Unmarshal(encoded, decoded.Interface()); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !proto.Equal(message, decoded.Interface()) {
			t.Errorf("%s did not round-trip", name)
		}
		if len(decoded.GetUnknown()) != 0 {
			t.Errorf("%s holds unknown fields after its own round trip", name)
		}
		fields := decoded.Descriptor().Fields()
		for i := range fields.Len() {
			if !decoded.Has(fields.Get(i)) {
				t.Errorf("%s.%s is unset after a round trip", name, fields.Get(i).Name())
			}
		}
		if again := testConfigEncode(t, decoded.Interface()); !bytes.Equal(again, encoded) {
			t.Errorf("%s re-encodes differently", name)
		}
	}
}

// A forwarding Delegation through the registry: it parses only as a Delegation under purpose authority, forward set
// says what it is, and its id is its statement id, which its row, its revocation and its DelegationWraps name.
func TestAForwardingDelegationParsesAsADelegationAlone(t *testing.T) {
	delegation := testForwardingDelegationBody()
	body := testConfigEncode(t, delegation)
	message, err := ParseConfigStatement(bridge.SignedPurposeAuthority, bridge.SignedType_SIGNED_DELEGATION, body)
	if err != nil {
		t.Fatal(err)
	}
	parsed, ok := message.(*protocol.Delegation)
	if !ok || !proto.Equal(parsed, delegation) {
		t.Fatalf("parsed as %T", message)
	}
	if !ConfigDelegationForwards(parsed) {
		t.Error("forward set is no forwarding Delegation")
	}
	if len(parsed.GetTagIds()) != 0 || parsed.GetMaxAdmits() != 0 || parsed.GetNotAfter() != 0 {
		t.Error("a forwarding Delegation carries tags, max_admits or a not_after")
	}
	// set means set: a ForwardScope naming nothing is still a forwarding Delegation, which its rule then refuses
	empty := testForwardingDelegationBody()
	empty.Forward = &bridge.ForwardScope{}
	emptyParsed := &protocol.Delegation{}
	if err := proto.Unmarshal(testConfigEncode(t, empty), emptyParsed); err != nil {
		t.Fatal(err)
	}
	if !ConfigDelegationForwards(emptyParsed) {
		t.Error("an empty forward reads as unset")
	}
	agent := testForwardingDelegationBody()
	agent.Forward = nil
	if ConfigDelegationForwards(agent) {
		t.Error("a Delegation with no forward reads as a forwarding one")
	}

	signed := testConfigSign(bridge.SignedType_SIGNED_DELEGATION, body)
	signedBytes := testConfigEncode(t, signed)
	statementId, err := StatementId(signedBytes)
	if err != nil {
		t.Fatal(err)
	}
	delegationId, err := DelegationId(signedBytes)
	if err != nil || delegationId != statementId {
		t.Errorf("delegation id %x, statement id %x: %v", delegationId, statementId, err)
	}
	for _, otherType := range testConfigTypes() {
		if otherType == bridge.SignedType_SIGNED_DELEGATION {
			continue
		}
		otherPurpose := configStatementTypes[otherType].purpose
		if err := testConfigVerify(signed, otherPurpose, otherType); !errors.Is(err, bridge.ErrSignedTypeMismatch) {
			t.Errorf("a forwarding Delegation presented as %s: %v", otherType, err)
		}
		rewritten := &bridge.Signed{Body: signed.GetBody(), Signature: signed.GetSignature(), Type: uint32(otherType)}
		if err := testConfigVerify(rewritten, otherPurpose, otherType); !errors.Is(err, bridge.ErrSignedSignature) {
			t.Errorf("a forwarding Delegation rewritten to %s: %v", otherType, err)
		}
	}
}

// What sidecar/device does with a Delegation: it may import only protocol/bridge, so it reads field 7 by wire and
// parses the value as a ForwardScope, never the Delegation's own message.
func TestADelegationsForwardReadsByWireAsAForwardScope(t *testing.T) {
	delegation := testForwardingDelegationBody()
	var forwardBytes []byte
	found := 0
	for _, record := range testConfigSplitFields(t, testConfigEncode(t, delegation)) {
		number, wireType, tagSize := protowire.ConsumeTag(record)
		if tagSize < 0 {
			t.Fatal("a record with no tag")
		}
		switch number {
		case 4, 5, 6:
			t.Errorf("a forwarding Delegation's bytes hold field %d", number)
		case 7:
			if wireType != protowire.BytesType {
				t.Fatalf("field 7 has wire type %d", wireType)
			}
			value, valueSize := protowire.ConsumeBytes(record[tagSize:])
			if valueSize < 0 {
				t.Fatal("field 7 does not hold bytes")
			}
			forwardBytes = value
			found += 1
		}
	}
	if found != 1 {
		t.Fatalf("field 7 appears %d times", found)
	}
	scope := &bridge.ForwardScope{}
	if err := proto.Unmarshal(forwardBytes, scope); err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(scope, delegation.GetForward()) {
		t.Error("field 7 by wire is not the Delegation's forward")
	}
}

// The closed direction for a reader built before the field: the message it knows has no field 7, so it keeps the
// field as unknown bytes, which leaves the signature and the id whole, and sees a Delegation with no tags, no
// max_admits and no not_after, which the agent rule refuses.
func TestAnOlderReaderSeesAForwardingDelegationWithNoNotAfter(t *testing.T) {
	body := testConfigEncode(t, testForwardingDelegationBody())
	older := []byte{}
	for _, record := range testConfigSplitFields(t, body) {
		if number, _, _ := protowire.ConsumeTag(record); number != 7 {
			older = append(older, record...)
		}
	}
	// what the older reader's message holds: every field but 7
	seen := &protocol.Delegation{}
	if err := proto.Unmarshal(older, seen); err != nil {
		t.Fatal(err)
	}
	if ConfigDelegationForwards(seen) {
		t.Fatal("the older reader's view still forwards")
	}
	if len(seen.GetTagIds()) != 0 || seen.GetMaxAdmits() != 0 || seen.GetNotAfter() != 0 {
		t.Fatalf("the older reader sees tags %d, max_admits %d, not_after %d", len(seen.GetTagIds()), seen.GetMaxAdmits(), seen.GetNotAfter())
	}
	// and an unknown field does not fail the parse or change the bytes a signature and an id cover (§6.4)
	unknown := protowire.AppendTag(nil, testConfigUnknownField, protowire.BytesType)
	unknown = protowire.AppendBytes(unknown, []byte("a field from later"))
	withUnknown := append(bytes.Clone(body), unknown...)
	message, err := ParseConfigStatement(bridge.SignedPurposeAuthority, bridge.SignedType_SIGNED_DELEGATION, withUnknown)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(message.ProtoReflect().GetUnknown(), unknown) {
		t.Error("an unknown field was dropped")
	}
}

// A forwarding Delegation's row carries its reader key's SHA-256 and never the key: with the key it would be over
// 1,216 B a device, and §8.8's 4 MiB of rows would be passed at about 2,600 app devices (DESIGN-DETAILS 4.1).
func TestAForwardingRowCarriesItsReaderKeysDigestNotTheKey(t *testing.T) {
	delegation := testForwardingDelegationBody()
	digest := DelegationReaderKeySha256(delegation.GetReaderXwingPublicKey())
	if want := sha256.Sum256(delegation.GetReaderXwingPublicKey()); digest != want {
		t.Fatalf("digest %x, want %x", digest, want)
	}
	row := &bridge.DelegationRow{
		DelegationId:        bytes.Repeat([]byte{0x77}, sha256.Size),
		Signer:              delegation.GetForward().GetForwardSidecarId(),
		At:                  1_000_000,
		Pubkey:              delegation.GetPubkey(),
		ForwardSidecarId:    delegation.GetForward().GetForwardSidecarId(),
		HostClientId:        delegation.GetForward().GetHostClientId(),
		HostClientPublicKey: delegation.GetForward().GetHostClientPublicKey(),
		SupersededAt:        2_000_000,
		ReaderKeySha256:     digest[:],
	}
	rowBytes := testConfigEncode(t, row)
	if 256 < len(rowBytes) {
		t.Errorf("a forwarding row is %d bytes", len(rowBytes))
	}
	withKey := proto.Clone(row).(*bridge.DelegationRow)
	withKey.ReaderXwingPublicKey = delegation.GetReaderXwingPublicKey()
	if len(testConfigEncode(t, withKey)) < len(rowBytes)+configXwingPublicKeyByteCount {
		t.Error("the key in the row would not be the cost DESIGN-DETAILS 4.1 measured")
	}
	decoded := &bridge.DelegationRow{}
	if err := proto.Unmarshal(rowBytes, decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded.GetReaderXwingPublicKey()) != 0 || !bytes.Equal(decoded.GetReaderKeySha256(), digest[:]) {
		t.Error("field 10 is not empty or field 16 is not the digest")
	}
}
