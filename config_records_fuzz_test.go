//go:build !js

// §22.6's typed Signed target as a fuzz target. Native Go fuzzing, whose seeds run as ordinary tests under go test. Not on
// js: testing.F reads its corpus directory before it runs a seed, and js has no directory to open, so
// config_records_test.go's tests carry the same cases on that leg.

package sidecar

import (
	"errors"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// Whatever the input claims to be, the registry refuses a pair it does not hold and never parses a body as another
// type's message, and a statement that verifies verifies as nothing else.
func FuzzConfigStatementType(f *testing.F) {
	signedTypes := testConfigTypes()
	for _, signedType := range signedTypes {
		signedBytes := testConfigSignedBytes(f, signedType)
		f.Add(configStatementTypes[signedType].purpose, uint32(signedType), signedBytes)
		for _, otherType := range signedTypes {
			f.Add(configStatementTypes[otherType].purpose, uint32(otherType), signedBytes)
		}
	}
	// a forwarding Delegation in DESIGN-DETAILS 4.2.2's form, forward set and no tags, max_admits or not_after, as
	// itself and as every other type; and one whose forward names nothing
	forwarding := testForwardingDelegationBody()
	emptyForward := testForwardingDelegationBody()
	emptyForward.Forward = &bridge.ForwardScope{}
	for _, delegation := range []*protocol.Delegation{forwarding, emptyForward} {
		signedBytes := testConfigEncode(f, testConfigSign(bridge.SignedType_SIGNED_DELEGATION, testConfigEncode(f, delegation)))
		for _, otherType := range signedTypes {
			f.Add(configStatementTypes[otherType].purpose, uint32(otherType), signedBytes)
		}
	}
	f.Fuzz(func(t *testing.T, purpose string, signedType uint32, signedBytes []byte) {
		id, idErr := StatementId(signedBytes)
		signed := &bridge.Signed{}
		if proto.Unmarshal(signedBytes, signed) != nil {
			if !errors.Is(idErr, ErrConfigStatementBody) {
				t.Fatalf("an id of no Signed: %x, %v", id, idErr)
			}
			return
		}
		if _, ok := configStatementTypes[bridge.SignedType(signed.GetType())]; ok != (idErr == nil) {
			t.Fatalf("a Signed of type %d: %v", signed.GetType(), idErr)
		}

		claimedType := bridge.SignedType(signedType)
		statementType, registered := configStatementTypes[claimedType]
		registered = registered && statementType.purpose == purpose
		message, err := ParseConfigStatement(purpose, claimedType, signed.GetBody())
		switch {
		case !registered:
			if !errors.Is(err, ErrConfigStatementType) {
				t.Fatalf("%q, %d: %v", purpose, signedType, err)
			}
		case err == nil:
			if message.ProtoReflect().Descriptor() != statementType.body.ProtoReflect().Descriptor() {
				t.Fatalf("%s parsed as %s", claimedType, message.ProtoReflect().Descriptor().Name())
			}
		case !errors.Is(err, ErrConfigStatementBody):
			t.Fatalf("%s: %v", claimedType, err)
		}

		if testConfigVerify(signed, purpose, claimedType) != nil {
			return
		}
		// Past here the fixture's key signed this, which it does only as a registered pair.
		if !registered {
			t.Fatalf("%q, %s verified", purpose, claimedType)
		}
		for _, otherType := range signedTypes {
			if otherType == claimedType {
				continue
			}
			otherPurpose := configStatementTypes[otherType].purpose
			if testConfigVerify(signed, otherPurpose, otherType) == nil {
				t.Fatalf("%s verified as %s", claimedType, otherType)
			}
			rewritten := &bridge.Signed{Body: signed.GetBody(), Signature: signed.GetSignature(), Type: uint32(otherType)}
			if testConfigVerify(rewritten, otherPurpose, otherType) == nil {
				t.Fatalf("%s verified rewritten to %s", claimedType, otherType)
			}
		}
	})
}
