//go:build !ios_extension

package sidecar

// QD-1132's completion ERASE: the key it names (evs_erase_completion.go's key row).

import (
	"errors"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// One committed ERASE as the key rule reads it.
type testCompletionErase struct {
	erasureId Id
	keys      []*EvsErasedKey
}

func testCompletionKey(erases []*testCompletionErase, erasureId Id) (*EvsErasedKey, bool) {
	return evsCompletionKeyOf(erases, erasureId, func(erase *testCompletionErase) (Id, []*EvsErasedKey) {
		return erase.erasureId, erase.keys
	})
}

// The key a completion names is the oldest its erasure's ERASEs named first that no ERASE has named since: the first
// ERASE's first key while it stands unnamed; once a completion took it, the next of that ERASE; once the erasure's
// keys are all taken, a late copy's, which reopened it; never a key another erasure named first, nor one a later
// ERASE of any erasure named; and none for an erasure with no ERASE.
func TestEvsCompletionKeyIsOneItsErasureNamedFirstAndNoEraseNamedSince(t *testing.T) {
	erasure, other := evsTestId("erasure"), evsTestId("other")
	key := func(label string) *EvsErasedKey {
		return &EvsErasedKey{SlotId: evsTestId(label)}
	}
	first := &testCompletionErase{erasureId: erasure, keys: []*EvsErasedKey{key("a"), key("b")}}
	erases := []*testCompletionErase{first}
	if got, ok := testCompletionKey(erases, erasure); !ok || *got != *key("a") {
		t.Fatalf("the first ERASE's first key: %v %v", got, ok)
	}
	// a completion took a: the next names b
	erases = append(erases, &testCompletionErase{erasureId: erasure, keys: []*EvsErasedKey{key("a")}})
	if got, ok := testCompletionKey(erases, erasure); !ok || *got != *key("b") {
		t.Fatalf("after a completion took a: %v %v", got, ok)
	}
	// another erasure's racing ERASE named b too, and destroyed its own c: b is not this erasure's to name
	erases = append(erases, &testCompletionErase{erasureId: other, keys: []*EvsErasedKey{key("b"), key("c")}})
	if got, ok := testCompletionKey(erases, erasure); ok {
		t.Fatalf("a key a later ERASE named: %v", got)
	}
	if got, ok := testCompletionKey(erases, other); !ok || *got != *key("c") {
		t.Fatalf("the other erasure's own key: %v %v", got, ok)
	}
	// a late copy's ERASE reopens the erasure with a key no completion took
	erases = append(erases, &testCompletionErase{erasureId: erasure, keys: []*EvsErasedKey{key("late")}})
	if got, ok := testCompletionKey(erases, erasure); !ok || *got != *key("late") {
		t.Fatalf("after the late copy: %v %v", got, ok)
	}
	// an ERASE of the erasure naming only keys another erasure named first destroyed nothing of its own
	racing := []*testCompletionErase{
		{erasureId: other, keys: []*EvsErasedKey{key("x")}},
		{erasureId: erasure, keys: []*EvsErasedKey{key("x")}},
	}
	if got, ok := testCompletionKey(racing, erasure); ok {
		t.Fatalf("a key another erasure destroyed: %v", got)
	}
	if got, ok := testCompletionKey(nil, erasure); ok || got != nil {
		t.Fatalf("an erasure with no ERASE: %v", got)
	}
}

// QD-1137's flag: COMPLETION is format 2's, and comes with ERASE alone. A format-1 reader refuses it as needing format
// 2; a format-2 one takes ERASE with COMPLETION and refuses COMPLETION alone or beside another flag as INVALID.
func TestEvsStatementTakesCompletionWithEraseAlone(t *testing.T) {
	signer := newEvsTestSigner("writer")
	base := evsTestBuiltInline(t, signer).Statement.Push
	resign := func(push *protocol.EvsPush) []byte {
		body, _ := proto.MarshalOptions{Deterministic: true}.Marshal(push)
		signed, _ := signer.sign(evsPushPurpose, bridge.SignedType_SIGNED_EVS_PUSH, body, nil)
		statementBytes, _ := proto.Marshal(signed)
		return statementBytes
	}
	erase, completion, force := uint32(protocol.EvsPushFlag_EVS_PUSH_ERASE), uint32(protocol.EvsPushFlag_EVS_PUSH_COMPLETION), uint32(protocol.EvsPushFlag_EVS_PUSH_FORCE)
	cases := []struct {
		name    string
		flags   uint32
		format2 error
	}{
		{name: "ERASE with COMPLETION", flags: erase | completion, format2: nil},
		{name: "COMPLETION alone", flags: completion, format2: ErrEvsPushInvalid},
		{name: "COMPLETION beside FORCE", flags: erase | completion | force, format2: ErrEvsPushInvalid},
	}
	for _, shape := range cases {
		push := proto.Clone(base).(*protocol.EvsPush)
		push.Flags = shape.flags
		push.ErasedSha256 = evsTestBytes("erased", 32)
		statementBytes := resign(push)
		if _, err := ParseEvsStatement(statementBytes); !errors.Is(err, ErrEvsFormatUnsupported) {
			t.Errorf("%s at format 1: %v", shape.name, err)
		}
		statement, err := ParseEvsStatementFormat2(statementBytes)
		if !errors.Is(err, shape.format2) || (shape.format2 == nil && statement.Push.GetFlags() != shape.flags) {
			t.Errorf("%s at format 2: %v", shape.name, err)
		}
	}
}

// A terminal flag on an ordinary ERASE does not change what it destroyed. A flagged completion has no physical keys.
func TestEvsCompletionDoesNotSupplyDestructionEvidence(t *testing.T) {
	key := &EvsErasedKey{SlotId: evsTestId("consumed slot"), KeyIndex: 4}
	for _, complete := range []bool{false, true} {
		row := &EvsErasure{ErasureId: evsTestId("erasure"), Keys: []*EvsErasedKey{key}, Complete: complete}
		if got := row.destroyedKeys(); len(got) != 1 || *got[0] != *key {
			t.Fatalf("ordinary ERASE with complete %t lost its physical key", complete)
		}
		row.Completion = true
		if got := row.destroyedKeys(); len(got) != 0 || len(row.Keys) != 1 {
			t.Fatalf("completion with complete %t yielded physical keys %v, named %v", complete, got, row.Keys)
		}
	}
}
