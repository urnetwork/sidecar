//go:build !ios_extension

package sidecar

// QD-1132's completion ERASE: the key it names (evs_erase_completion.go's key row).

import (
	"testing"
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
