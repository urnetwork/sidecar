//go:build !sidecar_http && !ios_extension

// WithBlobClientPaced (QD-1402): the mark rides its ctx and every ctx derived from it, and no other.

package sidecar

import (
	"context"
	"testing"
	"time"
)

// A ctx says its request's body moves at a client's own pace only once marked, and every ctx derived from a marked
// one says so too, whatever else it adds; a sibling of the marked ctx does not.
func TestBlobClientPacedRidesItsCtxAlone(t *testing.T) {
	parent := t.Context()
	if BlobClientPaced(parent) {
		t.Fatal("an unmarked ctx reads as client-paced")
	}
	paced := WithBlobClientPaced(parent)
	if !BlobClientPaced(paced) {
		t.Fatal("a marked ctx does not read as client-paced")
	}
	cancelled, cancel := context.WithCancel(paced)
	defer cancel()
	derived := []context.Context{
		cancelled,
		WithBlobDeadline(paced, time.Unix(1, 0)),
		WithBlobUnmodified(paced, time.Unix(1, 0)),
	}
	for i, ctx := range derived {
		if !BlobClientPaced(ctx) {
			t.Errorf("derived ctx %d lost the mark", i)
		}
	}
	if sibling := WithBlobDeadline(parent, time.Unix(1, 0)); BlobClientPaced(sibling) {
		t.Fatal("a sibling of the marked ctx reads as client-paced")
	}
}
