//go:build !sidecar_http && !ios_extension

// WithBlobProbe (owner decision 790): the mark rides its ctx and every ctx derived from it, and no other, and it is a
// mark of its own, apart from WithBlobClientPaced's.

package sidecar

import (
	"context"
	"testing"
	"time"
)

// A ctx says its request is a store check's only once marked, and every ctx derived from a marked one says so too,
// whatever else it adds; a sibling of the marked ctx does not. Neither mark reads as the other.
func TestBlobProbeRidesItsCtxAlone(t *testing.T) {
	parent := t.Context()
	if BlobProbe(parent) {
		t.Fatal("an unmarked ctx reads as a probe's")
	}
	probe := WithBlobProbe(parent)
	if !BlobProbe(probe) {
		t.Fatal("a marked ctx does not read as a probe's")
	}
	if BlobClientPaced(probe) {
		t.Fatal("a probe's ctx reads as client-paced")
	}
	if BlobProbe(WithBlobClientPaced(parent)) {
		t.Fatal("a client-paced ctx reads as a probe's")
	}
	cancelled, cancel := context.WithCancel(probe)
	defer cancel()
	derived := []context.Context{
		cancelled,
		WithBlobDeadline(probe, time.Unix(1, 0)),
		WithBlobUnmodified(probe, time.Unix(1, 0)),
		WithBlobClientPaced(probe),
	}
	for i, ctx := range derived {
		if !BlobProbe(ctx) {
			t.Errorf("derived ctx %d lost the mark", i)
		}
	}
	if sibling := WithBlobDeadline(parent, time.Unix(1, 0)); BlobProbe(sibling) {
		t.Fatal("a sibling of the marked ctx reads as a probe's")
	}
}
