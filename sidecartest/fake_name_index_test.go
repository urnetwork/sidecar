package sidecartest

import (
	"context"
	"slices"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// FakeNameIndex walks what stands, parents first, and gives every creation after a version, removed ones included,
// as a mapper's tail needs (DESIGN-DETAILS 9.2.7).
func TestFakeNameIndex(t *testing.T) {
	ctx := context.Background()
	index := NewFakeNameIndex(&sidecar.EvsNameIndexHead{Version: 3, PathEpoch: &protocol.EvsPathEpoch{Current: 1}})
	index.Add("d", protocol.EvsEntryKind_EVS_ENTRY_DIRECTORY, 0, 1)
	index.Add("d/x", protocol.EvsEntryKind_EVS_ENTRY_FILE, 0, 2)
	index.Add("d/y", protocol.EvsEntryKind_EVS_ENTRY_FILE, 1, 3)
	index.Remove("d/x")
	walked := []string{}
	if err := index.Walk(ctx, func(path *sidecar.EvsIndexedPath) error {
		walked = append(walked, path.Path())
		return nil
	}); err != nil || !slices.Equal(walked, []string{"", "d", "d/y"}) {
		t.Fatalf("walked %v %v", walked, err)
	}
	created, err := index.CreatedAfter(ctx, 1)
	if err != nil || len(created) != 2 || created[0].Path() != "d/x" || created[1].Born != 1 {
		t.Fatalf("created after 1: %v %v", created, err)
	}
	if head, err := index.Head(ctx); err != nil || head.Version != 3 {
		t.Fatalf("head %v %v", head, err)
	}
}
