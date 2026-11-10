package sidecar

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
)

// One classification for evs and its clients: a shrink after the starting generation's pin is immediate, anything
// else batched (question evs1-m2-16-due-classification, option 1).
func TestEvsClassifyPathEpochDue(t *testing.T) {
	cases := []struct {
		holdersShrunkAt uint64
		fromAuthVersion uint64
		immediate       bool
	}{
		{holdersShrunkAt: 0, fromAuthVersion: 0, immediate: false},
		{holdersShrunkAt: 0, fromAuthVersion: 7, immediate: false},
		{holdersShrunkAt: 7, fromAuthVersion: 7, immediate: false},
		{holdersShrunkAt: 7, fromAuthVersion: 9, immediate: false},
		{holdersShrunkAt: 8, fromAuthVersion: 7, immediate: true},
		{holdersShrunkAt: 1, fromAuthVersion: 0, immediate: true},
	}
	for _, c := range cases {
		if immediate := EvsClassifyPathEpochDue(c.holdersShrunkAt, c.fromAuthVersion); immediate != c.immediate {
			t.Errorf("shrunk at %d from %d: immediate %t", c.holdersShrunkAt, c.fromAuthVersion, immediate)
		}
	}
}

// Creation blocks on shared and owned refs of general, config and mailcfg repos alone (plan-EVS1-epoch-kinds #1, #2).
func TestEvsRefBlocksCreation(t *testing.T) {
	blockingKinds := map[protocol.RepoKind]bool{
		protocol.RepoKind_REPO_KIND_GENERAL: true, protocol.RepoKind_REPO_KIND_CONFIG: true, protocol.RepoKind_REPO_KIND_MAILCFG: true,
	}
	blockingRefs := map[protocol.EvsRefKind]bool{protocol.EvsRefKind_EVS_REF_SHARED: true, protocol.EvsRefKind_EVS_REF_OWNED: true}
	for repoKindValue := range protocol.RepoKind_name {
		for refKindValue := range protocol.EvsRefKind_name {
			repoKind, refKind := protocol.RepoKind(repoKindValue), protocol.EvsRefKind(refKindValue)
			want := blockingKinds[repoKind] && blockingRefs[refKind]
			if got := EvsRefBlocksCreation(repoKind, refKind); got != want {
				t.Errorf("%s %s: blocks %t", repoKind, refKind, got)
			}
		}
	}
}

// path_map_sha256 is SHA-256 over the parts' signed bytes in part order (DESIGN-DETAILS 9.2.2): the hasher one part at
// a time equals the hash of the parts joined, and another order is another hash.
func TestEvsPathMapSha256(t *testing.T) {
	parts := [][]byte{[]byte("part one's signed bytes"), []byte("part two's"), []byte("and three")}
	joined := sha256.Sum256(bytes.Join(parts, nil))
	if got := EvsPathMapSha256(parts); !bytes.Equal(got, joined[:]) {
		t.Fatalf("the map's hash %x, want %x", got, joined)
	}
	hasher := NewEvsPathMapHasher()
	for _, part := range parts {
		hasher.Add(part)
	}
	if !bytes.Equal(hasher.Sum(), joined[:]) || hasher.PartCount() != 3 {
		t.Fatalf("the hasher %x over %d parts", hasher.Sum(), hasher.PartCount())
	}
	if bytes.Equal(EvsPathMapSha256([][]byte{parts[1], parts[0], parts[2]}), joined[:]) {
		t.Fatal("two orders of the parts hash alike")
	}
}

// 409 MAP_SOURCE reads as itself and as no other refusal, MAP_PARTS among them.
func TestIsEvsMapSource(t *testing.T) {
	mapSource := &EvsError{Status: 409, Code: protocol.EvsRefusalCode_EVS_REFUSAL_MAP_SOURCE}
	if !IsEvsMapSource(mapSource) || !IsEvsMapSource(fmt.Errorf("a PATH_EPOCH: %w", mapSource)) {
		t.Fatal("MAP_SOURCE not read as itself")
	}
	if IsEvsMapSource(&EvsError{Status: 409, Code: protocol.EvsRefusalCode_EVS_REFUSAL_MAP_PARTS}) || IsEvsMapSource(errors.New("other")) {
		t.Fatal("another answer read as MAP_SOURCE")
	}
	if status, ok := EvsRefusalStatus(protocol.EvsRefusalCode_EVS_REFUSAL_MAP_SOURCE); !ok || status != 409 ||
		EvsRefusalRecordable(protocol.EvsRefusalCode_EVS_REFUSAL_MAP_SOURCE) || EvsRefusalRefusesNothing(protocol.EvsRefusalCode_EVS_REFUSAL_MAP_SOURCE) {
		t.Fatalf("MAP_SOURCE's row: %d %t", status, ok)
	}
}
