//go:build !ios_extension

// A mirror's newest-version rule (EVS2-M10-13): of a replaced versionless version the mirror drops only its unstaged
// kind-5 segments that the replacing push names nowhere; a staged one rides in its record, an adopted one is named, and
// a kind-1 one stays.

package sidecar

import (
	"bytes"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
)

func TestEvsMirrorReplacedSegmentIds(t *testing.T) {
	kind5 := uint32(protocol.EvsLocatorKind_EVS_LOCATOR_VERSIONLESS_SEGMENT)
	dropped, staged, adopted, kept := evsTestBytes("dropped", 32), evsTestBytes("staged", 32), evsTestBytes("adopted", 32), evsTestBytes("kept", 32)
	replaced := &protocol.EvsEntryVersion{Versioning: 1, Chain: []*protocol.EvsLocator{
		{Kind: kind5, Id: dropped},
		{Kind: kind5, Id: staged, Staged: true},
		{Kind: kind5, Id: adopted},
		{Kind: uint32(protocol.EvsLocatorKind_EVS_LOCATOR_SEGMENT), Id: kept},
	}}
	ids := EvsMirrorReplacedSegmentIds(replaced, map[string]bool{string(adopted): true})
	if len(ids) != 1 || !bytes.Equal(ids[0], dropped) {
		t.Fatalf("the mirror drops %d segments", len(ids))
	}
}
