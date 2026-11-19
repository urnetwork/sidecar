//go:build sidecar_testhooks && !ios_extension && !js

// A search world's index history, for sidecartest/fault's search invariants (TEST-M10-02; FI-18 to FI-22): every
// committed ref version, its signer and signed time, whether it was a CUT, and the index files it wrote, with their
// plaintexts, and removed. The oracle replays the ref from the bytes alone, with its own reading of the format and
// none of the index's code (D-TEST-14), so this hands over bytes and nothing decoded. Only the sidecar_testhooks build
// has it, which no release leg is (§22.4).

package sidecar

import (
	"bytes"
	"maps"
	"slices"
	"time"
)

// One committed ref version of a search world's index.
type SearchTestIndexPush struct {
	RefVersion uint64
	SignerId   Id
	SignedTime time.Time
	// The push moved the head's index_epoch to its own version: an erasure's CUT.
	Cut bool
	// The index files it wrote, by path, and the index paths it removed, sorted.
	Written []*SearchTestIndexFileVersion
	Removed []string
}

// One index file version as the world's store holds it.
type SearchTestIndexFileVersion struct {
	Path          string
	Version       uint64
	ContentSha256 []byte
	Plaintext     []byte
}

// Every committed ref version above afterRefVersion, in order, each with what it changed under the index: a content
// push that wrote no index file changes nothing there. Copies.
func (self *SearchTestWorld) IndexHistory(afterRefVersion uint64) []*SearchTestIndexPush {
	self.ref.stateLock.Lock()
	defer self.ref.stateLock.Unlock()
	pushes := []*SearchTestIndexPush{}
	for index := max(afterRefVersion+1, 1); index < uint64(len(self.ref.states)); index += 1 {
		previous := self.ref.states[index-1]
		state := self.ref.states[index]
		push := &SearchTestIndexPush{
			RefVersion: state.head.version,
			SignerId:   state.signer,
			SignedTime: time.UnixMilli(state.head.signedTimeMs).UTC(),
			Cut:        state.head.indexEpoch == state.head.version && previous.head.indexEpoch != state.head.indexEpoch,
		}
		for _, path := range slices.Sorted(maps.Keys(state.files)) {
			stored := state.files[path]
			if previous.files[path] == stored {
				continue
			}
			push.Written = append(push.Written, &SearchTestIndexFileVersion{
				Path:          path,
				Version:       stored.version.version,
				ContentSha256: bytes.Clone(stored.version.contentSha256[:]),
				Plaintext:     bytes.Clone(stored.plaintext),
			})
		}
		for _, path := range slices.Sorted(maps.Keys(previous.files)) {
			if _, ok := state.files[path]; !ok {
				push.Removed = append(push.Removed, path)
			}
		}
		pushes = append(pushes, push)
	}
	return pushes
}
