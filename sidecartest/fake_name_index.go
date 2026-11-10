// A sidecar.EvsNameIndex a test sets by hand (DESIGN-DETAILS 9.2.7; EVS1-M2-47): the head it is exact at, every path
// standing there with its born epoch, and the paths created after each version, so a mapper's build, tail and resume
// run on fakes, as a replaying mirror's index will feed them (EVS1-M2-33, EVS1-M2-35). Safe for concurrent use.

package sidecartest

import (
	"context"
	"slices"
	"strings"
	"sync"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// See the file header.
type FakeNameIndex struct {
	stateLock sync.Mutex
	head      *sidecar.EvsNameIndexHead
	paths     []*sidecar.EvsIndexedPath
	// each creation's version, in order
	created []*fakeNameIndexCreation
}

// One creation the index saw.
type fakeNameIndexCreation struct {
	version uint64
	path    *sidecar.EvsIndexedPath
}

// An index exact at head, holding only the root.
func NewFakeNameIndex(head *sidecar.EvsNameIndexHead) *FakeNameIndex {
	return &FakeNameIndex{head: head, paths: []*sidecar.EvsIndexedPath{{Kind: protocol.EvsEntryKind_EVS_ENTRY_DIRECTORY}}}
}

// Moves the head the index is exact at.
func (self *FakeNameIndex) SetHead(head *sidecar.EvsNameIndexHead) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.head = head
}

// Adds a standing path, its parents first, and records its creation at version.
func (self *FakeNameIndex) Add(path string, kind protocol.EvsEntryKind, born uint64, version uint64) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	names := [][]byte{}
	for _, name := range strings.Split(path, "/") {
		names = append(names, []byte(name))
	}
	indexed := &sidecar.EvsIndexedPath{Names: names, Kind: kind, Born: born}
	self.paths = append(self.paths, indexed)
	self.created = append(self.created, &fakeNameIndexCreation{version: version, path: indexed})
}

// Removes a standing path and everything below it; its creation stays in CreatedAfter's answers.
func (self *FakeNameIndex) Remove(path string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.paths = slices.DeleteFunc(self.paths, func(held *sidecar.EvsIndexedPath) bool {
		heldPath := held.Path()
		return heldPath == path || strings.HasPrefix(heldPath, path+"/")
	})
}

// The head SetHead set.
func (self *FakeNameIndex) Head(ctx context.Context) (*sidecar.EvsNameIndexHead, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.head, nil
}

// Every standing path, in the order Add gave them.
func (self *FakeNameIndex) Walk(ctx context.Context, visit func(path *sidecar.EvsIndexedPath) error) error {
	self.stateLock.Lock()
	paths := slices.Clone(self.paths)
	self.stateLock.Unlock()
	for _, path := range paths {
		if err := visit(path); err != nil {
			return err
		}
	}
	return nil
}

// Every path added at a version after version, removed ones included.
func (self *FakeNameIndex) CreatedAfter(ctx context.Context, version uint64) ([]*sidecar.EvsIndexedPath, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	created := []*sidecar.EvsIndexedPath{}
	for _, creation := range self.created {
		if version < creation.version {
			created = append(created, creation.path)
		}
	}
	return created, nil
}
