//go:build !ios_extension

// The tree builder (DESIGN-DETAILS 8.2.7's build), which export and the local tier's sync engine share: a commit's
// tree made from its first parent's tree and its changes, from the deepest directory up, each changed directory's
// bytes the canonical encoding of what it holds, or the raw tree the commit carries for it once git's reading of those
// bytes equals what was built. An unchanged directory keeps its oid, raw or not, since nothing below it changed, so a
// raw tree is used only where the commit that brought it, or an ancestor through unchanged directories, put it.
// Nothing here normalizes a byte (G1).
//
// A tree is read from the builder's cache, then the sink's pending objects, then the object source; what it reads
// and what it builds go in the cache, bounded by its byte count (TreeCacheByteCount), least recently used out first.
// Memory is the cache, the pending chunk the sink holds and one commit's changes; nothing is kept per commit.
//
// On every leg but the forwarding role's. An EvsGitTreeBuilder is one replay's, not safe for concurrent use.

package sidecar

import (
	"bytes"
	"container/list"
	"context"
	"errors"
	"fmt"
	"io"
	"slices"

	"github.com/urnetwork/sidecar/protocol"
)

// An object an object source does not hold.
var ErrEvsGitObjectMissing = errors.New("git object missing")

// Where a replay reads the objects it already holds: export's repository, or the local tier's bare repository
// through git cat-file. Safe for concurrent use as its implementation says.
type EvsGitObjectSource interface {
	// The object's kind and bytes; ErrEvsGitObjectMissing when the source holds none.
	ReadGitObject(ctx context.Context, oid EvsGitOid) (string, []byte, error)
}

// Where a replay writes the objects it rebuilds or opens: export's loose objects, or the local tier's packs. An
// object written already is not written again.
type EvsGitObjectSink interface {
	// Writes an object whose bytes are in memory, answering its oid.
	WriteGitObject(kind string, content []byte) (EvsGitOid, error)
	// Writes an object of size bytes from content, answering its oid.
	WriteGitObjectFrom(kind string, content io.Reader, size int64) (EvsGitOid, error)
	// Whether the sink holds oid, written or pending.
	HasGitObject(oid EvsGitOid) bool
	// An object written since the last flush, which no source may read yet; false for any other.
	PendingGitObject(oid EvsGitOid) (string, []byte, bool)
	// Makes every pending object readable through the source.
	Flush(ctx context.Context) error
}

// The empty tree's oid, git's 4b825dc6...: a commit with no file.
var EvsGitEmptyTreeOid = evsGitObjectOid(evsGitTreeKind, nil)

// What a tree held in the cache costs beyond its bytes: the entries' headers.
const evsGitTreeEntryOverheadByteCount = 64

// Builds commits' trees; see the file header.
type EvsGitTreeBuilder struct {
	source EvsGitObjectSource
	sink   EvsGitObjectSink
	cache  *evsGitTreeCache
}

// A builder reading through source, writing through sink, caching at most cacheByteCount of trees.
func NewEvsGitTreeBuilder(source EvsGitObjectSource, sink EvsGitObjectSink, cacheByteCount int64) *EvsGitTreeBuilder {
	return &EvsGitTreeBuilder{source: source, sink: sink, cache: newEvsGitTreeCache(cacheByteCount)}
}

// One directory a commit's changes or raw trees reach: its changed files by name, its subdirectories reached, and
// the raw tree the commit carries for it.
type evsGitBuildNode struct {
	files    map[string]*protocol.EvsSealedChange
	children map[string]*evsGitBuildNode
	raw      []byte
}

func newEvsGitBuildNode() *evsGitBuildNode {
	return &evsGitBuildNode{files: map[string]*protocol.EvsSealedChange{}, children: map[string]*evsGitBuildNode{}}
}

// The node for names, made on the way.
func (self *evsGitBuildNode) at(names [][]byte) *evsGitBuildNode {
	node := self
	for _, name := range names {
		child := node.children[string(name)]
		if child == nil {
			child = newEvsGitBuildNode()
			node.children[string(name)] = child
		}
		node = child
	}
	return node
}

// One entry of a tree being built: its mode as a rebuilt tree writes it, and its oid.
type evsGitBuiltEntry struct {
	mode uint32
	oid  EvsGitOid
}

// The tree of a commit whose first parent's tree is parentTree, nil for a commit with no parent, made from its
// changes (each {path, mode, oid}, a removal with no oid; a directory is never a change) and its raw trees, written to
// the sink: the root tree's oid. A change the parent tree cannot take, a raw tree whose reading differs from what was
// built, and a name a tree cannot hold are refused as ErrEvsGitObjectInvalid, naming no bytes.
func (self *EvsGitTreeBuilder) Build(ctx context.Context, parentTree *EvsGitOid, changes []*protocol.EvsSealedChange, raw []*protocol.EvsSealedTree) (EvsGitOid, error) {
	root := newEvsGitBuildNode()
	for _, change := range changes {
		names := change.GetPath()
		if len(names) == 0 {
			return EvsGitOid{}, fmt.Errorf("%w: a change of no path", ErrEvsGitObjectInvalid)
		}
		directory := root.at(names[:len(names)-1])
		name := string(names[len(names)-1])
		if _, ok := directory.files[name]; ok {
			return EvsGitOid{}, fmt.Errorf("%w: a commit changes one path twice", ErrEvsGitObjectInvalid)
		}
		directory.files[name] = change
	}
	for _, rawTree := range raw {
		node := root.at(rawTree.GetPath())
		if node.raw != nil {
			return EvsGitOid{}, fmt.Errorf("%w: two raw trees at one path", ErrEvsGitObjectInvalid)
		}
		node.raw = rawTree.GetObject()
	}
	oid, err := self.buildNode(ctx, root, parentTree, true)
	if err != nil {
		return EvsGitOid{}, err
	}
	return *oid, nil
}

// One directory's tree over base, its tree in the parent (nil: none), deepest first: nil when it ends empty, which
// only the root does not, the root of no file being the empty tree.
func (self *EvsGitTreeBuilder) buildNode(ctx context.Context, node *evsGitBuildNode, base *EvsGitOid, isRoot bool) (*EvsGitOid, error) {
	entries := map[string]*evsGitBuiltEntry{}
	// the parent's directories by name, which the subdirectories reached build on
	baseDirectories := map[string]EvsGitOid{}
	if base != nil {
		baseEntries, err := self.readTree(ctx, *base)
		if err != nil {
			return nil, err
		}
		for _, entry := range baseEntries {
			entries[string(entry.Name)] = &evsGitBuiltEntry{mode: entry.CanonMode, oid: entry.Oid}
			if entry.CanonMode == EvsGitModeDirectory {
				baseDirectories[string(entry.Name)] = entry.Oid
			}
		}
	}
	// the files first, then the directories reached, so a path that changes kind ends as the change says
	added := map[string]bool{}
	for name, change := range node.files {
		held := entries[name]
		if len(change.GetGitOid()) == 0 {
			if held == nil || held.mode == EvsGitModeDirectory {
				return nil, fmt.Errorf("%w: a removal of a file the tree does not hold", ErrEvsGitObjectInvalid)
			}
			delete(entries, name)
			continue
		}
		if len(change.GetGitOid()) != len(EvsGitOid{}) || EvsGitCanonMode(change.GetMode()) != change.GetMode() ||
			change.GetMode() == EvsGitModeDirectory {
			return nil, fmt.Errorf("%w: a change of mode %o", ErrEvsGitObjectInvalid, change.GetMode())
		}
		if held != nil && held.mode == EvsGitModeDirectory {
			// a file where a directory stood: the directory empties by its own changes, below
			if node.children[name] == nil {
				return nil, fmt.Errorf("%w: a file over a directory whose files stay", ErrEvsGitObjectInvalid)
			}
		}
		entries[name] = &evsGitBuiltEntry{mode: change.GetMode(), oid: EvsGitOid(change.GetGitOid())}
		added[name] = true
	}
	names := make([]string, 0, len(node.children))
	for name := range node.children {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		var childBase *EvsGitOid
		if directoryOid, ok := baseDirectories[name]; ok {
			childBase = &directoryOid
		}
		childOid, err := self.buildNode(ctx, node.children[name], childBase, false)
		if err != nil {
			return nil, err
		}
		switch {
		case childOid == nil && added[name]:
			// the directory emptied, and a file took its name
		case childOid == nil:
			delete(entries, name)
		case added[name]:
			return nil, fmt.Errorf("%w: a file and a directory of one name", ErrEvsGitObjectInvalid)
		default:
			entries[name] = &evsGitBuiltEntry{mode: EvsGitModeDirectory, oid: *childOid}
		}
	}
	if len(entries) == 0 && !isRoot {
		if node.raw != nil {
			return nil, fmt.Errorf("%w: a raw tree for a directory that ends empty", ErrEvsGitObjectInvalid)
		}
		return nil, nil
	}
	if node.raw != nil {
		oid, err := self.useRaw(node.raw, entries)
		if err != nil {
			return nil, err
		}
		return &oid, nil
	}
	tree := &EvsGitTree{Entries: make([]EvsGitTreeEntry, 0, len(entries))}
	for name, entry := range entries {
		tree.Entries = append(tree.Entries, EvsGitTreeEntry{Mode: entry.mode, Name: []byte(name), Oid: entry.oid})
	}
	encoded, err := tree.Encode()
	if err != nil {
		return nil, err
	}
	oid, err := self.sink.WriteGitObject(evsGitTreeKind, encoded)
	if err != nil {
		return nil, err
	}
	self.cache.put(oid, evsGitRawEntriesOf(tree), len(encoded))
	return &oid, nil
}

// A raw tree's oid, once git's reading of its bytes equals the built entries, name for name, canon mode and oid; its
// bytes are written as they are.
func (self *EvsGitTreeBuilder) useRaw(raw []byte, entries map[string]*evsGitBuiltEntry) (EvsGitOid, error) {
	rawEntries, err := EvsGitTreeRead(raw)
	if err != nil {
		return EvsGitOid{}, err
	}
	if len(rawEntries) != len(entries) {
		return EvsGitOid{}, fmt.Errorf("%w: a raw tree whose reading is not the built tree", ErrEvsGitObjectInvalid)
	}
	for _, rawEntry := range rawEntries {
		built := entries[string(rawEntry.Name)]
		if built == nil || built.mode != rawEntry.CanonMode || built.oid != rawEntry.Oid {
			return EvsGitOid{}, fmt.Errorf("%w: a raw tree whose reading is not the built tree", ErrEvsGitObjectInvalid)
		}
	}
	oid, err := self.sink.WriteGitObject(evsGitTreeKind, raw)
	if err != nil {
		return EvsGitOid{}, err
	}
	self.cache.put(oid, rawEntries, len(raw))
	return oid, nil
}

// A tree's entries as git reads them: the cache, the sink's pending objects, else the source.
func (self *EvsGitTreeBuilder) readTree(ctx context.Context, oid EvsGitOid) ([]EvsGitRawEntry, error) {
	if entries, ok := self.cache.get(oid); ok {
		return entries, nil
	}
	if oid == EvsGitEmptyTreeOid {
		return nil, nil
	}
	kind, encoded, ok := self.sink.PendingGitObject(oid)
	if !ok {
		var err error
		kind, encoded, err = self.source.ReadGitObject(ctx, oid)
		if err != nil {
			return nil, err
		}
	}
	if kind != evsGitTreeKind || evsGitObjectOid(kind, encoded) != oid {
		return nil, fmt.Errorf("%w: a tree that is no tree, or not its oid", ErrEvsGitObjectInvalid)
	}
	entries, err := EvsGitTreeRead(encoded)
	if err != nil {
		return nil, err
	}
	self.cache.put(oid, entries, len(encoded))
	return entries, nil
}

// The tree's entries as git would read its canonical bytes.
func evsGitRawEntriesOf(tree *EvsGitTree) []EvsGitRawEntry {
	entries := make([]EvsGitRawEntry, 0, len(tree.Entries))
	for _, entry := range tree.Entries {
		entries = append(entries, EvsGitRawEntry{
			ModeText: []byte(fmt.Sprintf("%o", entry.Mode)), Mode: entry.Mode, CanonMode: EvsGitCanonMode(entry.Mode),
			Name: bytes.Clone(entry.Name), Oid: entry.Oid,
		})
	}
	return entries
}

// The trees the builder holds, least recently used out first past byteCount. Not safe for concurrent use.
type evsGitTreeCache struct {
	byteCount int64
	held      int64
	order     *list.List
	trees     map[EvsGitOid]*list.Element
}

// One tree the cache holds.
type evsGitCachedTree struct {
	oid       EvsGitOid
	entries   []EvsGitRawEntry
	byteCount int64
}

func newEvsGitTreeCache(byteCount int64) *evsGitTreeCache {
	return &evsGitTreeCache{byteCount: byteCount, order: list.New(), trees: map[EvsGitOid]*list.Element{}}
}

func (self *evsGitTreeCache) get(oid EvsGitOid) ([]EvsGitRawEntry, bool) {
	element, ok := self.trees[oid]
	if !ok {
		return nil, false
	}
	self.order.MoveToFront(element)
	return element.Value.(*evsGitCachedTree).entries, true
}

// Holds a tree of encodedByteCount bytes, dropping the least recently used past the bound; a tree past the bound
// alone is not held. A non-positive bound holds nothing.
func (self *evsGitTreeCache) put(oid EvsGitOid, entries []EvsGitRawEntry, encodedByteCount int) {
	if _, ok := self.trees[oid]; ok {
		return
	}
	byteCount := int64(encodedByteCount + len(entries)*evsGitTreeEntryOverheadByteCount)
	if self.byteCount < byteCount {
		return
	}
	self.trees[oid] = self.order.PushFront(&evsGitCachedTree{oid: oid, entries: entries, byteCount: byteCount})
	self.held += byteCount
	for self.byteCount < self.held {
		oldest := self.order.Back()
		cached := oldest.Value.(*evsGitCachedTree)
		self.order.Remove(oldest)
		delete(self.trees, cached.oid)
		self.held -= cached.byteCount
	}
}

// One commit's changes and raw trees against its first parent's tree (DESIGN-DETAILS 8.2.2's changes and trees rows,
// 8.2.5's diff): a merge walk of the two trees in name order, each tree's entries sorted by name bytes first since a
// raw tree may be out of order, descending only where the oids differ. Each file that differs is a change {path,
// mode, oid}, its mode git's canon_mode with 100664 kept, a removal with no oid; a directory is never a change, and a
// path that changes kind is a removal of what stood and writes of what comes. Each tree visited, so differing from
// the first parent's at its path, whose bytes are not EvsGitTree.Encode of its entries is a raw tree. Changes ascend
// by path bytes, names joined with a slash. parentTree is nil for a commit with no parent. It never runs git diff-tree,
// whose walk assumes git's order; a tree the reader refuses (8.2.5) refuses the commit, naming the tree's oid.
func EvsGitCommitChanges(ctx context.Context, source EvsGitObjectSource, parentTree *EvsGitOid, tree EvsGitOid) ([]*protocol.EvsSealedChange, []*protocol.EvsSealedTree, error) {
	walk := &evsGitDiffWalk{ctx: ctx, source: source}
	if parentTree == nil || *parentTree != tree {
		if err := walk.trees(nil, parentTree, &tree); err != nil {
			return nil, nil, err
		}
	}
	slices.SortFunc(walk.changes, func(a *protocol.EvsSealedChange, b *protocol.EvsSealedChange) int {
		return bytes.Compare(bytes.Join(a.GetPath(), []byte{'/'}), bytes.Join(b.GetPath(), []byte{'/'}))
	})
	return walk.changes, walk.raw, nil
}

// One commit's diff walk.
type evsGitDiffWalk struct {
	ctx     context.Context
	source  EvsGitObjectSource
	changes []*protocol.EvsSealedChange
	raw     []*protocol.EvsSealedTree
}

// A tree's entries as git reads them, sorted by name bytes, and whether its bytes are canonical.
func (self *evsGitDiffWalk) read(oid EvsGitOid) ([]EvsGitRawEntry, []byte, bool, error) {
	if oid == EvsGitEmptyTreeOid {
		return nil, nil, true, nil
	}
	kind, encoded, err := self.source.ReadGitObject(self.ctx, oid)
	if err != nil {
		return nil, nil, false, fmt.Errorf("tree %x: %w", oid[:], err)
	}
	if kind != evsGitTreeKind || evsGitObjectOid(kind, encoded) != oid {
		return nil, nil, false, fmt.Errorf("%w: tree %x is no tree, or not its oid", ErrEvsGitObjectInvalid, oid[:])
	}
	entries, err := EvsGitTreeRead(encoded)
	if err != nil {
		return nil, nil, false, fmt.Errorf("tree %x: %w", oid[:], err)
	}
	canonical := evsGitTreeCanonical(entries, encoded)
	slices.SortFunc(entries, func(a EvsGitRawEntry, b EvsGitRawEntry) int {
		return bytes.Compare(a.Name, b.Name)
	})
	return entries, encoded, canonical, nil
}

// Whether a tree's bytes are EvsGitTree.Encode of its entries as git reads them.
func evsGitTreeCanonical(entries []EvsGitRawEntry, encoded []byte) bool {
	tree := &EvsGitTree{Entries: make([]EvsGitTreeEntry, 0, len(entries))}
	for _, entry := range entries {
		tree.Entries = append(tree.Entries, EvsGitTreeEntry{Mode: entry.CanonMode, Name: entry.Name, Oid: entry.Oid})
	}
	canonical, err := tree.Encode()
	return err == nil && bytes.Equal(canonical, encoded)
}

// The path names, extended by name, as a new slice.
func evsGitPathWith(path [][]byte, name []byte) [][]byte {
	return append(slices.Clone(path), bytes.Clone(name))
}

// The changes between the trees a and b at path, either nil for none there.
func (self *evsGitDiffWalk) trees(path [][]byte, a *EvsGitOid, b *EvsGitOid) error {
	if err := self.ctx.Err(); err != nil {
		return err
	}
	var aEntries, bEntries []EvsGitRawEntry
	if a != nil {
		entries, _, _, err := self.read(*a)
		if err != nil {
			return err
		}
		aEntries = entries
	}
	if b != nil {
		entries, encoded, canonical, err := self.read(*b)
		if err != nil {
			return err
		}
		bEntries = entries
		if !canonical {
			self.raw = append(self.raw, &protocol.EvsSealedTree{Path: slices.Clone(path), Object: encoded})
		}
	}
	for i, j := 0, 0; i < len(aEntries) || j < len(bEntries); {
		switch {
		case j == len(bEntries) || (i < len(aEntries) && bytes.Compare(aEntries[i].Name, bEntries[j].Name) < 0):
			if err := self.gone(evsGitPathWith(path, aEntries[i].Name), aEntries[i]); err != nil {
				return err
			}
			i += 1
		case i == len(aEntries) || bytes.Compare(bEntries[j].Name, aEntries[i].Name) < 0:
			if err := self.come(evsGitPathWith(path, bEntries[j].Name), bEntries[j]); err != nil {
				return err
			}
			j += 1
		default:
			if err := self.both(evsGitPathWith(path, aEntries[i].Name), aEntries[i], bEntries[j]); err != nil {
				return err
			}
			i += 1
			j += 1
		}
	}
	return nil
}

// What stood at path and is gone: a file's removal, or every file of a directory removed.
func (self *evsGitDiffWalk) gone(path [][]byte, entry EvsGitRawEntry) error {
	if entry.CanonMode == EvsGitModeDirectory {
		return self.trees(path, &entry.Oid, nil)
	}
	self.changes = append(self.changes, &protocol.EvsSealedChange{Path: path})
	return nil
}

// What comes at path where nothing stood: a file's write, or every file of a directory written.
func (self *evsGitDiffWalk) come(path [][]byte, entry EvsGitRawEntry) error {
	if entry.CanonMode == EvsGitModeDirectory {
		return self.trees(path, nil, &entry.Oid)
	}
	self.changes = append(self.changes, &protocol.EvsSealedChange{Path: path, Mode: entry.CanonMode, GitOid: bytes.Clone(entry.Oid[:])})
	return nil
}

// A name both trees hold: nothing when its kind, canon mode and oid stand, a walk down two directories, else what
// stood gone and what comes written.
func (self *evsGitDiffWalk) both(path [][]byte, a EvsGitRawEntry, b EvsGitRawEntry) error {
	aDirectory, bDirectory := a.CanonMode == EvsGitModeDirectory, b.CanonMode == EvsGitModeDirectory
	switch {
	case a.CanonMode == b.CanonMode && a.Oid == b.Oid:
		return nil
	case aDirectory && bDirectory:
		return self.trees(path, &a.Oid, &b.Oid)
	case !aDirectory && !bDirectory:
		self.changes = append(self.changes, &protocol.EvsSealedChange{Path: path, Mode: b.CanonMode, GitOid: bytes.Clone(b.Oid[:])})
		return nil
	}
	if err := self.gone(path, a); err != nil {
		return err
	}
	return self.come(path, b)
}
