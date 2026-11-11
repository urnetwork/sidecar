//go:build !sidecar_http && !js && !ios && !android && !sdk_mobile_bind

// The local tier's tree reader (DESIGN-DETAILS 8.2.5): the one place it reads a tree, through one long-lived
// `git cat-file --batch` over a mount's bare repository. Each answer's kind and size are read and its bytes hashed
// against the oid asked, so a corrupt or substituted object is refused, and a tree is read as git reads it
// (EvsGitTreeRead). The diff of two trees is EvsGitCommitChanges over this source: a merge walk in name order that
// descends only where the oids differ, never git diff-tree, whose walk assumes git's order. A tree the reader refuses
// refuses the update, or the import, before any evs write, naming the tree's oid.
//
// Desktop legs only. Safe for concurrent use: one request at a time reaches the process.

package sidecar

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/urnetwork/sidecar/protocol"
)

// A mount's objects, read through one git cat-file --batch (EvsGitObjectSource).
type EvsLocalObjects struct {
	stateLock sync.Mutex
	process   *EvsGitProcess
	reader    *bufio.Reader
	// a request whose answer was not read whole leaves the stream unusable
	broken error
}

// Starts the mount's object reader; the caller closes it.
func (self *EvsLocalRepo) Objects(ctx context.Context) (*EvsLocalObjects, error) {
	process, err := self.git.Start(ctx, self.BareDir, "cat-file", "--batch")
	if err != nil {
		return nil, err
	}
	return &EvsLocalObjects{process: process, reader: bufio.NewReaderSize(process.Stdout, 64*1024)}, nil
}

// Ends the reader's process.
func (self *EvsLocalObjects) Close() error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.broken == nil {
		self.broken = fmt.Errorf("%w: the object reader is closed", ErrEvsGitFailed)
	}
	self.process.Close()
	return nil
}

// Asks for oid and reads the answer's header: its kind and size, or ErrEvsGitObjectMissing.
func (self *EvsLocalObjects) ask(oid EvsGitOid) (string, int64, error) {
	if self.broken != nil {
		return "", 0, self.broken
	}
	hexOid := hex.EncodeToString(oid[:])
	if _, err := io.WriteString(self.process.Stdin, hexOid+"\n"); err != nil {
		self.broken = fmt.Errorf("%w: cat-file took no request", ErrEvsGitFailed)
		return "", 0, self.broken
	}
	line, err := self.reader.ReadString('\n')
	if err != nil {
		self.broken = fmt.Errorf("%w: cat-file ended", ErrEvsGitFailed)
		return "", 0, self.broken
	}
	fields := strings.Fields(line)
	switch {
	case len(fields) == 2 && fields[0] == hexOid && fields[1] == "missing":
		return "", 0, ErrEvsGitObjectMissing
	case len(fields) != 3 || fields[0] != hexOid:
		self.broken = fmt.Errorf("%w: cat-file answered another object", ErrEvsGitFailed)
		return "", 0, self.broken
	}
	size, err := strconv.ParseInt(fields[2], 10, 64)
	if err != nil || size < 0 {
		self.broken = fmt.Errorf("%w: cat-file answered no size", ErrEvsGitFailed)
		return "", 0, self.broken
	}
	return fields[1], size, nil
}

// Reads an answer's size bytes into out and its closing newline, its hash held to oid.
func (self *EvsLocalObjects) body(oid EvsGitOid, kind string, size int64, out io.Writer) error {
	digest := sha1.New()
	fmt.Fprintf(digest, "%s %d\x00", kind, size)
	if _, err := io.CopyN(io.MultiWriter(out, digest), self.reader, size); err != nil {
		self.broken = fmt.Errorf("%w: cat-file's answer cut short", ErrEvsGitFailed)
		return self.broken
	}
	if end, err := self.reader.ReadByte(); err != nil || end != '\n' {
		self.broken = fmt.Errorf("%w: cat-file's answer not ended", ErrEvsGitFailed)
		return self.broken
	}
	if EvsGitOid(digest.Sum(nil)) != oid {
		return fmt.Errorf("%w: object %x is not its oid", ErrEvsGitObjectInvalid, oid[:])
	}
	return nil
}

// The object's kind and bytes: ErrEvsGitObjectMissing for one the repository does not hold. A blob is read whole,
// so a caller reading content uses CopyBlob.
func (self *EvsLocalObjects) ReadGitObject(ctx context.Context, oid EvsGitOid) (string, []byte, error) {
	if err := ctx.Err(); err != nil {
		return "", nil, err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	kind, size, err := self.ask(oid)
	if err != nil {
		return "", nil, err
	}
	// a size past what memory takes for one object is refused rather than grown to
	if evsLocalObjectMaxByteCount < size {
		if err := self.body(oid, kind, size, io.Discard); err != nil {
			return "", nil, err
		}
		return "", nil, fmt.Errorf("%w: object %x of %d bytes, read whole", ErrEvsGitObjectInvalid, oid[:], size)
	}
	writer := &evsByteAppender{bytes: make([]byte, 0, size)}
	if err := self.body(oid, kind, size, writer); err != nil {
		return "", nil, err
	}
	return kind, writer.bytes, nil
}

// The most of one object ReadGitObject holds in memory: a tree, commit or tag, at git's own sizes; a blob of any size
// streams through CopyBlob.
const evsLocalObjectMaxByteCount = 64 * 1024 * 1024

// Streams a blob to out, its oid checked once it is read, answering its size; out may hold the bytes of an object
// that then fails its check, which the caller drops.
func (self *EvsLocalObjects) CopyBlob(ctx context.Context, oid EvsGitOid, out io.Writer) (int64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	kind, size, err := self.ask(oid)
	if err != nil {
		return 0, err
	}
	if kind != evsGitBlobKind {
		if bodyErr := self.body(oid, kind, size, io.Discard); bodyErr != nil {
			return 0, bodyErr
		}
		return 0, fmt.Errorf("%w: object %x is a %s, not a blob", ErrEvsGitObjectInvalid, oid[:], kind)
	}
	return size, self.body(oid, kind, size, out)
}

// A writer appending to a slice.
type evsByteAppender struct {
	bytes []byte
}

// Appends p.
func (self *evsByteAppender) Write(p []byte) (int, error) {
	self.bytes = append(self.bytes, p...)
	return len(p), nil
}

// An object source whose trees are kept once read, bounded by byteCount: what a publish's many lookups in a few trees
// read through, each tree once.
type evsGitCachedTrees struct {
	source EvsGitObjectSource
	cache  *evsGitTreeCache
}

func newEvsGitCachedTrees(source EvsGitObjectSource, byteCount int64) *evsGitCachedTrees {
	return &evsGitCachedTrees{source: source, cache: newEvsGitTreeCache(byteCount)}
}

// The object's kind and bytes, a tree's from the cache when held.
func (self *evsGitCachedTrees) ReadGitObject(ctx context.Context, oid EvsGitOid) (string, []byte, error) {
	return self.source.ReadGitObject(ctx, oid)
}

// A tree's entries as git reads them, sorted by name bytes, nil for none: the empty tree's, or a tree absent here.
func evsGitSortedEntries(ctx context.Context, source EvsGitObjectSource, oid *EvsGitOid) ([]EvsGitRawEntry, error) {
	if oid == nil || *oid == EvsGitEmptyTreeOid {
		return nil, nil
	}
	cached, isCached := source.(*evsGitCachedTrees)
	if isCached {
		if entries, ok := cached.cache.get(*oid); ok {
			return entries, nil
		}
	}
	kind, encoded, err := source.ReadGitObject(ctx, *oid)
	if err != nil {
		return nil, fmt.Errorf("tree %x: %w", oid[:], err)
	}
	if kind != evsGitTreeKind {
		return nil, fmt.Errorf("%w: object %x is a %s, not a tree", ErrEvsGitObjectInvalid, oid[:], kind)
	}
	entries, err := EvsGitTreeRead(encoded)
	if err != nil {
		return nil, fmt.Errorf("tree %x: %w", oid[:], err)
	}
	slices.SortFunc(entries, func(a EvsGitRawEntry, b EvsGitRawEntry) int { return bytes.Compare(a.Name, b.Name) })
	if isCached {
		cached.cache.put(*oid, entries, len(encoded))
	}
	return entries, nil
}

// An entry's kind on evs: a directory, or a file, which a symlink and a gitlink are too.
func evsGitEntryKind(entry EvsGitRawEntry) protocol.EvsEntryKind {
	if entry.CanonMode == EvsGitModeDirectory {
		return protocol.EvsEntryKind_EVS_ENTRY_DIRECTORY
	}
	return protocol.EvsEntryKind_EVS_ENTRY_FILE
}

// The net change of a branch's path state from the tree stood to the tree next (DESIGN-DETAILS 8.2.4), by the tree
// reader: a file in next and not in stood, or of another mode or oid, written; a file in stood and not in next
// removed; a directory whose children's names or kinds differ given a delta, created with every child when it is new;
// a directory gone removed, with every path below it; a path whose kind changes created as its new kind over the old
// (8.2.2's kinds row), what stood below a replaced directory removed. The root takes a delta when a top-level name
// comes, goes or changes kind; stood nil is the empty tree. It descends only where oids differ.
func evsGitNetChange(ctx context.Context, source EvsGitObjectSource, stood *EvsGitOid, next EvsGitOid) ([]*EvsGitPathChange, error) {
	walk := &evsGitNetWalk{ctx: ctx, source: source}
	if stood != nil && *stood == next {
		return nil, nil
	}
	if err := walk.directory("", stood, &next, true); err != nil {
		return nil, err
	}
	return walk.changes, nil
}

// One net change's walk.
type evsGitNetWalk struct {
	ctx     context.Context
	source  EvsGitObjectSource
	changes []*EvsGitPathChange
}

// The children of a and b, both directories at path or either nil for none there: the directory's own change when its
// children differ (always for one created, which root says to emit even when it is the root), then each child's.
func (self *evsGitNetWalk) directory(path string, a *EvsGitOid, b *EvsGitOid, root bool) error {
	if err := self.ctx.Err(); err != nil {
		return err
	}
	aEntries, err := evsGitSortedEntries(self.ctx, self.source, a)
	if err != nil {
		return err
	}
	bEntries, err := evsGitSortedEntries(self.ctx, self.source, b)
	if err != nil {
		return err
	}
	if b != nil {
		change := &EvsGitPathChange{Path: path, Kind: protocol.EvsEntryKind_EVS_ENTRY_DIRECTORY}
		if a != nil {
			change.Stood = protocol.EvsEntryKind_EVS_ENTRY_DIRECTORY
		}
		for _, entry := range bEntries {
			change.Children = append(change.Children, &EvsGitChild{Name: entry.Name, Kind: evsGitEntryKind(entry)})
		}
		aKinds := map[string]protocol.EvsEntryKind{}
		for _, entry := range aEntries {
			aKinds[string(entry.Name)] = evsGitEntryKind(entry)
		}
		bNames := map[string]bool{}
		for _, entry := range bEntries {
			bNames[string(entry.Name)] = true
			if kind, ok := aKinds[string(entry.Name)]; !ok || kind != evsGitEntryKind(entry) {
				change.Added = append(change.Added, &EvsGitChild{Name: entry.Name, Kind: evsGitEntryKind(entry)})
			}
		}
		for _, entry := range aEntries {
			if !bNames[string(entry.Name)] {
				change.Removed = append(change.Removed, entry.Name)
			}
		}
		// a directory created holds its every child (one with none, an empty tree, is no path); one standing takes
		// a delta when a name comes, goes or changes kind; the root is read from evs, so it says both
		created := a == nil && 0 < len(bEntries)
		if root {
			created = len(change.Added) != 0 || len(change.Removed) != 0
		}
		if created || (a != nil && (len(change.Added) != 0 || len(change.Removed) != 0)) {
			if root {
				change.Stood = protocol.EvsEntryKind_EVS_ENTRY_KIND_UNSPECIFIED
			}
			self.changes = append(self.changes, change)
		}
	}
	for i, j := 0, 0; i < len(aEntries) || j < len(bEntries); {
		switch {
		case j == len(bEntries) || (i < len(aEntries) && bytes.Compare(aEntries[i].Name, bEntries[j].Name) < 0):
			if err := self.gone(evsGitJoin(path, aEntries[i].Name), aEntries[i]); err != nil {
				return err
			}
			i += 1
		case i == len(aEntries) || bytes.Compare(bEntries[j].Name, aEntries[i].Name) < 0:
			if err := self.come(evsGitJoin(path, bEntries[j].Name), bEntries[j], protocol.EvsEntryKind_EVS_ENTRY_KIND_UNSPECIFIED); err != nil {
				return err
			}
			j += 1
		default:
			if err := self.both(evsGitJoin(path, aEntries[i].Name), aEntries[i], bEntries[j]); err != nil {
				return err
			}
			i += 1
			j += 1
		}
	}
	return nil
}

// What stood at path and is gone: a file's removal, or a directory's with every path below it.
func (self *evsGitNetWalk) gone(path string, entry EvsGitRawEntry) error {
	if entry.CanonMode == EvsGitModeDirectory {
		self.changes = append(self.changes, &EvsGitPathChange{Path: path, Stood: protocol.EvsEntryKind_EVS_ENTRY_DIRECTORY})
		return self.directory(path, &entry.Oid, nil, false)
	}
	self.changes = append(self.changes, &EvsGitPathChange{Path: path, Stood: protocol.EvsEntryKind_EVS_ENTRY_FILE, StoodOid: entry.Oid})
	return nil
}

// What comes at path over stood, nothing or a path of the other kind: a file written, or a directory created with
// every path below it.
func (self *evsGitNetWalk) come(path string, entry EvsGitRawEntry, stood protocol.EvsEntryKind) error {
	if entry.CanonMode == EvsGitModeDirectory {
		before := len(self.changes)
		if err := self.directory(path, nil, &entry.Oid, false); err != nil {
			return err
		}
		if before < len(self.changes) && self.changes[before].Path == path {
			self.changes[before].Stood = stood
		}
		return nil
	}
	self.changes = append(self.changes, &EvsGitPathChange{
		Path: path, Stood: stood, Kind: protocol.EvsEntryKind_EVS_ENTRY_FILE, Mode: entry.CanonMode, Oid: entry.Oid,
	})
	return nil
}

// A name both trees hold: nothing when its canon mode and oid stand; a walk down two directories; a file written over
// a file; else the new kind created over the old, with what stood below a directory removed.
func (self *evsGitNetWalk) both(path string, a EvsGitRawEntry, b EvsGitRawEntry) error {
	aDirectory, bDirectory := a.CanonMode == EvsGitModeDirectory, b.CanonMode == EvsGitModeDirectory
	switch {
	case a.CanonMode == b.CanonMode && a.Oid == b.Oid:
		return nil
	case aDirectory && bDirectory:
		return self.directory(path, &a.Oid, &b.Oid, false)
	case !aDirectory && !bDirectory:
		self.changes = append(self.changes, &EvsGitPathChange{
			Path: path, Stood: protocol.EvsEntryKind_EVS_ENTRY_FILE, Kind: protocol.EvsEntryKind_EVS_ENTRY_FILE,
			Mode: b.CanonMode, Oid: b.Oid, StoodOid: a.Oid,
		})
		return nil
	case aDirectory:
		// a file over a directory: the file created, and every path below the directory removed by its own change
		if err := self.come(path, b, protocol.EvsEntryKind_EVS_ENTRY_DIRECTORY); err != nil {
			return err
		}
		return self.directory(path, &a.Oid, nil, false)
	default:
		// a directory over a file: the directory created with every child, which its paths' creations follow
		return self.come(path, b, protocol.EvsEntryKind_EVS_ENTRY_FILE)
	}
}

// The commit an object peels to and the annotated tags on the way, outermost first, each one's object the next one's
// oid: a commit peels to itself. A tag of a tree or a blob is refused (DESIGN-DETAILS 8.2.3's tags row), naming it.
func evsGitPeel(ctx context.Context, source EvsGitObjectSource, oid EvsGitOid) (EvsGitOid, [][]byte, error) {
	tags := [][]byte{}
	for {
		kind, object, err := source.ReadGitObject(ctx, oid)
		if err != nil {
			return EvsGitOid{}, nil, err
		}
		switch kind {
		case evsGitCommitKind:
			return oid, tags, nil
		case evsGitTagKind:
			tag, err := EvsGitTagDecode(object)
			if err != nil {
				return EvsGitOid{}, nil, fmt.Errorf("tag %x: %w", oid[:], err)
			}
			if tag.ObjectKind != evsGitTagKind && tag.ObjectKind != evsGitCommitKind {
				return EvsGitOid{}, nil, fmt.Errorf("%w: tag %x of a %s", ErrEvsGitUpdateInvalid, oid[:], tag.ObjectKind)
			}
			tags = append(tags, object)
			oid = tag.ObjectOid
		default:
			return EvsGitOid{}, nil, fmt.Errorf("%w: object %x is a %s, which no ref points at", ErrEvsGitUpdateInvalid, oid[:], kind)
		}
	}
}

// A commit's tree.
func evsGitTreeOf(ctx context.Context, source EvsGitObjectSource, commit EvsGitOid) (EvsGitOid, error) {
	kind, object, err := source.ReadGitObject(ctx, commit)
	if err != nil {
		return EvsGitOid{}, err
	}
	if kind != evsGitCommitKind {
		return EvsGitOid{}, fmt.Errorf("%w: object %x is a %s, not a commit", ErrEvsGitObjectInvalid, commit[:], kind)
	}
	tree, _, err := EvsGitCommitGraph(object)
	if err != nil {
		return EvsGitOid{}, fmt.Errorf("commit %x: %w", commit[:], err)
	}
	return tree, nil
}

// The file entry at names below tree, false when none stands there or what stands is a directory.
func evsGitFileAt(ctx context.Context, source EvsGitObjectSource, tree EvsGitOid, names [][]byte) (EvsGitRawEntry, bool, error) {
	at := tree
	for depth, name := range names {
		entries, err := evsGitSortedEntries(ctx, source, &at)
		if err != nil {
			return EvsGitRawEntry{}, false, err
		}
		index, found := slices.BinarySearchFunc(entries, name, func(entry EvsGitRawEntry, name []byte) int { return bytes.Compare(entry.Name, name) })
		if !found {
			return EvsGitRawEntry{}, false, nil
		}
		entry := entries[index]
		last := depth == len(names)-1
		switch {
		case last && entry.CanonMode != EvsGitModeDirectory:
			return entry, true, nil
		case last || entry.CanonMode != EvsGitModeDirectory:
			return EvsGitRawEntry{}, false, nil
		}
		at = entry.Oid
	}
	return EvsGitRawEntry{}, false, nil
}
