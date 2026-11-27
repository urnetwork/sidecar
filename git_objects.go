//go:build !ios_extension && !sidecar_http

// The worktree's object database (DESIGN-COMPUTE §13.4's workspace row, D-GIT-1; GIT-M13-01): git's own loose objects
// under .git/objects/xx/, each zlib-deflated `<kind> <size>\0<content>` named by the SHA-1 of what it deflates, which
// stock git reads as its own. Packs appear only in transfer (§13.4), so the store writes none and reads none.
//
//	write    streamed through zlib into a temporary file in .git/objects, hashed as it goes, then renamed to its name
//	         once its oid is known; an object the store holds already is not written again. A blob is held to
//	         GitSettings.FileByteCount, a tree, commit or tag to ObjectByteCount, before a byte is written
//	read     the header held to ObjectHeaderByteCount and its kind's limit, exactly its size inflated and nothing after
//	         it, and its oid recomputed: a loose object that is not its oid, or holds trailing bytes, is refused, as
//	         git's unpack_loose_rest refuses one
//	codecs   a tree or commit the porcelain makes is written through the strict codecs (WriteTree, WriteCommit); a
//	         read of imported history is lenient, as export's is: ReadTree reads a tree as git does (EvsGitTreeRead)
//	         and ReadCommit falls back to the commit's tree and parents by git's rule (EvsGitCommitGraph)
//	promised a blob not fetched yet (GIT-M13-02's lazy blobs) is held by its promise: HasGitObject answers true for it,
//	         so a replay builds trees over it, and the first read fetches it through the promisor, held to its oid
//	         before it is written, tainting the run first where its push says so (git_promisor.go)
//
// It implements EvsGitObjectSource and EvsGitObjectSink, so export's replayer and the publish use it as they use
// export's repository or the local tier's.
//
// Safe for concurrent use as its file system is: two writers of one object both rename a whole copy into place.

package sidecar

import (
	"bufio"
	"bytes"
	"compress/zlib"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"path"
	"strconv"
	"strings"
)

// The directory the store keeps under .git.
const gitObjectsDirectory = ".git/objects"

// A loose object that does not read: not deflated, a header that is not git's, a size it does not hold, trailing
// bytes, or bytes that do not hash to its name.
var ErrGitObjectCorrupt = errors.New("git: a loose object that does not read as its oid")

// What a store asks about blobs it does not hold yet: GIT-M13-02's promisor, nil for a store that holds every object.
type gitPromisor interface {
	// Whether oid is a blob promised by a locator the store keeps.
	promised(oid EvsGitOid) bool
	// Fetches promised blobs into the store, each held to its oid before it is written, the run tainted first where
	// the push it comes from says so; one not promised is no error of this call's.
	fetch(ctx context.Context, store *GitObjectStore, oids []EvsGitOid) error
}

// The worktree's objects: see the file header.
type GitObjectStore struct {
	fileSystem GitFileSystem
	settings   *GitSettings
	promisor   gitPromisor
}

// A store over the objects of the worktree on fileSystem.
func newGitObjectStore(fileSystem GitFileSystem, settings *GitSettings) *GitObjectStore {
	return &GitObjectStore{fileSystem: fileSystem, settings: settings}
}

// Where an object's loose file lives.
func gitObjectName(oid EvsGitOid) string {
	hexOid := hex.EncodeToString(oid[:])
	return gitObjectsDirectory + "/" + hexOid[:2] + "/" + hexOid[2:]
}

// The most bytes an object of kind may hold.
func (self *GitObjectStore) kindLimit(kind string) int64 {
	if kind == evsGitBlobKind {
		return self.settings.FileByteCount
	}
	return self.settings.ObjectByteCount
}

// Whether the store holds oid as a loose object, not counting a promise.
func (self *GitObjectStore) Local(oid EvsGitOid) bool {
	_, err := self.fileSystem.Lstat(gitObjectName(oid))
	return err == nil
}

// Whether the store holds oid, as a loose object or by a promise (EvsGitObjectSink).
func (self *GitObjectStore) HasGitObject(oid EvsGitOid) bool {
	if self.Local(oid) {
		return true
	}
	return self.promisor != nil && self.promisor.promised(oid)
}

// Whether oid is promised and not held.
func (self *GitObjectStore) Promised(oid EvsGitOid) bool {
	return self.promisor != nil && !self.Local(oid) && self.promisor.promised(oid)
}

// Nothing: a loose object is readable once written (EvsGitObjectSink).
func (self *GitObjectStore) PendingGitObject(oid EvsGitOid) (string, []byte, bool) {
	return "", nil, false
}

// Nothing to flush: see PendingGitObject (EvsGitObjectSink).
func (self *GitObjectStore) Flush(ctx context.Context) error {
	return nil
}

// Writes an object whose bytes are in memory, answering its oid (EvsGitObjectSink).
func (self *GitObjectStore) WriteGitObject(kind string, content []byte) (EvsGitOid, error) {
	return self.WriteGitObjectFrom(kind, bytes.NewReader(content), int64(len(content)))
}

// Writes an object of size bytes from content: see the file header's write row (EvsGitObjectSink).
func (self *GitObjectStore) WriteGitObjectFrom(kind string, content io.Reader, size int64) (EvsGitOid, error) {
	switch kind {
	case evsGitBlobKind, evsGitTreeKind, evsGitCommitKind, evsGitTagKind:
	default:
		return EvsGitOid{}, fmt.Errorf("%w: an object of no kind git has", ErrEvsGitObjectInvalid)
	}
	if size < 0 || self.kindLimit(kind) < size {
		return EvsGitOid{}, fmt.Errorf("%w: a %s of %d bytes, past %d", ErrGitFileTooLarge, kind, size, self.kindLimit(kind))
	}
	if err := self.fileSystem.MkdirAll(gitObjectsDirectory, 0o755); err != nil {
		return EvsGitOid{}, err
	}
	temp, file, err := gitCreateTemp(self.fileSystem, gitObjectsDirectory, 0o644)
	if err != nil {
		return EvsGitOid{}, err
	}
	written := false
	defer func() {
		if !written {
			self.fileSystem.Remove(temp)
		}
	}()
	compressor, err := zlib.NewWriterLevel(file, zlib.BestSpeed)
	if err != nil {
		file.Close()
		return EvsGitOid{}, err
	}
	objectHash := newEvsGitObjectHash(kind, size)
	header := fmt.Appendf(nil, "%s %d\x00", kind, size)
	if _, err := compressor.Write(header); err != nil {
		file.Close()
		return EvsGitOid{}, err
	}
	copied, err := io.Copy(io.MultiWriter(compressor, objectHash), io.LimitReader(content, size+1))
	if err != nil {
		file.Close()
		return EvsGitOid{}, err
	}
	if copied != size {
		file.Close()
		return EvsGitOid{}, fmt.Errorf("%w: an object of %d bytes where %d were promised", ErrEvsGitObjectInvalid, copied, size)
	}
	if err := compressor.Close(); err != nil {
		file.Close()
		return EvsGitOid{}, err
	}
	if err := file.Close(); err != nil {
		return EvsGitOid{}, err
	}
	oid := EvsGitOid(objectHash.Sum(nil))
	if self.Local(oid) {
		return oid, nil
	}
	name := gitObjectName(oid)
	if err := self.fileSystem.MkdirAll(path.Dir(name), 0o755); err != nil {
		return EvsGitOid{}, err
	}
	if err := self.fileSystem.Rename(temp, name); err != nil {
		return EvsGitOid{}, err
	}
	written = true
	return oid, nil
}

// A loose object open to read, its content streamed and its oid checked at its end.
type gitObjectReader struct {
	file      io.Closer
	inflater  io.ReadCloser
	reader    *bufio.Reader
	remaining int64
	hash      hash.Hash
	oid       EvsGitOid
	failed    error
}

// Reads content; at its end, refuses trailing bytes and content that is not its oid, as ErrGitObjectCorrupt.
func (self *gitObjectReader) Read(p []byte) (int, error) {
	if self.failed != nil {
		return 0, self.failed
	}
	if self.remaining == 0 {
		if _, err := self.reader.ReadByte(); err != io.EOF {
			self.failed = fmt.Errorf("%w: bytes after its content", ErrGitObjectCorrupt)
			return 0, self.failed
		}
		if EvsGitOid(self.hash.Sum(nil)) != self.oid {
			self.failed = fmt.Errorf("%w: its content is not its oid", ErrGitObjectCorrupt)
			return 0, self.failed
		}
		self.failed = io.EOF
		return 0, io.EOF
	}
	if int64(len(p)) > self.remaining {
		p = p[:self.remaining]
	}
	n, err := self.reader.Read(p)
	self.hash.Write(p[:n])
	self.remaining -= int64(n)
	if err == io.EOF {
		if self.remaining != 0 {
			self.failed = fmt.Errorf("%w: its content stops short of its size", ErrGitObjectCorrupt)
			return n, self.failed
		}
		err = nil
	}
	if err != nil {
		self.failed = fmt.Errorf("%w: it does not inflate", ErrGitObjectCorrupt)
		return n, self.failed
	}
	return n, nil
}

func (self *gitObjectReader) Close() error {
	self.inflater.Close()
	return self.file.Close()
}

// The object's kind, its size and its content to read: see the file header's read row. A blob the store does not
// hold but holds a promise of is fetched first (GIT-M13-02); any other missing object is ErrEvsGitObjectMissing.
func (self *GitObjectStore) OpenGitObject(ctx context.Context, oid EvsGitOid) (string, int64, io.ReadCloser, error) {
	file, err := self.fileSystem.Open(gitObjectName(oid))
	if errors.Is(err, fs.ErrNotExist) && self.promisor != nil && self.promisor.promised(oid) {
		if err := self.promisor.fetch(ctx, self, []EvsGitOid{oid}); err != nil {
			return "", 0, nil, err
		}
		file, err = self.fileSystem.Open(gitObjectName(oid))
	}
	if errors.Is(err, fs.ErrNotExist) {
		return "", 0, nil, ErrEvsGitObjectMissing
	}
	if err != nil {
		return "", 0, nil, err
	}
	inflater, err := zlib.NewReader(file)
	if err != nil {
		file.Close()
		return "", 0, nil, fmt.Errorf("%w: it does not inflate", ErrGitObjectCorrupt)
	}
	reader := bufio.NewReader(inflater)
	header := make([]byte, 0, self.settings.ObjectHeaderByteCount)
	for {
		c, err := reader.ReadByte()
		if err != nil || len(header) == self.settings.ObjectHeaderByteCount {
			inflater.Close()
			file.Close()
			return "", 0, nil, fmt.Errorf("%w: a header that is not git's", ErrGitObjectCorrupt)
		}
		if c == 0 {
			break
		}
		header = append(header, c)
	}
	kind, sizeText, found := strings.Cut(string(header), " ")
	size, err := strconv.ParseInt(sizeText, 10, 64)
	refused := !found || err != nil || size < 0 || strconv.FormatInt(size, 10) != sizeText
	switch kind {
	case evsGitBlobKind, evsGitTreeKind, evsGitCommitKind, evsGitTagKind:
	default:
		refused = true
	}
	if refused {
		inflater.Close()
		file.Close()
		return "", 0, nil, fmt.Errorf("%w: a header that is not git's", ErrGitObjectCorrupt)
	}
	if self.kindLimit(kind) < size {
		inflater.Close()
		file.Close()
		return "", 0, nil, fmt.Errorf("%w: a %s of %d bytes, past %d", ErrGitFileTooLarge, kind, size, self.kindLimit(kind))
	}
	objectHash := newEvsGitObjectHash(kind, size)
	return kind, size, &gitObjectReader{file: file, inflater: inflater, reader: reader, remaining: size, hash: objectHash, oid: oid}, nil
}

// The object's kind and bytes, its oid checked (EvsGitObjectSource): ErrEvsGitObjectMissing for one neither held nor
// promised.
func (self *GitObjectStore) ReadGitObject(ctx context.Context, oid EvsGitOid) (string, []byte, error) {
	kind, size, reader, err := self.OpenGitObject(ctx, oid)
	if err != nil {
		return "", nil, err
	}
	defer reader.Close()
	content := make([]byte, 0, size)
	buffer := bytes.NewBuffer(content)
	if _, err := io.Copy(buffer, reader); err != nil {
		return "", nil, err
	}
	return kind, buffer.Bytes(), nil
}

// A tree's entries as git reads them (EvsGitTreeRead), whatever form its bytes hold.
func (self *GitObjectStore) ReadTree(ctx context.Context, oid EvsGitOid) ([]EvsGitRawEntry, error) {
	if oid == EvsGitEmptyTreeOid {
		return []EvsGitRawEntry{}, nil
	}
	kind, content, err := self.ReadGitObject(ctx, oid)
	if err != nil {
		return nil, err
	}
	if kind != evsGitTreeKind {
		return nil, fmt.Errorf("%w: a %s where a tree was named", ErrEvsGitObjectInvalid, kind)
	}
	return EvsGitTreeRead(content)
}

// A commit as the store reads it: its tree and parents always, and its fields where the strict codec reads it.
type GitCommitView struct {
	Oid        EvsGitOid
	TreeOid    EvsGitOid
	ParentOids []EvsGitOid
	// The commit by the strict codec, nil for imported history it refuses, which is read for its tree and parents
	// alone, by git's rule.
	Commit *EvsGitCommit
}

// A commit: strictly where it reads so, else by git's rule for its tree and parents.
func (self *GitObjectStore) ReadCommit(ctx context.Context, oid EvsGitOid) (*GitCommitView, error) {
	kind, content, err := self.ReadGitObject(ctx, oid)
	if err != nil {
		return nil, err
	}
	if kind != evsGitCommitKind {
		return nil, fmt.Errorf("%w: a %s where a commit was named", ErrEvsGitObjectInvalid, kind)
	}
	if commit, err := EvsGitCommitDecode(content); err == nil {
		return &GitCommitView{Oid: oid, TreeOid: commit.TreeOid, ParentOids: commit.ParentOids, Commit: commit}, nil
	}
	treeOid, parentOids, err := EvsGitCommitGraph(content)
	if err != nil {
		return nil, err
	}
	return &GitCommitView{Oid: oid, TreeOid: treeOid, ParentOids: parentOids}, nil
}

// Writes a tree the porcelain built, through the strict codec.
func (self *GitObjectStore) WriteTree(tree *EvsGitTree) (EvsGitOid, error) {
	encoded, err := tree.Encode()
	if err != nil {
		return EvsGitOid{}, err
	}
	return self.WriteGitObject(evsGitTreeKind, encoded)
}

// Writes a commit the porcelain built, through the strict codec, refused unless its bytes read back as themselves.
func (self *GitObjectStore) WriteCommit(commit *EvsGitCommit) (EvsGitOid, error) {
	encoded, err := commit.Encode()
	if err != nil {
		return EvsGitOid{}, err
	}
	if _, err := EvsGitCommitDecode(encoded); err != nil {
		return EvsGitOid{}, err
	}
	return self.WriteGitObject(evsGitCommitKind, encoded)
}

// Writes a blob of size bytes from content.
func (self *GitObjectStore) WriteBlob(content io.Reader, size int64) (EvsGitOid, error) {
	return self.WriteGitObjectFrom(evsGitBlobKind, content, size)
}

// Fetches the promised blobs among oids at once, as a checkout asks before it writes their paths; nothing for a store
// with no promisor or oids it holds.
func (self *GitObjectStore) FetchPromised(ctx context.Context, oids []EvsGitOid) error {
	if self.promisor == nil {
		return nil
	}
	wanted := []EvsGitOid{}
	for _, oid := range oids {
		if self.Promised(oid) {
			wanted = append(wanted, oid)
		}
	}
	if len(wanted) == 0 {
		return nil
	}
	return self.promisor.fetch(ctx, self, wanted)
}

// The SHA-1 of a blob's bytes as git hashes them.
func gitBlobOid(content []byte) EvsGitOid {
	return evsGitObjectOid(evsGitBlobKind, content)
}
