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
	"context"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
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
