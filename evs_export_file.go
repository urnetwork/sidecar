// Export's git side (§11.12's export row, §11.7's mode table): a plain bare repository written object by object as
// git's loose objects, with no git process, so what an export writes depends only on what it reads: no local time, map
// order or locale reaches a byte, and two exporters of one history give equal oids.
//
// A tree is rebuilt from a state, each path's raw names with its mode and blob oid, nested directories written
// first; a file-mode ref's version becomes one commit (§11.7's export column): tree the state at that version, parent
// the previous version's commit, author and committer the signer's client as <client_id>@ur.invalid with the push's
// time_ms in UTC, message "ur push <push_id hex>\n". An erased or expired entry's content renders as a stub blob
// naming its token path and entry hash, so the tree keeps the path (EVS1-M2-32's stub).
//
// On every leg; only a desktop host runs it. Not safe for concurrent use.

package sidecar

import (
	"bytes"
	"compress/zlib"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// The git modes export writes for a tree and the files it knows.
const (
	evsGitModeTree uint32 = 0o40000
)

// The email domain every evs committer has (owner decision 81).
const evsCommitterDomain = "@ur.invalid"

// An export that cannot finish: a path whose name no listing gives, a blob no push carries, or a target that holds a
// repository already.
var ErrEvsExport = errors.New("evs: export")

// One path of a state: its raw names, mode and blob.
type evsExportPath struct {
	names [][]byte
	mode  uint32
	oid   EvsGitOid
}

// A tree's state: every file path, by its names joined with a NUL, which no name holds.
type evsExportState map[string]*evsExportPath

// The state's key for names.
func evsExportKey(names [][]byte) string {
	return string(bytes.Join(names, []byte{0}))
}

// A copy that shares no map.
func (self evsExportState) clone() evsExportState {
	clone := evsExportState{}
	for key, path := range self {
		clone[key] = path
	}
	return clone
}

// Writes git's loose objects and refs into a bare repository.
type evsGitObjectWriter struct {
	dir     string
	written map[EvsGitOid]bool
}

// A new bare repository at dir, which must not hold one: HEAD naming main, an objects store and refs.
func newEvsGitObjectWriter(dir string) (*evsGitObjectWriter, error) {
	if _, err := os.Stat(filepath.Join(dir, "HEAD")); err == nil {
		return nil, fmt.Errorf("%w: the target holds a repository already", ErrEvsExport)
	}
	for _, sub := range []string{"objects", "refs/heads", "refs/tags", "refs/notes"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o755); err != nil {
			return nil, err
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "HEAD"), []byte("ref: refs/heads/main\n"), 0o644); err != nil {
		return nil, err
	}
	config := "[core]\n\trepositoryformatversion = 0\n\tbare = true\n"
	if err := os.WriteFile(filepath.Join(dir, "config"), []byte(config), 0o644); err != nil {
		return nil, err
	}
	return &evsGitObjectWriter{dir: dir, written: map[EvsGitOid]bool{}}, nil
}

// Writes an object of kind whose content is in memory, answering its oid.
func (self *evsGitObjectWriter) write(kind string, content []byte) (EvsGitOid, error) {
	return self.writeFrom(kind, bytes.NewReader(content), int64(len(content)))
}

// Writes an object of kind and size from content, streamed through zlib, answering its oid. An object already
// written is not written again.
func (self *evsGitObjectWriter) writeFrom(kind string, content io.Reader, size int64) (EvsGitOid, error) {
	temp, err := os.CreateTemp(filepath.Join(self.dir, "objects"), "tmp-")
	if err != nil {
		return EvsGitOid{}, err
	}
	defer os.Remove(temp.Name())
	defer temp.Close()
	compressor := zlib.NewWriter(temp)
	digest := sha1.New()
	header := fmt.Appendf(nil, "%s %d\x00", kind, size)
	digest.Write(header)
	compressor.Write(header)
	copied, err := io.Copy(io.MultiWriter(compressor, digest), content)
	if err != nil {
		return EvsGitOid{}, err
	}
	if copied != size {
		return EvsGitOid{}, fmt.Errorf("%w: an object of %d bytes where %d were promised", ErrEvsExport, copied, size)
	}
	if err := compressor.Close(); err != nil {
		return EvsGitOid{}, err
	}
	oid := EvsGitOid(digest.Sum(nil))
	if self.written[oid] {
		return oid, nil
	}
	hexOid := hex.EncodeToString(oid[:])
	objectDir := filepath.Join(self.dir, "objects", hexOid[:2])
	if err := os.MkdirAll(objectDir, 0o755); err != nil {
		return EvsGitOid{}, err
	}
	if err := temp.Close(); err != nil {
		return EvsGitOid{}, err
	}
	if err := os.Rename(temp.Name(), filepath.Join(objectDir, hexOid[2:])); err != nil {
		return EvsGitOid{}, err
	}
	self.written[oid] = true
	return oid, nil
}

// Whether an object is in the repository.
func (self *evsGitObjectWriter) has(oid EvsGitOid) bool {
	if self.written[oid] {
		return true
	}
	hexOid := hex.EncodeToString(oid[:])
	_, err := os.Stat(filepath.Join(self.dir, "objects", hexOid[:2], hexOid[2:]))
	return err == nil
}

// Points a ref, refs/heads/<b>, refs/tags/<t> or refs/notes/ur, at oid.
func (self *evsGitObjectWriter) setRef(gitRef string, oid EvsGitOid) error {
	if !strings.HasPrefix(gitRef, "refs/") || strings.Contains(gitRef, "..") {
		return fmt.Errorf("%w: a ref outside refs/", ErrEvsExport)
	}
	path := filepath.Join(self.dir, filepath.FromSlash(gitRef))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(hex.EncodeToString(oid[:])+"\n"), 0o644)
}

// Writes the trees of a state, nested directories first, and answers the root tree's oid. Every blob it names must
// be written already.
func (self *evsGitObjectWriter) writeTree(state evsExportState) (EvsGitOid, error) {
	type node struct {
		files    []EvsGitTreeEntry
		children map[string]*node
	}
	root := &node{children: map[string]*node{}}
	for _, path := range state {
		at := root
		for _, name := range path.names[:len(path.names)-1] {
			child := at.children[string(name)]
			if child == nil {
				child = &node{children: map[string]*node{}}
				at.children[string(name)] = child
			}
			at = child
		}
		if !self.has(path.oid) {
			return EvsGitOid{}, fmt.Errorf("%w: a tree naming a blob not written", ErrEvsExport)
		}
		at.files = append(at.files, EvsGitTreeEntry{Mode: path.mode, Name: path.names[len(path.names)-1], Oid: path.oid})
	}
	var write func(at *node) (EvsGitOid, error)
	write = func(at *node) (EvsGitOid, error) {
		tree := &EvsGitTree{Entries: slices.Clone(at.files)}
		names := []string{}
		for name := range at.children {
			names = append(names, name)
		}
		slices.Sort(names)
		for _, name := range names {
			oid, err := write(at.children[name])
			if err != nil {
				return EvsGitOid{}, err
			}
			tree.Entries = append(tree.Entries, EvsGitTreeEntry{Mode: evsGitModeTree, Name: []byte(name), Oid: oid})
		}
		encoded, err := tree.Encode()
		if err != nil {
			return EvsGitOid{}, err
		}
		return self.write("tree", encoded)
	}
	return write(root)
}

// A file-mode version's commit (§11.7): tree, the previous version's commit as parent, the signer's client as author
// and committer at the push's time in UTC, message "ur push <push_id hex>\n". Every field comes from the signed
// statement, so two exporters give one oid.
func evsFileModeCommit(tree EvsGitOid, parent *EvsGitOid, clientId Id, timeMs int64, pushId Id) ([]byte, error) {
	ident := &EvsGitIdent{
		Name:        []byte(clientId.String()),
		Email:       []byte(clientId.String() + evsCommitterDomain),
		TimeSeconds: max(0, timeMs/1000),
		TimeZone:    "+0000",
	}
	identBytes, err := ident.Encode()
	if err != nil {
		return nil, err
	}
	commit := &EvsGitCommit{
		TreeOid:   tree,
		Author:    identBytes,
		Committer: identBytes,
		Message:   []byte("ur push " + hex.EncodeToString(pushId[:]) + "\n"),
	}
	if parent != nil {
		commit.ParentOids = []EvsGitOid{*parent}
	}
	return commit.Encode()
}

// The stub an erased or expired entry's content exports as: its token path and its entry hash, so the path keeps its
// place and the stub says what it stands for.
func evsExportErasedStub(tokenPath EvsTokenPath, entrySha256 []byte) []byte {
	return []byte("ur-erased " + hex.EncodeToString(tokenPath.Bytes()) + " " + hex.EncodeToString(entrySha256) + "\n")
}
