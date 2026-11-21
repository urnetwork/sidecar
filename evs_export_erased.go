//go:build !ios_extension

// Export's rewrite of a git-mode ref one of whose blobs a committed ERASE destroyed (QD-1156; §11.12's export and
// retention rows, D-EVS-22, DESIGN-DETAILS 8.5). The blob's original oid cannot be rebuilt by any means, so export
// gives up the original oids from the first commit holding it on, says where in refs/notes/ur, and keeps the rest of
// the ref's history, plain git of everything still readable, git fsck clean and alike from every exporter.
//
//	stub      a git-mode version's blob read as erased (ErrEvsErased, evs_read_erased.go) is file mode's erased stub,
//	          `ur-erased <token path hex> <entry hash hex>\n` (evs_export_file.go), one a blob: the token path and
//	          entry hash of the first entry version in the replay that carried it, which every exporter replays first.
//	          A blob the repository holds anyway, written from an entry still read, is no erased one and keeps its oid
//	originals the replay goes on in the original oids, so its checks, its tree builder and its sources read every
//	          original object by the oid its sealed commits name: an original the repository does not hold, a tree,
//	          commit or tag that was rewritten, is kept in a store of its own, a directory beside the export made at
//	          the first erased blob and removed when the export ends; an erased blob counts as held, so a commit
//	          naming it passes the check a commit naming a blob neither held nor carried does not
//	rewrite   a tree holding an erased blob, or a tree that was rewritten, is written to the repository with each such
//	          entry's oid replaced and every other byte its own, a raw tree's included; a commit whose tree or a
//	          parent was rewritten likewise, its tree and parent lines alone replaced, and a tag whose object was or is
//	          an erased blob. A commit before the first erased blob keeps its oid. A rewritten commit's signature, if it
//	          carries one, no longer verifies: the notes carry the push's signed provenance
//	notes     a rewritten commit's note names its original oid (`rewritten <oid hex>`), and the note of the push that
//	          wrote a stub names the stub's token path and entry hash (`erased <token path hex> <entry hash hex>`);
//	          a rewritten commit a push carried before its tip gets a note of its own, with the push's provenance
//	closed    a history blob a committed ERASE destroyed, which names no token path or entry hash for a stub, still
//	          ends the export with ErrEvsErased, as before QD-1156
//
// Export's alone: the local tier's sync engine replays over its own store with none of this, unchanged, since a mount
// must hold the tip's original oid to push on it (D-EVS-22's tip rule), and a git-mode rekey over an erased blob
// stays refused (evs_plan_erased.go). Not safe for concurrent use.

package sidecar

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
)

// One erased blob: the stub the repository holds for it, and the entry version whose token path and entry hash it
// names.
type evsGitErasedBlob struct {
	stub        EvsGitOid
	tokenPath   EvsTokenPath
	entrySha256 []byte
}

// One commit export rewrote: its original oid and the repository's.
type evsGitRewrittenCommit struct {
	original  EvsGitOid
	rewritten EvsGitOid
}

// Export's git-mode object store (an evsGitReplayStore): the repository, and the originals it does not hold. See the
// file header.
type evsGitExportStore struct {
	repository *evsGitObjectWriter
	// made at the first erased blob, nil before it
	originals    *evsGitObjectWriter
	originalsDir string
	// each erased blob by its original oid
	erased map[EvsGitOid]*evsGitErasedBlob
	// each tree, commit and tag rewritten, by its original oid: the oid the repository holds for it
	rewritten map[EvsGitOid]EvsGitOid
	// the push being applied: the note lines its stubs add, and the commits it rewrote, in order
	pushLines   []string
	pushCommits []*evsGitRewrittenCommit
}

// A store over the export's repository, holding nothing else until an erased blob.
func newEvsGitExportStore(repository *evsGitObjectWriter) *evsGitExportStore {
	return &evsGitExportStore{repository: repository, erased: map[EvsGitOid]*evsGitErasedBlob{}, rewritten: map[EvsGitOid]EvsGitOid{}}
}

// Removes the originals' directory, when one was made.
func (self *evsGitExportStore) close() error {
	if self.originalsDir == "" {
		return nil
	}
	err := os.RemoveAll(self.originalsDir)
	self.originals, self.originalsDir = nil, ""
	return err
}

// The oid the repository holds for an original object: its rewritten one, else its own.
func (self *evsGitExportStore) exported(oid EvsGitOid) EvsGitOid {
	if rewritten, ok := self.rewritten[oid]; ok {
		return rewritten
	}
	return oid
}

// Starts a push: what the last one left of its notes is dropped, as a refused version's is.
func (self *evsGitExportStore) beginPush() {
	self.pushLines, self.pushCommits = nil, nil
}

// The push's note lines and rewritten commits, taken.
func (self *evsGitExportStore) takePush() ([]string, []*evsGitRewrittenCommit) {
	lines, commits := self.pushLines, self.pushCommits
	self.beginPush()
	return lines, commits
}

// Takes oid as an erased blob, its entry change's: the first entry version that carried it names its stub. False
// where the repository holds the blob anyway, from an entry still read, so nothing of it is erased.
func (self *evsGitExportStore) erase(change *EvsCheckedChange, oid EvsGitOid) (bool, error) {
	if self.repository.has(oid) {
		return false, nil
	}
	if self.erased[oid] != nil {
		return true, nil
	}
	if self.originals == nil {
		// beside the repository, on its file system; never inside it, so nothing of it is left in the export
		dir, err := os.MkdirTemp(filepath.Dir(self.repository.dir), ".ur-export-originals-")
		if err != nil {
			return false, err
		}
		originals, err := newEvsGitObjectWriter(dir)
		if err != nil {
			os.RemoveAll(dir)
			return false, err
		}
		self.originals, self.originalsDir = originals, dir
	}
	stub, err := self.repository.write(evsGitBlobKind, evsExportErasedStub(change.TokenPath, change.Change.GetEntrySha256()))
	if err != nil {
		return false, err
	}
	self.erased[oid] = &evsGitErasedBlob{stub: stub, tokenPath: change.TokenPath, entrySha256: bytes.Clone(change.Change.GetEntrySha256())}
	self.pushLines = append(self.pushLines, fmt.Sprintf("erased %s %x", hex.EncodeToString(change.TokenPath.Bytes()), change.Change.GetEntrySha256()))
	return true, nil
}

// See EvsGitObjectSource: an original the repository does not hold from the originals, else the repository's.
func (self *evsGitExportStore) ReadGitObject(ctx context.Context, oid EvsGitOid) (string, []byte, error) {
	if self.originals != nil && self.originals.has(oid) {
		return self.originals.ReadGitObject(ctx, oid)
	}
	return self.repository.ReadGitObject(ctx, oid)
}

// See EvsGitObjectSink. A tree holding an erased blob or a rewritten tree goes to the originals, and its rewrite to
// the repository; the oid answered is always the original's.
func (self *evsGitExportStore) WriteGitObject(kind string, content []byte) (EvsGitOid, error) {
	if self.originals == nil || kind != evsGitTreeKind {
		return self.repository.write(kind, content)
	}
	rewritten, changed, err := self.rewriteTree(content)
	if err != nil {
		return EvsGitOid{}, err
	}
	if !changed {
		return self.repository.write(kind, content)
	}
	return self.writeRewritten(kind, content, rewritten)
}

// See EvsGitObjectSink: a blob streamed into the repository.
func (self *evsGitExportStore) WriteGitObjectFrom(kind string, content io.Reader, size int64) (EvsGitOid, error) {
	return self.repository.writeFrom(kind, content, size)
}

// See EvsGitObjectSink: the repository's objects, the originals, and each erased blob.
func (self *evsGitExportStore) HasGitObject(oid EvsGitOid) bool {
	return self.repository.has(oid) || (self.originals != nil && self.originals.has(oid)) || self.erased[oid] != nil
}

// Nothing: loose objects are readable once written.
func (self *evsGitExportStore) PendingGitObject(oid EvsGitOid) (string, []byte, bool) {
	return "", nil, false
}

// Nothing to flush: see PendingGitObject.
func (self *evsGitExportStore) Flush(ctx context.Context) error {
	return nil
}

// Writes original to the originals and its rewrite to the repository, answering the original's oid.
func (self *evsGitExportStore) writeRewritten(kind string, original []byte, rewritten []byte) (EvsGitOid, error) {
	originalOid, err := self.originals.write(kind, original)
	if err != nil {
		return EvsGitOid{}, err
	}
	rewrittenOid, err := self.repository.write(kind, rewritten)
	if err != nil {
		return EvsGitOid{}, err
	}
	self.rewritten[originalOid] = rewrittenOid
	return originalOid, nil
}

// A tree's bytes with each erased blob's oid replaced by its stub's and each rewritten tree's by its rewrite's, every
// other byte its own, and whether any was. A gitlink names a commit of another repository and is never replaced.
func (self *evsGitExportStore) rewriteTree(content []byte) ([]byte, bool, error) {
	var rewritten []byte
	for at := 0; at < len(content); {
		space := bytes.IndexByte(content[at:], ' ')
		if space <= 0 {
			return nil, false, fmt.Errorf("%w: a tree entry has no mode", ErrEvsGitObjectInvalid)
		}
		mode, err := strconv.ParseUint(string(content[at:at+space]), 8, 32)
		if err != nil {
			return nil, false, fmt.Errorf("%w: a tree entry's mode", ErrEvsGitObjectInvalid)
		}
		nul := bytes.IndexByte(content[at+space:], 0)
		if nul < 0 {
			return nil, false, fmt.Errorf("%w: a tree entry has no name's end", ErrEvsGitObjectInvalid)
		}
		oidAt := at + space + nul + 1
		if len(content) < oidAt+len(EvsGitOid{}) {
			return nil, false, fmt.Errorf("%w: a tree entry's oid is cut short", ErrEvsGitObjectInvalid)
		}
		oid := EvsGitOid(content[oidAt : oidAt+len(EvsGitOid{})])
		replacement, replaced := EvsGitOid{}, false
		switch EvsGitCanonMode(uint32(mode)) {
		case EvsGitModeDirectory:
			replacement, replaced = self.rewritten[oid]
		case EvsGitModeGitlink:
		default:
			if erased := self.erased[oid]; erased != nil && !self.repository.has(oid) {
				replacement, replaced = erased.stub, true
			}
		}
		if replaced {
			if rewritten == nil {
				rewritten = bytes.Clone(content)
			}
			copy(rewritten[oidAt:], replacement[:])
		}
		at = oidAt + len(EvsGitOid{})
	}
	return rewritten, rewritten != nil, nil
}

// What the repository holds for an original object a commit or tag names: a rewritten one's rewrite, an erased blob's
// stub; false for any other, which keeps its oid.
func (self *evsGitExportStore) replacement(oid EvsGitOid) (EvsGitOid, bool) {
	if rewritten, ok := self.rewritten[oid]; ok {
		return rewritten, true
	}
	if erased := self.erased[oid]; erased != nil && !self.repository.has(oid) {
		return erased.stub, true
	}
	return EvsGitOid{}, false
}

// Writes a carried commit: as it is where neither its tree nor any parent was rewritten, else rewritten, its original
// kept in the originals and the rewrite noted for the push.
func (self *evsGitExportStore) commit(commit *EvsGitCarriedCommit) error {
	object := commit.Sealed.GetObject()
	if self.originals == nil {
		_, err := self.repository.write(evsGitCommitKind, object)
		return err
	}
	rewritten, err := evsGitHeaderRewritten(object, self.replacement, "tree ", "parent ")
	if err != nil {
		return err
	}
	if bytes.Equal(rewritten, object) {
		_, err := self.repository.write(evsGitCommitKind, object)
		return err
	}
	original, err := self.writeRewritten(evsGitCommitKind, object, rewritten)
	if err != nil {
		return err
	}
	self.pushCommits = append(self.pushCommits, &evsGitRewrittenCommit{original: original, rewritten: self.rewritten[original]})
	return nil
}

// Writes a tag object, answering its original oid: rewritten where the object it names was, or is an erased blob.
func (self *evsGitExportStore) tag(object []byte) (EvsGitOid, error) {
	if self.originals == nil {
		return self.repository.write(evsGitTagKind, object)
	}
	rewritten, err := evsGitHeaderRewritten(object, self.replacement, "object ")
	if err != nil {
		return EvsGitOid{}, err
	}
	if bytes.Equal(rewritten, object) {
		return self.repository.write(evsGitTagKind, object)
	}
	return self.writeRewritten(evsGitTagKind, object, rewritten)
}

// A commit's or tag's bytes with the leading header lines of the given prefixes, `tree <hex>` and `parent <hex>` or
// `object <hex>`, naming an oid replace replaces, naming its replacement, every other byte its own: the headers after
// them, a signature's and a mergetag's included, and the message are not read.
func evsGitHeaderRewritten(object []byte, replace func(oid EvsGitOid) (EvsGitOid, bool), prefixes ...string) ([]byte, error) {
	rewritten := bytes.Clone(object)
	hexLength := hex.EncodedLen(len(EvsGitOid{}))
	for at := 0; at < len(object); {
		end := bytes.IndexByte(object[at:], '\n')
		if end < 0 {
			return nil, fmt.Errorf("%w: a header that does not end", ErrEvsGitObjectInvalid)
		}
		line := object[at : at+end]
		prefixed := ""
		for _, prefix := range prefixes {
			if bytes.HasPrefix(line, []byte(prefix)) {
				prefixed = prefix
			}
		}
		if prefixed == "" {
			break
		}
		hexOid := line[len(prefixed):]
		if len(hexOid) != hexLength {
			return nil, fmt.Errorf("%w: a %sline of no oid", ErrEvsGitObjectInvalid, prefixed)
		}
		var oid EvsGitOid
		if _, err := hex.Decode(oid[:], hexOid); err != nil {
			return nil, fmt.Errorf("%w: a %sline of no oid", ErrEvsGitObjectInvalid, prefixed)
		}
		if replacement, ok := replace(oid); ok {
			copy(rewritten[at+len(prefixed):], hex.EncodeToString(replacement[:]))
		}
		at += end + 1
	}
	return rewritten, nil
}
