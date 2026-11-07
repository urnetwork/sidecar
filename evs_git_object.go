// Git's object forms, on every leg: the ids blobs, trees and commits hash to and the bytes they
// encode to, so head mode checks a file against its sealed oid and export rebuilds plain git with no
// git binary (§11.7, §11.11, §11.12). gitformat-pack and git's own fsck.c give the forms. mlsinterop's
// git_oracle_test.go holds these equal to go-git, and evs_git_test.go to stock git where a host has it.
//
// An object's oid covers its exact bytes, so nothing here normalizes. Names, idents and messages stay
// raw bytes, a decoder keeps every byte it reads, and it refuses what its encoder would not reproduce,
// which also leaves no reading of a commit that this code and git could take differently. A refusal
// names the fault and never the bytes, since an error may reach a log (I-13).
//
// Oids are SHA-1, 20 B: what go-git and a default repository use. The owner's answer to
// plan-EVS1-format-bytes#4 keeps v0 to SHA-1, head mode's codec and export included, so nothing here
// decodes a sha256 repository's 32 B ids: ur mount add, ur evs import and git-remote-ur are to refuse
// one before any evs write. Format 1's records keep a 32 B oid with its kind, so sha256 can come later
// with no format change.
// crypto/sha1 has no collision detection, which stock git's default build and go-git add, so a blob
// built to collide hashes here as plain SHA-1, where they would refuse or alter it. An oid is what
// keeps git compatible, and what binds a file's content is its AEAD and §11.6's SHA-256 chain.

package sidecar

import (
	"bytes"
	"cmp"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"slices"
	"strconv"
)

// Git's object kinds, as its object header spells them.
const (
	evsGitBlobKind   = "blob"
	evsGitTreeKind   = "tree"
	evsGitCommitKind = "commit"
)

// The modes a tree entry may hold: fsck.c's standard five, and the group-writable file early git
// wrote, which fsck still takes, so old history keeps its oids. A mode is written in octal with no
// leading zero. Anything else is refused.
const (
	EvsGitModeDirectory         uint32 = 0o40000
	EvsGitModeFile              uint32 = 0o100644
	EvsGitModeFileGroupWritable uint32 = 0o100664
	EvsGitModeExecutable        uint32 = 0o100755
	EvsGitModeSymlink           uint32 = 0o120000
	EvsGitModeGitlink           uint32 = 0o160000
)

// An object that does not hold git's form, or that could not be reproduced exactly from its fields.
var ErrEvsGitObjectInvalid = errors.New("git object invalid")

// A git object id.
type EvsGitOid [sha1.Size]byte

// Lowercase hex, as git prints an oid and as commits hold one.
func (self EvsGitOid) String() string {
	return hex.EncodeToString(self[:])
}

// An oid from the hex a commit holds.
func evsGitOidDecodeHex(text []byte) (EvsGitOid, error) {
	oid := EvsGitOid{}
	if len(text) != hex.EncodedLen(len(oid)) {
		return oid, fmt.Errorf("%w: an oid is not %d hex digits", ErrEvsGitObjectInvalid, hex.EncodedLen(len(oid)))
	}
	if _, err := hex.Decode(oid[:], text); err != nil {
		return EvsGitOid{}, fmt.Errorf("%w: an oid is not hex", ErrEvsGitObjectInvalid)
	}
	return oid, nil
}

// SHA-1 begun over git's object header, `<kind> <size>` and a NUL, ready for the content.
func newEvsGitObjectHash(kind string, size int64) hash.Hash {
	objectHash := sha1.New()
	objectHash.Write(fmt.Appendf(nil, "%s %d\x00", kind, size))
	return objectHash
}

// The oid of whole content of a kind.
func evsGitObjectOid(kind string, content []byte) EvsGitOid {
	objectHash := newEvsGitObjectHash(kind, int64(len(content)))
	objectHash.Write(content)
	return EvsGitOid(objectHash.Sum(nil))
}

// The running hash of a blob whose size is known before its bytes, so a reader checks a file's oid
// as the file streams past and never holds it (R-EVS-14). Not safe for concurrent use.
type evsGitBlobHash struct {
	objectHash hash.Hash
	// bytes the size still expects
	remainingSize int64
}

// Refuses a negative size.
func newEvsGitBlobHash(size int64) (*evsGitBlobHash, error) {
	if size < 0 {
		return nil, fmt.Errorf("%w: a blob's size is negative", ErrEvsGitObjectInvalid)
	}
	return &evsGitBlobHash{
		objectHash:    newEvsGitObjectHash(evsGitBlobKind, size),
		remainingSize: size,
	}, nil
}

// Takes the next bytes. Bytes past the size are refused, since the header already hashed says
// otherwise.
func (self *evsGitBlobHash) Write(content []byte) (int, error) {
	if self.remainingSize < int64(len(content)) {
		return 0, fmt.Errorf("%w: a blob runs past its size", ErrEvsGitObjectInvalid)
	}
	self.objectHash.Write(content)
	self.remainingSize -= int64(len(content))
	return len(content), nil
}

// Answers the oid once the size has been written, and refuses before that.
func (self *evsGitBlobHash) Oid() (EvsGitOid, error) {
	if self.remainingSize != 0 {
		return EvsGitOid{}, fmt.Errorf("%w: a blob stops short of its size", ErrEvsGitObjectInvalid)
	}
	return EvsGitOid(self.objectHash.Sum(nil)), nil
}

// The oid of a blob of size bytes, read to the end of content, which must hold exactly that many.
func EvsGitBlobOid(content io.Reader, size int64) (EvsGitOid, error) {
	blobHash, err := newEvsGitBlobHash(size)
	if err != nil {
		return EvsGitOid{}, err
	}
	if _, err := io.Copy(blobHash, content); err != nil {
		return EvsGitOid{}, err
	}
	return blobHash.Oid()
}

// One child of a tree.
type EvsGitTreeEntry struct {
	// One of the EvsGitMode values.
	Mode uint32
	// Raw bytes, never normalized (§11.6): any byte but NUL and a slash, and not empty.
	Name []byte
	Oid  EvsGitOid
}

// A directory's git form, which evs never stores: a reader rebuilds it from directory names and each
// child's sealed {mode, oid} (§11.6). This checks what git's format needs and no more: `..` and `.git`
// encode as they did in the history that held them, so what such a name means is for whoever
// materializes a tree.
type EvsGitTree struct {
	// In any order, since encoding sorts a copy.
	Entries []EvsGitTreeEntry
}

// The order git keeps a tree's entries in (read-cache.c's base_name_compare): bytewise, with a
// directory's name read as if it ended in a slash, so `a.txt` falls before the directory `a` and
// after the file `a`. A gitlink is not a directory here.
func evsGitTreeEntryCompare(a EvsGitTreeEntry, b EvsGitTreeEntry) int {
	common := min(len(a.Name), len(b.Name))
	if order := bytes.Compare(a.Name[:common], b.Name[:common]); order != 0 {
		return order
	}
	next := func(entry EvsGitTreeEntry) int {
		switch {
		case common < len(entry.Name):
			return int(entry.Name[common])
		case entry.Mode == EvsGitModeDirectory:
			return '/'
		default:
			return 0
		}
	}
	return cmp.Compare(next(a), next(b))
}

// The object's bytes, entries sorted. A name git's format cannot hold, a mode outside the six and a
// repeated name are refused. A repeat is any two entries of one name, whatever their modes, which
// sorting need not leave adjacent: the file `a`, then `a.txt`, then the directory `a`.
func (self *EvsGitTree) Encode() ([]byte, error) {
	names := make(map[string]bool, len(self.Entries))
	encodedSize := 0
	for _, entry := range self.Entries {
		switch entry.Mode {
		case EvsGitModeDirectory, EvsGitModeFile, EvsGitModeFileGroupWritable, EvsGitModeExecutable,
			EvsGitModeSymlink, EvsGitModeGitlink:
		default:
			return nil, fmt.Errorf("%w: a tree entry's mode is not one git writes", ErrEvsGitObjectInvalid)
		}
		if len(entry.Name) == 0 || bytes.ContainsAny(entry.Name, "/\x00") {
			return nil, fmt.Errorf("%w: a tree entry's name is empty or holds a NUL or slash", ErrEvsGitObjectInvalid)
		}
		if names[string(entry.Name)] {
			return nil, fmt.Errorf("%w: a tree repeats a name", ErrEvsGitObjectInvalid)
		}
		names[string(entry.Name)] = true
		// the mode's six digits, a space, the name, a NUL and the oid
		encodedSize += len(entry.Name) + len(entry.Oid) + 8
	}
	entries := slices.Clone(self.Entries)
	slices.SortFunc(entries, evsGitTreeEntryCompare)
	encoded := make([]byte, 0, encodedSize)
	for _, entry := range entries {
		encoded = strconv.AppendUint(encoded, uint64(entry.Mode), 8)
		encoded = append(encoded, ' ')
		encoded = append(encoded, entry.Name...)
		encoded = append(encoded, 0)
		encoded = append(encoded, entry.Oid[:]...)
	}
	return encoded, nil
}

// The oid the encoded tree hashes to.
func (self *EvsGitTree) Oid() (EvsGitOid, error) {
	encoded, err := self.Encode()
	if err != nil {
		return EvsGitOid{}, err
	}
	return evsGitObjectOid(evsGitTreeKind, encoded), nil
}

// A tree from its object's bytes, which it refuses unless Encode gives them back: entries out of git's
// order, a repeat, a zero-padded mode or a mode outside the six. fsck reports all of these, and a
// reader rebuilds a tree only from {mode, oid} and a name, so bytes that form could not reproduce
// could not keep their oid anyway. Each Name is a copy, so encoded may be reused.
func EvsGitTreeDecode(encoded []byte) (*EvsGitTree, error) {
	tree := &EvsGitTree{Entries: []EvsGitTreeEntry{}}
	for rest := encoded; 0 < len(rest); {
		mode, afterMode, found := bytes.Cut(rest, []byte{' '})
		if !found {
			return nil, fmt.Errorf("%w: a tree entry has no mode", ErrEvsGitObjectInvalid)
		}
		name, afterName, found := bytes.Cut(afterMode, []byte{0})
		if !found {
			return nil, fmt.Errorf("%w: a tree entry's name does not end", ErrEvsGitObjectInvalid)
		}
		entry := EvsGitTreeEntry{Name: bytes.Clone(name)}
		if len(afterName) < len(entry.Oid) {
			return nil, fmt.Errorf("%w: a tree entry's oid is cut short", ErrEvsGitObjectInvalid)
		}
		modeNumber, err := strconv.ParseUint(string(mode), 8, 32)
		if err != nil {
			return nil, fmt.Errorf("%w: a tree entry's mode is not octal", ErrEvsGitObjectInvalid)
		}
		entry.Mode = uint32(modeNumber)
		copy(entry.Oid[:], afterName)
		tree.Entries = append(tree.Entries, entry)
		rest = afterName[len(entry.Oid):]
	}
	reencoded, err := tree.Encode()
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(reencoded, encoded) {
		return nil, fmt.Errorf("%w: a tree is out of order or not in canonical form", ErrEvsGitObjectInvalid)
	}
	return tree, nil
}

// Who and when, as an author or committer header's value holds them: `name <email> seconds zone`.
// The grammar is fsck.c's fsck_ident. The strict reading of a commit's identity lives here, apart
// from EvsGitCommitDecode, because owner decision 81's committer check needs it on every new commit
// while an imported commit keeps an ident fsck refuses, and only its oid and parents matter.
type EvsGitIdent struct {
	// Raw bytes, free-form and possibly empty: no `<`, `>`, LF or NUL. Decoding keeps every byte, spaces
	// included.
	Name []byte
	// Raw bytes under the same rule, also possibly empty.
	Email []byte
	// Seconds since the epoch, never negative.
	TimeSeconds int64
	// `+hhmm` or `-hhmm`. Kept as text because git does, and `-0000` is not `+0000` to an oid.
	TimeZone string
}

// A header's value, refusing fields git could not read back.
func (self *EvsGitIdent) Encode() ([]byte, error) {
	if bytes.ContainsAny(self.Name, "<>\n\x00") || bytes.ContainsAny(self.Email, "<>\n\x00") {
		return nil, fmt.Errorf("%w: an ident's name or email holds a mark", ErrEvsGitObjectInvalid)
	}
	if self.TimeSeconds < 0 {
		return nil, fmt.Errorf("%w: an ident's time is negative", ErrEvsGitObjectInvalid)
	}
	timeZoneValid := func() bool {
		zone := self.TimeZone
		if len(zone) != 5 || zone[0] != '+' && zone[0] != '-' {
			return false
		}
		for _, digit := range []byte(zone[1:]) {
			if digit < '0' || '9' < digit {
				return false
			}
		}
		return true
	}
	if !timeZoneValid() {
		return nil, fmt.Errorf("%w: an ident's time zone is not +hhmm or -hhmm", ErrEvsGitObjectInvalid)
	}
	encoded := append(bytes.Clone(self.Name), " <"...)
	encoded = append(encoded, self.Email...)
	encoded = append(encoded, "> "...)
	encoded = strconv.AppendInt(encoded, self.TimeSeconds, 10)
	encoded = append(encoded, ' ')
	encoded = append(encoded, self.TimeZone...)
	return encoded, nil
}

// An ident from a header's value, which it refuses unless Encode gives it back. So no other reader of
// the value finds a different email in it: the only `<` and `>` it holds are the ones this read.
func EvsGitIdentDecode(encoded []byte) (*EvsGitIdent, error) {
	refused := fmt.Errorf("%w: an ident is not name <email> seconds zone", ErrEvsGitObjectInvalid)
	name, afterName, found := bytes.Cut(encoded, []byte(" <"))
	if !found {
		return nil, refused
	}
	email, afterEmail, found := bytes.Cut(afterName, []byte("> "))
	if !found {
		return nil, refused
	}
	seconds, zone, found := bytes.Cut(afterEmail, []byte{' '})
	if !found {
		return nil, refused
	}
	timeSeconds, err := strconv.ParseInt(string(seconds), 10, 64)
	if err != nil {
		return nil, refused
	}
	ident := &EvsGitIdent{
		Name:        bytes.Clone(name),
		Email:       bytes.Clone(email),
		TimeSeconds: timeSeconds,
		TimeZone:    string(zone),
	}
	reencoded, err := ident.Encode()
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(reencoded, encoded) {
		return nil, refused
	}
	return ident, nil
}

// A commit's fields. Commits travel sealed as their exact bytes (§11.6), so this is a view of those
// bytes for replay and the form export builds a new commit from: oids come from the bytes, and
// encoding a decoded commit reproduces them.
type EvsGitCommit struct {
	TreeOid    EvsGitOid
	ParentOids []EvsGitOid
	// A header's value: no LF or NUL, otherwise as read. EvsGitIdent's Encode gives a new commit its
	// value, and EvsGitIdentDecode reads one strictly.
	Author []byte
	// As Author.
	Committer []byte
	// Whatever headers follow the committer, encoding, gpgsig and mergetag among them, in their
	// exact bytes, each line with its LF and a continuation line with its leading space.
	ExtraHeaders []byte
	// The bytes end with the headers: no blank line, so no message, not even an empty one. git writes
	// the blank line before every message, but stock git stores a commit without one and fsck --strict
	// passes it ("not having a body is not a crime", fsck.c's verify_headers), so imported history can
	// hold one, and this keeps its oid. Message is empty when this is set.
	HeadersOnly bool
	// Everything after the blank line, as is.
	Message []byte
}

// The object's bytes. Refuses fields that would not read back as themselves: an ident with a line
// break or NUL, extra headers with a line that has no LF, a blank line, a NUL, a continuation with
// nothing to continue, or any of the headers a commit holds only at the top, and a message on a commit
// that ends with its headers. Further down, one of those top headers would be a second answer to who
// committed, and git and go-git would each settle it their own way.
func (self *EvsGitCommit) Encode() ([]byte, error) {
	for _, value := range [][]byte{self.Author, self.Committer} {
		if bytes.ContainsAny(value, "\n\x00") {
			return nil, fmt.Errorf("%w: a commit's ident holds a line break or NUL", ErrEvsGitObjectInvalid)
		}
	}
	if self.HeadersOnly && len(self.Message) != 0 {
		return nil, fmt.Errorf("%w: a commit that ends with its headers holds a message", ErrEvsGitObjectInvalid)
	}
	if bytes.IndexByte(self.ExtraHeaders, 0) != -1 {
		return nil, fmt.Errorf("%w: a commit's headers hold a NUL", ErrEvsGitObjectInvalid)
	}
	for first, rest := true, self.ExtraHeaders; 0 < len(rest); first = false {
		line, afterLine, found := bytes.Cut(rest, []byte{'\n'})
		if !found || len(line) == 0 {
			return nil, fmt.Errorf("%w: a commit's extra header is not a line", ErrEvsGitObjectInvalid)
		}
		if line[0] == ' ' && first {
			return nil, fmt.Errorf("%w: a commit's header continues nothing", ErrEvsGitObjectInvalid)
		}
		key, _, _ := bytes.Cut(line, []byte{' '})
		switch string(key) {
		case "tree", "parent", "author", "committer":
			return nil, fmt.Errorf("%w: a commit repeats a header", ErrEvsGitObjectInvalid)
		}
		rest = afterLine
	}
	encoded := fmt.Appendf(nil, "tree %s\n", self.TreeOid)
	for _, parentOid := range self.ParentOids {
		encoded = fmt.Appendf(encoded, "parent %s\n", parentOid)
	}
	encoded = fmt.Appendf(encoded, "author %s\ncommitter %s\n", self.Author, self.Committer)
	encoded = append(encoded, self.ExtraHeaders...)
	if !self.HeadersOnly {
		encoded = append(encoded, '\n')
		encoded = append(encoded, self.Message...)
	}
	return encoded, nil
}

// The oid the encoded commit hashes to.
func (self *EvsGitCommit) Oid() (EvsGitOid, error) {
	encoded, err := self.Encode()
	if err != nil {
		return EvsGitOid{}, err
	}
	return evsGitObjectOid(evsGitCommitKind, encoded), nil
}

// A commit from its object's bytes: a tree, its parents, exactly one author and one committer in
// that order, any extra headers, then a blank line and a message, or else the end, as in a commit
// with no body, which stock git and go-git both read. A second header of those kinds, however late,
// and a NUL before the message are refused, which is stricter than git and go-git, who read the first
// and drop the rest. Those are the commits that could show a reader one committer and git another. A
// last header with no LF is refused, as fsck refuses it. Fields are copies, so encoded may be reused.
//
// The idents are left as read, so history fsck refuses in its dates or names still replays: an
// importer's commit needs its oid and parents, and the committer check decodes the ident itself.
func EvsGitCommitDecode(encoded []byte) (*EvsGitCommit, error) {
	refused := func(what string) error {
		return fmt.Errorf("%w: %s", ErrEvsGitObjectInvalid, what)
	}
	rest := encoded
	// the next line if it opens with prefix, less both, and leaves rest alone if it does not
	takeHeader := func(prefix string) ([]byte, bool) {
		if !bytes.HasPrefix(rest, []byte(prefix)) {
			return nil, false
		}
		value, afterValue, found := bytes.Cut(rest[len(prefix):], []byte{'\n'})
		if !found {
			return nil, false
		}
		rest = afterValue
		return value, true
	}
	treeHex, found := takeHeader("tree ")
	if !found {
		return nil, refused("a commit does not open with its tree")
	}
	treeOid, err := evsGitOidDecodeHex(treeHex)
	if err != nil {
		return nil, err
	}
	commit := &EvsGitCommit{TreeOid: treeOid, ParentOids: []EvsGitOid{}}
	for {
		parentHex, found := takeHeader("parent ")
		if !found {
			break
		}
		parentOid, err := evsGitOidDecodeHex(parentHex)
		if err != nil {
			return nil, err
		}
		commit.ParentOids = append(commit.ParentOids, parentOid)
	}
	author, found := takeHeader("author ")
	if !found {
		return nil, refused("a commit has no author where git keeps it")
	}
	committer, found := takeHeader("committer ")
	if !found {
		return nil, refused("a commit has no committer where git keeps it")
	}
	commit.Author = bytes.Clone(author)
	commit.Committer = bytes.Clone(committer)

	// the blank line, and with it the extra headers: the first line that is empty, and with none the
	// headers run to the end, where Encode refuses a last line that has no LF
	endOfHeaders := len(rest)
	for offset := 0; offset < len(rest); {
		if rest[offset] == '\n' {
			endOfHeaders = offset
			break
		}
		lineSize := bytes.IndexByte(rest[offset:], '\n')
		if lineSize == -1 {
			break
		}
		offset += lineSize + 1
	}
	commit.ExtraHeaders = bytes.Clone(rest[:endOfHeaders])
	if endOfHeaders == len(rest) {
		commit.HeadersOnly = true
	} else {
		commit.Message = bytes.Clone(rest[endOfHeaders+1:])
	}

	reencoded, err := commit.Encode()
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(reencoded, encoded) {
		return nil, refused("a commit is not in canonical form")
	}
	return commit, nil
}
