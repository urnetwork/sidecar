//go:build !sidecar_http && !js && !ios && !android && !sdk_mobile_bind

// R(c), the git-lfs objects a commit or tag c requires (§11.11's requires row; D-EVS-41; FS-73; EVS2-M10-26): each
// blob of c's tree, a tag peeled to its commit, at a path whose filter attribute under that tree's own .gitattributes
// files is lfs and whose bytes are a git-lfs v1 pointer, under LfsPointerMaxByteCount (1024, git-lfs's spec).
//
//	attributes   come from the tree, never the bare repository's state: a temporary git directory whose objects
//	             are the repository's by an alternate, its own index read from the tree, with no info/attributes,
//	             core.attributesFile an empty file and GIT_ATTR_NOSYSTEM set, asked with `check-attr --cached`.
//	             `git check-attr --source` is not used, since it needs git 2.40 and §22.9's matrix starts at 2.34
//	pointers     parsed by git-lfs's spec (docs/spec.md): `version`, any `ext-<digit>-<name>` lines, `oid
//	             sha256:<64 lowercase hex>` and `size <decimal>`, each `key value\n`, nothing else. Anything else is no
//	             pointer, a plain blob and never an error: a filter=lfs blob that is no pointer requires nothing, and
//	             neither does a stored pointer under no filter=lfs. Only regular files count, since git runs no
//	             filter on a symlink or a gitlink
//	the diff     R(new) less R(old) walks only the paths whose entries differ, descending only where tree oids
//	             differ, unless a .gitattributes file differs between old and new, which can bring an unchanged
//	             pointer under filter=lfs (FS-73), and then takes both trees whole. On the changed paths it is the
//	             pointers new names less those old names there; an object a changed path names that an unchanged
//	             path names too is kept, a superset, since finding it would read every unchanged path, and keeping
//	             it costs the tip check one head read
//
// A requirement carries one path that needs its object, the least by bytes, for the tip check's message. The path is
// the caller's own plaintext and goes into no log beside its oid (I-13).
//
// Desktop legs only, as the local tier is. Package-level functions are safe for concurrent use.

package sidecar

import (
	"bufio"
	"bytes"
	"cmp"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

// git-lfs's pointer versions (docs/spec.md): the public one, and the pre-release one git-lfs still reads.
var evsLfsPointerVersions = []string{
	"https://git-lfs.github.com/spec/v1",
	"https://hawser.github.com/spec/v1",
}

// A blob that is not a git-lfs pointer by the spec, or an oid that is no SHA-256.
var ErrEvsLfsPointerInvalid = errors.New("evs: not a git-lfs pointer")

// A git-lfs object's id: the SHA-256 of its content.
type EvsLfsOid [32]byte

// Lowercase hex, as git-lfs spells an oid.
func (self EvsLfsOid) String() string {
	return hex.EncodeToString(self[:])
}

// An oid from 64 lowercase hex digits, as a pointer and git-lfs's protocol spell it.
func EvsLfsOidDecodeHex(text string) (EvsLfsOid, error) {
	oid := EvsLfsOid{}
	if len(text) != hex.EncodedLen(len(oid)) || strings.ToLower(text) != text {
		return oid, fmt.Errorf("%w: an oid is 64 lowercase hex digits", ErrEvsLfsPointerInvalid)
	}
	if _, err := hex.Decode(oid[:], []byte(text)); err != nil {
		return EvsLfsOid{}, fmt.Errorf("%w: an oid is 64 lowercase hex digits", ErrEvsLfsPointerInvalid)
	}
	return oid, nil
}

// What a pointer names.
type EvsLfsPointer struct {
	Oid  EvsLfsOid
	Size int64
}

// The pointer data holds, by git-lfs's spec, false for anything else: see the file header. maxByteCount is the
// spec's bound, which data must be under.
func EvsLfsParsePointer(data []byte, maxByteCount int64) (EvsLfsPointer, bool) {
	if len(data) == 0 || maxByteCount <= int64(len(data)) || data[len(data)-1] != '\n' {
		return EvsLfsPointer{}, false
	}
	lines := strings.Split(string(data[:len(data)-1]), "\n")
	if len(lines) < 3 {
		return EvsLfsPointer{}, false
	}
	keyValue := func(line string) (string, string, bool) {
		key, value, found := strings.Cut(line, " ")
		if !found || key == "" || value == "" || strings.ContainsRune(value, '\r') {
			return "", "", false
		}
		for _, c := range key {
			if !('a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '.' || c == '-') {
				return "", "", false
			}
		}
		return key, value, true
	}
	key, version, ok := keyValue(lines[0])
	if !ok || key != "version" || !slices.Contains(evsLfsPointerVersions, version) {
		return EvsLfsPointer{}, false
	}
	// ext-<priority>-<name> sha256:<hex>, ascending, before oid and size: the keys after version are sorted
	previous := ""
	for _, line := range lines[1 : len(lines)-2] {
		key, value, ok := keyValue(line)
		if !ok || !evsLfsExtensionKey(key) || key <= previous {
			return EvsLfsPointer{}, false
		}
		hash, found := strings.CutPrefix(value, "sha256:")
		if !found {
			return EvsLfsPointer{}, false
		}
		if _, err := EvsLfsOidDecodeHex(hash); err != nil {
			return EvsLfsPointer{}, false
		}
		previous = key
	}
	key, oidValue, ok := keyValue(lines[len(lines)-2])
	if !ok || key != "oid" {
		return EvsLfsPointer{}, false
	}
	hash, found := strings.CutPrefix(oidValue, "sha256:")
	if !found {
		return EvsLfsPointer{}, false
	}
	oid, err := EvsLfsOidDecodeHex(hash)
	if err != nil {
		return EvsLfsPointer{}, false
	}
	key, sizeValue, ok := keyValue(lines[len(lines)-1])
	if !ok || key != "size" {
		return EvsLfsPointer{}, false
	}
	for _, c := range sizeValue {
		if c < '0' || '9' < c {
			return EvsLfsPointer{}, false
		}
	}
	size, err := strconv.ParseInt(sizeValue, 10, 64)
	if err != nil {
		return EvsLfsPointer{}, false
	}
	return EvsLfsPointer{Oid: oid, Size: size}, true
}

// Whether key is a pointer extension's: ext-<one digit>-<word characters>.
func evsLfsExtensionKey(key string) bool {
	rest, found := strings.CutPrefix(key, "ext-")
	if !found || len(rest) < 3 || rest[0] < '0' || '9' < rest[0] || rest[1] != '-' {
		return false
	}
	for _, c := range rest[2:] {
		if !('a' <= c && c <= 'z' || '0' <= c && c <= '9') {
			return false
		}
	}
	return true
}

// One object a commit requires, and one path of its tree that needs it.
type EvsLfsRequirement struct {
	Oid  EvsLfsOid
	Size int64
	// the least path by bytes whose pointer names it; plaintext, never logged with the oid (I-13)
	Path string
}

// The repository R reads: a mount's bare repository by the system git, with a hook's quarantine variables where it
// runs inside one.
type EvsLfsGitRepo struct {
	Git *EvsGitRunner
	// The repository, absolute.
	Dir string
	// Variables beside the runner's clean environment: a hook's quarantine, nil outside one. Never a credential.
	Env      []string
	Settings *EvsSettings

	// Each path whose attributes are asked and each blob read, for tests; nil for none.
	judged func(path string)
}

// R(c) for c a commit or an annotated tag of one: see the file header. Sorted by oid.
func EvsLfsRequired(ctx context.Context, repo *EvsLfsGitRepo, c EvsGitOid) ([]*EvsLfsRequirement, error) {
	run, err := repo.open(ctx)
	if err != nil {
		return nil, err
	}
	defer run.close()
	required, err := run.whole(ctx, c)
	if err != nil {
		return nil, err
	}
	return evsLfsSorted(required), nil
}

// R(new) less R(old), old nil for none (a new ref, or the first push after a DELETE): see the file header. Sorted by
// oid.
func EvsLfsRequiredDiff(ctx context.Context, repo *EvsLfsGitRepo, old *EvsGitOid, new EvsGitOid) ([]*EvsLfsRequirement, error) {
	run, err := repo.open(ctx)
	if err != nil {
		return nil, err
	}
	defer run.close()
	if old == nil {
		required, err := run.whole(ctx, new)
		if err != nil {
			return nil, err
		}
		return evsLfsSorted(required), nil
	}
	oldTree, err := run.treeOf(ctx, *old)
	if err != nil {
		return nil, err
	}
	newTree, err := run.treeOf(ctx, new)
	if err != nil {
		return nil, err
	}
	if oldTree == newTree {
		return nil, nil
	}
	walk := &evsLfsDiffWalk{ctx: ctx, objects: run.objects, attributes: map[string]EvsGitRawEntry{}}
	if err := walk.directory("", &oldTree, &newTree); err != nil {
		return nil, err
	}
	var gained, lost map[EvsLfsOid]*EvsLfsRequirement
	if walk.attributesDiffer {
		// a .gitattributes file differs: both trees whole, since an unchanged pointer may now be required
		if gained, err = run.wholeTree(ctx, newTree); err != nil {
			return nil, err
		}
		if lost, err = run.wholeTree(ctx, oldTree); err != nil {
			return nil, err
		}
	} else {
		// the attributes stand, so one index of new's .gitattributes judges both sides' changed paths
		index, err := run.indexOfEntries(ctx, walk.attributes)
		if err != nil {
			return nil, err
		}
		gainedCandidates, err := run.small(walk.gained)
		if err != nil {
			return nil, err
		}
		lostCandidates, err := run.small(walk.lost)
		if err != nil {
			return nil, err
		}
		if gained, err = run.pointers(ctx, index, gainedCandidates); err != nil {
			return nil, err
		}
		if lost, err = run.pointers(ctx, index, lostCandidates); err != nil {
			return nil, err
		}
	}
	for oid := range lost {
		delete(gained, oid)
	}
	return evsLfsSorted(gained), nil
}

// The requirements by oid.
func evsLfsSorted(required map[EvsLfsOid]*EvsLfsRequirement) []*EvsLfsRequirement {
	sorted := make([]*EvsLfsRequirement, 0, len(required))
	for _, requirement := range required {
		sorted = append(sorted, requirement)
	}
	slices.SortFunc(sorted, func(a *EvsLfsRequirement, b *EvsLfsRequirement) int { return bytes.Compare(a.Oid[:], b.Oid[:]) })
	return sorted
}

// One computation of R: the repository's object readers and a temporary git directory for attributes.
type evsLfsRun struct {
	repo    *EvsLfsGitRepo
	objects *evsLocalHookObjects
	// the temporary git directory's parent, removed by close
	scratch string
	indexes int
}

// Opens the readers and the scratch directory, inside the repository so plaintext paths stay where its objects are.
func (self *EvsLfsGitRepo) open(ctx context.Context) (*evsLfsRun, error) {
	if self.Git == nil || self.Settings == nil || !filepath.IsAbs(self.Dir) {
		return nil, fmt.Errorf("%w: R needs a runner, settings and an absolute repository", errInvalidSettings)
	}
	mount := &EvsLocalRepo{BareDir: self.Dir, git: self.Git}
	objects, err := mount.objectsWith(ctx, self.Env)
	if err != nil {
		return nil, err
	}
	scratch, err := os.MkdirTemp(self.Dir, "ur-lfs-attributes-")
	if err != nil {
		objects.Close()
		return nil, err
	}
	gitDir := filepath.Join(scratch, "git")
	objectsDir := filepath.Join(self.Dir, "objects")
	for _, directory := range []string{filepath.Join(gitDir, "objects", "info"), filepath.Join(gitDir, "refs")} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			objects.Close()
			os.RemoveAll(scratch)
			return nil, err
		}
	}
	files := map[string]string{
		filepath.Join(gitDir, "HEAD"):                          "ref: refs/heads/main\n",
		filepath.Join(gitDir, "objects", "info", "alternates"): objectsDir + "\n",
		filepath.Join(scratch, "attributes"):                   "",
	}
	for name, content := range files {
		if err := os.WriteFile(name, []byte(content), 0o600); err != nil {
			objects.Close()
			os.RemoveAll(scratch)
			return nil, err
		}
	}
	return &evsLfsRun{repo: self, objects: objects, scratch: scratch}, nil
}

// Ends the readers and removes the scratch directory.
func (self *evsLfsRun) close() {
	self.objects.Close()
	os.RemoveAll(self.scratch)
}

// The tree c peels to: a commit's, or that of the commit an annotated tag names.
func (self *evsLfsRun) treeOf(ctx context.Context, c EvsGitOid) (EvsGitOid, error) {
	commit, _, err := evsGitPeel(ctx, self.objects, c)
	if err != nil {
		return EvsGitOid{}, err
	}
	return evsGitTreeOf(ctx, self.objects, commit)
}

// R(c) by c's whole tree.
func (self *evsLfsRun) whole(ctx context.Context, c EvsGitOid) (map[EvsLfsOid]*EvsLfsRequirement, error) {
	tree, err := self.treeOf(ctx, c)
	if err != nil {
		return nil, err
	}
	return self.wholeTree(ctx, tree)
}

// One path that may hold a pointer: a file's blob, judged by its mode and size before its attributes are asked.
type evsLfsCandidate struct {
	path string
	mode uint32
	oid  EvsGitOid
}

// The candidates among entries that may point: regular files whose blobs are under the pointer bound, each sized by
// batch-check, so no larger blob is read.
func (self *evsLfsRun) small(entries []*evsLfsCandidate) ([]*evsLfsCandidate, error) {
	kept := []*evsLfsCandidate{}
	for _, entry := range entries {
		if !evsLfsMayPoint(entry.mode, 1, self.repo.Settings) {
			continue
		}
		size, err := self.objects.size(entry.oid)
		if err != nil {
			return nil, fmt.Errorf("blob %s: %w", entry.oid, err)
		}
		if evsLfsMayPoint(entry.mode, size, self.repo.Settings) {
			kept = append(kept, entry)
		}
	}
	return kept, nil
}

// R of a tree, every path judged: ls-tree lists each blob with its size, streamed, keeping only small regular files;
// the index is the tree read whole.
func (self *evsLfsRun) wholeTree(ctx context.Context, tree EvsGitOid) (map[EvsLfsOid]*EvsLfsRequirement, error) {
	if tree == EvsGitEmptyTreeOid {
		return map[EvsLfsOid]*EvsLfsRequirement{}, nil
	}
	process, err := self.repo.Git.StartWith(ctx, self.repo.Dir, self.repo.Env, "ls-tree", "-r", "-z", "-l", "--full-tree", tree.String())
	if err != nil {
		return nil, err
	}
	candidates, err := self.listCandidates(process.Stdout)
	if err != nil {
		process.Close()
		return nil, err
	}
	// every record read, the exit status says whether they were all
	process.Stdin.Close()
	waitErr := process.command.Wait()
	process.cancel()
	if waitErr != nil {
		return nil, fmt.Errorf("%w: ls-tree of %s", ErrEvsGitFailed, tree)
	}
	index, err := self.newIndex()
	if err != nil {
		return nil, err
	}
	if _, err := self.git(ctx, index, nil, "read-tree", tree.String()); err != nil {
		return nil, err
	}
	return self.pointers(ctx, index, candidates)
}

// Reads ls-tree -r -z -l's records: "<mode> <kind> <oid> <size padded>\t<path>\0", keeping small regular blobs.
func (self *evsLfsRun) listCandidates(out io.Reader) ([]*evsLfsCandidate, error) {
	reader := bufio.NewReaderSize(out, 64*1024)
	candidates := []*evsLfsCandidate{}
	for {
		record, err := reader.ReadBytes(0)
		if err == io.EOF && len(record) == 0 {
			return candidates, nil
		}
		if err != nil {
			return nil, fmt.Errorf("%w: ls-tree's output cut short", ErrEvsGitFailed)
		}
		record = record[:len(record)-1]
		meta, path, found := bytes.Cut(record, []byte{'\t'})
		fields := strings.Fields(string(meta))
		if !found || len(fields) != 4 || len(path) == 0 {
			return nil, fmt.Errorf("%w: ls-tree answered a record it should not", ErrEvsGitFailed)
		}
		if fields[1] != evsGitBlobKind {
			continue
		}
		mode, err := strconv.ParseUint(fields[0], 8, 32)
		if err != nil {
			return nil, fmt.Errorf("%w: ls-tree answered no mode", ErrEvsGitFailed)
		}
		size, err := strconv.ParseInt(fields[3], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("%w: ls-tree answered no size", ErrEvsGitFailed)
		}
		if !evsLfsMayPoint(uint32(mode), size, self.repo.Settings) {
			continue
		}
		oid, err := evsGitOidDecodeHex([]byte(fields[2]))
		if err != nil {
			return nil, fmt.Errorf("%w: ls-tree answered no oid", ErrEvsGitFailed)
		}
		candidates = append(candidates, &evsLfsCandidate{path: string(path), mode: uint32(mode), oid: oid})
	}
}

// Whether a blob of mode and size may be a pointer: a regular file, not empty, under the spec's bound.
func evsLfsMayPoint(mode uint32, size int64, settings *EvsSettings) bool {
	switch EvsGitCanonMode(mode) {
	case EvsGitModeFile, EvsGitModeExecutable, EvsGitModeFileGroupWritable:
		return 0 < size && size < settings.LfsPointerMaxByteCount
	}
	return false
}

// A new index file's path in the scratch directory.
func (self *evsLfsRun) newIndex() (string, error) {
	self.indexes += 1
	return filepath.Join(self.scratch, fmt.Sprintf("index-%d", self.indexes)), nil
}

// Runs git on the scratch git directory with index as its index: the repository's objects by the alternate, or by a
// hook's quarantine variables, and no attributes but the index's.
func (self *evsLfsRun) git(ctx context.Context, index string, input io.Reader, args ...string) ([]byte, error) {
	env := append([]string{
		"GIT_DIR=" + filepath.Join(self.scratch, "git"),
		"GIT_INDEX_FILE=" + index,
		"GIT_ATTR_NOSYSTEM=1",
	}, self.repo.Env...)
	full := append([]string{"-c", "core.attributesFile=" + filepath.Join(self.scratch, "attributes")}, args...)
	return self.repo.Git.RunWith(ctx, &EvsGitRunArgs{Dir: self.scratch, Args: full, Input: input, Env: env})
}

// An index holding only the given .gitattributes entries, by path: what check-attr --cached reads for every path
// below them.
func (self *evsLfsRun) indexOfEntries(ctx context.Context, attributes map[string]EvsGitRawEntry) (string, error) {
	index, err := self.newIndex()
	if err != nil {
		return "", err
	}
	paths := make([]string, 0, len(attributes))
	for path := range attributes {
		paths = append(paths, path)
	}
	slices.Sort(paths)
	info := &bytes.Buffer{}
	for _, path := range paths {
		entry := attributes[path]
		fmt.Fprintf(info, "%o %s %s\t%s\x00", EvsGitCanonMode(entry.Mode), evsGitBlobKind, entry.Oid, path)
	}
	if _, err := self.git(ctx, index, info, "update-index", "-z", "--index-info"); err != nil {
		return "", err
	}
	return index, nil
}

// The pointers among candidates whose filter attribute in index is lfs, by oid, each with its least path.
func (self *evsLfsRun) pointers(ctx context.Context, index string, candidates []*evsLfsCandidate) (map[EvsLfsOid]*EvsLfsRequirement, error) {
	required := map[EvsLfsOid]*EvsLfsRequirement{}
	if len(candidates) == 0 {
		return required, nil
	}
	input := &bytes.Buffer{}
	for _, candidate := range candidates {
		if self.repo.judged != nil {
			self.repo.judged(candidate.path)
		}
		input.WriteString(candidate.path)
		input.WriteByte(0)
	}
	out, err := self.git(ctx, index, input, "check-attr", "--cached", "-z", "--stdin", "filter")
	if err != nil {
		return nil, err
	}
	// "<path>\0filter\0<value>\0" per path, in the input's order
	fields := bytes.Split(out, []byte{0})
	if len(fields) != 3*len(candidates)+1 || len(fields[len(fields)-1]) != 0 {
		return nil, fmt.Errorf("%w: check-attr answered %d fields for %d paths", ErrEvsGitFailed, len(fields)-1, len(candidates))
	}
	read := map[EvsGitOid]*EvsLfsPointer{}
	for i, candidate := range candidates {
		path, attribute, value := fields[3*i], fields[3*i+1], fields[3*i+2]
		if string(path) != candidate.path || string(attribute) != "filter" {
			return nil, fmt.Errorf("%w: check-attr answered another path", ErrEvsGitFailed)
		}
		if string(value) != "lfs" {
			continue
		}
		pointer, isRead := read[candidate.oid]
		if !isRead {
			kind, blob, err := self.objects.ReadGitObject(ctx, candidate.oid)
			if err != nil {
				return nil, err
			}
			if kind != evsGitBlobKind {
				return nil, fmt.Errorf("%w: object %s is a %s, not a blob", ErrEvsGitObjectInvalid, candidate.oid, kind)
			}
			if parsed, ok := EvsLfsParsePointer(blob, self.repo.Settings.LfsPointerMaxByteCount); ok {
				pointer = &parsed
			}
			read[candidate.oid] = pointer
		}
		if pointer == nil {
			continue
		}
		if standing, ok := required[pointer.Oid]; !ok || cmp.Less(candidate.path, standing.Path) {
			required[pointer.Oid] = &EvsLfsRequirement{Oid: pointer.Oid, Size: pointer.Size, Path: candidate.path}
		}
	}
	return required, nil
}

// One diff's walk of two trees: the small regular files that differ on each side, new's .gitattributes entries in
// every directory it read, and whether any .gitattributes differs.
type evsLfsDiffWalk struct {
	ctx     context.Context
	objects *evsLocalHookObjects
	// files new holds that old does not hold alike, and those old held that new does not, each a possible pointer
	gained []*evsLfsCandidate
	lost   []*evsLfsCandidate
	// new's .gitattributes by path, in every directory the walk read: each ancestor of every changed path
	attributes       map[string]EvsGitRawEntry
	attributesDiffer bool
}

// The name of the file attributes are read from in each directory.
var evsLfsAttributesName = []byte(".gitattributes")

// The children of a and b, both trees at path or either nil for none there, descending only where oids differ.
func (self *evsLfsDiffWalk) directory(path string, a *EvsGitOid, b *EvsGitOid) error {
	if err := self.ctx.Err(); err != nil {
		return err
	}
	aEntries, err := evsGitSortedEntries(self.ctx, self.objects, a)
	if err != nil {
		return err
	}
	bEntries, err := evsGitSortedEntries(self.ctx, self.objects, b)
	if err != nil {
		return err
	}
	for i, j := 0, 0; i < len(aEntries) || j < len(bEntries); {
		switch {
		case j == len(bEntries) || (i < len(aEntries) && bytes.Compare(aEntries[i].Name, bEntries[j].Name) < 0):
			if err := self.side(evsGitJoin(path, aEntries[i].Name), aEntries[i], false); err != nil {
				return err
			}
			i += 1
		case i == len(aEntries) || bytes.Compare(bEntries[j].Name, aEntries[i].Name) < 0:
			if err := self.side(evsGitJoin(path, bEntries[j].Name), bEntries[j], true); err != nil {
				return err
			}
			j += 1
		default:
			child := evsGitJoin(path, aEntries[i].Name)
			if aEntries[i].CanonMode != bEntries[j].CanonMode || aEntries[i].Oid != bEntries[j].Oid {
				aDirectory, bDirectory := aEntries[i].CanonMode == EvsGitModeDirectory, bEntries[j].CanonMode == EvsGitModeDirectory
				if aDirectory && bDirectory {
					if err := self.directory(child, &aEntries[i].Oid, &bEntries[j].Oid); err != nil {
						return err
					}
				} else {
					if err := self.side(child, aEntries[i], false); err != nil {
						return err
					}
					if err := self.side(child, bEntries[j], true); err != nil {
						return err
					}
				}
			} else if b != nil && bytes.Equal(bEntries[j].Name, evsLfsAttributesName) {
				self.attributes[child] = bEntries[j]
			}
			i += 1
			j += 1
		}
	}
	return nil
}

// An entry one side holds that the other does not hold alike: a .gitattributes marks the attributes changed, a tree
// is walked whole on its side, and a file is noted for its side.
func (self *evsLfsDiffWalk) side(path string, entry EvsGitRawEntry, isNew bool) error {
	if entry.CanonMode == EvsGitModeDirectory {
		if isNew {
			return self.directory(path, nil, &entry.Oid)
		}
		return self.directory(path, &entry.Oid, nil)
	}
	if bytes.Equal(evsLfsBaseName(path), evsLfsAttributesName) {
		self.attributesDiffer = true
		if isNew {
			self.attributes[path] = entry
		}
		return nil
	}
	candidate := &evsLfsCandidate{path: path, mode: entry.Mode, oid: entry.Oid}
	if isNew {
		self.gained = append(self.gained, candidate)
	} else {
		self.lost = append(self.lost, candidate)
	}
	return nil
}

// The last name of a path.
func evsLfsBaseName(path string) []byte {
	if i := strings.LastIndexByte(path, '/'); 0 <= i {
		return []byte(path[i+1:])
	}
	return []byte(path)
}
