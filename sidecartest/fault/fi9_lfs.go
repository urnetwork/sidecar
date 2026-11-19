// FI-9's git-lfs clauses (§22.8; §11.11's store, requires, tip check, smudge and prune rows; D-EVS-41, owner
// decisions 141 and 162; TEST-M10-01): a git-mode tip commits only once ur/lfs holds every git-lfs object it
// requires, safe from every prune, and no prune removes an object a current tip requires.
//
// A world records, beside its pushes and exports (fi9.go), what ur/lfs holds at a point of its run
// (GitLedger.RecordLfsStore): each object's content as a reader of the store read it, by its oid. The oracle hashes
// every object itself, so a store whose object does not hash to its oid fails, and reads what each commit requires
// from an export with fi9.go's own parse of git's object format, never through ur's tip check or agent:
//
//	requires  R(c), as §11.11 states it: each blob of c's tree (a tag peeled to it) at a path whose filter attribute,
//	          under that tree's own .gitattributes files (gitattributes(5): a pattern without a slash matches a name at
//	          any depth below its file, one with a slash matches the path relative to its file, a leading **/ at any
//	          depth; later lines and deeper files win), is lfs, and whose bytes, under 1,024, are a git-lfs v1 pointer:
//	          the version line, then oid sha256:<64 hex> and size <n>
//	committed every acknowledged update's commit, read in the first export recorded after its push, requires only
//	          objects the first store record after that push holds, each at its pointer's size: a tip that committed
//	          while ur/lfs lacked one fails
//	pruned    every store record holds every object each ref's tip requires in the newest export recorded before it
//
// Readings and gaps, in TEST-M10-01's report: the store is read through what a world records, so "only once" is held
// at the first store record after the push, not at the push's own commit point; a world that records an acknowledged
// push whose commit needs objects and no store record after it fails at the end; a .gitattributes macro, a negated
// pattern and ** anywhere but a leading **/ match nothing here, so a tip relying on one requires less than git-lfs
// would make it; no world records into the ledger yet: evsgit's FS-73 world checks its own store.

package fault

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

// git-lfs's pointer format (https://github.com/git-lfs/git-lfs/blob/main/docs/spec.md): identifiers of the format.
const (
	gitLfsPointerVersionLine = "version https://git-lfs.github.com/spec/v1"
	gitLfsOidPrefix          = "sha256:"
)

// The tunables FI-9's git-lfs clauses read: the format's own bounds.
type GitLfsSettings struct {
	// A pointer blob is under this many bytes: git-lfs's 1,024.
	PointerMaxByteCount int
	// How deep a tree the requires walk descends before it fails: past any tree a world pushes, 64.
	TreeMaxDepth int
	// How many tags a ref's tip peels through before it fails: past any a world tags, 16.
	TagMaxDepth int
}

func DefaultGitLfsSettings() *GitLfsSettings {
	return &GitLfsSettings{
		PointerMaxByteCount: 1024,
		TreeMaxDepth:        64,
		TagMaxDepth:         16,
	}
}

// Records what ur/lfs holds now, objects by oid (64 lowercase hex), each with its content as a reader read it, after
// every push and export recorded before it.
func (self *GitLedger) RecordLfsStore(objects map[string][]byte) {
	copied := map[string][]byte{}
	for oid, content := range objects {
		copied[oid] = slices.Clone(content)
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.events = append(self.events, &gitLedgerEvent{lfs: copied, lfsRecorded: true})
}

// Names the bounds the ledger's git-lfs clauses read; until it is called they are DefaultGitLfsSettings'.
func (self *GitLedger) SetLfsSettings(settings *GitLfsSettings) {
	settingsCopy := *settings
	self.checkLock.Lock()
	defer self.checkLock.Unlock()
	self.lfsSettings = &settingsCopy
}

// The git-lfs clauses over events, under checkLock: each store record and each acknowledged push not yet held.
func (self *GitLedger) checkLfsWithLock(events []*gitLedgerEvent, final bool) []error {
	if self.lfsPushesChecked == nil {
		self.lfsPushesChecked = map[int]bool{}
	}
	if self.lfsSettings == nil {
		self.lfsSettings = DefaultGitLfsSettings()
	}
	settings := self.lfsSettings
	errs := []error{}
	for index := self.lfsCheckedThrough; index < len(events); index += 1 {
		if !events[index].lfsRecorded {
			continue
		}
		errs = append(errs, gitLfsStoreHashes(index, events[index].lfs)...)
		exportIndex := -1
		for before := index - 1; 0 <= before; before -= 1 {
			if events[before].export != "" {
				exportIndex = before
				break
			}
		}
		if 0 <= exportIndex {
			repository, err := self.repositoryWithLock(exportIndex, events[exportIndex].export)
			if err != nil {
				errs = append(errs, err)
			} else {
				errs = append(errs, gitLfsTipsHeld(repository, events[index].lfs, settings)...)
			}
		}
		self.lfsCheckedThrough = index + 1
	}
	for index, event := range events {
		if event.push == nil || self.lfsPushesChecked[index] {
			continue
		}
		exportIndex, storeIndex := -1, -1
		for after := index + 1; after < len(events); after += 1 {
			if exportIndex < 0 && events[after].export != "" {
				exportIndex = after
			}
			if storeIndex < 0 && events[after].lfsRecorded {
				storeIndex = after
			}
		}
		if exportIndex < 0 {
			// fi9.go's own final clause fails an acknowledged push no export follows
			continue
		}
		repository, err := self.repositoryWithLock(exportIndex, events[exportIndex].export)
		if err != nil {
			errs = append(errs, err)
			self.lfsPushesChecked[index] = true
			continue
		}
		pushErrs, complete := gitLfsPushHeld(repository, event.push, storeIndex, events, final, settings)
		errs = append(errs, pushErrs...)
		if complete {
			self.lfsPushesChecked[index] = true
		}
	}
	return errs
}

// Every object of a store record hashes to its oid.
func gitLfsStoreHashes(index int, objects map[string][]byte) []error {
	oids := []string{}
	for oid := range objects {
		oids = append(oids, oid)
	}
	slices.Sort(oids)
	errs := []error{}
	for _, oid := range oids {
		digest := sha256.Sum256(objects[oid])
		if hex.EncodeToString(digest[:]) != oid {
			errs = append(errs, fmt.Errorf("the ur/lfs store recorded at event %d holds %s, whose content hashes to %x", index, oid, digest))
		}
	}
	return errs
}

// An acknowledged push's updates against the first store record after it; complete is false while none is
// recorded yet and the run has not ended.
func gitLfsPushHeld(repository *GitRepository, push *GitPush, storeIndex int, events []*gitLedgerEvent, final bool, settings *GitLfsSettings) ([]error, bool) {
	errs := []error{}
	for _, update := range push.Updates {
		if update.Status != GitPushOk || update.New == "" {
			continue
		}
		required, err := GitLfsRequires(repository, update.New, settings)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s's acknowledged %s at %s: %w", push.Actor, update.Ref, update.New, err))
			continue
		}
		if len(required) == 0 {
			continue
		}
		if storeIndex < 0 {
			if !final {
				return nil, false
			}
			errs = append(errs, fmt.Errorf("%s's acknowledged %s at %s requires %d git-lfs objects, and no ur/lfs store was recorded after it, so nothing checked them", push.Actor, update.Ref, update.New, len(required)))
			continue
		}
		errs = append(errs, gitLfsHeld(events[storeIndex].lfs, required, fmt.Sprintf("%s's push of %s at %s committed", push.Actor, update.Ref, update.New), "a git-mode tip commits only once ur/lfs holds every git-lfs object it requires")...)
	}
	return errs, true
}

// Every ref's tip in an export, and what it requires, held by a store record.
func gitLfsTipsHeld(repository *GitRepository, objects map[string][]byte, settings *GitLfsSettings) []error {
	refs, err := gitRefNames(repository)
	if err != nil {
		return []error{err}
	}
	errs := []error{}
	for _, ref := range refs {
		tip, found, err := repository.Ref(ref)
		if err != nil || !found {
			continue
		}
		commitOid, err := gitPeel(repository, tip, settings)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s at %s: %w", ref, tip, err))
			continue
		}
		required, err := GitLfsRequires(repository, commitOid, settings)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s at %s: %w", ref, tip, err))
			continue
		}
		errs = append(errs, gitLfsHeld(objects, required, fmt.Sprintf("%s's tip %s", ref, commitOid), "no prune removes an object a current tip requires")...)
	}
	return errs
}

// Each required object in objects at its size.
func gitLfsHeld(objects map[string][]byte, required map[string]int64, what string, rule string) []error {
	oids := []string{}
	for oid := range required {
		oids = append(oids, oid)
	}
	slices.Sort(oids)
	errs := []error{}
	for _, oid := range oids {
		content, ok := objects[oid]
		switch {
		case !ok:
			errs = append(errs, fmt.Errorf("%s requires git-lfs object %s, which ur/lfs does not hold: %s", what, oid, rule))
		case int64(len(content)) != required[oid]:
			errs = append(errs, fmt.Errorf("%s requires git-lfs object %s of %d bytes, and ur/lfs holds %d", what, oid, required[oid], len(content)))
		}
	}
	return errs
}

// The refs under refs/ in the repository, loose and packed, in order.
func gitRefNames(repository *GitRepository) ([]string, error) {
	names := map[string]bool{}
	for name := range repository.packedRefs {
		names[name] = true
	}
	root := filepath.Join(repository.dir, "refs")
	err := filepath.WalkDir(root, func(walked string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		relative, err := filepath.Rel(repository.dir, walked)
		if err != nil {
			return err
		}
		names[filepath.ToSlash(relative)] = true
		return nil
	})
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	sorted := []string{}
	for name := range names {
		sorted = append(sorted, name)
	}
	slices.Sort(sorted)
	return sorted, nil
}

// The commit oid names, a tag peeled to its object as many times as it takes.
func gitPeel(repository *GitRepository, oid string, settings *GitLfsSettings) (string, error) {
	for range settings.TagMaxDepth {
		kind, content, err := repository.Object(oid)
		if err != nil {
			return "", err
		}
		switch kind {
		case "commit":
			return oid, nil
		case "tag":
			first, _, _ := strings.Cut(string(content), "\n")
			target, ok := strings.CutPrefix(first, "object ")
			if !ok || !gitIsOid(target) {
				return "", fmt.Errorf("tag %s names no object", oid)
			}
			oid = target
		default:
			return "", fmt.Errorf("%s is a %s, which requires nothing", oid, kind)
		}
	}
	return "", fmt.Errorf("tag %s peels through more than %d tags", oid, settings.TagMaxDepth)
}

// One .gitattributes line's filter: its pattern and the value it gives filter, "" unsetting it.
type gitLfsAttributeLine struct {
	// the directory of its file, relative to the tree's root, "" at the root
	directory string
	pattern   string
	filter    string
}

// R(c): the git-lfs objects the commit requires, by oid, each with its pointer's size.
func GitLfsRequires(repository *GitRepository, commitOid string, settings *GitLfsSettings) (map[string]int64, error) {
	commit, err := repository.Commit(commitOid)
	if err != nil {
		return nil, err
	}
	required := map[string]int64{}
	var walk func(treeOid string, directory string, inherited []*gitLfsAttributeLine, depth int) error
	walk = func(treeOid string, directory string, inherited []*gitLfsAttributeLine, depth int) error {
		if settings.TreeMaxDepth < depth {
			return fmt.Errorf("a tree deeper than %d", settings.TreeMaxDepth)
		}
		entries, err := repository.Tree(treeOid)
		if err != nil {
			return err
		}
		lines := slices.Clone(inherited)
		for _, entry := range entries {
			if entry.Name != ".gitattributes" || entry.Mode == "40000" {
				continue
			}
			_, content, err := repository.Object(entry.Oid)
			if err != nil {
				return err
			}
			lines = append(lines, gitLfsAttributeLines(directory, string(content))...)
		}
		for _, entry := range entries {
			entryPath := path.Join(directory, entry.Name)
			switch entry.Mode {
			case "40000":
				if err := walk(entry.Oid, entryPath, lines, depth+1); err != nil {
					return err
				}
				continue
			case "100644", "100664", "100755":
			default:
				continue
			}
			if gitLfsFilter(lines, entryPath) != "lfs" {
				continue
			}
			kind, content, err := repository.Object(entry.Oid)
			if err != nil {
				return err
			}
			if kind != "blob" || settings.PointerMaxByteCount <= len(content) {
				continue
			}
			if oid, size, ok := ParseGitLfsPointer(content); ok {
				required[oid] = size
			}
		}
		return nil
	}
	if err := walk(commit.Tree, "", nil, 0); err != nil {
		return nil, fmt.Errorf("commit %s's tree: %w", commitOid, err)
	}
	return required, nil
}

// A .gitattributes file's lines that set or unset filter, in order.
func gitLfsAttributeLines(directory string, content string) []*gitLfsAttributeLine {
	lines := []*gitLfsAttributeLine{}
	for _, raw := range strings.Split(content, "\n") {
		fields := strings.Fields(raw)
		if len(fields) < 2 || strings.HasPrefix(fields[0], "#") || strings.HasPrefix(fields[0], "[attr]") {
			continue
		}
		for _, attribute := range fields[1:] {
			switch {
			case strings.HasPrefix(attribute, "filter="):
				lines = append(lines, &gitLfsAttributeLine{directory: directory, pattern: fields[0], filter: strings.TrimPrefix(attribute, "filter=")})
			case attribute == "-filter", attribute == "!filter":
				lines = append(lines, &gitLfsAttributeLine{directory: directory, pattern: fields[0], filter: ""})
			}
		}
	}
	return lines
}

// The filter value the lines give the file at filePath, the last matching line winning, deeper files coming later.
func gitLfsFilter(lines []*gitLfsAttributeLine, filePath string) string {
	filter := ""
	for _, line := range lines {
		relative := filePath
		if line.directory != "" {
			var ok bool
			if relative, ok = strings.CutPrefix(filePath, line.directory+"/"); !ok {
				continue
			}
		}
		if gitLfsPatternMatches(line.pattern, relative) {
			filter = line.filter
		}
	}
	return filter
}

// Whether a gitattributes pattern matches a path relative to its file's directory.
func gitLfsPatternMatches(pattern string, relative string) bool {
	if strings.HasPrefix(pattern, "!") || strings.HasSuffix(pattern, "/") {
		// a negated pattern is refused by git for attributes, and a directory pattern names no file
		return false
	}
	if anyDepth, ok := strings.CutPrefix(pattern, "**/"); ok {
		components := strings.Split(relative, "/")
		for i := range components {
			if matched, err := path.Match(anyDepth, strings.Join(components[i:], "/")); err == nil && matched {
				return true
			}
		}
		return false
	}
	if strings.Contains(pattern, "**") {
		return false
	}
	pattern = strings.TrimPrefix(pattern, "/")
	if !strings.Contains(pattern, "/") {
		matched, err := path.Match(pattern, path.Base(relative))
		return err == nil && matched
	}
	matched, err := path.Match(pattern, relative)
	return err == nil && matched
}

// A git-lfs v1 pointer's oid and size: its version line first, then sorted key lines, each ended by a newline, with
// an oid of sha256 and a decimal size among them.
func ParseGitLfsPointer(content []byte) (oid string, size int64, ok bool) {
	text := string(content)
	if !strings.HasSuffix(text, "\n") {
		return "", 0, false
	}
	lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	if len(lines) < 3 || lines[0] != gitLfsPointerVersionLine {
		return "", 0, false
	}
	previous := ""
	for _, line := range lines[1:] {
		key, value, found := strings.Cut(line, " ")
		if !found || key <= previous {
			return "", 0, false
		}
		previous = key
		switch key {
		case "oid":
			hexOid, isSha256 := strings.CutPrefix(value, gitLfsOidPrefix)
			decoded, err := hex.DecodeString(hexOid)
			if !isSha256 || err != nil || len(decoded) != sha256.Size || strings.ToLower(hexOid) != hexOid {
				return "", 0, false
			}
			oid = hexOid
		case "size":
			parsed, err := strconv.ParseInt(value, 10, 64)
			if err != nil || parsed < 0 || strconv.FormatInt(parsed, 10) != value {
				return "", 0, false
			}
			size = parsed
		}
	}
	if oid == "" || !strings.Contains(text, "\nsize ") {
		return "", 0, false
	}
	return oid, size, true
}
