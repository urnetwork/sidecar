// FI-9, git (§22.8; §11.11, §11.12's export row, R-EVS-10, D-EVS-22; D-TEST-10): an acknowledged push has the declared
// ref, tree, ancestry and per-ref outcome, and stock clients see standard non-fast-forward errors. Its git-lfs clauses
// (a git-mode tip commits only once ur/lfs holds every object it requires, and no prune removes one a current tip
// requires) wait for format 2 and are TEST-M10-01's.
//
// The oracle holds what stock clients were told to what an export of the repo holds:
//
//	ledger   a world records each push a stock client made (GitLedger.RecordPush): per ref, the commit the client
//	         declared, its tree and its parents, as the client's own repository holds them, and the status its
//	         porcelain line printed (ParseGitPushPorcelain). Then it records an export of the repo taken after the
//	         pushes' outcomes reached evs (RecordExport): an owned ref's queue drained, since its ok comes first
//	parse    the export is read by this file's own parse of git's object format (GitRepository), never through ur's
//	         export result or the root's evs_git_* code: every object is inflated and hashed again, so an export that
//	         names an object by an oid its bytes do not hash to fails, and the client's oids are checked against
//	         those hashes. go-git, §22.6's git codec oracle, is linked only by the mlsinterop module (dependencies.yml),
//	         so the root's oracle reads with its own code, which shares none with what it checks
//	check    each push is held to the first export recorded after it: an ok update's commit is on its ref, with the
//	         declared tree and parents, its whole tree stored and hashing right, and the newest ok update of each ref
//	         is that ref's tip; an ok deletion leaves no ref; a refused update's commit is not on its ref unless a
//	         later acknowledged update of that ref carries it, so an atomic push's refusal moved none of its refs, while
//	         one git heard as remote outcome pending is unsettled and may be either, its commit even the tip; a
//	         refusal whose cause the recorder knows reads git's standard non-fast-forward words when another push
//	         moved the tip ([rejected] (non-fast-forward) or (fetch first), [remote rejected] (non-fast-forward)) and
//	         never otherwise, as SEGMENT_GONE, 429, GATE_CLOSED and an unknown outcome never do (EVS1-M2-36); and a
//	         non-fast-forward is borne out: the ref's tip at the export is not in the refused commit's ancestry
//
// FI(9) on a Net reads GitLedgerOf(net) after every step and at the end, where an acknowledged push no export checked
// fails. A world with no Net checks its own ledger with CheckGitPushes.
//
// Readings and gaps, each in TEST-M2-06's report: tip equality assumes every client that pushes to the repo records
// into the ledger; the parse reads loose objects and refs, which is all export writes, and fails closed on an object
// it would have to find in a pack; SHA-1 repositories only, since ur refuses sha256 ones before any evs write.

package fault

import (
	"bytes"
	"compress/zlib"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
)

var _ = RegisterInvariant(9, func(ctx context.Context, oracle *Oracle) error {
	return GitLedgerOf(oracle.Net).check(oracle.Final)
})

// What git's porcelain line said of one ref.
type GitPushStatus string

const (
	GitPushOk       GitPushStatus = "ok"
	GitPushRejected GitPushStatus = "rejected"
)

// The cause of a refusal that another push moved the ref's tip, the one cause git reports as non-fast-forward.
const GitCauseTipMoved = "tip-moved"

// One ref's update in a stock client's push, as the client named it and was answered.
type GitPushUpdate struct {
	// The ref pushed to, "refs/heads/main".
	Ref string
	// The source as the client named it, "HEAD" or "refs/heads/work"; empty for a deletion.
	Source string
	// The commit the client declared, its tree and its parents in order, all lowercase hex, as the client's own
	// repository holds them: a recorder reads them on the client's side, never from ur's export. Empty New is a
	// deletion.
	New     string
	Tree    string
	Parents []string
	Status  GitPushStatus
	// The client's summary and reason as its porcelain line printed them: "[rejected]" and "non-fast-forward",
	// "[remote rejected]" and "remote outcome pending", "[new branch]" and "".
	Summary string
	Reason  string
	// Why the remote refused it, where the recorder knows: GitCauseTipMoved, or the name of evs's refusal code
	// (protocol.EvsRefusalCode's), or "unknown" for an outcome no answer settled; empty when the recorder does not
	// know.
	Cause string
}

// One push of a stock client: its updates, each with its own status.
type GitPush struct {
	// Who pushed: the device's label.
	Actor string
	// git push --atomic: one refusal refuses every update.
	Atomic  bool
	Updates []*GitPushUpdate
}

// The pushes and exports a world records for FI-9, in order. Safe for concurrent use: a record never waits on a check,
// and checks run one at a time.
type GitLedger struct {
	stateLock sync.Mutex
	events    []*gitLedgerEvent

	// held across a check, which reads exports from disk
	checkLock sync.Mutex
	// the events before this one are checked, each push against the export after it
	checkedThrough int
	// each export's parse, by event index
	repositories map[int]*GitRepository
}

type gitLedgerEvent struct {
	push   *GitPush
	export string
}

func NewGitLedger() *GitLedger {
	return &GitLedger{repositories: map[int]*GitRepository{}}
}

var gitLedgers sync.Map

// The Net's git ledger, made at first use; it goes with the Net.
func GitLedgerOf(net *Net) *GitLedger {
	return netMemoryOf(&gitLedgers, net, NewGitLedger)
}

// Records push, a copy, after every push and export recorded before it.
func (self *GitLedger) RecordPush(push *GitPush) {
	copied := &GitPush{Actor: push.Actor, Atomic: push.Atomic}
	for _, update := range push.Updates {
		updateCopy := *update
		updateCopy.Parents = slices.Clone(update.Parents)
		copied.Updates = append(copied.Updates, &updateCopy)
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.events = append(self.events, &gitLedgerEvent{push: copied})
}

// Records an export of the repo into dir, a bare repository as `ur evs export` writes it, taken after every push
// recorded so far reached evs. The directory must stay until the check has read it.
func (self *GitLedger) RecordExport(dir string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.events = append(self.events, &gitLedgerEvent{export: dir})
}

// Every push the ledger holds checked against the first export recorded after it. final also fails an acknowledged
// push no export follows.
func CheckGitPushes(ledger *GitLedger, final bool) error {
	return ledger.check(final)
}

func (self *GitLedger) check(final bool) error {
	self.checkLock.Lock()
	defer self.checkLock.Unlock()
	events := func() []*gitLedgerEvent {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return slices.Clone(self.events)
	}()
	errs := []error{}
	for index := self.checkedThrough; index < len(events); index += 1 {
		event := events[index]
		if event.export == "" {
			continue
		}
		repository, err := self.repositoryWithLock(index, event.export)
		if err != nil {
			errs = append(errs, fmt.Errorf("the export in %s: %w", event.export, err))
			self.checkedThrough = index + 1
			continue
		}
		errs = append(errs, gitCheckExport(events, index, repository)...)
		self.checkedThrough = index + 1
	}
	if final {
		for index := self.checkedThrough; index < len(events); index += 1 {
			push := events[index].push
			if push == nil {
				continue
			}
			for _, update := range push.Updates {
				if update.Status == GitPushOk {
					errs = append(errs, fmt.Errorf("%s's push of %s was acknowledged and no export after it was recorded, so nothing checked it", push.Actor, update.Ref))
				}
			}
		}
	}
	return errors.Join(errs...)
}

// The parse of the export at event index, under checkLock.
func (self *GitLedger) repositoryWithLock(index int, dir string) (*GitRepository, error) {
	if repository := self.repositories[index]; repository != nil {
		return repository, nil
	}
	repository, err := OpenGitRepository(dir)
	if err != nil {
		return nil, err
	}
	self.repositories[index] = repository
	return repository, nil
}

// The pushes since the export before exportIndex, held to the export at it; the newest acknowledged update of each
// ref among every push before it must be the ref's tip.
func gitCheckExport(events []*gitLedgerEvent, exportIndex int, repository *GitRepository) []error {
	start := 0
	for index := exportIndex - 1; 0 <= index; index -= 1 {
		if events[index].export != "" {
			start = index + 1
			break
		}
	}
	// each ref's acknowledged updates before the export, in order, every push counted; and the updates whose commit
	// may be its tip: the newest acknowledged one and every pending one after it, whose outcome no answer settled
	refUpdates := map[string][]*GitPushUpdate{}
	refTips := map[string][]*GitPushUpdate{}
	for index := 0; index < exportIndex; index += 1 {
		if push := events[index].push; push != nil {
			for _, update := range push.Updates {
				switch {
				case update.Status == GitPushOk:
					refUpdates[update.Ref] = append(refUpdates[update.Ref], update)
					refTips[update.Ref] = []*GitPushUpdate{update}
				case gitPending(update) && 0 < len(refTips[update.Ref]):
					refTips[update.Ref] = append(refTips[update.Ref], update)
				}
			}
		}
	}
	errs := []error{}
	for index := start; index < exportIndex; index += 1 {
		push := events[index].push
		if push == nil {
			continue
		}
		errs = append(errs, gitCheckPush(repository, push, refUpdates)...)
	}
	// the newest acknowledged update of each ref is its tip, or a pending update after it that landed
	refs := []string{}
	for ref := range refTips {
		refs = append(refs, ref)
	}
	slices.Sort(refs)
	for _, ref := range refs {
		candidates := refTips[ref]
		newest := candidates[0]
		tip, found, err := repository.Ref(ref)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		matches := false
		for _, candidate := range candidates {
			matches = matches || (candidate.New == "" && !found) || (candidate.New != "" && found && tip == candidate.New)
		}
		switch {
		case matches:
		case newest.New == "" && found:
			errs = append(errs, fmt.Errorf("%s was deleted by its newest acknowledged push, and the export holds it at %s", ref, tip))
		case !found:
			errs = append(errs, fmt.Errorf("%s's newest acknowledged push declared %s, and the export holds no %s: an acknowledged push has the declared ref", ref, newest.New, ref))
		default:
			errs = append(errs, fmt.Errorf("%s's newest acknowledged push declared %s (%s), and the export's %s is at %s (%s): an acknowledged push has the declared ref", ref, newest.New, gitShapeOfUpdate(newest), ref, tip, repository.shape(tip)))
		}
	}
	return errs
}

// Whether git heard an update's outcome as unsettled: ng remote outcome pending, which the journal resolves later,
// either way (EVS1-M2-36), or a recorder that knows the outcome was unknown.
func gitPending(update *GitPushUpdate) bool {
	return update.Status == GitPushRejected && (update.Reason == "remote outcome pending" || update.Cause == "unknown")
}

// One push's updates against the export: see the file header.
func gitCheckPush(repository *GitRepository, push *GitPush, refUpdates map[string][]*GitPushUpdate) []error {
	errs := []error{}
	refused := false
	for _, update := range push.Updates {
		refused = refused || update.Status != GitPushOk
	}
	for _, update := range push.Updates {
		if push.Atomic && refused && update.Status == GitPushOk {
			errs = append(errs, fmt.Errorf("%s's atomic push answered %s ok while another of its refs was refused: an atomic push takes every ref or none", push.Actor, update.Ref))
		}
		switch update.Status {
		case GitPushOk:
			errs = append(errs, gitCheckAcknowledged(repository, push, update)...)
		case GitPushRejected:
			errs = append(errs, gitCheckRefused(repository, push, update, refUpdates)...)
		default:
			errs = append(errs, fmt.Errorf("%s's push of %s has no status git prints: %q", push.Actor, update.Ref, update.Status))
		}
	}
	return errs
}

// An acknowledged update: its commit on its ref, with the declared tree and parents, its tree stored whole.
func gitCheckAcknowledged(repository *GitRepository, push *GitPush, update *GitPushUpdate) []error {
	if update.New == "" {
		// a deletion: the newest acknowledged update's rule holds it
		return nil
	}
	tip, found, err := repository.Ref(update.Ref)
	if err != nil {
		return []error{err}
	}
	if !found {
		return []error{fmt.Errorf("%s's push of %s was acknowledged at %s, and the export holds no %s: an acknowledged push has the declared ref", push.Actor, update.Ref, update.New, update.Ref)}
	}
	ancestry, err := repository.Ancestry(tip)
	if err != nil {
		return []error{fmt.Errorf("%s in the export: %w", update.Ref, err)}
	}
	if !ancestry[update.New] {
		return []error{fmt.Errorf("%s's push of %s was acknowledged at %s (%s), which the export's %s at %s (%s) does not hold: an acknowledged push has the declared ref", push.Actor, update.Ref, update.New, gitShapeOfUpdate(update), update.Ref, tip, repository.shape(tip))}
	}
	commit, err := repository.Commit(update.New)
	if err != nil {
		return []error{fmt.Errorf("%s's acknowledged %s in the export: %w", push.Actor, update.New, err)}
	}
	errs := []error{}
	if commit.Tree != update.Tree {
		errs = append(errs, fmt.Errorf("%s's push of %s was acknowledged at %s with tree %s, and the export's %s names tree %s: an acknowledged push has the declared tree", push.Actor, update.Ref, update.New, update.Tree, update.New, commit.Tree))
	}
	if !slices.Equal(commit.Parents, update.Parents) {
		errs = append(errs, fmt.Errorf("%s's push of %s was acknowledged at %s with parents %v, and the export's %s names parents %v: an acknowledged push has the declared ancestry", push.Actor, update.Ref, update.New, update.Parents, update.New, commit.Parents))
	}
	if err := repository.CheckTree(commit.Tree); err != nil {
		errs = append(errs, fmt.Errorf("%s's acknowledged %s on %s, its tree %s in the export: %w", push.Actor, update.New, update.Ref, commit.Tree, err))
	}
	return errs
}

// A refused update: its commit not on its ref unless a later acknowledged update of that ref carries it, and a
// non-fast-forward in git's words exactly when another push moved the tip.
func gitCheckRefused(repository *GitRepository, push *GitPush, update *GitPushUpdate, refUpdates map[string][]*GitPushUpdate) []error {
	errs := []error{}
	nonFastForward := gitReadsNonFastForward(update)
	switch {
	case update.Cause == GitCauseTipMoved && !nonFastForward && !strings.Contains(update.Reason, "atomic push failed"):
		errs = append(errs, fmt.Errorf("%s's push of %s was refused because another push moved the tip, and git printed %s (%s): a stock client sees git's standard non-fast-forward error", push.Actor, update.Ref, update.Summary, update.Reason))
	case update.Cause != "" && update.Cause != GitCauseTipMoved && nonFastForward:
		errs = append(errs, fmt.Errorf("%s's push of %s was refused for %s, and git printed %s (%s): only a moved tip reaches git as non-fast-forward", push.Actor, update.Ref, update.Cause, update.Summary, update.Reason))
	}
	if update.New == "" || gitPending(update) {
		// a pending update may have landed or not
		return errs
	}
	tip, found, err := repository.Ref(update.Ref)
	if err != nil {
		return append(errs, err)
	}
	if !found {
		return errs
	}
	ancestry, err := repository.Ancestry(tip)
	if err != nil {
		return append(errs, fmt.Errorf("%s in the export: %w", update.Ref, err))
	}
	if ancestry[update.New] {
		carried := false
		for _, later := range refUpdates[update.Ref] {
			if later.New == "" {
				continue
			}
			if later.New == update.New {
				carried = true
				break
			}
			if laterAncestry, err := repository.Ancestry(later.New); err == nil && laterAncestry[update.New] {
				carried = true
				break
			}
		}
		if !carried {
			errs = append(errs, fmt.Errorf("%s's push of %s was refused (%s %s), and the export's %s at %s holds its commit %s, which no acknowledged update carried: a refused update moves no ref", push.Actor, update.Ref, update.Summary, update.Reason, update.Ref, tip, update.New))
		}
		return errs
	}
	if nonFastForward {
		// the refused commit is stored, on another ref or below a later one, yet off this ref: a fast-forward of the
		// tip the export holds was no non-fast-forward, whatever moved the tip since
		if newAncestry, err := repository.Ancestry(update.New); err == nil && newAncestry[tip] {
			errs = append(errs, fmt.Errorf("%s's push of %s was refused as non-fast-forward, and its commit %s descends from the export's tip %s: a non-fast-forward the ref's tip does not bear out", push.Actor, update.Ref, update.New, tip))
		}
	}
	return errs
}

// A push as a recorder builds it from `git push --porcelain`'s output, each update's declared commit, tree and
// parents taken from the client's own repository through resolve (stock git's `log -1 --format=%H %T %P <source>`,
// say), never from ur's export. A deletion declares no commit.
func GitPushOf(actor string, atomic bool, output string, resolve func(source string) (oid string, tree string, parents []string, err error)) (*GitPush, error) {
	updates, err := ParseGitPushPorcelain(output)
	if err != nil {
		return nil, err
	}
	for _, update := range updates {
		if update.Source == "" {
			continue
		}
		if update.New, update.Tree, update.Parents, err = resolve(update.Source); err != nil {
			return nil, fmt.Errorf("%s's %s: %w", actor, update.Source, err)
		}
	}
	return &GitPush{Actor: actor, Atomic: atomic, Updates: updates}, nil
}

// Whether a refusal reads as git's standard non-fast-forward error: [rejected] (non-fast-forward) or (fetch first),
// or [remote rejected] (non-fast-forward).
func gitReadsNonFastForward(update *GitPushUpdate) bool {
	switch {
	case update.Summary == "[rejected]" && (update.Reason == "non-fast-forward" || update.Reason == "fetch first"):
		return true
	case update.Summary == "[remote rejected]" && update.Reason == "non-fast-forward":
		return true
	}
	return strings.Contains(update.Reason, "non-fast-forward")
}

func gitShapeOfUpdate(update *GitPushUpdate) string {
	return fmt.Sprintf("tree %s, parents %v", update.Tree, update.Parents)
}

// The updates of `git push --porcelain`'s output, in order: one per line of the form <flag> TAB <from>:<to> TAB
// <summary> [(<reason>)], every other line (To, Done, error:, hint:, remote:) left out. An output with no such line
// is an error, since a push that reported nothing is no evidence.
func ParseGitPushPorcelain(output string) ([]*GitPushUpdate, error) {
	updates := []*GitPushUpdate{}
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSuffix(line, "\r")
		fields := strings.Split(line, "\t")
		if len(fields) != 3 || len(fields[0]) != 1 || !strings.Contains(" +-*!=", fields[0]) {
			continue
		}
		source, ref, ok := strings.Cut(fields[1], ":")
		if !ok {
			return nil, fmt.Errorf("a porcelain line names no <from>:<to>: %q", line)
		}
		update := &GitPushUpdate{Ref: ref, Source: source, Status: GitPushOk}
		summary := fields[2]
		if open := strings.Index(summary, " ("); 0 <= open && strings.HasSuffix(summary, ")") {
			update.Reason = summary[open+2 : len(summary)-1]
			summary = summary[:open]
		}
		update.Summary = summary
		if fields[0] == "!" {
			update.Status = GitPushRejected
		}
		updates = append(updates, update)
	}
	if len(updates) == 0 {
		return nil, fmt.Errorf("git push's porcelain output holds no ref's line: %q", output)
	}
	return updates, nil
}

// What a commit names, as the parse read it.
type GitCommit struct {
	Oid     string
	Tree    string
	Parents []string
}

// One git object as the parse read it: its kind and content, its bytes hashed to its oid.
type gitObject struct {
	kind    string
	content []byte
}

// A bare repository read by FI-9's own parse of git's object format: loose objects, each inflated and hashed again,
// and refs from refs/ and packed-refs. It shares no code with the root's evs_git_* or export. Safe for concurrent use.
type GitRepository struct {
	dir string

	stateLock sync.Mutex
	objects   map[string]*gitObject
	ancestry  map[string]map[string]bool
	trees     map[string]error
	// packed-refs, read once
	packedRefs map[string]string
}

// The repository in dir, a bare repository with objects/ and refs/.
func OpenGitRepository(dir string) (*GitRepository, error) {
	if info, err := os.Stat(filepath.Join(dir, "objects")); err != nil || !info.IsDir() {
		return nil, fmt.Errorf("%s holds no objects directory: %v", dir, err)
	}
	repository := &GitRepository{
		dir: dir, objects: map[string]*gitObject{}, ancestry: map[string]map[string]bool{}, trees: map[string]error{},
	}
	packedRefs, err := gitReadPackedRefs(filepath.Join(dir, "packed-refs"))
	if err != nil {
		return nil, err
	}
	repository.packedRefs = packedRefs
	return repository, nil
}

func gitReadPackedRefs(path string) (map[string]string, error) {
	refs := map[string]string{}
	body, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return refs, nil
	}
	if err != nil {
		return nil, err
	}
	for _, line := range strings.Split(string(body), "\n") {
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "^") {
			continue
		}
		oid, ref, ok := strings.Cut(line, " ")
		if !ok || !gitIsOid(oid) {
			return nil, fmt.Errorf("packed-refs holds a line git does not write: %q", line)
		}
		refs[ref] = oid
	}
	return refs, nil
}

func gitIsOid(text string) bool {
	if len(text) != 2*sha1.Size {
		return false
	}
	_, err := hex.DecodeString(text)
	return err == nil && strings.ToLower(text) == text
}

// The oid ref names, following symbolic refs; false when the repository holds no such ref. A symbolic ref that comes
// back to one it passed is an error.
func (self *GitRepository) Ref(ref string) (string, bool, error) {
	followed := map[string]bool{}
	for !followed[ref] {
		followed[ref] = true
		body, err := os.ReadFile(filepath.Join(self.dir, filepath.FromSlash(ref)))
		if errors.Is(err, os.ErrNotExist) {
			oid, ok := self.packedRefs[ref]
			return oid, ok, nil
		}
		if err != nil {
			return "", false, err
		}
		text := strings.TrimSpace(string(body))
		if target, ok := strings.CutPrefix(text, "ref: "); ok {
			ref = target
			continue
		}
		if !gitIsOid(text) {
			return "", false, fmt.Errorf("ref %s holds %q, no oid", ref, text)
		}
		return text, true, nil
	}
	return "", false, fmt.Errorf("ref %s: symbolic refs form a cycle", ref)
}

// The object oid names, inflated and hashed again: an object whose bytes do not hash to its name, or whose header
// does not hold its size, is an error.
func (self *GitRepository) object(oid string) (*gitObject, error) {
	self.stateLock.Lock()
	object := self.objects[oid]
	self.stateLock.Unlock()
	if object != nil {
		return object, nil
	}
	if !gitIsOid(oid) {
		return nil, fmt.Errorf("%q is no oid", oid)
	}
	path := filepath.Join(self.dir, "objects", oid[:2], oid[2:])
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		if packs, _ := filepath.Glob(filepath.Join(self.dir, "objects", "pack", "*.pack")); 0 < len(packs) {
			return nil, fmt.Errorf("object %s is not loose and the repository holds packs, which FI-9's parse does not read", oid)
		}
		return nil, fmt.Errorf("object %s is not stored", oid)
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()
	inflater, err := zlib.NewReader(file)
	if err != nil {
		return nil, fmt.Errorf("object %s: %w", oid, err)
	}
	defer inflater.Close()
	raw, err := io.ReadAll(inflater)
	if err != nil {
		return nil, fmt.Errorf("object %s: %w", oid, err)
	}
	digest := sha1.Sum(raw)
	if hashed := hex.EncodeToString(digest[:]); hashed != oid {
		return nil, fmt.Errorf("the object stored as %s hashes to %s", oid, hashed)
	}
	header, content, ok := bytes.Cut(raw, []byte{0})
	if !ok {
		return nil, fmt.Errorf("object %s has no header", oid)
	}
	kind, sizeText, ok := strings.Cut(string(header), " ")
	if !ok {
		return nil, fmt.Errorf("object %s's header %q names no size", oid, header)
	}
	size, err := strconv.Atoi(sizeText)
	if err != nil || size != len(content) {
		return nil, fmt.Errorf("object %s's header says %q bytes and it holds %d", oid, sizeText, len(content))
	}
	switch kind {
	case "blob", "tree", "commit", "tag":
	default:
		return nil, fmt.Errorf("object %s is of kind %q", oid, kind)
	}
	object = &gitObject{kind: kind, content: content}
	self.stateLock.Lock()
	self.objects[oid] = object
	self.stateLock.Unlock()
	return object, nil
}

// The commit oid names: its tree and its parents, in order.
func (self *GitRepository) Commit(oid string) (*GitCommit, error) {
	object, err := self.object(oid)
	if err != nil {
		return nil, err
	}
	if object.kind != "commit" {
		return nil, fmt.Errorf("%s is a %s, not a commit", oid, object.kind)
	}
	commit := &GitCommit{Oid: oid}
	headers, _, _ := bytes.Cut(object.content, []byte("\n\n"))
	for i, line := range strings.Split(string(headers), "\n") {
		key, value, _ := strings.Cut(line, " ")
		switch {
		case i == 0 && key == "tree" && gitIsOid(value):
			commit.Tree = value
		case i == 0:
			return nil, fmt.Errorf("commit %s does not begin with its tree", oid)
		case key == "parent":
			if !gitIsOid(value) || len(commit.Parents) != i-1 {
				return nil, fmt.Errorf("commit %s has a parent line out of place: %q", oid, line)
			}
			commit.Parents = append(commit.Parents, value)
		}
	}
	return commit, nil
}

// Every commit oid reaches through its parents, itself included.
func (self *GitRepository) Ancestry(oid string) (map[string]bool, error) {
	self.stateLock.Lock()
	cached := self.ancestry[oid]
	self.stateLock.Unlock()
	if cached != nil {
		return cached, nil
	}
	ancestry := map[string]bool{}
	queue := []string{oid}
	for 0 < len(queue) {
		next := queue[0]
		queue = queue[1:]
		if ancestry[next] {
			continue
		}
		ancestry[next] = true
		commit, err := self.Commit(next)
		if err != nil {
			return nil, err
		}
		queue = append(queue, commit.Parents...)
	}
	self.stateLock.Lock()
	self.ancestry[oid] = ancestry
	self.stateLock.Unlock()
	return ancestry, nil
}

// Whether the tree oid names, and every tree and blob below it, is stored, of its kind and hashing to its name. A
// gitlink (mode 160000) names a commit of another repository and is not followed.
func (self *GitRepository) CheckTree(oid string) error {
	self.stateLock.Lock()
	checked, ok := self.trees[oid]
	self.stateLock.Unlock()
	if ok {
		return checked
	}
	err := func() error {
		object, err := self.object(oid)
		if err != nil {
			return err
		}
		if object.kind != "tree" {
			return fmt.Errorf("%s is a %s, not a tree", oid, object.kind)
		}
		rest := object.content
		for 0 < len(rest) {
			header, after, ok := bytes.Cut(rest, []byte{0})
			if !ok || len(after) < sha1.Size {
				return fmt.Errorf("tree %s ends inside an entry", oid)
			}
			mode, name, ok := strings.Cut(string(header), " ")
			if !ok || name == "" {
				return fmt.Errorf("tree %s has an entry with no name", oid)
			}
			entryOid := hex.EncodeToString(after[:sha1.Size])
			rest = after[sha1.Size:]
			switch mode {
			case "40000":
				if err := self.CheckTree(entryOid); err != nil {
					return fmt.Errorf("%s/: %w", name, err)
				}
			case "160000":
			case "100644", "100755", "120000":
				entry, err := self.object(entryOid)
				if err != nil {
					return fmt.Errorf("%s: %w", name, err)
				}
				if entry.kind != "blob" {
					return fmt.Errorf("%s is a %s, not a blob", name, entry.kind)
				}
			default:
				return fmt.Errorf("tree %s has an entry of mode %q", oid, mode)
			}
		}
		return nil
	}()
	self.stateLock.Lock()
	self.trees[oid] = err
	self.stateLock.Unlock()
	return err
}

// A commit's tree and parents for a message, or why it cannot be read.
func (self *GitRepository) shape(oid string) string {
	commit, err := self.Commit(oid)
	if err != nil {
		return err.Error()
	}
	return fmt.Sprintf("tree %s, parents %v", commit.Tree, commit.Parents)
}
