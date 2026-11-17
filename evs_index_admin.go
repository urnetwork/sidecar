//go:build !ios_extension

// The index's settings, off, status and rebuild (§11.14's settings, off, limit, on, rebuild and status rows; R-EVS-21,
// R-EVS-24, D-EVS-43, D-EVS-61, D-QUOTA-10, D-MCP-17; SEARCH-M10-15): what `ur evs index` does to a repo's index
// roots, and the EvsRepo methods it calls.
//
//	settings  <root>/settings is the one versioned index file, and a version counts only if one of the repo's admins
//	          signed it (§8.8); absent, the index is on with 30-day windows (7 in the team directory). on, off and
//	          window <days> write the next version on every root of the repo: each named file-mode ref's
//	          .ur-index/i<n>, main's where none is named, and ur/index's i<n> where the repo holds that ref. A device
//	          that is not a repo admin writes none, since its version would not count. window_days 0 means 30, else
//	          7-365; the team directory refuses off and a window past 90. A window applies from the next bucket,
//	          whose W it fixes.
//	off       the off version and the removal of every other file of the root, heads and the lock included, ride one
//	          push; the erasure set beside the roots stays for a later build to apply, and ur/index itself is never
//	          deleted, since its settings file's absence would mean on. At the storage limit or while spent a settings
//	          version, a new inline record, is refused, so the off goes in steps: the files go first (a deletion,
//	          accepted), then the off version, then the files writers re-created meanwhile. While the off version
//	          waits the call answers ErrEvsIndexWaits, and calling again resumes from what the ref holds then.
//	on        the version that turns the index on; a device holding the text then builds it (evs_index_build.go)
//	status    each root's state, window and format, its files' count and bytes apart from content (D-QUOTA-10), and
//	          each content ref's coverage where a content reader is given
//	rebuild   the root rebuilt whole from the text under the lock (IndexBuilder.Build)
//
// A settings or removal push holds no document, so it names the head's index_epoch as every index push does and
// needs no erasure set to read. MCP never writes settings or turns the index off (D-MCP-17): no tool does, and
// `ur evs index`'s settings and rebuild methods are Confirm ones, which run only from a control session a person
// confirmed on /dev/tty. Paths are this device's plaintext and go into no log or error's text (I-13). Safe for
// concurrent use as EvsRepo is.

package sidecar

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

var (
	// This device is not an admin of the repo now, or its admins cannot be judged, so a settings version it signed
	// would not count (§11.14's settings row).
	ErrEvsIndexNotAdmin = errors.New("evs index: only a repo admin's settings version counts, and this device is none")
	// A config, mailcfg or secret repo, which holds no index.
	ErrEvsIndexExcluded = errors.New("evs index: config, mailcfg and secret repos hold no index")
	// Settings the repo does not take: a window outside 7-365 days, or the team directory's index off or past 90.
	ErrEvsIndexSettings = errors.New("evs index: settings this repo does not take")
	// No reader of the repo's text is given to this call, so nothing can be built from it here.
	ErrEvsIndexNoText = errors.New("evs index: this device holds no reader of the repo's text for a build")
	// The off version waits until the repo is under its storage limit and not spent; its files are gone already.
	ErrEvsIndexWaits = errors.New("evs index: the off version waits until the repo is under its storage limit")
	// The index is in a newer format than this build reads: nothing is written over it (status update).
	ErrEvsIndexNewerFormat = errors.New("evs index: the index is in a newer format than this build; update ur")
	// Another device holds the index's lock and has not lapsed.
	ErrEvsIndexLocked = errors.New("evs index: another device holds the index's lock; try again later")
)

// `ur evs index`'s settings actions.
const (
	EvsIndexOn     = "on"
	EvsIndexOff    = "off"
	EvsIndexWindow = "window"
)

// A root's states in status.
const (
	EvsIndexStateOn     = "on"
	EvsIndexStateOff    = "off"
	EvsIndexStateUpdate = "update"
	EvsIndexStateNone   = "none"
)

// What a settings change makes of a root's counted settings, nil for none.
type indexSettingsChange func(current *protocol.IndexSettings) *protocol.IndexSettings

// The change an action gives.
func indexSettingsChangeOf(action string, windowDays uint32) (indexSettingsChange, error) {
	switch action {
	case EvsIndexOn, EvsIndexOff:
		off := action == EvsIndexOff
		return func(current *protocol.IndexSettings) *protocol.IndexSettings {
			next := &protocol.IndexSettings{Off: off}
			if current != nil {
				next.WindowDays = current.WindowDays
			}
			return next
		}, nil
	case EvsIndexWindow:
		return func(current *protocol.IndexSettings) *protocol.IndexSettings {
			next := &protocol.IndexSettings{WindowDays: windowDays}
			if current != nil {
				next.Off = current.Off
			}
			return next
		}, nil
	}
	return nil, fmt.Errorf("%w: no action %q", ErrEvsIndexSettings, action)
}

// What a settings write reads and writes one index ref with.
type indexSettingsArgs struct {
	store     indexRefStore
	repoId    Id
	refId     Id
	repoKind  protocol.RepoKind
	companion bool
	isAdmin   func(file *indexFileVersion) bool
	format    *IndexFormatSettings
	// Builds of one push before it gives up on the refusals it rebuilds after: IndexBuilderSettings.AttemptCount.
	attemptCount int
	// Nil is real time.
	clock Clock
}

// What a settings write did on one root.
type indexSettingsOutcome struct {
	rootNumber uint32
	// The settings the root holds as the write left them.
	settings *protocol.IndexSettings
	// The settings path's new version, 0 where the root held these settings already.
	version uint64
	// Files an off removed, over its steps.
	removedCount int
	// The off version waits at the storage limit: the files are gone and the version is not written yet.
	waiting bool
}

// The ref's index at its head.
func (self *indexSettingsArgs) loadView(ctx context.Context) (*indexView, error) {
	return indexLoadView(ctx, &indexViewArgs{
		store:     self.store,
		repoId:    self.repoId,
		refId:     self.refId,
		repoKind:  self.repoKind,
		companion: self.companion,
		isAdmin:   self.isAdmin,
		settings:  self.format,
	})
}

// A push of files and removals that holds no document: settings and removals, at the view's base and epoch.
func indexAdminPush(view *indexView, signedTimeMs int64, files []*indexPushFile, removals []*indexPushRemoval) *indexPush {
	return &indexPush{
		pushId:       NewId(),
		kind:         indexPushIndex,
		baseVersion:  view.head.version,
		indexEpoch:   view.head.indexEpoch,
		signedTimeMs: signedTimeMs,
		files:        files,
		removals:     removals,
	}
}

// Every file the listing holds under root, but its settings, in path order, and the settings path's newest version, 0
// for none.
func indexRootListing(listing *indexListing, root *indexViewRoot) ([]*indexPushRemoval, uint64) {
	prefix := root.paths.root + "/"
	removals := []*indexPushRemoval{}
	settingsVersion := uint64(0)
	for _, file := range listing.files {
		switch {
		case file.path == root.paths.settings():
			settingsVersion = file.version
		case strings.HasPrefix(file.path, prefix):
			removals = append(removals, &indexPushRemoval{path: file.path, version: file.version})
		}
	}
	slices.SortFunc(removals, func(a *indexPushRemoval, b *indexPushRemoval) int {
		return cmp.Compare(a.path, b.path)
	})
	return removals, settingsVersion
}

// Applies change to every root of the ref, or to root 1 where none is written yet. Each root's next settings are
// checked for the repo's kind before anything is sent.
func indexApplySettings(ctx context.Context, args *indexSettingsArgs, change indexSettingsChange) ([]*indexSettingsOutcome, error) {
	view, err := args.loadView(ctx)
	if err != nil {
		return nil, err
	}
	if view.newerFormat {
		return nil, ErrEvsIndexNewerFormat
	}
	roots := view.roots
	if len(roots) == 0 {
		roots = []*indexViewRoot{view.writeRoot()}
	}
	outcomes := []*indexSettingsOutcome{}
	for _, root := range roots {
		outcome, err := indexApplyRootSettings(ctx, args, root.number, change)
		if err != nil {
			return outcomes, err
		}
		outcomes = append(outcomes, outcome)
	}
	return outcomes, nil
}

// One root's settings write, rebuilt from its read after each refusal it rebuilds after, at most attemptCount builds.
func indexApplyRootSettings(ctx context.Context, args *indexSettingsArgs, rootNumber uint32, change indexSettingsChange) (*indexSettingsOutcome, error) {
	clock := clockOrReal(args.clock)
	outcome := &indexSettingsOutcome{rootNumber: rootNumber}
	for attempt := 0; attempt < max(1, args.attemptCount); attempt += 1 {
		signedTime := clock.Now()
		view, err := args.loadView(ctx)
		if errors.Is(err, errIndexCollected) {
			continue
		}
		if err != nil {
			return outcome, err
		}
		if view.newerFormat {
			return outcome, ErrEvsIndexNewerFormat
		}
		root := view.root(rootNumber)
		if root == nil {
			root = &indexViewRoot{number: rootNumber, paths: indexNewPaths(args.companion, rootNumber)}
		}
		var current *protocol.IndexSettings
		if root.settings != nil {
			current = proto.CloneOf(root.settings)
		}
		next := change(current)
		if err := indexCheckSettingsForKind(next, args.repoKind); err != nil {
			return outcome, fmt.Errorf("%w: %w", ErrEvsIndexSettings, err)
		}
		outcome.settings = next
		listing, err := args.store.List(ctx, view.head.version)
		if errors.Is(err, errIndexCollected) {
			continue
		}
		if err != nil {
			return outcome, err
		}
		files, settingsVersion := indexRootListing(listing, root)
		pushFiles := []*indexPushFile{}
		if root.settings == nil || !proto.Equal(root.settings, next) {
			plaintext, err := indexEncodeSettings(next)
			if err != nil {
				return outcome, err
			}
			pushFiles = append(pushFiles, &indexPushFile{path: root.paths.settings(), plaintext: plaintext, replaces: settingsVersion})
		}
		removals := []*indexPushRemoval{}
		if next.Off {
			removals = files
		}
		if len(pushFiles) == 0 && len(removals) == 0 {
			return outcome, nil
		}
		committed, err := indexSendPush(ctx, args.store, indexAdminPush(view, signedTime.UnixMilli(), pushFiles, removals), signedTime, clock, args.format.PushLife)
		switch {
		case isIndexRefusal(err, indexRefusalConflict), isIndexRefusal(err, indexRefusalIndexEpoch), errors.Is(err, errIndexPushLifePassed):
			continue
		case next.Off && isIndexRefusal(err, indexRefusalQuota) && 0 < len(pushFiles):
			// at the storage limit or while spent: the files first, then the off version, then what writers re-created
			return indexOffInSteps(ctx, args, rootNumber, outcome)
		case err != nil:
			return outcome, err
		}
		outcome.version = indexWrittenVersion(committed, root.paths.settings())
		outcome.removedCount += len(removals)
		return outcome, nil
	}
	return outcome, errIndexBuildAttempts
}

// The version committed of path, 0 where the push wrote none.
func indexWrittenVersion(committed *indexCommitted, path string) uint64 {
	if committed == nil {
		return 0
	}
	for _, file := range committed.files {
		if file.path == path {
			return file.version
		}
	}
	return 0
}

// §11.14's off at the storage limit: (1) the root's files but its settings go, a deletion the limit accepts; (2) the
// off version, once a push of it is taken, which while it is refused leaves the outcome waiting; (3) the files writers
// re-created between the two go.
func indexOffInSteps(ctx context.Context, args *indexSettingsArgs, rootNumber uint32, outcome *indexSettingsOutcome) (*indexSettingsOutcome, error) {
	clock := clockOrReal(args.clock)
	remove := func() error {
		for attempt := 0; attempt < max(1, args.attemptCount); attempt += 1 {
			signedTime := clock.Now()
			view, err := args.loadView(ctx)
			if errors.Is(err, errIndexCollected) {
				continue
			}
			if err != nil {
				return err
			}
			root := view.root(rootNumber)
			if root == nil {
				return nil
			}
			listing, err := args.store.List(ctx, view.head.version)
			if errors.Is(err, errIndexCollected) {
				continue
			}
			if err != nil {
				return err
			}
			removals, _ := indexRootListing(listing, root)
			if len(removals) == 0 {
				return nil
			}
			_, err = indexSendPush(ctx, args.store, indexAdminPush(view, signedTime.UnixMilli(), nil, removals), signedTime, clock, args.format.PushLife)
			switch {
			case isIndexRefusal(err, indexRefusalConflict), isIndexRefusal(err, indexRefusalIndexEpoch), errors.Is(err, errIndexPushLifePassed):
				continue
			case err != nil:
				return err
			}
			outcome.removedCount += len(removals)
			return nil
		}
		return errIndexBuildAttempts
	}
	// 1
	if err := remove(); err != nil {
		return outcome, err
	}
	// 2
	for attempt := 0; ; attempt += 1 {
		if max(1, args.attemptCount) <= attempt {
			return outcome, errIndexBuildAttempts
		}
		signedTime := clock.Now()
		view, err := args.loadView(ctx)
		if errors.Is(err, errIndexCollected) {
			continue
		}
		if err != nil {
			return outcome, err
		}
		root := view.root(rootNumber)
		if root == nil {
			root = &indexViewRoot{number: rootNumber, paths: indexNewPaths(args.companion, rootNumber)}
		}
		if root.off() {
			break
		}
		listing, err := args.store.List(ctx, view.head.version)
		if errors.Is(err, errIndexCollected) {
			continue
		}
		if err != nil {
			return outcome, err
		}
		_, settingsVersion := indexRootListing(listing, root)
		plaintext, err := indexEncodeSettings(outcome.settings)
		if err != nil {
			return outcome, err
		}
		file := &indexPushFile{path: root.paths.settings(), plaintext: plaintext, replaces: settingsVersion}
		committed, err := indexSendPush(ctx, args.store, indexAdminPush(view, signedTime.UnixMilli(), []*indexPushFile{file}, nil), signedTime, clock, args.format.PushLife)
		switch {
		case isIndexRefusal(err, indexRefusalConflict), isIndexRefusal(err, indexRefusalIndexEpoch), errors.Is(err, errIndexPushLifePassed):
			continue
		case isIndexRefusal(err, indexRefusalQuota), isIndexRefusal(err, indexRefusalRetry):
			outcome.waiting = true
			return outcome, nil
		case err != nil:
			return outcome, err
		}
		outcome.version = indexWrittenVersion(committed, root.paths.settings())
		break
	}
	// 3
	return outcome, remove()
}

// One index root's status.
type indexRootStatus struct {
	rootNumber uint32
	state      string
	windowDays uint32
	// The counted settings' version, 0 for none.
	settingsVersion uint64
	fileCount       int
	byteCount       int64
	bucketCount     int
	allShardCount   int
	alarmCount      int
}

// Every root's status at the view: its state, window, files and bytes, read from the listing so a file the view
// dropped still counts toward the bytes.
func indexStatusOf(view *indexView, listing *indexListing) []*indexRootStatus {
	if view.newerFormat {
		return []*indexRootStatus{{state: EvsIndexStateUpdate, alarmCount: len(view.alarms)}}
	}
	roots := view.roots
	statuses := []*indexRootStatus{}
	for _, root := range roots {
		status := &indexRootStatus{
			rootNumber:    root.number,
			state:         EvsIndexStateOn,
			windowDays:    root.windowDays(view.repoKind),
			bucketCount:   len(root.buckets),
			allShardCount: len(root.allShards),
			alarmCount:    len(view.alarms),
		}
		if root.off() {
			status.state = EvsIndexStateOff
		}
		if root.settingsFile != nil {
			status.settingsVersion = root.settingsFile.version
		}
		prefix := root.paths.root + "/"
		for _, file := range listing.files {
			if strings.HasPrefix(file.path, prefix) {
				status.fileCount += 1
				status.byteCount += int64(file.byteCount)
			}
		}
		statuses = append(statuses, status)
	}
	if len(statuses) == 0 {
		statuses = append(statuses, &indexRootStatus{
			rootNumber: indexRootNumber,
			state:      EvsIndexStateNone,
			windowDays: view.writeRoot().windowDays(view.repoKind),
			alarmCount: len(view.alarms),
		})
	}
	return statuses
}

// What `ur evs index on|off|window` asks of a repo.
type EvsIndexSettingsArgs struct {
	// EvsIndexOn, EvsIndexOff or EvsIndexWindow.
	Action string
	// window's days: 0 means 30, else 7-365 (7-90 in the team directory).
	WindowDays uint32
	// The file-mode refs whose own index takes the settings, by name; none names main. ur/index's root takes them
	// too where the repo holds that ref.
	RefNames [][]byte
}

// What one root's settings write did.
type EvsIndexRootSettings struct {
	RefId Id
	// ur/index's root rather than a file-mode ref's own.
	Companion  bool
	RootNumber uint32
	Off        bool
	WindowDays uint32
	// The settings path's new version, 0 where the root held these settings already.
	Version uint64
	// Files an off removed.
	RemovedCount int
	// The off version waits at the storage limit: its files are gone, and calling again writes it.
	Waiting bool
}

// What IndexSettings did, a root at a time.
type EvsIndexSettingsResult struct {
	Roots []*EvsIndexRootSettings
}

// What `ur evs index status` reads of a repo.
type EvsIndexStatusArgs struct {
	// The file-mode refs whose own index is read; none names main. ur/index is read where the repo holds it.
	RefNames [][]byte
	// Each index ref's content readers, for coverage; nil reads no coverage. Given in this package only, until an
	// EvsRepo reader of a content ref's text lands.
	contents func(refId Id, companion bool) []indexContentRef
}

// One content ref's coverage in status.
type EvsIndexCoverage struct {
	RefId Id
	// The content ref's head as read, and the newest version up to which every push is indexed.
	Through        uint64
	IndexedThrough uint64
	UnindexedCount int
}

// One root's status (§11.14's status row).
type EvsIndexRootStatus struct {
	RefId      Id
	Companion  bool
	RootNumber uint32
	// EvsIndexStateOn, Off, Update (a newer format this build does not read) or None (no file yet: on, unbuilt).
	State      string
	WindowDays uint32
	// The counted settings' version, 0 for none.
	SettingsVersion uint64
	// The index's files and their plaintext bytes, pads included: what the index stores apart from content
	// (D-QUOTA-10).
	FileCount     int
	ByteCount     int64
	BucketCount   int
	AllShardCount int
	// index_malformed alarms the read raised.
	AlarmCount int
	Coverage   []*EvsIndexCoverage
}

// The repo's index status, a root at a time.
type EvsIndexStatus struct {
	Roots []*EvsIndexRootStatus
}

// What `ur evs index rebuild` asks of a repo.
type EvsIndexRebuildArgs struct {
	// A file-mode ref whose own index is rebuilt, nil for main; Companion rebuilds ur/index's instead.
	RefName   []byte
	Companion bool
	// The content refs the index covers, whose text this device holds. Given in this package only, until an EvsRepo
	// reader of a content ref's text lands: without them the rebuild answers ErrEvsIndexNoText.
	contents   []indexContentRef
	groupInbox bool
}

// What a rebuild did.
type EvsIndexRebuildResult struct {
	RefId Id
	// The index ref's version the build committed at, 0 where it was skipped.
	Version uint64
	// Off where the index is off, locked where another device holds its lock.
	Skipped string
	// The documents the build wrote.
	EntryCount int
}

// One index ref of the repo: a file-mode ref's own, or ur/index.
type evsIndexTarget struct {
	store     *indexEvsStore
	refId     Id
	companion bool
}

// The index refs a call reaches: each named file-mode ref that the repo lists, main where none is named, and
// ur/index where the repo lists it.
func (self *EvsRepo) indexTargets(ctx context.Context, refNames [][]byte) ([]*evsIndexTarget, error) {
	listing, err := self.ListRefs(ctx, nil)
	if err != nil {
		return nil, err
	}
	listed := map[Id]bool{}
	for _, summary := range listing.Refs {
		if refId, err := IdFromBytes(summary.GetRefId()); err == nil {
			listed[refId] = true
		}
	}
	if len(refNames) == 0 {
		refNames = [][]byte{EvsMainRefName}
	}
	targets := []*evsIndexTarget{}
	for _, refName := range refNames {
		store := newIndexEvsStore(self, refName, false)
		refId, err := store.refId(ctx)
		if err != nil {
			return nil, err
		}
		if listed[refId] {
			targets = append(targets, &evsIndexTarget{store: store, refId: refId})
		}
	}
	companion := newIndexEvsStore(self, nil, true)
	companionRefId, err := companion.refId(ctx)
	if err != nil {
		return nil, err
	}
	if listed[companionRefId] {
		targets = append(targets, &evsIndexTarget{store: companion, refId: companionRefId, companion: true})
	}
	return targets, nil
}

// The repo's admin judge from the newest verified config state: indexAclAdmins over its ACL state. Nil, with no
// error, where the state holds no ACL state, which counts no settings version.
func (self *EvsRepo) indexAdmins() (func(file *indexFileVersion) bool, error) {
	state, err := self.client.verifier.config()
	if err != nil {
		return nil, err
	}
	holder, ok := state.(interface{ Acl() (*AclState, error) })
	if !ok {
		return nil, nil
	}
	acl, err := holder.Acl()
	if err != nil {
		return nil, err
	}
	return indexAclAdmins(acl, self.repoId), nil
}

// This device's sidecar_id.
func (self *EvsRepo) indexSidecarId() (Id, error) {
	if self.client.args.Identity == nil {
		return Id{}, ErrEvsNoConfig
	}
	identity := self.client.args.Identity()
	if identity == nil {
		return Id{}, ErrEvsNoConfig
	}
	return identity.SidecarId, nil
}

// The repo's kind, refusing one that holds no index.
func (self *EvsRepo) indexRepoKind() (protocol.RepoKind, error) {
	kind, err := self.repoKind()
	if err != nil {
		return 0, err
	}
	if indexRepoExcluded(kind) {
		return kind, ErrEvsIndexExcluded
	}
	return kind, nil
}

// Writes the next settings version on every index root of the repo (§11.14's settings, on, off and limit rows), as
// one of its admins. on leaves the build to a device holding the text (IndexRebuild, or an indexer); off removes every
// other file of each root in the same push, or in steps at the storage limit, answering ErrEvsIndexWaits beside the
// result while the off version waits.
func (self *EvsRepo) IndexSettings(ctx context.Context, args *EvsIndexSettingsArgs) (*EvsIndexSettingsResult, error) {
	if args == nil {
		return nil, fmt.Errorf("%w: no args", ErrEvsIndexSettings)
	}
	change, err := indexSettingsChangeOf(args.Action, args.WindowDays)
	if err != nil {
		return nil, err
	}
	kind, err := self.indexRepoKind()
	if err != nil {
		return nil, err
	}
	if err := indexCheckSettingsForKind(change(nil), kind); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrEvsIndexSettings, err)
	}
	isAdmin, err := self.indexAdmins()
	if err != nil {
		return nil, err
	}
	sidecarId, err := self.indexSidecarId()
	if err != nil {
		return nil, err
	}
	if isAdmin == nil || !isAdmin(&indexFileVersion{signerSidecarId: sidecarId, signedTimeMs: self.client.clock.Now().UnixMilli()}) {
		return nil, ErrEvsIndexNotAdmin
	}
	targets, err := self.indexTargets(ctx, args.RefNames)
	if err != nil {
		return nil, err
	}
	result := &EvsIndexSettingsResult{}
	waiting := false
	for _, target := range targets {
		outcomes, err := indexApplySettings(ctx, &indexSettingsArgs{
			store:        target.store,
			repoId:       self.repoId,
			refId:        target.refId,
			repoKind:     kind,
			companion:    target.companion,
			isAdmin:      isAdmin,
			format:       DefaultIndexFormatSettings(),
			attemptCount: DefaultIndexBuilderSettings().AttemptCount,
			clock:        self.client.clock,
		}, change)
		for _, outcome := range outcomes {
			root := &EvsIndexRootSettings{
				RefId: target.refId, Companion: target.companion, RootNumber: outcome.rootNumber, Version: outcome.version,
				RemovedCount: outcome.removedCount, Waiting: outcome.waiting,
			}
			if outcome.settings != nil {
				root.Off, root.WindowDays = outcome.settings.Off, outcome.settings.WindowDays
			}
			waiting = waiting || outcome.waiting
			result.Roots = append(result.Roots, root)
		}
		if err != nil {
			return result, err
		}
	}
	if waiting {
		return result, ErrEvsIndexWaits
	}
	return result, nil
}

// The repo's index status (§11.14's status row): each root's state, window, files and bytes apart from content, and
// coverage where content readers are given.
func (self *EvsRepo) IndexStatus(ctx context.Context, args *EvsIndexStatusArgs) (*EvsIndexStatus, error) {
	if args == nil {
		args = &EvsIndexStatusArgs{}
	}
	kind, err := self.indexRepoKind()
	if err != nil {
		return nil, err
	}
	isAdmin, err := self.indexAdmins()
	if err != nil {
		return nil, err
	}
	targets, err := self.indexTargets(ctx, args.RefNames)
	if err != nil {
		return nil, err
	}
	status := &EvsIndexStatus{}
	for _, target := range targets {
		roots, err := indexReadStatus(ctx, &indexStatusArgs{
			store:     target.store,
			repoId:    self.repoId,
			refId:     target.refId,
			repoKind:  kind,
			companion: target.companion,
			isAdmin:   isAdmin,
			format:    DefaultIndexFormatSettings(),
		}, args.contents)
		if err != nil {
			return status, err
		}
		status.Roots = append(status.Roots, roots...)
	}
	return status, nil
}

// What one index ref's status reads.
type indexStatusArgs struct {
	store     indexRefStore
	repoId    Id
	refId     Id
	repoKind  protocol.RepoKind
	companion bool
	isAdmin   func(file *indexFileVersion) bool
	format    *IndexFormatSettings
}

// One index ref's roots' status, with each content ref's coverage where contents gives readers.
func indexReadStatus(ctx context.Context, args *indexStatusArgs, contents func(refId Id, companion bool) []indexContentRef) ([]*EvsIndexRootStatus, error) {
	view, err := indexLoadView(ctx, &indexViewArgs{
		store: args.store, repoId: args.repoId, refId: args.refId, repoKind: args.repoKind, companion: args.companion,
		isAdmin: args.isAdmin, settings: args.format,
	})
	if err != nil {
		return nil, err
	}
	listing, err := args.store.List(ctx, view.head.version)
	if err != nil {
		return nil, err
	}
	statuses := []*EvsIndexRootStatus{}
	for _, root := range indexStatusOf(view, listing) {
		status := &EvsIndexRootStatus{
			RefId: args.refId, Companion: args.companion, RootNumber: root.rootNumber, State: root.state,
			WindowDays: root.windowDays, SettingsVersion: root.settingsVersion, FileCount: root.fileCount,
			ByteCount: root.byteCount, BucketCount: root.bucketCount, AllShardCount: root.allShardCount,
			AlarmCount: root.alarmCount,
		}
		viewRoot := view.root(root.rootNumber)
		if contents != nil && viewRoot != nil && root.state == EvsIndexStateOn {
			for _, content := range indexSortContents(contents(args.refId, args.companion)) {
				coverage, err := indexCoverageOf(ctx, &indexCoverageArgs{view: view, root: viewRoot, content: content})
				if err != nil {
					return statuses, err
				}
				status.Coverage = append(status.Coverage, &EvsIndexCoverage{
					RefId: content.RefId(), Through: coverage.through, IndexedThrough: coverage.indexedThrough,
					UnindexedCount: coverage.unindexedCount,
				})
			}
		}
		statuses = append(statuses, status)
	}
	return statuses, nil
}

// Rebuilds one index ref's root whole from the text under the lock (`ur evs index rebuild`; §11.14's rebuild and site
// loss rows): IndexBuilder.Build with this device as the builder, its newest generation's pad key and K_ref.
func (self *EvsRepo) IndexRebuild(ctx context.Context, args *EvsIndexRebuildArgs) (*EvsIndexRebuildResult, error) {
	if args == nil {
		args = &EvsIndexRebuildArgs{}
	}
	kind, err := self.indexRepoKind()
	if err != nil {
		return nil, err
	}
	if len(args.contents) == 0 {
		return nil, ErrEvsIndexNoText
	}
	isAdmin, err := self.indexAdmins()
	if err != nil {
		return nil, err
	}
	sidecarId, err := self.indexSidecarId()
	if err != nil {
		return nil, err
	}
	store := newIndexEvsStore(self, args.RefName, args.Companion)
	refId, err := store.refId(ctx)
	if err != nil {
		return nil, err
	}
	repoKey, err := self.client.args.Gkm.EnsureWritable(ctx, self.repoId)
	if err != nil {
		return nil, err
	}
	refKey, err := indexRefKey(repoKey)
	if err != nil {
		return nil, err
	}
	builder, err := indexNewBuilder(&indexBuilderArgs{
		store:      store,
		repoId:     self.repoId,
		refId:      refId,
		repoKind:   kind,
		companion:  args.Companion,
		groupInbox: args.groupInbox,
		isAdmin:    isAdmin,
		format:     DefaultIndexFormatSettings(),
		tables:     indexLinkedTables(),
		clock:      self.client.clock,
		builder:    sidecarId,
		refKey:     refKey,
		contents:   args.contents,
		padKey: func(ctx context.Context) (*indexPadKey, error) {
			return indexNewPadKey(repoKey)
		},
	})
	if err != nil {
		return nil, err
	}
	outcome, err := builder.Build(ctx)
	result := &EvsIndexRebuildResult{RefId: refId}
	for _, ref := range outcome.refs {
		result.EntryCount += ref.entryCount
	}
	switch outcome.skipped {
	case indexBuildSkipOff:
		result.Skipped = EvsIndexStateOff
	case indexBuildSkipLocked:
		return result, ErrEvsIndexLocked
	}
	if outcome.committed != nil {
		result.Version = outcome.committed.version
	}
	switch {
	case errors.Is(err, errIndexBuildNewerFormat):
		return result, ErrEvsIndexNewerFormat
	case errors.Is(err, errIndexBuildExcluded):
		return result, ErrEvsIndexExcluded
	}
	return result, err
}
