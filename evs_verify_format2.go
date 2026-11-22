//go:build !ios_extension

// The verifying reader in format 2 (§11.7's setting, refused, content and cite rows, §11.8's Readers verify; R-EVS-12,
// D-EVS-35, D-EVS-39, D-EVS-43, I-4, I-EVS-10, FI-17, FS-68, FS-72; EVS2-M10-17): what a reader adds to format 1's
// checks once it reads format 2, against a server that may lie about everything it stores. evs checks most of this
// too, at 5c and 5h, and a reader trusts none of that.
//
//	format    a client whose composition installed this reader (EnableFormat2Reader) and whose EvsSettings.MaxFormat
//	          is 2 accepts versioning 1 and 2, kind-5 and staged locators, flags 256 and 512 and fields 33 and 34;
//	          any other answers each as format 1 does, FORMAT_UNSUPPORTED, never a fork, tampering or a missing
//	          segment (D-EVS-39). The network extensions' leg links none of this file and so reads format 1 alone:
//	          what it reads of evs is the config repo, which holds no versionless version
//	refused   versioning past 2; 1 or 2 in a config or mailcfg repo, on a git-mode ref or on a creates-only ref (a
//	          record-class stream, a deposit ref, the erasure ref); 1 in a push whose auth pin includes the repo's
//	          lock (§8.8): the version is refused and alarms version_rule, naming its signer; a pin the reader no
//	          longer retains leaves the lock unjudged (QD-1178), the lock rows here and under ignored taking the
//	          version either way
//	ignored   2 anywhere but under an index root, .ur-index/ on a file-mode ref or the ur/index ref; under an index
//	          root, any file version that is not 2 but the root's settings file, and any path that is none of
//	          §11.14's; on ur/lfs, an object that is not 1, or 0 in a locked repo, its settings file aside
//	          (plan-EVS2-lfs-settings): the version is ignored, as if the path held none, and alarms version_rule
//	shape     kind-5 locators only in a versionless version, no inline record in one, a staged locator only as kind
//	          5: what one version shows alone, which a head reader checks
//	cite      the citation rule proper (EvsCheckCitation, I-EVS-10), which needs each path's base and the push's
//	          other versions, is the replaying reader's: EvsReplayPaths.ApplyFormat2 runs it over every push's new
//	          versions with the bases the replay holds, and a base it does not hold fails closed unless its caller
//	          supplies it; evs runs the same rule at 5h, which a reader does not trust
//	CUT       a CUT's signer is a repo admin at the statement's own auth pin (I-EVS-16's reader half); a DROP's
//	          authority and lists are EVS2-M10-22's, so here a DROP is walked as a signed statement and shows
//	          nothing dropped
//
// A head's window bits 4 and 5 are hints evs keeps for its own jobs: no reply carries them to a reader, which checks
// every statement's change list, so a wrong one changes nothing a reader shows.
//
// What a reader knows of a path decides the ignored rows: a head reader knows the names it asked for, and a replaying
// reader the names its tables hold. A path whose names the reader does not hold is judged by the refused rows alone.
//
// On every leg. Package-level functions are safe for concurrent use.

package sidecar

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// ur/lfs's one versioned file, at its root (plan-EVS2-lfs-settings).
const evsLfsSettingsName = "settings"

// The reserved ref name names, none for any other.
func EvsReservedRefOf(refName []byte) EvsReservedRef {
	switch {
	case bytes.Equal(refName, EvsIndexRefName):
		return EvsReservedRefIndex
	case bytes.Equal(refName, EvsLfsRefName):
		return EvsReservedRefLfs
	}
	return EvsReservedRefNone
}

// Where a version sits, as its reader knows it.
type EvsVersioningContext struct {
	RepoKind protocol.RepoKind
	RefKind  protocol.EvsRefKind
	RefMode  protocol.EvsRefMode
	// The reserved ref the version's ref is, when the reader knows the ref by name.
	Reserved EvsReservedRef
	// The repo's lock stands in the authorization state at the push's auth pin (§8.8; AclState.RepoLocked there).
	Locked bool
	// The push's auth pin lies before what the reader retains, so whether the lock stood there is not judged
	// (QD-1178): neither row that turns on the lock refuses or ignores the version.
	LockUnjudged bool
}

// Format 2's reader, which EnableFormat2Reader installs.
type evsFormat2Rules struct{}

// Installs format 2's reader: from here the client takes format-2 constructs under this file's rules, while its
// settings allow format 2 (EvsSettings.MaxFormat). A client is made without it and answers each construct
// FORMAT_UNSUPPORTED until its composition calls this, as it writes none until SetFormat2Source admits it.
func (self *EvsClient) EnableFormat2Reader() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.format2Reads = &evsFormat2Rules{}
}

// Whether a ref takes no versionless version at all (§11.7's refused row): a config or mailcfg repo's, a git-mode
// ref, a creates-only ref.
func (self *EvsVersioningContext) refusesVersionless() bool {
	switch {
	case self.RepoKind == protocol.RepoKind_REPO_KIND_CONFIG || self.RepoKind == protocol.RepoKind_REPO_KIND_MAILCFG:
		return true
	case self.RefMode == protocol.EvsRefMode_EVS_REF_GIT:
		return true
	case self.RefKind == protocol.EvsRefKind_EVS_REF_DEPOSIT || self.RefKind == protocol.EvsRefKind_EVS_REF_ERASURE:
		return true
	case self.RefKind == protocol.EvsRefKind_EVS_REF_OWNED && EvsRepoKindRecordClass(self.RepoKind):
		return true
	}
	return false
}

// Whether names sit under an index root on a ref of the context, and whether they name the root's settings file or
// any file of §11.14's at all. names nil, a path the reader holds no names of, is under none.
func (self *EvsVersioningContext) indexPath(names [][]byte) (under bool, settings bool, known bool) {
	if names == nil {
		return false, false, false
	}
	path := string(bytes.Join(names, []byte("/")))
	companion := self.Reserved == EvsReservedRefIndex
	if !companion {
		if self.Reserved != EvsReservedRefNone || self.RefMode != protocol.EvsRefMode_EVS_REF_FILE ||
			len(names) == 0 || !bytes.Equal(names[0], evsReservedIndexDirectory) {
			return false, false, false
		}
	}
	parsed, ok := indexParsePath(path, companion)
	if !ok {
		return true, false, false
	}
	return true, parsed.kind == indexPathSettings, true
}

// §11.7's setting and refused rows over one file version at names: nil accepts it, ErrEvsVersioningRefused refuses
// it, and ErrEvsVersionIgnored has the reader ignore it; a directory carries 0. See the file header.
func EvsCheckVersioning(context *EvsVersioningContext, names [][]byte, entry *protocol.EvsEntryVersion) error {
	versioning := protocol.EvsVersioning(entry.GetVersioning())
	directory := entry.GetKind() == uint32(protocol.EvsEntryKind_EVS_ENTRY_DIRECTORY)
	switch {
	case protocol.EvsVersioning_EVS_VERSIONING_INDEX < versioning:
		return fmt.Errorf("%w: versioning %d", ErrEvsVersioningRefused, versioning)
	case directory && versioning != protocol.EvsVersioning_EVS_VERSIONING_KEPT:
		return fmt.Errorf("%w: versioning %d on a directory", ErrEvsVersioningRefused, versioning)
	}
	versionless := versioning != protocol.EvsVersioning_EVS_VERSIONING_KEPT
	if versionless && context.refusesVersionless() {
		return fmt.Errorf("%w: versioning %d in a repo or on a ref that keeps every version", ErrEvsVersioningRefused, versioning)
	}
	if versioning == protocol.EvsVersioning_EVS_VERSIONING_VERSIONLESS && context.Locked {
		return fmt.Errorf("%w: versioning 1 in a push whose auth pin includes the lock", ErrEvsVersioningRefused)
	}
	if directory {
		return nil
	}
	under, settings, known := context.indexPath(names)
	switch {
	case under && !known:
		return fmt.Errorf("%w: a path under an index root that is none of the index's", ErrEvsVersionIgnored)
	case under && settings:
		if versionless {
			return fmt.Errorf("%w: an index's settings file written versionless", ErrEvsVersionIgnored)
		}
		return nil
	case under:
		if versioning != protocol.EvsVersioning_EVS_VERSIONING_INDEX {
			return fmt.Errorf("%w: versioning %d under an index root", ErrEvsVersionIgnored, versioning)
		}
		return nil
	case versioning == protocol.EvsVersioning_EVS_VERSIONING_INDEX && (names != nil || context.Reserved != EvsReservedRefNone):
		// a path the reader holds no names of, on a ref it knows by id alone, could sit under .ur-index/: it is
		// judged once a reader that holds its names reads it
		return fmt.Errorf("%w: versioning 2 outside an index root", ErrEvsVersionIgnored)
	}
	if context.Reserved == EvsReservedRefLfs && names != nil {
		lfsSettings := len(names) == 1 && string(names[0]) == evsLfsSettingsName
		want := protocol.EvsVersioning_EVS_VERSIONING_VERSIONLESS
		if lfsSettings {
			want = protocol.EvsVersioning_EVS_VERSIONING_KEPT
		}
		// in a locked repo the store writes 0, and a version written before the lock keeps its 1, which the lock
		// row above refuses only in a push whose auth pin includes it
		locked := context.Locked || context.LockUnjudged
		if versioning != want && !(versioning == protocol.EvsVersioning_EVS_VERSIONING_KEPT && !lfsSettings && locked) {
			return fmt.Errorf("%w: versioning %d on ur/lfs", ErrEvsVersionIgnored, versioning)
		}
	}
	return nil
}

// What one file version shows alone of §11.7's content row: kind-5 locators only in a versionless version, no inline
// record in one, a staged locator only as kind 5. ErrEvsVersioning names the breach.
func EvsCheckVersionShapeFormat2(entry *protocol.EvsEntryVersion) error {
	versionless := evsVersionless(entry)
	for _, locator := range entry.GetChain() {
		kind := protocol.EvsLocatorKind(locator.GetKind())
		switch {
		case kind == protocol.EvsLocatorKind_EVS_LOCATOR_VERSIONLESS_SEGMENT && !versionless:
			return fmt.Errorf("%w: a kind-5 locator in a versioned version", ErrEvsVersioning)
		case kind == protocol.EvsLocatorKind_EVS_LOCATOR_INLINE && versionless:
			return fmt.Errorf("%w: an inline record in a versionless version", ErrEvsVersioning)
		case locator.GetStaged() && kind != protocol.EvsLocatorKind_EVS_LOCATOR_VERSIONLESS_SEGMENT:
			return fmt.Errorf("%w: a staged locator that is not kind 5", ErrEvsVersioning)
		}
	}
	return nil
}

// The context of a version statement wrote in repoId, at the statement's own auth pin: the repo's kind and whether its
// lock stands there. reserved is the ref's, as the reader knows it. A pin before what the reader retains is not judged
// (QD-1178): the repo's kind is the newest state's, which its creation fixed, and its lock at the pin is left unjudged.
func (self *EvsVerifier) versioningContext(statement *EvsStatement, repoId Id, reserved EvsReservedRef) (*EvsVersioningContext, error) {
	push := statement.Push
	newest, err := self.config()
	if err != nil {
		return nil, err
	}
	state, err := newest.At(push.GetAuth())
	unjudged := errors.Is(err, ErrGkmAuthNotRetained)
	switch {
	case unjudged:
		state = newest
	case err != nil:
		return nil, fmt.Errorf("%w: its authorization pin: %w", ErrEvsStatementRefused, err)
	}
	repo := state.Repo(repoId)
	if repo == nil {
		return nil, fmt.Errorf("%w: a repo the state does not hold", ErrEvsStatementRefused)
	}
	return &EvsVersioningContext{
		RepoKind:     repo.GetKind(),
		RefKind:      protocol.EvsRefKind(push.GetRefKind()),
		RefMode:      protocol.EvsRefMode(push.GetRefMode()),
		Reserved:     reserved,
		Locked:       !unjudged && repo.GetLock() == protocol.RepoVersioningLock_REPO_VERSIONING_LOCK_LOCKED,
		LockUnjudged: unjudged,
	}, nil
}

// Format 2's checks of one version a statement wrote at names: its versioning where it sits and its shape. A refusal
// and an ignored version both alarm version_rule, naming the signer; ErrEvsVersionIgnored is the caller's to act on,
// by showing the path as holding no such version.
func (self *evsFormat2Rules) verifyVersion(verifier *EvsVerifier, repoId Id, refId Id, statement *EvsStatement, names [][]byte, reserved EvsReservedRef, entry *protocol.EvsEntryVersion) error {
	context, err := verifier.versioningContext(statement, repoId, reserved)
	if err != nil {
		return err
	}
	err = EvsCheckVersioning(context, names, entry)
	if err == nil {
		err = EvsCheckVersionShapeFormat2(entry)
		if err != nil {
			err = fmt.Errorf("%w: %w", ErrEvsVersioningRefused, err)
		}
	}
	if err != nil {
		verifier.client.alarm(repoId, refId, SidecarEvsAlarmVersionRule, "", evsSignerOf(statement.Bytes))
	}
	return err
}

// A format-2 statement's own rules beside the refs table (see the file header's CUT row): a CUT by a repo admin at the
// statement's state.
func (self *evsFormat2Rules) checkRefRules(state GkmAuthView, statement *EvsStatement, repoId Id, signerId Id) error {
	push := statement.Push
	if push.GetFlags()&uint32(protocol.EvsPushFlag_EVS_PUSH_CUT) != 0 {
		repo := state.Repo(repoId)
		if repo == nil || !evsRepoAdmin(state, repo, signerId) {
			return fmt.Errorf("%w: a CUT by a non-admin", ErrEvsStatementRefused)
		}
	}
	return nil
}

// Which reserved ref refId is in the repo, from K_ref, which is the same at every generation, so the two ids are
// derived once a repo and kept: none for any other ref, a deposit's or the erasure ref's among them.
func (self *evsFormat2Rules) reservedRef(ctx context.Context, repo *EvsRepo, refId Id) (EvsReservedRef, error) {
	ids, err := repo.reservedRefIds(ctx)
	if err != nil {
		return EvsReservedRefNone, err
	}
	switch refId {
	case ids.indexRefId:
		return EvsReservedRefIndex, nil
	case ids.lfsRefId:
		return EvsReservedRefLfs, nil
	}
	return EvsReservedRefNone, nil
}

// The repo's two reserved ref ids, derived on first use.
func (self *EvsRepo) reservedRefIds(ctx context.Context) (*evsReservedRefIds, error) {
	held := func() *evsReservedRefIds {
		self.client.stateLock.Lock()
		defer self.client.stateLock.Unlock()
		return self.client.repoIdReservedRefs[self.repoId]
	}()
	if held != nil {
		return held, nil
	}
	indexRefId, err := self.resolveRefId(ctx, EvsIndexRefName, nil)
	if err != nil {
		return nil, err
	}
	lfsRefId, err := self.resolveRefId(ctx, EvsLfsRefName, nil)
	if err != nil {
		return nil, err
	}
	ids := &evsReservedRefIds{indexRefId: indexRefId, lfsRefId: lfsRefId}
	self.client.stateLock.Lock()
	defer self.client.stateLock.Unlock()
	if self.client.repoIdReservedRefs == nil {
		self.client.repoIdReservedRefs = map[Id]*evsReservedRefIds{}
	}
	self.client.repoIdReservedRefs[self.repoId] = ids
	return ids, nil
}

// What a format-2 replay is told beside a push's statement and entry versions.
type EvsReplayFormat2 struct {
	// The push's ref.
	RefId Id
	// Where the push's versions sit, at its own auth pin (EvsVerifier.VersioningContext).
	Context *EvsVersioningContext
	// A changed path's raw names as the reader's tables hold them, nil for one it holds no names of; nil for a reader
	// that holds none.
	Names func(tokenPath EvsTokenPath) [][]byte
	// The newest committed version of a path the replay does not hold, at the entry version a change bases on or
	// removes: a replay that began above version 0 reads it from evs, verified as any version. nil, or a nil answer,
	// fails the push closed.
	Base func(tokenPath EvsTokenPath, entryVersion uint64) *protocol.EvsEntryVersion
	// The push's staged segments, and every segment its new-objects list names, each read with its kind-5 header
	// checked (EvsCitationSources).
	Staged             map[[sha256.Size]byte]bool
	VersionlessUploads map[[sha256.Size]byte]bool
	// The committed versions its reuse list names.
	Reuse []*EvsCitedVersion
}

// Apply, then format 2's rules over the push's new versions (see the file header's refused, ignored and cite rows):
// ErrEvsVersioningRefused for a version refused where it sits, ErrEvsVersioning for a breach of the citation rule,
// each of which refuses the push, and the token paths of the versions a reader ignores, whose paths it shows as
// holding none. Nothing of the replay's state moves on an error from the format-2 rules but what Apply moved.
func (self *EvsReplayPaths) ApplyFormat2(statement *EvsVerifiedStatement, changes []*EvsCheckedChange, entries map[string][]byte, format2 *EvsReplayFormat2) ([]EvsTokenPath, error) {
	// each changed path's newest version before this push
	baseOf := func(change *EvsCheckedChange) (*protocol.EvsEntryVersion, error) {
		baseEntryVersion := change.Change.GetBaseEntryVersion()
		if baseEntryVersion == 0 {
			return nil, nil
		}
		if held := self.paths[change.TokenPath.KeyString()]; held != nil {
			if held.entry == nil || held.entry.GetVersion() != baseEntryVersion {
				// Apply refuses it by the versions row
				return nil, nil
			}
			return held.entry, nil
		}
		if format2.Base != nil {
			if base := format2.Base(change.TokenPath, baseEntryVersion); base != nil {
				if base.GetVersion() != baseEntryVersion {
					return nil, fmt.Errorf("%w: a base at another version", ErrEvsEntryRefused)
				}
				return base, nil
			}
		}
		return nil, fmt.Errorf("%w: a base version the replay does not hold, so its citations go unjudged", ErrEvsEntryRefused)
	}
	bases := make([]*protocol.EvsEntryVersion, len(changes))
	for i, change := range changes {
		base, err := baseOf(change)
		if err != nil {
			return nil, err
		}
		bases[i] = base
	}
	if err := self.Apply(statement, changes, entries); err != nil {
		return nil, err
	}
	sources := &EvsCitationSources{
		RefId: format2.RefId, Staged: format2.Staged, VersionlessUploads: format2.VersionlessUploads, Reuse: format2.Reuse,
	}
	citations := []*EvsCitation{}
	ignored := []EvsTokenPath{}
	for i, change := range changes {
		entryBytes, writes := entries[change.TokenPath.KeyString()]
		if !writes {
			if bases[i] != nil {
				sources.Removed = append(sources.Removed, &EvsCitedVersion{RefId: format2.RefId, TokenPath: change.TokenPath, Entry: bases[i]})
			}
			continue
		}
		entry := &protocol.EvsEntryVersion{}
		if err := proto.Unmarshal(entryBytes, entry); err != nil {
			return nil, fmt.Errorf("%w: an entry that does not parse", ErrEvsEntryRefused)
		}
		var names [][]byte
		if format2.Names != nil {
			names = format2.Names(change.TokenPath)
		}
		if err := EvsCheckVersioning(format2.Context, names, entry); err != nil {
			if !errors.Is(err, ErrEvsVersionIgnored) {
				return nil, err
			}
			// ignored where it sits, and still held to the citation rule: what it names it must not take from another
			// path
			ignored = append(ignored, change.TokenPath)
		}
		citations = append(citations, &EvsCitation{TokenPath: change.TokenPath, Version: entry, Base: bases[i]})
	}
	if err := EvsCheckCitation(citations, sources); err != nil {
		return nil, err
	}
	return ignored, nil
}

// Where a statement's versions sit in repoId, at the statement's own auth pin, for a replay's EvsReplayFormat2.
func (self *EvsVerifier) VersioningContext(statement *EvsStatement, repoId Id, reserved EvsReservedRef) (*EvsVersioningContext, error) {
	return self.versioningContext(statement, repoId, reserved)
}

// A replaying reader's format-2 step over one verified push: the context at the push's own auth pin, then
// ApplyFormat2, whose refusals and ignored versions alarm version_rule, naming the signer. format2's Context is set
// here.
func (self *EvsVerifier) ReplayFormat2(repoId Id, refId Id, replay *EvsReplayPaths, reserved EvsReservedRef, statement *EvsVerifiedStatement, changes []*EvsCheckedChange, entries map[string][]byte, format2 *EvsReplayFormat2) ([]EvsTokenPath, error) {
	context, err := self.versioningContext(statement.Statement, repoId, reserved)
	if err != nil {
		return nil, err
	}
	told := *format2
	told.RefId = refId
	told.Context = context
	ignored, err := replay.ApplyFormat2(statement, changes, entries, &told)
	if 0 < len(ignored) || errors.Is(err, ErrEvsVersioning) || errors.Is(err, ErrEvsVersioningRefused) || errors.Is(err, ErrEvsVersionRule) {
		self.client.alarm(repoId, refId, SidecarEvsAlarmVersionRule, "", evsSignerOf(statement.Statement.Bytes))
	}
	return ignored, err
}
