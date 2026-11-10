// A client's path epochs (§11.6's read row; D-EVS-12; DESIGN-DETAILS 9.2.1 to 9.2.5): what a request may name of a
// path while a ref's entries live in two to four epochs, how a path is looked up without naming it, and what a push
// does when the epoch moves under it.
//
//	floor     the lowest epoch in which this device holds evidence evs was shown the path's token (9.2.3): E1 a
//	          verified version or removal whose statement names the path's own token path in its epoch; E2 a verified
//	          row of the path in its parent's table, its token the reader's own for the row's epoch; E3 a request of
//	          this device naming the path in an epoch that evs answered, any status, a transport failure not; E4 the
//	          push a verified version names as its predecessor, its statement declaring an epoch. A floor only falls,
//	          and only on evidence: a lost record loses it, which only sends less. The root has no token and no floor
//	rules     a path with floor f, on a ref whose verified state is (cur, S), is named in cur, in each s of S at or
//	          above f, in its record's PinEpoch when that is at or above f, and in any other epoch at or above f whose
//	          statements the verifier needs proofs under; never below f. A path with no floor is a new name: named in
//	          cur alone, only on a state verified within EpochFresh and, on a blocking ref, with no immediate pressure
//	          (quiet); a read of one needs S empty besides. Otherwise it is looked up
//	lookup    a path P/name with no floor is found through P's verified listing at the head, which names no token of
//	          it: no row, it is absent; a row, its epoch is the floor (E2). A lookup recurses to the first directory
//	          with a floor, at the latest to the root, each level one round at most and cached for the head version
//	          (ListingCacheCount listings, in memory)
//	read      (9.2.4) a round names each path by the rules, verifies the head, and starts again on a head of another
//	          epoch state once it has pinned it; it verifies each path in each statement's own epoch, asks once more
//	          for an epoch a rooted statement needs a proof in, takes a miss as absent only when every listed source
//	          was asked or the parent's table has no row for the name, and then pins and writes the records' floors
//	pressure  on a blocking ref (a shared or owned ref of a general, config or mailcfg repo), a head that records a due
//	          above cur, else the newest generation this device holds above max(the head's generation, cur) whose
//	          GenRotate cause is REMOVE, classed by evs's own rule (EvsClassifyPathEpochDue): immediate holds new
//	          names. A ref with no head takes none, since its first push creates in epoch 1 and records the due itself
//	          (question evs1-m2-44-new-ref-crossing, option 1, as landed)
//	exempt    deposit and erasure refs name entries by random ids under no path key, stay at path epoch 1 for life,
//	          and take neither floors nor rules: every push on them declares epoch 1 and can meet neither 412
//	          PATH_EPOCH nor PATH_EPOCH_DUE (plan-EVS1-epoch-kinds #2)
//	retoken   a push refused 412 PATH_EPOCH never commits, since the epoch only rises; the sender lowers the floor of
//	          every path it named to its epoch (E3), reads the new head, and sends it again with every sealed byte
//	          kept and every token made again in the new epoch (evs_push.go, EvsWritePlan.Retoken)
//
// What the rules leave is one window, published in §11.5: a new name's token sent on a head at most EpochFreshFor
// old can reach evs after a cut-over committed in between, under the epoch just left.
//
// The ref epoch held for a ref is the epoch state of the last head this client verified, with the time it verified
// it, in memory only, as is the listing cache.
//
// On every leg. Package-level functions are safe for concurrent use; the client's epoch state is under its stateLock.

package sidecar

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// Whether a ref of refKind is a deposit or the erasure ref: see the file header.
func evsEpochExempt(refKind protocol.EvsRefKind) bool {
	return refKind == protocol.EvsRefKind_EVS_REF_DEPOSIT || refKind == protocol.EvsRefKind_EVS_REF_ERASURE
}

// floor lowered by evidence of epoch, 0 meaning none.
func evsLowerFloor(floor uint64, epoch uint64) uint64 {
	if epoch == 0 {
		return floor
	}
	if floor == 0 || epoch < floor {
		return epoch
	}
	return floor
}

// A head's current path epoch: 1 before a ref's first PATH_EPOCH.
func evsCurrentEpoch(epoch *protocol.EvsPathEpoch) uint64 {
	return max(1, epoch.GetCurrent())
}

// The epochs a head lists as sources, newest first.
func evsSourceEpochs(epoch *protocol.EvsPathEpoch) []uint64 {
	sources := make([]uint64, 0, len(epoch.GetSources()))
	for _, source := range epoch.GetSources() {
		sources = append(sources, source.GetEpoch())
	}
	return sources
}

// Whether two path epochs name the same current epoch and sources.
func evsSamePathEpoch(a *protocol.EvsPathEpoch, b *protocol.EvsPathEpoch) bool {
	if evsCurrentEpoch(a) != evsCurrentEpoch(b) || len(a.GetSources()) != len(b.GetSources()) {
		return false
	}
	for i, source := range a.GetSources() {
		if source.GetEpoch() != b.GetSources()[i].GetEpoch() {
			return false
		}
	}
	return true
}

// What the rules let one request name of a path with floor (0 none), on a ref whose verified epoch state is epoch:
// epochs, cur first; else lookup, when the path has no floor and the new-name rule does not hold; else needFresh, when
// it would hold on a state verified within EpochFreshFor (see the file header). pinEpoch is the path's record's,
// 0 for none, and more the epochs the verifier asked for. Never an epoch below the floor.
func evsEpochTokens(epoch *protocol.EvsPathEpoch, floor uint64, pinEpoch uint64, more []uint64, quiet bool, fresh bool) (epochs []uint64, lookup bool, needFresh bool) {
	current := evsCurrentEpoch(epoch)
	sources := evsSourceEpochs(epoch)
	if floor == 0 {
		switch {
		case len(sources) != 0 || !quiet:
			return nil, true, false
		case !fresh:
			return nil, false, true
		}
		return []uint64{current}, false, false
	}
	epochs = []uint64{current}
	add := func(e uint64) {
		if floor <= e && e <= current && !slices.Contains(epochs, e) {
			epochs = append(epochs, e)
		}
	}
	for _, source := range sources {
		add(source)
	}
	add(pinEpoch)
	for _, e := range more {
		add(e)
	}
	return epochs, false, false
}

// The epoch state of the last head this client verified for a ref, and when it verified it.
type evsRefEpoch struct {
	refId      Id
	epoch      *protocol.EvsPathEpoch
	verifiedAt time.Time
	// the head's version, generation pin and ref kind
	version    uint64
	generation uint64
	refKind    protocol.EvsRefKind
}

// The ref's epoch state as the last verified head gave it, nil when this client has verified none.
func (self *EvsClient) refEpochState(repoId Id, refId Id) *evsRefEpoch {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.refEpochs[evsRefKey{repoId: repoId, refId: refId}]
}

// Keeps a verified head's epoch state, verified now, unless a newer head's is held, and drops the listings cached
// below it once it moves the epoch state; then raises the overdue alarm it calls for (evs_epoch.go).
func (self *EvsClient) noteVerifiedHead(repoId Id, refId Id, head *protocol.EvsHeadSummary) {
	noted := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		key := evsRefKey{repoId: repoId, refId: refId}
		held := self.refEpochs[key]
		if held != nil && head.GetVersion() < held.version {
			return false
		}
		self.refEpochs[key] = &evsRefEpoch{
			refId:      refId,
			epoch:      head.GetPathEpoch(),
			verifiedAt: self.clock.Now(),
			version:    head.GetVersion(),
			generation: head.GetGeneration(),
			refKind:    head.GetRefKind(),
		}
		return true
	}()
	if noted {
		self.epochs.noteHead(self, repoId, refId, head)
	}
}

// Whether a state was verified within EpochFreshFor.
func (self *EvsClient) epochFresh(state *evsRefEpoch) bool {
	return state != nil && self.clock.Now().Sub(state.verifiedAt) <= self.settings.EpochFreshFor
}

// One round for the ref's head alone (§11.9's read with no path), verified from the pin and pinned, its epoch state
// kept: what a read does first when it holds no epoch state for the ref or a new name needs a fresh one, and what a
// retoken waits on.
func (self *EvsRepo) readHeadAlone(ctx context.Context, refId Id, fresh bool) (*EvsVerifiedHead, error) {
	fromVersion := uint64(0)
	fromChain := EvsChainStart(self.repoId, refId)
	pin, pinned, err := self.client.pins.Pin(self.repoId, refId)
	if err != nil {
		return nil, err
	}
	if pinned {
		fromVersion, fromChain = pin.Version, pin.Chain
		if pin.Version < self.client.hintedVersion(self.repoId, refId) {
			fresh = true
		}
	}
	reply, objects, err := self.client.postRead(ctx, self.repoId, &protocol.EvsReadRequest{RefId: refId.Bytes(), PinVersion: fromVersion, Fresh: fresh})
	if err != nil {
		return nil, err
	}
	objects.close()
	head, err := self.client.verifier.VerifyHead(ctx, &EvsHeadRead{
		RepoId:      self.repoId,
		RefId:       refId,
		Head:        reply.head,
		FromVersion: fromVersion,
		FromChain:   fromChain,
		Statements:  reply.statements,
		Behind:      reply.behind,
	})
	if err != nil {
		return nil, err
	}
	if err := self.client.verifier.Pin(head); err != nil {
		return nil, err
	}
	self.client.noteVerifiedHead(self.repoId, refId, head.Head)
	return head, nil
}

// The ref's head read fresh until its current epoch is above epoch: what a push refused 412 PATH_EPOCH waits for
// before it is re-tokenized (DESIGN-DETAILS 9.2.5). evs refuses a push's epoch only when its head's current epoch
// differs, and the current epoch only rises, so a head that still shows epoch is a cache or a lagging read, asked
// again after ReadRetryWait at most ReadRetryCount times.
func (self *EvsRepo) readHeadPast(ctx context.Context, refId Id, epoch uint64) (*EvsVerifiedHead, error) {
	for attempt := 0; ; attempt += 1 {
		head, err := self.readHeadAlone(ctx, refId, true)
		if err != nil {
			return nil, err
		}
		if epoch < evsCurrentEpoch(head.Head.GetPathEpoch()) {
			return head, nil
		}
		if self.client.settings.ReadRetryCount <= attempt {
			return nil, fmt.Errorf("%w: a head still in path epoch %d after 412 PATH_EPOCH", ErrEvsReplyInvalid, epoch)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-self.client.clock.After(self.client.settings.ReadRetryWait):
		}
	}
}

// How a ref's coming epoch weighs on new names (see the file header's pressure row).
type evsPressure int

const (
	evsPressureNone evsPressure = iota
	evsPressureBatched
	evsPressureImmediate
)

// The pressure on a ref whose verified state is state, from its head's due, else from the REMOVE generations this
// device holds above it. A generation gkm does not answer for reads as immediate, as evs reads a crossing it cannot
// judge: failing closed holds new names, never sends one.
func (self *EvsRepo) pressure(ctx context.Context, state *evsRefEpoch) (evsPressure, uint64, error) {
	epoch := state.epoch
	current := evsCurrentEpoch(epoch)
	if current < epoch.GetDueGeneration() {
		if epoch.GetDueBlocksCreation() {
			return evsPressureImmediate, epoch.GetDueGeneration(), nil
		}
		return evsPressureBatched, epoch.GetDueGeneration(), nil
	}
	if state.version == 0 && self.client.epochs.committedVersion(self.repoId, state.refId) == 0 {
		// a ref with no head, which no push of this device has given one either
		return evsPressureNone, 0, nil
	}
	newest, err := self.client.args.Gkm.CurrentRepoKey(ctx, self.repoId)
	if err != nil {
		return evsPressureNone, 0, err
	}
	from := max(state.generation, current)
	removal := uint64(0)
	for generation := from + 1; generation <= newest.Generation(); generation += 1 {
		key, err := self.client.args.Gkm.RepoKey(ctx, self.repoId, generation)
		if err != nil {
			return evsPressureImmediate, generation, nil
		}
		if key.Cause() == GkmCauseRemove {
			removal = generation
		}
	}
	if removal == 0 {
		return evsPressureNone, 0, nil
	}
	self.client.epochs.noteHeldRemoval(self.repoId, removal, self.client.clock.Now())
	immediate := true
	if fromKey, err := self.client.args.Gkm.RepoKey(ctx, self.repoId, from); err == nil {
		if config, err := self.client.verifier.config(); err == nil {
			if repo := config.Repo(self.repoId); repo != nil {
				immediate = EvsClassifyPathEpochDue(repo.GetHoldersShrunkAt(), fromKey.Auth().GetVersion())
			}
		}
	}
	if immediate {
		return evsPressureImmediate, removal, nil
	}
	return evsPressureBatched, removal, nil
}

// Whether new names may be sent on the ref (9.2.3's quiet): always on a ref whose kind never blocks creation, else
// only without immediate pressure.
func (self *EvsRepo) quiet(ctx context.Context, state *evsRefEpoch) (bool, error) {
	repoKind, err := self.repoKind()
	if err != nil {
		return false, err
	}
	refKind := state.refKind
	if refKind == protocol.EvsRefKind_EVS_REF_KIND_UNSPECIFIED {
		// a ref no push created yet is created shared or owned, as a file-mode write makes it
		refKind = protocol.EvsRefKind_EVS_REF_SHARED
	}
	if !EvsRefBlocksCreation(repoKind, refKind) {
		return true, nil
	}
	pressure, _, err := self.pressure(ctx, state)
	if err != nil {
		return false, err
	}
	return pressure != evsPressureImmediate, nil
}

// One row of a directory's verified listing: its child's kind and the epoch it opened under, which is that child's
// E2 floor.
type evsListedRow struct {
	kind  protocol.EvsEntryKind
	epoch uint64
	token EvsToken
}

// A directory's verified listing at a head version: its rows by raw name, nil for a directory that does not stand.
type evsListedDirectory struct {
	headVersion uint64
	rows        map[string]*evsListedRow
}

// The client's path-epoch state beside its ref epochs: the listing cache, and the overdue alarm's and the mapper's
// bookkeeping (evs_epoch.go). Under its own lock, never held across I/O.
type evsClientEpochs struct {
	stateLock sync.Mutex
	// (repo, ref, directory) to its newest cached listings by head version, oldest first in order
	listings map[evsListingKey]*evsListedDirectory
	order    []evsListingKey
	// the first time this device held each REMOVE generation of a repo, which the overdue alarm counts from
	heldRemovals map[evsHeldRemovalKey]time.Time
	// per ref: when it first showed fewer than two sources after showing two, and the last alarm per due generation
	refAlarms map[evsRefKey]*evsRefAlarm
	// per ref, closed at its next verified head (evs_epoch.go's moved)
	waiters map[evsRefKey]chan struct{}
	// what a mapper on this device says of a ref's job, nil until one registers (evs_epoch_map.go)
	mapperStatus evsMapperStatusFunction
	// the client's *evsMapper, made on first use: untyped here, since the mapper's files stay off the ios_extension
	// leg, which links this one
	mapper any
	// per ref, the newest version a push of this device committed at: a ref with a head though no verified one shows it
	committed map[evsRefKey]uint64
	// per repo, the newest generation this device's own EnsureWritable returned, which a mapper starts at once for
	writable map[Id]uint64
}

// A cached listing's key.
type evsListingKey struct {
	repoId      Id
	refId       Id
	headVersion uint64
	directory   string
}

// A held REMOVE generation's key.
type evsHeldRemovalKey struct {
	repoId     Id
	generation uint64
}

// A new client's epoch state.
func newEvsClientEpochs() *evsClientEpochs {
	return &evsClientEpochs{
		listings:     map[evsListingKey]*evsListedDirectory{},
		heldRemovals: map[evsHeldRemovalKey]time.Time{},
		refAlarms:    map[evsRefKey]*evsRefAlarm{},
		waiters:      map[evsRefKey]chan struct{}{},
		committed:    map[evsRefKey]uint64{},
		writable:     map[Id]uint64{},
	}
}

// Notes the generation this device's own EnsureWritable returned for a repo.
func (self *evsClientEpochs) noteWritable(repoId Id, generation uint64) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.writable[repoId] = max(self.writable[repoId], generation)
}

// Whether this device's own EnsureWritable returned generation, so it rotated to it and maps at once.
func (self *evsClientEpochs) rotatedTo(repoId Id, generation uint64) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.writable[repoId] == generation
}

// Notes a push of this device committed on a ref at version.
func (self *evsClientEpochs) noteCommitted(repoId Id, refId Id, version uint64) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	key := evsRefKey{repoId: repoId, refId: refId}
	self.committed[key] = max(self.committed[key], version)
}

// The newest version a push of this device committed at on a ref, 0 for none.
func (self *evsClientEpochs) committedVersion(repoId Id, refId Id) uint64 {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.committed[evsRefKey{repoId: repoId, refId: refId}]
}

// The listing cached for a directory at headVersion, nil when none is.
func (self *evsClientEpochs) cachedListing(repoId Id, refId Id, headVersion uint64, directory string) *evsListedDirectory {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.listings[evsListingKey{repoId: repoId, refId: refId, headVersion: headVersion, directory: directory}]
}

// Caches a directory's listing at its head version, the oldest out past count.
func (self *evsClientEpochs) cacheListing(repoId Id, refId Id, directory string, listing *evsListedDirectory, count int) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	key := evsListingKey{repoId: repoId, refId: refId, headVersion: listing.headVersion, directory: directory}
	if _, held := self.listings[key]; !held {
		self.order = append(self.order, key)
	}
	self.listings[key] = listing
	for count < len(self.order) {
		delete(self.listings, self.order[0])
		self.order = self.order[1:]
	}
}

// The lowest epoch any cached listing's row for path shows, 0 for none: E2 does not lapse with the head version.
func (self *evsClientEpochs) cachedRowFloor(repoId Id, refId Id, path string) uint64 {
	if path == "" {
		return 0
	}
	parent, name := evsSplitParent(path)
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	floor := uint64(0)
	for key, listing := range self.listings {
		if key.repoId != repoId || key.refId != refId || key.directory != parent || listing.rows == nil {
			continue
		}
		if row := listing.rows[string(name)]; row != nil {
			floor = evsLowerFloor(floor, row.epoch)
		}
	}
	return floor
}

// Notes that this device holds a REMOVE generation of a repo, the first time it does.
func (self *evsClientEpochs) noteHeldRemoval(repoId Id, generation uint64, now time.Time) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	key := evsHeldRemovalKey{repoId: repoId, generation: generation}
	if _, held := self.heldRemovals[key]; !held {
		self.heldRemovals[key] = now
	}
}

// When this device first held a REMOVE generation of a repo, zero when it never noted one.
func (self *evsClientEpochs) heldRemovalSince(repoId Id, generation uint64) time.Time {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.heldRemovals[evsHeldRemovalKey{repoId: repoId, generation: generation}]
}

// The listing of directory at the ref's head: cached for the head version this client verified last, else read and
// opened, then cached. nil rows when the directory does not stand.
func (self *EvsRepo) listingAt(ctx context.Context, refId Id, directory string) (*evsListedDirectory, error) {
	if state := self.client.refEpochState(self.repoId, refId); state != nil {
		if listing := self.client.epochs.cachedListing(self.repoId, refId, state.version, directory); listing != nil {
			return listing, nil
		}
	}
	result, err := self.readPaths(ctx, refId, []*evsReadPath{{path: directory}}, false)
	if err != nil {
		return nil, err
	}
	defer result.objects.close()
	listing := &evsListedDirectory{headVersion: result.head.Version}
	verified := result.replies[0]
	switch {
	case verified.Base != nil:
		return nil, ErrEvsOverlayBase
	case verified.Removal != nil || verified.Absent || verified.Entry == nil:
	case verified.Entry.GetKind() != uint32(protocol.EvsEntryKind_EVS_ENTRY_DIRECTORY):
	default:
		opened, err := self.openListing(ctx, result, 0)
		if err != nil {
			return nil, err
		}
		listing.rows = map[string]*evsListedRow{}
		for token, row := range opened {
			listing.rows[string(row.name)] = &evsListedRow{kind: row.kind, epoch: row.epoch, token: token}
		}
	}
	self.client.epochs.cacheListing(self.repoId, refId, directory, listing, self.client.settings.ListingCacheCount)
	return listing, nil
}

// A path's row in its parent's verified listing at the head, nil when the parent does not stand or holds no row for
// the name (9.2.4's lookup): what a path with no floor is found by, sending no token of it.
func (self *EvsRepo) lookup(ctx context.Context, refId Id, path string) (*evsListedRow, error) {
	parent, name := evsSplitParent(path)
	listing, err := self.listingAt(ctx, refId, parent)
	if err != nil {
		return nil, err
	}
	if listing.rows == nil {
		return nil, nil
	}
	return listing.rows[string(name)], nil
}

// One opened row of a listing: the child's raw name, kind, the epoch it opened under, and the source epoch a carried
// row keeps, else 0.
type evsOpenedRow struct {
	name    []byte
	kind    protocol.EvsEntryKind
	epoch   uint64
	carried uint64
}

// The rows of the directory result reads at index, opened and checked, by token: the folded table, whose untagged rows
// open under entry_epoch (0: the head's current one) and carried rows under their own epoch, then each delta after it
// in version order, a walked delta's rows under its statement's epoch and one below the walk under the current epoch
// (DESIGN-DETAILS 9.3's W1), each delta adding or replacing rows and removing the tokens it lists. Every row opens
// under its own epoch's keys and AAD and is checked against its token, recomputed from the directory's token in that
// epoch, since evs folds the table itself and only the token ties a row to a path. Any failure refuses the whole
// listing, alarmed as tamper.
func (self *EvsRepo) openListing(ctx context.Context, result *evsReadResult, index int) (map[EvsToken]*evsOpenedRow, error) {
	verified := result.replies[index]
	names := result.paths[index].names
	epochKeys := func(epoch uint64) (*EvsManifestKey, *EvsPathKey, EvsToken, error) {
		manifest, err := result.keys.manifest(ctx, epoch)
		if err != nil {
			return nil, nil, EvsToken{}, err
		}
		pathKey, err := result.keys.path(ctx, epoch)
		if err != nil {
			return nil, nil, EvsToken{}, err
		}
		tokenPath, err := EvsPathTokens(pathKey, names)
		if err != nil {
			return nil, nil, EvsToken{}, err
		}
		return manifest, pathKey, tokenPath.Last(), nil
	}
	children := map[EvsToken]*evsOpenedRow{}
	apply := func(table *protocol.EvsNameTable, tableEpoch uint64) error {
		if table == nil {
			return nil
		}
		opened, err := EvsOpenNameTable(table, tableEpoch, epochKeys)
		if err != nil {
			self.client.alarm(self.repoId, result.refId, SidecarEvsAlarmTamper, result.paths[index].path, nil)
			return err
		}
		for _, removed := range table.GetRemovedTokens() {
			delete(children, EvsToken(removed))
		}
		for _, name := range opened {
			epoch := tableEpoch
			if name.Epoch != 0 {
				epoch = name.Epoch
			}
			children[name.Token] = &evsOpenedRow{name: name.Name, kind: name.Kind, epoch: epoch, carried: name.Epoch}
		}
		return nil
	}
	headEpoch := evsCurrentEpoch(result.head.Head.GetPathEpoch())
	if verified.Names != nil {
		tableEpoch := headEpoch
		if verified.EntryEpoch != 0 {
			tableEpoch = verified.EntryEpoch
		}
		if err := apply(verified.Names, tableEpoch); err != nil {
			return nil, err
		}
	} else if err := apply(verified.Entry.GetNames(), max(1, verified.Statement.Push.GetPathEpoch())); err != nil {
		return nil, err
	}
	for _, delta := range verified.Deltas {
		deltaEpoch := headEpoch
		if delta.Statement != nil {
			deltaEpoch = max(1, delta.Statement.Push.GetPathEpoch())
		}
		if err := apply(delta.Entry.GetNames(), deltaEpoch); err != nil {
			return nil, err
		}
	}
	return children, nil
}

// A read that took more rounds than ReadEpochRoundCount: evs moving the epoch state or the walk's needs each round.
var errEvsReadRounds = errors.New("evs: a read past its rounds")

// Reads paths of a ref by DESIGN-DETAILS 9.2.4's loop (see the file header's read row): each path's request named by
// the rules, a path with no floor looked up first where they need it, the head verified, the round started again on a
// head of another epoch state once it is pinned, each path verified in its statements' own epochs and asked once more
// for an epoch the walk needs, a miss settled by its sources or its parent's table, then the read records' rule, the
// pin, and the records raised with their floors. A path's own failure fails the read: the caller asked for it.
func (self *EvsRepo) readPaths(ctx context.Context, refId Id, paths []*evsReadPath, fresh bool) (*evsReadResult, error) {
	keys := newEvsReadKeys(self)
	for _, path := range paths {
		if path.token != nil {
			continue
		}
		names, err := evsReadPathNames(path.path)
		if err != nil {
			return nil, err
		}
		path.names = names
		record, ok, err := self.client.pins.ReadRecord(self.repoId, refId, path.path)
		if err != nil {
			return nil, err
		}
		if ok {
			path.record = record
			path.floor = evsLowerFloor(path.floor, record.Floor)
		}
		path.floor = evsLowerFloor(path.floor, self.client.epochs.cachedRowFloor(self.repoId, refId, path.path))
	}
	if len(paths) == 0 {
		// the head alone, verified and pinned as any round's
		round, err := self.readRound(ctx, refId, keys, nil, fresh)
		if err != nil {
			return nil, err
		}
		return self.finishRead(ctx, refId, keys, round, nil)
	}
	// the caller's fresh goes to the first request this call sends
	roundFresh := fresh
	for roundCount := 0; ; roundCount += 1 {
		if self.client.settings.ReadEpochRoundCount <= roundCount {
			return nil, errEvsReadRounds
		}
		state := self.client.refEpochState(self.repoId, refId)
		if state == nil {
			if _, err := self.readHeadAlone(ctx, refId, roundFresh); err != nil {
				return nil, err
			}
			roundFresh = false
			continue
		}
		asked, needFresh, err := self.choose(ctx, refId, keys, state, paths)
		if err != nil {
			return nil, err
		}
		if needFresh {
			if _, err := self.readHeadAlone(ctx, refId, roundFresh); err != nil {
				return nil, err
			}
			roundFresh = false
			continue
		}
		if moved := self.client.refEpochState(self.repoId, refId); moved != state && !evsSamePathEpoch(moved.epoch, state.epoch) {
			// a lookup's read pinned a head of another epoch state: choose again on it
			continue
		}
		round, err := self.readRound(ctx, refId, keys, asked, roundFresh)
		if err != nil {
			return nil, err
		}
		roundFresh = false
		if !evsSamePathEpoch(round.head.Head.GetPathEpoch(), state.epoch) {
			// a head of another epoch state: pinned, adopted, and every path asked again on it
			round.objects.close()
			if err := self.client.verifier.Pin(round.head); err != nil {
				return nil, err
			}
			self.client.noteVerifiedHead(self.repoId, refId, round.head.Head)
			continue
		}
		again, err := self.verifyRound(ctx, refId, state, round, asked)
		if err != nil {
			round.objects.close()
			return nil, err
		}
		if again {
			round.objects.close()
			continue
		}
		return self.finishRead(ctx, refId, keys, round, paths)
	}
}

// Chooses each path's epochs for one round on state, looking up a path with no floor where the rules need it: the
// paths to ask, or needFresh when a new name waits on a state verified within EpochFreshFor. A path a lookup finds no
// row for is settled absent with no token of it sent.
func (self *EvsRepo) choose(ctx context.Context, refId Id, keys *evsReadKeys, state *evsRefEpoch, paths []*evsReadPath) ([]*evsReadPath, bool, error) {
	current := evsCurrentEpoch(state.epoch)
	var quiet *bool
	fresh := self.client.epochFresh(state)
	asked := []*evsReadPath{}
	for _, path := range paths {
		// each round chooses afresh on its state, a lookup hitting the listing cache while the head stands
		path.epochs, path.settled, path.verified = nil, nil, nil
		if path.token != nil {
			// an id in epoch 1, which deposit and erasure refs never leave
			if current != 1 {
				return nil, false, fmt.Errorf("%w: an exempt ref in path epoch %d", ErrEvsReplyInvalid, current)
			}
			path.epochs, path.current, path.named = []uint64{1}, path.token, map[uint64]bool{1: true}
			path.epochPaths = []*protocol.EvsSourcePath{{Epoch: 1, TokenPath: path.token.Components()}}
			asked = append(asked, path)
			continue
		}
		if path.path == "" {
			path.epochs = []uint64{current}
		} else {
			if quiet == nil && path.floor == 0 {
				value, err := self.quiet(ctx, state)
				if err != nil {
					return nil, false, err
				}
				quiet = &value
			}
			pinEpoch := uint64(0)
			if path.record != nil {
				pinEpoch = path.record.PinEpoch
			}
			epochs, lookup, needFresh := evsEpochTokens(state.epoch, path.floor, pinEpoch, path.more, quiet != nil && *quiet, fresh)
			if needFresh {
				return nil, true, nil
			}
			if lookup {
				row, err := self.lookup(ctx, refId, path.path)
				if err != nil {
					return nil, false, err
				}
				path.lookedUp = true
				if row == nil {
					path.settled = &EvsVerifiedPath{Absent: true}
					continue
				}
				path.floor = evsLowerFloor(path.floor, row.epoch)
				epochs, _, _ = evsEpochTokens(state.epoch, path.floor, pinEpoch, path.more, true, true)
			}
			path.epochs = epochs
		}
		if min(self.client.settings.ReadEpochCount, EvsReadPathMaxEpochCount) < len(path.epochs) {
			return nil, false, fmt.Errorf("%w: a path named in %d epochs", ErrEvsReplyInvalid, len(path.epochs))
		}
		path.epochPaths = nil
		path.named = map[uint64]bool{}
		for _, epoch := range path.epochs {
			tokenPath, err := keys.tokenPathIn(ctx, path.names, epoch)
			if err != nil {
				return nil, false, err
			}
			if epoch == current {
				path.current = tokenPath
			}
			path.epochPaths = append(path.epochPaths, &protocol.EvsSourcePath{Epoch: epoch, TokenPath: tokenPath.Components()})
			path.named[epoch] = true
		}
		asked = append(asked, path)
	}
	return asked, false, nil
}

// Verifies one round's asked paths on its head, whose epoch state is state's: E3 for each epoch asked, each path's
// reply in its statements' own epochs, E1 from what verifies; again when a path needs another round: an epoch the
// walk needs a proof in, a statement alone whose epoch the path may be named in, or a miss whose sources were not
// all asked, which the parent's table settles.
func (self *EvsRepo) verifyRound(ctx context.Context, refId Id, state *evsRefEpoch, round *evsReadRound, asked []*evsReadPath) (bool, error) {
	if len(round.reply.paths) != len(asked) {
		return false, fmt.Errorf("%w: %d path replies for %d paths", ErrEvsReplyInvalid, len(round.reply.paths), len(asked))
	}
	sources := evsSourceEpochs(state.epoch)
	again := false
	for i, path := range asked {
		// evs answered a request naming the path in each of these epochs (E3)
		for _, epoch := range path.epochs {
			path.floor = evsLowerFloor(path.floor, epoch)
		}
		since := round.refPinVersion
		if path.record != nil {
			since = path.record.PinVersion
		}
		tokenPathIn := func(epoch uint64) (EvsTokenPath, error) { return round.keys.tokenPathIn(ctx, path.names, epoch) }
		if path.token != nil {
			tokenPathIn = func(epoch uint64) (EvsTokenPath, error) {
				if epoch != 1 {
					return nil, fmt.Errorf("%w: an exempt ref's statement of path epoch %d", ErrEvsEntryRefused, epoch)
				}
				return path.token, nil
			}
		}
		epochs := &EvsPathEpochs{
			TokenPathIn: tokenPathIn,
			Named:       path.named,
			History:     path.version != 0,
			Since:       since,
		}
		verified, more, err := self.client.verifier.VerifyPath(round.head, epochs, round.reply.paths[i])
		if err != nil {
			return false, err
		}
		path.floor = evsLowerFloor(path.floor, verified.Floor)
		if alone := verified.StatementAlone; alone != nil {
			epoch := max(1, alone.Push.GetPathEpoch())
			named, err := self.statementNames(ctx, round.keys, alone, path)
			if err != nil {
				return false, err
			}
			if path.named[epoch] || !named {
				return false, fmt.Errorf("%w: a statement alone that names nothing of the path", ErrEvsEntryRefused)
			}
			path.floor = evsLowerFloor(path.floor, epoch)
			path.more = append(path.more, epoch)
			again = true
			continue
		}
		if 0 < len(more) {
			if path.moreAsked {
				return false, fmt.Errorf("%w: a later statement's change list with no proof the path is absent", ErrEvsEntryRefused)
			}
			path.moreAsked = true
			path.more = append(path.more, more...)
			again = true
			continue
		}
		if verified.Absent && path.version == 0 && path.path != "" && path.token == nil {
			allAsked := true
			for _, source := range sources {
				allAsked = allAsked && path.named[source]
			}
			if !allAsked && !path.lookedUp {
				row, err := self.lookup(ctx, refId, path.path)
				if err != nil {
					return false, err
				}
				path.lookedUp = true
				if row != nil && row.epoch < path.floor {
					path.floor = row.epoch
					again = true
					continue
				}
			}
		}
		path.verified = verified
	}
	return again, nil
}

// Whether a statement evs sent alone names the path: its inline list holds the path's own token path in the
// statement's epoch (E1), or its push is the one the newer version names as its predecessor (E4).
func (self *EvsRepo) statementNames(ctx context.Context, keys *evsReadKeys, statement *EvsStatement, path *evsReadPath) (bool, error) {
	if 0 < len(path.prevPushId) && string(statement.Push.GetPushId()) == string(path.prevPushId) {
		return true, nil
	}
	tokenPath, err := keys.tokenPathIn(ctx, path.names, max(1, statement.Push.GetPathEpoch()))
	if err != nil {
		return false, err
	}
	for _, change := range statement.Changes {
		if change.TokenPath.Equal(tokenPath) {
			return true, nil
		}
	}
	return false, nil
}

// Ends a read: the records' rule over each path, the pin, and each record raised with its floor and the epoch it is
// pinned in. A path a lookup settled absent was never asked, so its record, which a lookup never consults, keeps.
func (self *EvsRepo) finishRead(ctx context.Context, refId Id, keys *evsReadKeys, round *evsReadRound, paths []*evsReadPath) (*evsReadResult, error) {
	head := round.head
	current := evsCurrentEpoch(head.Head.GetPathEpoch())
	verifiedPaths := []*EvsVerifiedPath{}
	for _, path := range paths {
		verified := path.verified
		if verified == nil {
			verified = path.settled
			tokenPath, err := keys.tokenPathIn(ctx, path.names, current)
			if err != nil {
				round.objects.close()
				return nil, err
			}
			verified.TokenPath = tokenPath
			path.current = tokenPath
		} else if path.version == 0 && path.record != nil &&
			(verified.Absent || (verified.Entry != nil && verified.Entry.GetVersion() < path.record.EntryVersion)) {
			// an older version asked for by number is history, not a rollback, and a path this device read a version
			// of is never absent: removed at most
			round.objects.close()
			self.client.alarm(self.repoId, refId, SidecarEvsAlarmTamper, path.path, nil)
			return nil, fmt.Errorf("%w: a version below the one this device read", ErrEvsEntryRefused)
		}
		verifiedPaths = append(verifiedPaths, verified)
	}
	if err := self.client.verifier.Pin(head); err != nil {
		round.objects.close()
		return nil, err
	}
	self.client.noteVerifiedHead(self.repoId, refId, head.Head)
	records := []*EvsReadRecord{}
	for i, path := range paths {
		if path.version != 0 || verifiedPaths[i].Entry == nil || path.token != nil {
			continue
		}
		chain := head.Chain
		records = append(records, &EvsReadRecord{
			RefId:        refId,
			Path:         path.path,
			EntryVersion: verifiedPaths[i].Entry.GetVersion(),
			PinVersion:   head.Version,
			PinChain:     &chain,
			UsedAt:       self.client.clock.Now(),
			Floor:        path.floor,
			PinEpoch:     current,
		})
	}
	if err := self.client.pins.RaiseReadRecords(self.repoId, records); err != nil {
		round.objects.close()
		return nil, err
	}
	return &evsReadResult{refId: refId, head: head, keys: keys, paths: paths, replies: verifiedPaths, objects: round.objects}, nil
}
