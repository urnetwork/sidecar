// Head reads (§11.9): ReadHead's and List's round trips to POST /evs/v1/repos/<id>/read, the verifying reader's checks
// over what comes back, the pin and read records it raises, and the receipt gate before anything is decrypted.
//
// A read names its ref by id, which any reader derives from K_ref for a named ref (§11.6), and its path by tokens
// computed here from the plaintext path, which never leaves the device (I-13, X2), in the epochs DESIGN-DETAILS
// 9.2.3's rules let it name: the current epoch, and the listed sources and other epochs at or above the path's floor;
// a path with no floor is a new name, looked up through its parent's table where the rules hold it back. The loop
// that chooses them, verifies each round and starts again on a head of another epoch state is evs_epoch_read.go's;
// a ref this client has not verified a head of takes one round for its head first. A path read before is read from
// its read record's pin, so every statement since that read is checked against it
// (g0-recheck-0-head-reader-read-paths#1), and a version below the record is refused and alarmed as tampering. A
// verified EvsReseed drops the records of entries the incident lost and lowers the rest to the re-seeded head
// (QD-816), so a lost path's surviving version reads as part of the loss. A hint naming a newer version sends the read
// past evs's head cache.
//
// Objects the reply carries (segment ranges, slots) stream into spills (evs_reconstruct.go), never a whole reply in
// memory. Nothing is decrypted before the head and the path verify and the head is pinned, and nothing at all of an
// owner-bound repo this sidecar does not write until EVS1-M2-29's receipt gate deposits a read receipt: until that
// gate is wired such reads are refused, as §8.19's owner-bound shares stay closed.
//
// Under a repo's prefix write rules (DESIGN-DETAILS 16.2.5) the version a read shows is the effective one: the round
// verifies evs's newest event of the path and raises the pin and the record on it as above, since those say what evs
// was shown, and the prefix reader (evs_prefix.go) then walks back under the versions this device ignores. A repo
// whose rows hold a rule set is read only by a client that holds such a reader: any other answers EVS_PREFIX_RULE.
//
// A read that asks for it (EvsReadArgs.Provenance) gives the version's push's sealed provenance in its EvsFileInfo:
// the writing run's tainted bit, its agent and whether a signed import brought it in (§11.6's Records; QD-042,
// QD-851). A path read carries no push's sealed metadata, so the push's record is one more round, after the receipt
// gate and the content's checks and before any byte reaches the caller's writer (evs_read_provenance.go).
//
// On every leg. Safe for concurrent use.

package sidecar

import (
	"context"
	"errors"
	"fmt"
	"io"
	"iter"
	"net/http"
	"slices"
	"strings"

	"github.com/urnetwork/sidecar/protocol"
)

var (
	// A read of an owner-bound repo by a sidecar that does not write it needs a read receipt deposited first
	// (§16.8, D-MCP-18), and the gate that deposits it (EVS1-M2-29) is not wired: the read is refused.
	ErrEvsReceiptGate = errors.New("evs: read receipt gate not wired")
	// The path is not there at the version read: never created, or removed, its removal's evidence checked.
	ErrEvsPathAbsent = errors.New("evs: path absent")
	// An overlay's path the overlay holds no version of: its base ref answers it, which head mode does not read.
	ErrEvsOverlayBase = errors.New("evs: path on the overlay's base")
)

// A repo's prefix write rules as a client's reads follow them (DESIGN-DETAILS 16.2.5), once its composition enables
// them (EvsClient.EnablePrefixRules, evs_prefix.go): behind a seam, so that the forwarding role's leg, which reads no
// repo under rules, links none of them. The rules are dark at launch (QD-1032): a reader whose settings keep them off
// is asked nothing but enabled.
type evsPrefixReader interface {
	// Whether its settings run the rules (AclPrefixSettings.Enabled); false, the launch default, keeps them dark.
	enabled() bool
	// 16.2.5's effective(X) over a head read of one path, result's only one: the read to show in its place, which is
	// result itself where its rules allow the newest event, and what the walk found. It closes every read it
	// replaces, result included, and on an error result too.
	effective(ctx context.Context, repo *EvsRepo, path string, result *evsReadResult) (*evsReadResult, *evsPrefixRead, error)
	// Whether its rules ignore the version or removal a read verified at index, as a version asked for by number or
	// History's walk meets one; a version nobody can judge, under a pending or newer set, is not ignored.
	ignored(ctx context.Context, repo *EvsRepo, result *evsReadResult, index int) (bool, error)
	// Whether its rules ignore one walked delta of the directory a read verified at index, applied to the table that
	// held gives: the kind of the row a child's token of that delta names there, false for none.
	deltaIgnored(ctx context.Context, repo *EvsRepo, result *evsReadResult, index int, delta *EvsVerifiedPath, held func(token EvsToken) (protocol.EvsEntryKind, bool)) (bool, error)
	// Whether a child of a directory listed at a head is one its record holds as effectively absent, its row added
	// at or below addedAt, the ref version of the delta or fold that gave it.
	rowAbsent(repo *EvsRepo, refId Id, path string, addedAt uint64) (bool, error)
	// The token paths a walked statement names that this reader follows, and false where it follows none of an
	// inline list: every change ignored, which raises the alarm and no change event (§11.10).
	followed(ctx context.Context, repo *EvsRepo, refId Id, statement *EvsVerifiedStatement) ([]EvsTokenPath, bool)
	// The writer's local refusal (DESIGN-DETAILS 16.2.7; EVS1-M6-05): nil where this device may write every path of
	// ask under the repo's rules, else EVS_PREFIX_RULE naming the first path refused. Asked before a write's first
	// round trip.
	allowWrite(ctx context.Context, repo *EvsRepo, ask *evsPrefixWriteAsk) error
	// What a write of the path read at index stands on: nil where evs's newest event of it is the effective one, else
	// the effective version, which the write then repairs to. A set this device cannot read is EVS_PREFIX_RULE.
	writeBase(ctx context.Context, repo *EvsRepo, result *evsReadResult, index int) (*evsPrefixWriteBase, error)
}

// One write as the writer's local refusal is asked about it: the ref by its name and what the caller knows of its
// kind and mode before any read, the push's flags, and each path's raw names joined by /: a list, or a sequence the
// engine draws from and stops drawing at the first path it refuses (QD-801), which a git update measured from nothing
// draws a tree's files through.
type evsPrefixWriteAsk struct {
	refName []byte
	refKind protocol.EvsRefKind
	refMode protocol.EvsRefMode
	flags   uint32
	paths   []string
	drawn   iter.Seq[string]
}

// The effective version of a path whose newest event at evs this device ignores: its number, 0 for a path that is
// effectively absent, and how many ignored versions lie over it; and the ignored events between it and evs's newest,
// newest first, whose push ids the repair form's sealed metadata names (QD-833).
type evsPrefixWriteBase struct {
	version      uint64
	ignoredAbove int
	writtenOver  []evsPrefixIgnoredPush
}

// What 16.2.5's walk found over the version a read shows: how many ignored versions lie over it, and whether a set
// this device cannot read holds everything above it back (held: pending; update: a later release's); and the ignored
// events the walk passed, newest first, none where the read record answered with no walk.
type evsPrefixRead struct {
	ignoredAbove int
	state        string
	ignored      []evsPrefixIgnoredPush
}

// One ignored event of a path, a version or a removal: the push that made it and the ref version that push committed
// at, which orders a repair's written_over (QD-833).
type evsPrefixIgnoredPush struct {
	commitVersion uint64
	pushId        Id
}

// The prefix reader of this repo's reads: nil while the client's rules are dark (QD-1032), so nothing is judged
// against them whatever rows the state holds, as a release that does not enforce reads a ruled repo (DESIGN-DETAILS
// 16.2.12); nil where the repo's rows hold no rule set (16.2.4's line 2); else the client's, or EVS_PREFIX_RULE with
// detail pending for a client that holds none, which cannot read the rules in force and so shows nothing under them.
func (self *EvsRepo) prefixRuled() (evsPrefixReader, error) {
	reader, enabled := self.client.prefixReader()
	if !enabled {
		return nil, nil
	}
	state, err := self.client.verifier.config()
	if err != nil {
		// no state judges anything, and the read's own checks refuse
		return nil, nil
	}
	repo := state.Repo(self.repoId)
	if repo == nil || len(repo.GetPrefixRules()) == 0 {
		return nil, nil
	}
	if reader == nil {
		return nil, &EvsPrefixRuleError{Detail: EvsPrefixDetailPending}
	}
	return reader, nil
}

// The prefix reader a composition installed, nil for none, and whether the client runs the rules: the reader's
// settings, else the defaults, whose rules are dark at launch (QD-1032).
func (self *EvsClient) prefixReader() (evsPrefixReader, bool) {
	reader := func() evsPrefixReader {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.prefixReads
	}()
	if reader == nil {
		return nil, DefaultAclPrefixSettings().Enabled
	}
	return reader, reader.enabled()
}

// Whether this client runs the client-checked prefix write rules: its judge's settings, else the defaults, whose
// rules are dark at launch (QD-1032). Off, it files, judges, journals, alarms, repairs and pin-pushes nothing under
// them.
func (self *EvsClient) PrefixRulesEnabled() bool {
	_, enabled := self.prefixReader()
	return enabled
}

// How a read gives a version's push provenance: the push's record read by its id and version, its sealed metadata
// opened and its agent's subkey signature checked (evs_read_provenance.go). Behind a seam, so that the forwarding
// role's legs, which read no file for an agent, link no agent-subkey check.
type evsProvenanceReadFunction func(ctx context.Context, repo *EvsRepo, result *evsReadResult, verified *EvsVerifiedPath) (*EvsPushProvenance, error)

// The provenance reader of every leg that links one, which evs_read_provenance.go registers from its init: nil on
// the forwarding role's legs, where a read gives no provenance. Written only by init.
var evsProvenanceRead evsProvenanceReadFunction

// Called before any object of a read is decrypted, with the ids of the objects it names (segments and slots): the
// receipt gate EVS1-M2-29 fills, which deposits a read receipt and awaits evs's 200 (§16.8). An error refuses the
// read.
type EvsPreDecryptFunction func(ctx context.Context, repoId Id, refId Id, objectIds [][]byte) error

// Installs the receipt gate. nil leaves the default, which refuses reads of owner-bound repos this sidecar does not
// write.
func (self *EvsClient) SetPreDecrypt(preDecrypt EvsPreDecryptFunction) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.preDecryptHook = preDecrypt
}

// The receipt gate before decrypting objectIds of a read.
func (self *EvsClient) preDecrypt(ctx context.Context, repoId Id, refId Id, objectIds [][]byte) error {
	hook := func() EvsPreDecryptFunction {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.preDecryptHook
	}()
	if hook != nil {
		return hook(ctx, repoId, refId, objectIds)
	}
	state, err := self.verifier.config()
	if err != nil {
		return err
	}
	repo := state.Repo(repoId)
	if repo == nil {
		return fmt.Errorf("%w: a repo the state does not hold", ErrEvsNoConfig)
	}
	if aclRepoKindOwnerBound(repo.GetKind()) && !slices.Contains(state.RepoWriters(repoId), self.args.Identity().SidecarId) {
		return ErrEvsReceiptGate
	}
	return nil
}

// A path as its raw names, refusing an empty component, and the empty path, which only a read names (the root).
func evsPathNames(path string) ([][]byte, error) {
	if path == "" {
		return nil, fmt.Errorf("%w: the empty path, which names the root only to a read", ErrEvsTokenInvalid)
	}
	names := [][]byte{}
	for _, name := range strings.Split(path, "/") {
		if err := checkEvsPathName([]byte(name)); err != nil {
			return nil, err
		}
		names = append(names, []byte(name))
	}
	return names, nil
}

// A path a read names as its raw names: the empty path is the ref's root, with no names, whose token path is empty in
// every epoch (question evs1-m2-24-root-directory-names, option 1; DESIGN-DETAILS 9.2.8); any other as evsPathNames.
func evsReadPathNames(path string) ([][]byte, error) {
	if path == "" {
		return [][]byte{}, nil
	}
	return evsPathNames(path)
}

// The repo keys one read uses, each generation asked of gkm once.
type evsReadKeys struct {
	repo         *EvsRepo
	generations  map[uint64]*EvsRepoKey
	manifestKeys map[uint64]*EvsManifestKey
	fekKeys      map[uint64]*EvsFekKey
	pathKeys     map[uint64]*EvsPathKey
	// a deposit's slot key and K_dep, set once its slot is opened, which take manifest's and the slot's place for
	// its generation (evs_consume.go)
	deposit *evsDepositKeys
	// the read's judge of keys gone from their slots, made at the first one (evs_reconstruct.go's erasureJudge)
	erasures evsErasureJudge
}

// A deposit's keys for one read: its slot's object key and the K_dep it derives, which take the slot's and
// manifest's place for that slot and generation (EVS-FORMAT.md's deposits; evs_consume.go sets them).
type evsDepositKeys struct {
	slotId     Id
	generation uint64
	objectKey  *EvsObjectKey
	manifest   *EvsManifestKey
}

// A read's keys, none asked yet.
func newEvsReadKeys(repo *EvsRepo) *evsReadKeys {
	return &evsReadKeys{
		repo:         repo,
		generations:  map[uint64]*EvsRepoKey{},
		manifestKeys: map[uint64]*EvsManifestKey{},
		fekKeys:      map[uint64]*EvsFekKey{},
		pathKeys:     map[uint64]*EvsPathKey{},
	}
}

// RK_g, through the ladder from what this sidecar holds (§10.5).
func (self *evsReadKeys) repoKey(ctx context.Context, generation uint64) (*EvsRepoKey, error) {
	if key := self.generations[generation]; key != nil {
		return key, nil
	}
	key, err := self.repo.client.args.Gkm.RepoKey(ctx, self.repo.repoId, generation)
	if err != nil {
		return nil, err
	}
	self.generations[generation] = key
	return key, nil
}

// manifest_g, or a deposit's K_dep in its generation's place.
func (self *evsReadKeys) manifest(ctx context.Context, generation uint64) (*EvsManifestKey, error) {
	if self.deposit != nil && self.deposit.generation == generation {
		return self.deposit.manifest, nil
	}
	if key := self.manifestKeys[generation]; key != nil {
		return key, nil
	}
	repoKey, err := self.repoKey(ctx, generation)
	if err != nil {
		return nil, err
	}
	key, err := NewEvsManifestKey(repoKey)
	if err != nil {
		return nil, err
	}
	self.manifestKeys[generation] = key
	return key, nil
}

// fek_g.
func (self *evsReadKeys) fek(ctx context.Context, generation uint64) (*EvsFekKey, error) {
	if key := self.fekKeys[generation]; key != nil {
		return key, nil
	}
	repoKey, err := self.repoKey(ctx, generation)
	if err != nil {
		return nil, err
	}
	key, err := NewEvsFekKey(repoKey)
	if err != nil {
		return nil, err
	}
	self.fekKeys[generation] = key
	return key, nil
}

// K_path_p.
func (self *evsReadKeys) path(ctx context.Context, epoch uint64) (*EvsPathKey, error) {
	if key := self.pathKeys[epoch]; key != nil {
		return key, nil
	}
	repoKey, err := self.repoKey(ctx, epoch)
	if err != nil {
		return nil, err
	}
	key, err := NewEvsPathKey(repoKey)
	if err != nil {
		return nil, err
	}
	self.pathKeys[epoch] = key
	return key, nil
}

// The ref a read names: its id, from K_ref for a named ref.
func (self *EvsRepo) resolveRefId(ctx context.Context, refName []byte, refId *Id) (Id, error) {
	if refId != nil {
		return *refId, nil
	}
	if refName == nil {
		refName = EvsMainRefName
	}
	repoKey, err := self.client.args.Gkm.CurrentRepoKey(ctx, self.repoId)
	if err != nil {
		return Id{}, err
	}
	refKey, err := NewEvsRefKey(repoKey)
	if err != nil {
		return Id{}, err
	}
	return EvsRefId(refKey, refName)
}

// A path's token path in epoch, from its raw names and K_path of that epoch: the root's is empty in every epoch.
func (self *evsReadKeys) tokenPathIn(ctx context.Context, names [][]byte, epoch uint64) (EvsTokenPath, error) {
	if len(names) == 0 {
		return EvsTokenPath{}, nil
	}
	pathKey, err := self.path(ctx, epoch)
	if err != nil {
		return nil, err
	}
	return EvsPathTokens(pathKey, names)
}

// One path a read asks for: its plaintext and names, the version asked, and what the rounds named and learned of it
// (evs_epoch_read.go).
type evsReadPath struct {
	path  string
	names [][]byte
	// 0 the newest version, else that older version; the ref version its push committed at when known (history's
	// prev_commit_version), and the push the newer version names as its predecessor, which E4 reads
	version       uint64
	commitVersion uint64
	prevPushId    []byte
	// its token path in the current epoch, and the epochs and token paths the last round named it in
	current    EvsTokenPath
	epochs     []uint64
	epochPaths []*protocol.EvsSourcePath
	named      map[uint64]bool
	record     *EvsReadRecord
	// the floor the call gathered, 0 none
	floor uint64
	// epochs the verifier needs proofs in, asked once more
	more      []uint64
	moreAsked bool
	// the reads again that a drop's body left out of a reply asked (EvsSettings.DropBodyReadCount)
	dropReads int
	// the head version of the parent listing used for this path, zero when none was needed
	lookupVersion uint64
	// the reply as verified, or the absence a lookup settled with no token of the path sent
	verified *EvsVerifiedPath
	settled  *EvsVerifiedPath
	// a deposit's or the erasure ref's entry, named by its random id in token's place, on a ref that stays at epoch 1
	// (evsEpochExempt): no names, record, floor or lookup
	token EvsTokenPath
}

// What one verified read gives its caller.
type evsReadResult struct {
	refId   Id
	head    *EvsVerifiedHead
	keys    *evsReadKeys
	paths   []*evsReadPath
	replies []*EvsVerifiedPath
	objects *evsReadObjects
	// set only by the config head reader at an anchor (QD-814; evs_config_head.go), for the config repo its trusted
	// genesis names, whose kind no read receipt covers: its content is decrypted without asking the receipt gate,
	// which asks a verified state that a reader starting at a base does not hold yet
	receiptExempt bool
}

// One round's reply: its parts as they arrived and their objects, its head verified but not pinned, and the ref pin
// it read from, which a path with no record is walked from (DESIGN-DETAILS 9.2.4's pin(X)).
type evsReadRound struct {
	reply         *evsReadReply
	objects       *evsReadObjects
	head          *EvsVerifiedHead
	keys          *evsReadKeys
	refPinVersion uint64
}

// Reads paths of a ref at version (0 the newest), each by DESIGN-DETAILS 9.2.4's loop (evs_epoch_read.go): verifies
// the head and every path, checks the read records, pins the head and raises the records, all before the caller
// decrypts anything. A path's own failure fails the read: the caller asked for it.
func (self *EvsRepo) read(ctx context.Context, refId Id, paths []string, version uint64, fresh bool) (*evsReadResult, error) {
	readPaths := make([]*evsReadPath, 0, len(paths))
	for _, path := range paths {
		readPaths = append(readPaths, &evsReadPath{path: path, version: version})
	}
	return self.readPaths(ctx, refId, readPaths, fresh)
}

// One round: the request naming each path in the epochs the loop chose, its framed reply, and the head's check from
// the pin, or from the oldest read record's pin of the paths asked, so every statement since is walked. The paths'
// checks, the pin and the records are the loop's.
func (self *EvsRepo) readRound(ctx context.Context, refId Id, keys *evsReadKeys, paths []*evsReadPath, fresh bool) (*evsReadRound, error) {
	return self.readRoundFromPin(ctx, refId, keys, paths, fresh, true)
}

// readRound, taking a head below the pin under the ref's EvsReseed at most once (reseed): the round after one reads
// from the lowered pin and refuses a head below that.
func (self *EvsRepo) readRoundFromPin(ctx context.Context, refId Id, keys *evsReadKeys, paths []*evsReadPath, fresh bool, reseed bool) (*evsReadRound, error) {
	fromVersion := uint64(0)
	fromChain := EvsChainStart(self.repoId, refId)
	pin, pinned, err := self.client.pins.Pin(self.repoId, refId)
	if err != nil {
		return nil, err
	}
	refPinVersion := uint64(0)
	if pinned {
		fromVersion, fromChain, refPinVersion = pin.Version, pin.Chain, pin.Version
	}
	for _, path := range paths {
		// a recorded path reads from its last read's pin, so every statement since is checked against it
		if path.record != nil && path.record.PinVersion < fromVersion && path.record.PinChain != nil {
			fromVersion, fromChain = path.record.PinVersion, *path.record.PinChain
		}
	}
	if pinned && pin.Version < self.client.hintedVersion(self.repoId, refId) {
		fresh = true
	}
	request := &protocol.EvsReadRequest{RefId: refId.Bytes(), PinVersion: fromVersion, Fresh: fresh}
	if reader := self.client.format2Reader(); reader != nil {
		// the DROP bodies this device holds checked, which evs sends none of again (DESIGN-DETAILS 10.2.3)
		request.HeldDrops = reader.heldDrops(self.client, self.repoId, refId)
	}
	for _, path := range paths {
		readPath := &protocol.EvsReadPath{TokenPaths: path.epochPaths, Version: path.version}
		if path.version != 0 {
			readPath.CommitVersion = path.commitVersion
		}
		request.Paths = append(request.Paths, readPath)
	}
	reply, objects, err := self.client.postRead(ctx, self.repoId, request)
	if err != nil {
		return nil, err
	}
	if reseed && pinned && reply.head.GetVersion() < pin.Version {
		again, err := self.acceptReseedBelowPin(ctx, refId, pin, reply, fromVersion)
		if err != nil {
			objects.close()
			return nil, err
		}
		if again {
			// the pin now stands at the re-seeded head, or the head has passed the pin since: the round again
			objects.close()
			return self.readRoundFromPin(ctx, refId, keys, paths, fresh, false)
		}
	}
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
		objects.close()
		return nil, err
	}
	return &evsReadRound{reply: reply, objects: objects, head: head, keys: keys, refPinVersion: refPinVersion}, nil
}

// A head served below this device's pin of the ref (§11.9's reader row; §11.13's re-seed row, §19.10): the shorter
// history a site loss left, which the device takes only under the ref's Signed EvsReseed, a repo admin's, naming
// exactly the head served (EvsVerifier.AcceptReseed). evs serves the statement after a head below the request's
// pin_version (QD-725), so a round that asked from an older path record's pin asks once more from the ref's. True
// when the caller is to read again: the pin stands lowered to the re-seeded head, kept as a loss, the ref's read
// records with it (QD-816), or the head has passed the pin while this asked. False with no statement or one that does
// not verify: nothing changed, and the caller's own check refuses the head and alarms, as it does without this.
func (self *EvsRepo) acceptReseedBelowPin(ctx context.Context, refId Id, pin *EvsPin, reply *evsReadReply, askedVersion uint64) (bool, error) {
	head, statement := reply.head, reply.reseed
	if statement == nil && askedVersion < pin.Version {
		again, objects, err := self.client.postRead(ctx, self.repoId, &protocol.EvsReadRequest{RefId: refId.Bytes(), PinVersion: pin.Version, Fresh: true})
		if err != nil {
			return false, err
		}
		objects.close()
		head, statement = again.head, again.reseed
		if pin.Version <= head.GetVersion() {
			return true, nil
		}
	}
	if statement == nil {
		return false, nil
	}
	if err := self.client.verifier.AcceptReseed(statement, self.repoId, refId, head); err != nil {
		if errors.Is(err, ErrEvsStatementRefused) {
			self.client.log.Warningf("[evs]the reseed served for repo %s ref %s is refused: %v", self.repoId, refId, err)
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// A read reply's parts as they arrived.
type evsReadReply struct {
	head       *protocol.EvsHeadSummary
	statements []*protocol.EvsReadStatement
	behind     uint64
	paths      []*protocol.EvsReadPathReply
	// The ref's Signed EvsReseed as evs keeps it, served after a head below the request's pin_version (§11.13;
	// QD-725); nil when the reply carried none. Unverified: EvsVerifier.AcceptReseed checks it.
	reseed []byte
}

// POST /evs/v1/repos/<id>/read, its frames read one at a time: the head first, then statements, paths and objects,
// each object's bytes into a spill as they come.
func (self *EvsClient) postRead(ctx context.Context, repoId Id, request *protocol.EvsReadRequest) (*evsReadReply, *evsReadObjects, error) {
	response, err := self.http.send(ctx, &evsCall{
		route:  "POST /evs/v1/repos/{repo_id}/read",
		method: http.MethodPost,
		path:   "/evs/v1/repos/" + evsUrlId(repoId) + "/read",
		repoId: repoId,
		role:   evsScopeRead,
		body:   request,
		retry:  true,
	})
	if err != nil {
		return nil, nil, err
	}
	defer response.Body.Close()
	objects := newEvsReadObjects(self)
	reply := &evsReadReply{}
	frames := NewEvsReadFrames(response.Body)
	for {
		frame, err := frames.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			objects.close()
			return nil, nil, err
		}
		if frame.GetHead() != nil {
			if reply.head != nil {
				objects.close()
				return nil, nil, fmt.Errorf("%w: a second head", ErrEvsReplyInvalid)
			}
			reply.head = frame.GetHead()
		}
		if frame.GetStatement() != nil {
			reply.statements = append(reply.statements, frame.GetStatement())
		}
		if frame.GetBehind() != 0 {
			reply.behind = frame.GetBehind()
		}
		if frame.GetPath() != nil {
			reply.paths = append(reply.paths, frame.GetPath())
		}
		if object := frame.GetObject(); object != nil && object.GetKind() == protocol.EvsReadObjectKind_EVS_READ_OBJECT_RESEED {
			// one frame, whole, within the statement's bound: never spilled, and never read as a path's object
			if reply.reseed != nil || object.GetMissing() || object.GetOffset() != 0 || len(object.GetBody()) == 0 ||
				frames.format.ReseedStatementMaxByteCount < len(object.GetBody()) {
				objects.close()
				return nil, nil, fmt.Errorf("%w: a reseed frame", ErrEvsReplyInvalid)
			}
			reply.reseed = object.GetBody()
		} else if object != nil {
			if err := objects.add(object); err != nil {
				objects.close()
				return nil, nil, err
			}
		}
	}
	if reply.head == nil {
		objects.close()
		return nil, nil, fmt.Errorf("%w: a read reply with no head", ErrEvsReplyInvalid)
	}
	return reply, objects, nil
}

// The ref's path epoch as the last verified head gave it, nil when this client has read none.
func (self *EvsClient) refEpoch(repoId Id, refId Id) *protocol.EvsPathEpoch {
	if state := self.refEpochState(repoId, refId); state != nil {
		return state.epoch
	}
	return nil
}

// Reads the newest committed version of a file, or an older one (args.Version), verified and pinned, then
// reconstructed, its oid checked, and only then written to out (§11.7's reconstruction row). A versionless file
// replaced mid-read is read again from the new head (§18.5), a fresh one, at most
// EvsSettings.ReadReplacedRestartCount times; an older version that was replaced answers ErrEvsCollected.
func (self *EvsRepo) ReadHead(ctx context.Context, args *EvsReadArgs, out io.Writer) (*EvsFileInfo, error) {
	refId, err := self.resolveRefId(ctx, args.RefName, args.RefId)
	if err != nil {
		return nil, err
	}
	fresh := args.Fresh
	for restartCount := 0; ; restartCount += 1 {
		// nothing reaches out before a version's content is whole and checked, so a failed pass wrote none of it
		info, err := self.readFile(ctx, refId, args, fresh, out)
		if args.Version != 0 || !errors.Is(err, ErrEvsCollected) {
			return info, err
		}
		if self.client.settings.ReadReplacedRestartCount <= restartCount {
			return nil, fmt.Errorf("%w: %d times", ErrEvsReplacedMidRead, restartCount+1)
		}
		fresh = true
	}
}

// One pass of ReadHead: the file at args.Version on a head read fresh or not.
func (self *EvsRepo) readFile(ctx context.Context, refId Id, args *EvsReadArgs, fresh bool, out io.Writer) (*EvsFileInfo, error) {
	ruled, err := self.prefixRuled()
	if err != nil {
		return nil, err
	}
	result, err := self.read(ctx, refId, []string{args.Path}, args.Version, fresh)
	if err != nil {
		return nil, err
	}
	walk := &evsPrefixRead{}
	if ruled != nil && args.Version == 0 {
		// the effective version: evs's newest one this device does not ignore (DESIGN-DETAILS 16.2.5)
		if result, walk, err = ruled.effective(ctx, self, args.Path, result); err != nil {
			return nil, err
		}
	}
	defer result.objects.close()
	if entry := result.replies[0].Entry; args.Version != 0 && entry != nil && entry.GetVersion() != args.Version {
		// evs answers a number the path holds no version at with its newest version below it (§11.9's reply row;
		// owner decision 380): there is none at the number asked
		return nil, ErrEvsPathAbsent
	}
	if ruled != nil && args.Version != 0 {
		// a version asked for by number that this device ignores is not shown
		ignored, err := ruled.ignored(ctx, self, result, 0)
		if err != nil {
			return nil, err
		}
		if ignored {
			return nil, &EvsPrefixRuleError{Detail: EvsPrefixDetailRefused, Path: args.Path}
		}
	}
	verified := result.replies[0]
	switch {
	case verified.Base != nil:
		return nil, ErrEvsOverlayBase
	case verified.Removal != nil, verified.Absent:
		return nil, ErrEvsPathAbsent
	case verified.Entry.GetKind() != uint32(protocol.EvsEntryKind_EVS_ENTRY_FILE):
		return nil, fmt.Errorf("%w: a directory, which List reads", ErrEvsTokenInvalid)
	}
	if !args.Provenance || evsProvenanceRead == nil {
		info, err := self.reconstruct(ctx, result, verified, out)
		if err != nil {
			return nil, err
		}
		info.Path = args.Path
		info.IgnoredAbove, info.RuleState = walk.ignoredAbove, walk.state
		return info, nil
	}
	// reconstruct's steps with the push's provenance read between them: after the receipt gate and the content's
	// checks, and before a byte reaches out, so a read that cannot say whose words these are returns none of them
	info := evsFileInfoOf(result.refId, result.head, verified)
	content, fields, oid, err := self.reconstructContent(ctx, result, verified, nil)
	if err != nil {
		return nil, err
	}
	defer content.close()
	if info.Provenance, err = evsProvenanceRead(ctx, self, result, verified); err != nil {
		return nil, err
	}
	if _, err := io.Copy(out, content.reader()); err != nil {
		return nil, err
	}
	info.Mode, info.GitOid, info.Size = fields.GetMode(), oid, fields.GetSize()
	info.Path = args.Path
	info.IgnoredAbove, info.RuleState = walk.ignoredAbove, walk.state
	return info, nil
}

// The file info a verified version gives, before its sealed fields are opened.
func evsFileInfoOf(refId Id, head *EvsVerifiedHead, verified *EvsVerifiedPath) *EvsFileInfo {
	push := verified.Statement.Push
	info := &EvsFileInfo{
		RefId:         refId,
		Version:       verified.Entry.GetVersion(),
		CommitVersion: verified.CommitVersion,
		Time:          evsTime(verified.Entry.GetTimeMs()),
		Kind:          protocol.EvsEntryKind(verified.Entry.GetKind()),
		HeadVersion:   head.Version,
	}
	info.PushId, _ = IdFromBytes(push.GetPushId())
	info.SignerSidecarId, _ = IdFromBytes(push.GetSignerSidecarId())
	info.ClientId, _ = IdFromBytes(push.GetClientId())
	return info
}
