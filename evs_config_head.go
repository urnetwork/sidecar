//go:build !ios_extension

// The config repo's head reader over evs (QD-804; §7.9's BASE row, §11.8's replay row, §11.9): ConfigClient's
// ConfigHeadReader for a network whose config repo is an EvsRepo. A base names a config head as (config_version,
// config_head_sha256), the version v of the config repo's file-mode main ref and its chain value C_v. The reader
// answers the files that ref held at v, every path of the head, only when C_v is the ref's chain value there on the
// chain from C_0 through pushes config writers signed, and refuses rather than guesses.
//
// It reads as a replaying reader does (§11.8's replay row), from the ref's log and each push's record, never from
// evs's folded tables or its head: a table is evs's own fold, which may leave a path out (Q-EVS-6's disclosed limit),
// and a head read answers the newest version only, while a base names a version that later pushes may have passed.
//
//	chain    C_0 = SHA-256("UR evs 1.0 ref" || repo_id || ref_id), then each statement as received, in version order;
//	         the chain passes through this device's pin, and its value at v is the one the base names
//	writers  every statement after the newest point this device already vouches for, its pin (unless the pin was
//	         taken past the catch-up budget, which is evs's word) or else C_0, is judged by the verifier at its own
//	         authorization pin: its signature under its signer's admitted identity key, and §11.8's refs table, where
//	         a shared ref of the config repo takes pushes from config writers alone (ACL's kind default). A main ref
//	         that is not a shared file-mode ref is no config head's
//	tree     each push's record is read by its push id and version and checked against its signed statement, then
//	         applied in order: a directory's delta names its children, each name opened under the push's epoch and
//	         checked against its token, a file's entry stands until a later push writes or removes it, and a removal
//	         takes the path and everything below it. Across a path epoch every standing name is tokenized again in the
//	         push's epoch, so a change is found by the token path its statement names
//	files    each file standing at v is rebuilt from its entry as ReadHead rebuilds one: the receipt gate, its chain
//	         of records, and its size and oid held to its sealed fields
//
// What it answers (ConfigHeadReader's contract):
//
//	the head          C_v is the ref's at v, through config writers' pushes; the pin is raised to (v, C_v) first
//	unavailable       evs serves no version v yet, or a log that does not pass through this device's pin, or a
//	                  record that is not its statement's; this device's state is behind a push's authorization pin or
//	                  no longer retains it, which is unjudged and never allowed (§7.9's state by pin); a key it does
//	                  not hold; a push this reader does not replay (below). Each withholds the base
//	mismatch          the verified chain holds another value at v, or the chain the base names holds a push the
//	                  verifier refuses, a non-writer's among them: the base is a fork
//	malformed         the files at v are no config head (NewConfigHead's refusals)
//
// Not replayed, so unavailable: a FORCE, BASE, IMMUTABLE, CONSUME, ERASE, CLOSURE, DROP or CUT push on the ref, and a
// format-2 statement. A DELETE empties the tree, and a PATH_EPOCH push changes none of it.
//
// A reader that starts at a base holds no state before it, so it judges no push there and this reader withholds its
// anchor's head (question config-head-reader-anchor-push-signers).
//
// The replay is kept in memory between reads, the tree at the last version read with the bytes of the files it read,
// so a follower checking bases in order reads each push once and each file version once; a read of an older version
// replays from the first. The newest heads answered are kept whole, so the base a device stands on is not read twice.
//
// On desktop and mobile legs. Safe for concurrent use; one read replays at a time. Nothing here creates, derives or
// unwraps a key but through the read's keys (evs_read.go), whose derivations are hooked.

package sidecar

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"sync"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// A push on the config repo's main ref that is no config head's, or that this reader does not replay.
var errEvsConfigHeadPush = errors.New("evs config head: push not replayed")

// Tunables of an EvsConfigHeadReader.
type EvsConfigHeadSettings struct {
	// The push records one read asks for: 64, the most one read names (§11.9's request row; evs's ReadObjectMaxCount).
	PushReadCount int
	// The most files a head may hold before the read is withheld: 262,144, past a bridge ledger's 65,536 rule shards
	// and a fold a day for a century. Non-positive withholds every head.
	HeadMaxFileCount int
	// The most bytes a head's files may hold together before the read is withheld, since a ConfigHead holds them in
	// memory: 256 MiB. Non-positive withholds every head.
	HeadMaxByteCount int64
	// The heads kept whole after they are answered, newest first out last: 2, the bases a ConfigClient keeps rows for,
	// its current and previous. Non-positive keeps none.
	HeadCacheCount int
}

// 64 records a read, 262,144 files and 256 MiB a head, 2 heads kept.
func DefaultEvsConfigHeadSettings() *EvsConfigHeadSettings {
	return &EvsConfigHeadSettings{
		PushReadCount:    64,
		HeadMaxFileCount: 262144,
		HeadMaxByteCount: 256 * 1024 * 1024,
		HeadCacheCount:   2,
	}
}

// What an EvsConfigHeadReader runs on.
type EvsConfigHeadReaderArgs struct {
	// The network's config repo, the one its Genesis names, on the network's EvsClient: its verifier's Config judges
	// each push, its Gkm opens the repo and its pins hold the main ref's.
	Repo *EvsRepo
	// Nil for DefaultEvsConfigHeadSettings.
	Settings *EvsConfigHeadSettings
}

// One named path of the replayed tree.
type evsConfigHeadPath struct {
	names     [][]byte
	directory bool
	// a file's standing version, nil until a push writes it: its entry as its statement signed it, the statement,
	// the ref version it committed at and the token path its statement names it by
	entry         *protocol.EvsEntryVersion
	entryBytes    []byte
	statement     *EvsStatement
	commitVersion uint64
	tokenPath     EvsTokenPath
	// the standing version's bytes, once read
	content     []byte
	contentRead bool
}

// The main ref's tree as its pushes through version leave it.
type evsConfigHeadReplay struct {
	refId   Id
	version uint64
	// C at version, which this reader vouched for when it replayed to it
	chain [sha256.Size]byte
	// every named path by evsExportKey of its names, the root included
	paths map[string]*evsConfigHeadPath
	// each path's key by its token path's bytes in epoch, 0 before the first push
	epoch         uint64
	tokenPathKeys map[string]string
}

// The tree of a ref nothing was pushed to: its root alone, at C_0.
func newEvsConfigHeadReplay(repoId Id, refId Id) *evsConfigHeadReplay {
	return &evsConfigHeadReplay{
		refId:         refId,
		chain:         EvsChainStart(repoId, refId),
		paths:         map[string]*evsConfigHeadPath{"": {names: [][]byte{}, directory: true}},
		tokenPathKeys: map[string]string{"": ""},
	}
}

// A head this reader answered.
type evsConfigCachedHead struct {
	version uint64
	chain   [sha256.Size]byte
	head    *ConfigHead
}

// ConfigHeadReader over the config repo's main ref on evs.
type EvsConfigHeadReader struct {
	repo     *EvsRepo
	settings *EvsConfigHeadSettings

	// one read replays at a time: held from a read's first call to evs to its answer
	turn chan struct{}
	// the replay the last read left, nil before the first; only the turn's holder reads or changes it
	replay *evsConfigHeadReplay

	stateLock sync.Mutex
	// most recently answered last
	cachedHeads []*evsConfigCachedHead
}

var _ ConfigHeadReader = (*EvsConfigHeadReader)(nil)

// A reader of args.Repo's main ref as config heads.
func NewEvsConfigHeadReader(args *EvsConfigHeadReaderArgs) (*EvsConfigHeadReader, error) {
	if args == nil || args.Repo == nil {
		return nil, errors.New("evs config head reader: no repo")
	}
	settings := args.Settings
	if settings == nil {
		settings = DefaultEvsConfigHeadSettings()
	}
	if settings.PushReadCount <= 0 {
		return nil, errors.New("evs config head reader: no push records a read")
	}
	return &EvsConfigHeadReader{repo: args.Repo, settings: settings, turn: make(chan struct{}, 1)}, nil
}

// A head answered before at configVersion with chain, nil for none.
func (self *EvsConfigHeadReader) cachedHead(configVersion uint64, chain [sha256.Size]byte) *ConfigHead {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for i, cached := range self.cachedHeads {
		if cached.version == configVersion && cached.chain == chain {
			self.cachedHeads = append(slices.Delete(self.cachedHeads, i, i+1), cached)
			return cached.head
		}
	}
	return nil
}

// Keeps a head answered, the least recently answered out past HeadCacheCount.
func (self *EvsConfigHeadReader) cacheHead(configVersion uint64, chain [sha256.Size]byte, head *ConfigHead) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.settings.HeadCacheCount <= 0 {
		return
	}
	self.cachedHeads = append(self.cachedHeads, &evsConfigCachedHead{version: configVersion, chain: chain, head: head})
	if over := len(self.cachedHeads) - self.settings.HeadCacheCount; 0 < over {
		self.cachedHeads = slices.Delete(self.cachedHeads, 0, over)
	}
}

// ConfigHeadReader: see the file header for what each answer means.
func (self *EvsConfigHeadReader) ReadConfigHead(ctx context.Context, configVersion uint64, configHeadSha256 []byte) (*ConfigHead, error) {
	named, err := EvsChainFromBytes(configHeadSha256)
	if err != nil {
		return nil, fmt.Errorf("%w: a config_head_sha256 of %d bytes", ErrConfigHeadMismatch, len(configHeadSha256))
	}
	if configVersion == 0 {
		// version 0 is the ref before its first push, which holds no head
		return nil, fmt.Errorf("%w: no head at config version 0", ErrConfigHeadUnavailable)
	}
	if head := self.cachedHead(configVersion, named); head != nil {
		return head, nil
	}
	select {
	case self.turn <- struct{}{}:
	case <-ctx.Done():
		return nil, fmt.Errorf("%w: %w", ErrConfigHeadUnavailable, ctx.Err())
	}
	defer func() { <-self.turn }()
	// a read that waited its turn behind one of the same head
	if head := self.cachedHead(configVersion, named); head != nil {
		return head, nil
	}
	head, err := self.readWithTurn(ctx, configVersion, named)
	if err != nil {
		return nil, err
	}
	self.cacheHead(configVersion, named, head)
	return head, nil
}

// One read, by the turn's holder: the chain and its writers through version, the pin, the tree and its files.
func (self *EvsConfigHeadReader) readWithTurn(ctx context.Context, version uint64, named [sha256.Size]byte) (*ConfigHead, error) {
	repo := self.repo
	client := repo.client
	unavailable := func(what string, err error) error {
		return fmt.Errorf("%w: %s: %w", ErrConfigHeadUnavailable, what, err)
	}
	refId, err := repo.resolveRefId(ctx, nil, nil)
	if err != nil {
		return nil, unavailable("the main ref's id", err)
	}
	pin, pinned, err := client.pins.Pin(repo.repoId, refId)
	if err != nil {
		return nil, unavailable("the main ref's pin", err)
	}

	replay := self.replay
	// a replay of another ref, past the version asked, or past a pin a reseed lowered starts again
	if replay == nil || replay.refId != refId || version < replay.version || (pinned && pin.Version < replay.version) {
		replay = newEvsConfigHeadReplay(repo.repoId, refId)
	}

	// the newest point this device vouches for: its pin, unless that was taken on evs's word, else the replay's own
	trustedVersion, trustedChain := replay.version, replay.chain
	if pinned && pin.VerifiedSince.IsZero() {
		trustedVersion, trustedChain = pin.Version, pin.Chain
	}

	// the log after the replay, through the version asked and the trusted point, chained as received
	through := max(version, trustedVersion)
	read, err := client.readLog(ctx, repo.repoId, refId, replay.version+1, through)
	if err != nil {
		return nil, unavailable("the main ref's log", err)
	}
	if uint64(len(read)) < through-replay.version {
		return nil, fmt.Errorf("%w: evs serves the main ref through version %d, not %d", ErrConfigHeadUnavailable, replay.version+uint64(len(read)), through)
	}
	statements := make([]*EvsVerifiedStatement, 0, len(read))
	chain := replay.chain
	// a push through version that is no config head's, the first
	var refused error
	for i, readStatement := range read {
		statementVersion := replay.version + uint64(i) + 1
		if readStatement.GetVersion() != statementVersion {
			return nil, fmt.Errorf("%w: the log holds version %d where %d was due", ErrConfigHeadUnavailable, readStatement.GetVersion(), statementVersion)
		}
		statement, err := ParseEvsStatement(readStatement.GetStatement())
		if err != nil {
			return nil, unavailable(fmt.Sprintf("the statement at version %d", statementVersion), err)
		}
		push := statement.Push
		if !bytes.Equal(push.GetRepoId(), repo.repoId.Bytes()) || !bytes.Equal(push.GetRefId(), refId.Bytes()) {
			return nil, fmt.Errorf("%w: the log holds another ref's statement at version %d", ErrConfigHeadUnavailable, statementVersion)
		}
		pushId, err := IdFromBytes(push.GetPushId())
		if err != nil {
			return nil, unavailable(fmt.Sprintf("the push id at version %d", statementVersion), err)
		}
		if statementVersion <= version && refused == nil &&
			(protocol.EvsRefKind(push.GetRefKind()) != protocol.EvsRefKind_EVS_REF_SHARED || protocol.EvsRefMode(push.GetRefMode()) != protocol.EvsRefMode_EVS_REF_FILE) {
			refused = fmt.Errorf("%w: the push at version %d is not a shared file-mode ref's", ErrEvsStatementRefused, statementVersion)
		}
		chain = EvsChainNext(chain, pushId, statement.Sha256)
		statements = append(statements, &EvsVerifiedStatement{Version: statementVersion, Statement: statement, Chain: chain})
	}
	chainAt := func(at uint64) [sha256.Size]byte {
		if at == replay.version {
			return replay.chain
		}
		return statements[at-replay.version-1].Chain
	}

	// the log is this device's pinned history
	if chainAt(trustedVersion) != trustedChain {
		if pinned {
			client.verifier.alarmFork(repo.repoId, refId, pin, trustedVersion, chainAt(trustedVersion))
		}
		// evs serves another log than the one the replay was built on, or than the pin's: the next read starts again
		self.replay = nil
		return nil, fmt.Errorf("%w: the log evs serves does not pass through this device's pin at version %d", ErrConfigHeadUnavailable, trustedVersion)
	}
	if pinned && replay.version <= pin.Version && pin.Version <= through && chainAt(pin.Version) != pin.Chain {
		client.verifier.alarmFork(repo.repoId, refId, pin, pin.Version, chainAt(pin.Version))
		return nil, fmt.Errorf("%w: the log evs serves does not pass through this device's pin at version %d", ErrConfigHeadUnavailable, pin.Version)
	}

	// every push after the trusted point through the version asked, judged at its own authorization pin
	if trustedVersion < version {
		judged := read[trustedVersion-replay.version : version-replay.version]
		if _, err := client.verifier.walk(repo.repoId, refId, trustedVersion, trustedChain, judged, version); err != nil {
			// what proves nothing against a signer withholds; anything else is a push no config writer validly signed
			quiet := errors.Is(err, ErrEvsFormatUnsupported) || errors.Is(err, ErrEvsNoConfig) ||
				errors.Is(err, ErrGkmAuthAhead) || errors.Is(err, ErrGkmAuthNotRetained)
			if quiet {
				return nil, unavailable("the pushes after this device's pin", err)
			}
			refused = err
		}
	}
	if refused != nil {
		if chainAt(version) == named {
			// the chain the base names holds the refused push, so no log evs could serve makes the head a writer's
			client.log.Warningf("[evs]the config head at version %d of repo %s rests on a refused push", version, repo.repoId)
			return nil, fmt.Errorf("%w: the head's chain holds a push no config writer validly signed: %w", ErrConfigHeadMismatch, refused)
		}
		return nil, unavailable("the pushes evs serves", refused)
	}
	if chainAt(version) != named {
		client.log.Warningf("[evs]the config repo %s holds another chain value at version %d than the one named", repo.repoId, version)
		return nil, fmt.Errorf("%w: the main ref's chain at version %d is another", ErrConfigHeadMismatch, version)
	}

	// pinned before anything it backs is opened
	pinVersion := version
	if pinned && version <= pin.Version {
		pinVersion = pin.Version
	} else {
		push := statements[version-replay.version-1].Statement.Push
		raised := &EvsVerifiedHead{
			RepoId: repo.repoId, RefId: refId, Version: version, Chain: named, FromVersion: trustedVersion,
			// the group the pin keeps, as a head's summary gives it
			Head: &protocol.EvsHeadSummary{RefId: refId.Bytes(), Version: version, Chain: named[:], GroupId: push.GetGroupId()},
		}
		if err := client.verifier.Pin(raised); err != nil {
			return nil, unavailable("the main ref's pin", err)
		}
	}

	// the tree at the version asked; a replay a failed push leaves half applied is dropped
	keys := newEvsReadKeys(repo)
	pinnedHead := &EvsVerifiedHead{RepoId: repo.repoId, RefId: refId, Version: pinVersion}
	pending := statements[:version-replay.version]
	self.replay = nil
	for 0 < len(pending) {
		batch := pending[:min(len(pending), self.settings.PushReadCount)]
		pending = pending[len(batch):]
		payloads, err := self.readPayloads(ctx, pinnedHead, batch)
		if err != nil {
			return nil, unavailable("the pushes' records", err)
		}
		for _, statement := range batch {
			if err := replay.apply(ctx, keys, statement, payloads[statement.Version]); err != nil {
				return nil, unavailable(fmt.Sprintf("the push at version %d", statement.Version), err)
			}
			replay.version, replay.chain = statement.Version, statement.Chain
		}
	}

	files, err := self.readFiles(ctx, pinnedHead, keys, replay)
	// the replay stands as far as it came, with the files it read, whatever the files' read came to
	self.replay = replay
	if err != nil {
		if errors.Is(err, ErrConfigHeadMalformed) {
			return nil, err
		}
		return nil, unavailable("the head's files", err)
	}
	return NewConfigHead(files)
}

// The checked payload of each push of batch that carries one, by its version: a one-part push's record read with the
// others in one round, a push in parts by its own rounds. A PATH_EPOCH or DELETE push changes no path by a payload,
// and has none here.
func (self *EvsConfigHeadReader) readPayloads(ctx context.Context, head *EvsVerifiedHead, batch []*EvsVerifiedStatement) (map[uint64]*EvsCheckedPayload, error) {
	repo := self.repo
	payloads := map[uint64]*EvsCheckedPayload{}
	request := &protocol.EvsReadRequest{RefId: head.RefId.Bytes(), PinVersion: head.Version}
	single := []*EvsVerifiedStatement{}
	for _, statement := range batch {
		push := statement.Statement.Push
		switch {
		case push.GetFlags()&uint32(protocol.EvsPushFlag_EVS_PUSH_PATH_EPOCH|protocol.EvsPushFlag_EVS_PUSH_DELETE) != 0:
		case push.GetPartCount() != 0:
			payload, err := repo.pushContent(ctx, head, statement)
			if err != nil {
				return nil, err
			}
			payloads[statement.Version] = payload
		default:
			request.Pushes = append(request.Pushes, &protocol.EvsReadPush{PushId: push.GetPushId(), Version: statement.Version})
			single = append(single, statement)
		}
	}
	if len(single) == 0 {
		return payloads, nil
	}
	_, objects, err := repo.client.postRead(ctx, repo.repoId, request)
	if err != nil {
		return nil, err
	}
	defer objects.close()
	for _, statement := range single {
		pushIdHex := hex.EncodeToString(statement.Statement.Push.GetPushId())
		var record []byte
		for key, spill := range objects.objects {
			if key.kind == protocol.EvsReadObjectKind_EVS_READ_OBJECT_BATCH_RECORD && key.id == pushIdHex && key.number == 0 {
				record, err = io.ReadAll(spill.reader())
				if err != nil {
					return nil, err
				}
			}
		}
		if record == nil {
			return nil, fmt.Errorf("%w: the push record at version %d, which evs did not serve", ErrEvsObjectMissing, statement.Version)
		}
		// the batch record as its place holds it: its header, then the push's statement and payload
		batchRecord, err := ParseEvsBatchRecord(record)
		if err != nil || batchRecord.Type != protocol.EvsBatchRecordType_EVS_BATCH_PUSH {
			return nil, fmt.Errorf("%w: a push record that is not one push's", ErrEvsEntryRefused)
		}
		statementBytes, payloadBytes, err := ParseEvsPushRecordBody(batchRecord.Body)
		if err != nil || !bytes.Equal(statementBytes, statement.Statement.Bytes) {
			return nil, fmt.Errorf("%w: a push record of another statement", ErrEvsEntryRefused)
		}
		payload, err := EvsCheckPayload(statement.Statement, payloadBytes)
		if err != nil {
			return nil, err
		}
		payloads[statement.Version] = payload
	}
	return payloads, nil
}

// Takes the path at key and everything below it out of the tree; the root stays, emptied.
func (self *evsConfigHeadReplay) remove(key string) {
	removed := self.paths[key]
	if removed == nil {
		return
	}
	for heldKey, held := range self.paths {
		if heldKey != "" && evsNamesHavePrefix(held.names, removed.names) {
			delete(self.paths, heldKey)
		}
	}
	for tokenPathKey, heldKey := range self.tokenPathKeys {
		if _, standing := self.paths[heldKey]; !standing {
			delete(self.tokenPathKeys, tokenPathKey)
		}
	}
}

// Applies one push of the ref, the next after the tree's version, with its checked payload: see the file header's
// tree row. payload is nil for a PATH_EPOCH or DELETE push.
func (self *evsConfigHeadReplay) apply(ctx context.Context, keys *evsReadKeys, statement *EvsVerifiedStatement, payload *EvsCheckedPayload) error {
	push := statement.Statement.Push
	flags := push.GetFlags()
	switch {
	case flags == uint32(protocol.EvsPushFlag_EVS_PUSH_PATH_EPOCH):
		// the cut-over moves every token and no path; the next push's epoch tokenizes the tree again
		return nil
	case flags == uint32(protocol.EvsPushFlag_EVS_PUSH_DELETE):
		self.remove("")
		return nil
	case flags != 0:
		return fmt.Errorf("%w: flags %d", errEvsConfigHeadPush, flags)
	case payload == nil:
		return fmt.Errorf("%w: no payload", ErrEvsObjectMissing)
	}

	epoch := max(1, push.GetPathEpoch())
	if self.epoch != epoch {
		tokenPathKeys := make(map[string]string, len(self.paths))
		for key, path := range self.paths {
			tokenPath, err := keys.tokenPathIn(ctx, path.names, epoch)
			if err != nil {
				return err
			}
			tokenPathKeys[string(tokenPath.Bytes())] = key
		}
		self.epoch, self.tokenPathKeys = epoch, tokenPathKeys
	}
	nameKey, err := keys.manifest(ctx, epoch)
	if err != nil {
		return err
	}
	pathKey, err := keys.path(ctx, epoch)
	if err != nil {
		return err
	}

	// the token paths this push took out, which a later change of it may name again
	removedTokenPaths := []EvsTokenPath{}
	for _, change := range payload.Changes {
		key, named := self.tokenPathKeys[string(change.TokenPath.Bytes())]
		if !change.WritesEntry() {
			if !named {
				if !slices.ContainsFunc(removedTokenPaths, change.TokenPath.HasPrefix) {
					return fmt.Errorf("%w: a removal of a path no directory's row names", ErrEvsEntryRefused)
				}
				continue
			}
			self.remove(key)
			removedTokenPaths = append(removedTokenPaths, change.TokenPath)
			continue
		}
		if !named {
			return fmt.Errorf("%w: a path whose name no directory's row gives", ErrEvsEntryRefused)
		}
		path := self.paths[key]
		entry := &protocol.EvsEntryVersion{}
		if err := proto.Unmarshal(change.EntryVersion, entry); err != nil {
			return fmt.Errorf("%w: an entry that does not parse", ErrEvsEntryRefused)
		}
		switch protocol.EvsEntryKind(entry.GetKind()) {
		case protocol.EvsEntryKind_EVS_ENTRY_DIRECTORY:
			if !path.directory {
				return fmt.Errorf("%w: a directory's delta at a file's name", ErrEvsEntryRefused)
			}
			for _, removedToken := range entry.GetNames().GetRemovedTokens() {
				child, err := EvsTokenFromBytes(removedToken)
				if err != nil {
					return err
				}
				childTokenPath := append(slices.Clone(change.TokenPath), child)
				if childKey, standing := self.tokenPathKeys[string(childTokenPath.Bytes())]; standing {
					self.remove(childKey)
				}
				removedTokenPaths = append(removedTokenPaths, childTokenPath)
			}
			for _, row := range entry.GetNames().GetNames() {
				child, err := EvsTokenFromBytes(row.GetToken())
				if err != nil {
					return err
				}
				name, err := EvsNameOpen(nameKey, pathKey, change.TokenPath.Last(), child, row.GetSealedName())
				if err != nil {
					return err
				}
				childNames := append(slices.Clone(path.names), name)
				childKey := evsExportKey(childNames)
				childDirectory := protocol.EvsEntryKind(row.GetKind()) == protocol.EvsEntryKind_EVS_ENTRY_DIRECTORY
				if held := self.paths[childKey]; held != nil {
					if held.directory == childDirectory {
						// a row replaced in place names the path it named
						continue
					}
					self.remove(childKey)
				}
				self.paths[childKey] = &evsConfigHeadPath{names: childNames, directory: childDirectory}
				self.tokenPathKeys[string(append(slices.Clone(change.TokenPath), child).Bytes())] = childKey
			}
		case protocol.EvsEntryKind_EVS_ENTRY_FILE:
			if path.directory {
				return fmt.Errorf("%w: a file's version at a directory's name", ErrEvsEntryRefused)
			}
			path.entry, path.entryBytes = entry, change.EntryVersion
			path.statement, path.commitVersion = statement.Statement, statement.Version
			path.tokenPath = slices.Clone(change.TokenPath)
			path.content, path.contentRead = nil, false
		default:
			return fmt.Errorf("%w: entry kind %d", ErrEvsEntryRefused, entry.GetKind())
		}
	}
	return nil
}

// The bytes of every file standing in the tree, by its path, each version read once and kept on the tree. A file a
// directory's row names and no push wrote is not a head's.
func (self *EvsConfigHeadReader) readFiles(ctx context.Context, head *EvsVerifiedHead, keys *evsReadKeys, replay *evsConfigHeadReplay) (map[string][]byte, error) {
	repo := self.repo
	files := map[string][]byte{}
	byteCount := int64(0)
	for _, path := range replay.paths {
		if path.directory {
			continue
		}
		parts := make([]string, len(path.names))
		for i, name := range path.names {
			parts[i] = string(name)
		}
		filePath := strings.Join(parts, "/")
		if path.entry == nil {
			return nil, fmt.Errorf("%w: a path %q a directory names and no push wrote", ErrConfigHeadMalformed, filePath)
		}
		if self.settings.HeadMaxFileCount <= len(files) {
			return nil, fmt.Errorf("a head of more than %d files", self.settings.HeadMaxFileCount)
		}
		if !path.contentRead {
			content, err := func() ([]byte, error) {
				result := &evsReadResult{refId: head.RefId, head: head, keys: keys, objects: newEvsReadObjects(repo.client)}
				defer result.objects.close()
				verified := &EvsVerifiedPath{
					TokenPath: path.tokenPath, EntryBytes: path.entryBytes, Entry: path.entry,
					Statement: path.statement, CommitVersion: path.commitVersion,
				}
				spill, fields, _, err := repo.reconstructContent(ctx, result, verified, nil)
				if err != nil {
					return nil, err
				}
				defer spill.close()
				if fields.GetMode() == EvsGitModeGitlink {
					return nil, fmt.Errorf("%w: a gitlink at %q", ErrConfigHeadMalformed, filePath)
				}
				if self.settings.HeadMaxByteCount < byteCount+spill.Size() {
					return nil, fmt.Errorf("a head of more than %d bytes", self.settings.HeadMaxByteCount)
				}
				return io.ReadAll(spill.reader())
			}()
			if err != nil {
				return nil, err
			}
			path.content, path.contentRead = content, true
		}
		byteCount += int64(len(path.content))
		if self.settings.HeadMaxByteCount < byteCount {
			return nil, fmt.Errorf("a head of more than %d bytes", self.settings.HeadMaxByteCount)
		}
		files[filePath] = path.content
	}
	return files, nil
}
