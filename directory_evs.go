//go:build !ios_extension

// DirectoryCards over the directory repo's EvsRepo (RECORD-M6-28; QD-986, question
// record-m6-24-directory-cards-evs-binding-owner, option 1; §16.11's desktops row, D-MCP-31, D-EVS-61, §11.9, §11.10):
// the real binding of the team directory's evs, which RECORD-M6-13's sync and every later directory task reach through
// DirectoryCards, in place of sidecartest's FakeDirectoryCards.
//
//	refs      GET .../refs?moved_after= (EvsRepo.ListRefs): 0 lists every ref, as GET .../refs does, and evs's own all,
//	          for a value from before a push sequence's restart or a ref its head cache lost, answers every ref. Each
//	          listed head is named by its id: the erasure ref's, the cards ref's (the shared ref named cards, §11.6's
//	          ref ids), a writer's stream where an owned ref's id is its owner's ur/<sidecar_id>/record
//	          (RecordStreamRefName), anything else Other. Heads are evs's word: what a sync acts on it reads verified
//	streams   POST .../read {refs} (EvsRepo.ReadStreams), up to ReadStreamMaxRefCount streams in the order asked, each
//	          walked and verified from the version the reader holds and C there (the chain row), and pinned once read to
//	          its head. Each version's payload is held to the creates-only rule as far as its entry versions show it
//	          (EvsVerifier.VerifyPayloadRefRules, with no path state: a directory delta's base on its newest version is
//	          the record chain's to hold), each file it creates is named by its counter in its push epoch, RECORD.md
//	          section 5.2's e/<a>/<b>/<n> (record_evs.go's counter row), and its own slot, the new slot no file's chain
//	          names, is opened row by row under fek of each key's generation. Every version is answered, one creating
//	          no entry too, so a copy keeps its stream's versions with no gap
//	log       GET .../log?ref=&since= for a stream past the window: one page, LogPageVersionCount versions at most,
//	          verified from the version before it, its pin raised as far as it reaches, each version's push record read
//	          ReadObjectCount to a read and each file rebuilt as the streams read rebuilds it. A page that ends before
//	          the head gives the next page's first version as HeadVersion, so a caller pages on until more ends
//	chain     a read verifies from (v, C_v): C_0 for none; else C_v as a read of this binding was asked from or answered
//	          to for the ref, the two newest kept for ChainRefCount refs; else the client's pin when it stands at v;
//	          else a walk of the ref's log from its first statement, verified, which only a restart between a read
//	          and its copy's write needs
//	cards     the shared file-mode ref cards: one read for its head and the window's statements after the copy's
//	          version, GET .../log past the window, CardsPageVersionCount statements a page, verified from the version
//	          and pinned. Each statement's push record is read, ReadObjectCount to a read, and its changes taken in
//	          commit order: a directory's delta teaches the names it adds, a file's version is rebuilt (its per-path
//	          keys from its slots, a page's slots and segment ranges read together) and a removal is one. Each file is named by its
//	          plaintext path, found from its token path in its push's epoch among the names this binding knows: the
//	          rows of the deltas it read, the shards of q/, d/ and r/, the copy's own paths
//	          (DirectoryCardsCopyPaths), and for a token no known name gives the listing of the directory above it at
//	          the head (EvsRepo.List). A change no name places is no file the copy holds or will hold: its path was
//	          never one the copy kept, and it stands nowhere at the head, so it is left out. A removed directory
//	          removes each file the names hold below it
//	format 2  a format-2 repo's push records are read as format 2 keeps them (ParseEvsBatchRecordFormat2: the record
//	          and its tail, whose staged segments answer the payload's new objects), each payload checked as stored
//	          (EvsCheckStoredPayload). A versionless file's version names its path to evs's reader in its push's
//	          epoch, and a replaced one answers collected: the statement stands in the changes with no content. A
//	          version whose slots hold no key reads the same way where a committed ERASE names each slot, as an
//	          erasure's CLOSURE and ERASE leave every version the path held before them (§11.12's closure row); with
//	          no such ERASE the key was withheld, which alarms tamper, and the version is left out
//	erased    every read here judges a key gone from its slot, the cards ref's and a stream's alike, on the repo's
//	          ERASEs read after the slot (evs_read_erased.go): a page read a statement at a time reads them again,
//	          once, before a slot the ERASEs it read earlier do not name alarms, since an ERASE may commit between
//	writes    PutCard, RemoveCard and RemoveCards by path CAS on the cards ref (EvsRepo.WritePaths, each write's
//	          IfVersion), as the directory's reserved writer (EvsReservedDirectory), so format 2's d/, r/ and q/ files
//	          are versionless and format 1's keep every version; only a directory path (directoryCardPathKept) is
//	          written. The push declares the client's verified pin, which must stand at or above each write's AuthPin
//	          and on its chain, else ErrEvsStreamPinBehind with nothing sent. A conflict, the planner's own or evs's
//	          409, is PATH_CONFLICT. The push's id is WritePaths' own: a retry after an answer that never came meets
//	          the path CAS, which a notice's writer reads as another write landing
//	leases    Lease on EvsRepo.Subscribe for the cards ref with a notice prefix q/<h>/<tgt>/ or a notice's own path
//	          q/<h>/<tgt>/<rid> alone, tokenized in the ref's current path epoch and leased again at a PATH_EPOCH by
//	          the subscriber; any other path is ErrDirectoryLeaseRefused before anything is sent, so the cards ref
//	          itself is never leased (D-MCP-31). A change touching the path calls back on a goroutine of its own, with
//	          no lock held. The subscriber's rounds are the client's (EvsClient.StartSubscriptions), which the evs
//	          component starts
//
// Every refusal of evs comes back as *RecordStreamRefusal with its code, so the sync tells a lost read (SCOPE,
// NOT_FOUND) from any other failure; a verification failure comes back as it is, alarmed where evs's reader alarms it.
// Nothing of a view or a search reaches evs (I-19): every read here names refs, versions, push ids, slots and the
// directories above a changed path. Paths are this device's plaintext and never reach an error or a log (I-13).
//
// On every leg but the ios_extension legs. Safe for concurrent use.

package sidecar

import (
	"bytes"
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The cards ref's name bytes: the bare name of a ref that is no branch or tag (§11.6's ref ids), one shared file-mode
// ref a directory (§16.11).
const directoryCardsRefNameText = "cards"

// The cards ref's name bytes, from which every reader of the directory derives its id.
func DirectoryCardsRefName() []byte {
	return []byte(directoryCardsRefNameText)
}

// The top-level directories of the cards ref's files (§16.11's ref cards row), each sharded 256 ways by <h>.
var directoryCardsTopNames = []string{"d", "q", "r"}

// What the binding runs by.
type DirectoryEvsCardsSettings struct {
	// The cards ref's statements one ReadCards walks and opens: GET .../log's page, 1,000 statements (§11.9), so a
	// page past the window costs one log read. Positive.
	CardsPageVersionCount int
	// A stream's versions one ReadStreamLog answers: GET .../log's page, 1,000. Positive.
	LogPageVersionCount int
	// Push records, or slots, one read names: §11.9's request row, 64 of each. Positive.
	ReadObjectCount int
	// The level directories a stream's e/ holds, which finding an entry's counter tries: RECORD.md section 5.2's,
	// RecordEvsStreamsSettings.StreamLevelCount's default. A format value.
	StreamLevelCount int
	// The refs whose chains the binding keeps between reads (the file header's chain row): 4,096, a Team's moved
	// streams and its cards ref with room; past it the ref read least recently goes. Non-positive keeps none, so every
	// read finds its chain from the client's pins or the ref's log.
	ChainRefCount int
	// The cards ref paths a directory's names keep, directories among them: 65,536, past a Team's cards, repo files and
	// standing notices (§16.11's sizes); past it the names are forgotten and learned again, from the copy's paths and
	// listings. Non-positive keeps the fixed shards alone.
	CardPathCount int
	// How long Lease waits for its lease's 200 before answering with it still owed, which the subscriber's rounds keep
	// trying: 30 s. Positive.
	LeaseWait time.Duration
}

// §11.9's pages and bounds, RECORD.md section 5.2's levels, and room for a Team at its limit.
func DefaultDirectoryEvsCardsSettings() *DirectoryEvsCardsSettings {
	return &DirectoryEvsCardsSettings{
		CardsPageVersionCount: 1000,
		LogPageVersionCount:   1000,
		ReadObjectCount:       64,
		StreamLevelCount:      DefaultRecordEvsStreamsSettings().StreamLevelCount,
		ChainRefCount:         4096,
		CardPathCount:         64 * 1024,
		LeaseWait:             30 * time.Second,
	}
}

// What the binding runs on.
type DirectoryEvsCardsArgs struct {
	// The directory's network's evs client, whose verified state, pins and subscriber every call uses.
	Client   *EvsClient
	Settings *DirectoryEvsCardsSettings
}

// DirectoryCards, DirectoryCardsRemover and DirectoryCardsCopyPaths over an EvsClient. See the file header.
type DirectoryEvsCards struct {
	client   *EvsClient
	settings *DirectoryEvsCardsSettings

	stateLock sync.Mutex
	// each ref's chain at the newest versions a read was asked from or answered to, and the count of reads that orders
	// them for eviction
	refKeyChains  map[evsRefKey]*directoryEvsRefChains
	chainUseCount uint64
	// each directory's cards ref names
	repoIdNames map[Id]*directoryEvsNames
}

// A binding on args.
func NewDirectoryEvsCards(args *DirectoryEvsCardsArgs) (*DirectoryEvsCards, error) {
	if args == nil || args.Client == nil {
		return nil, fmt.Errorf("%w: the directory's evs binding needs an evs client", ErrDirectoryCardsUnavailable)
	}
	settings := args.Settings
	if settings == nil {
		settings = DefaultDirectoryEvsCardsSettings()
	}
	return &DirectoryEvsCards{
		client:       args.Client,
		settings:     settings,
		refKeyChains: map[evsRefKey]*directoryEvsRefChains{},
		repoIdNames:  map[Id]*directoryEvsNames{},
	}, nil
}

// A refusal of a call this binding makes no request for, as evs would answer it.
func directoryEvsInvalid() error {
	return &RecordStreamRefusal{Code: protocol.EvsRefusalCode_EVS_REFUSAL_INVALID}
}

// The listed refs, each named by its id: see the file header's refs row.
func (self *DirectoryEvsCards) Refs(ctx context.Context, repoId Id, movedAfter uint64) (*DirectoryRefListing, error) {
	repo := self.client.Repo(repoId)
	args := &EvsListRefsArgs{}
	if 0 < movedAfter {
		args.MovedAfter = &movedAfter
	}
	listing, err := repo.ListRefs(ctx, args)
	if err != nil {
		return nil, recordEvsRefusal(err)
	}
	cardsRefId, err := repo.RefIdOf(ctx, DirectoryCardsRefName())
	if err != nil {
		return nil, err
	}
	erasureRefId := EvsErasureRefId(repoId)
	answer := &DirectoryRefListing{Sequence: listing.PushSequence, Format: listing.Format, All: listing.All}
	for _, head := range listing.Refs {
		refId, err := IdFromBytes(head.GetRefId())
		if err != nil {
			return nil, fmt.Errorf("%w: a listed ref id of %d bytes", ErrEvsReplyInvalid, len(head.GetRefId()))
		}
		ref := &DirectoryRef{Kind: DirectoryRefOther, Version: head.GetVersion(), Sequence: head.GetPushSequence()}
		switch {
		case refId == erasureRefId:
			ref.Kind = DirectoryRefErasure
		case refId == cardsRefId:
			ref.Kind = DirectoryRefCards
		case head.GetRefKind() == protocol.EvsRefKind_EVS_REF_OWNED:
			ownerId, err := IdFromBytes(head.GetOwnerSidecarId())
			if err != nil {
				break
			}
			streamRefId, err := repo.RefIdOf(ctx, RecordStreamRefName(ownerId))
			if err != nil {
				return nil, err
			}
			if streamRefId == refId {
				ref.Kind = DirectoryRefStream
				ref.WriterSidecarId = ownerId
			}
		}
		answer.Refs = append(answer.Refs, ref)
	}
	return answer, nil
}

// A ref's chain at the two newest versions a read was asked from or answered to.
type directoryEvsRefChains struct {
	versionChains map[uint64][sha256.Size]byte
	useCount      uint64
}

// Keeps a ref's chain at version: see the file header's chain row.
func (self *DirectoryEvsCards) keepChain(repoId Id, refId Id, version uint64, chain [sha256.Size]byte) {
	if version == 0 || self.settings.ChainRefCount <= 0 {
		return
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	key := evsRefKey{repoId: repoId, refId: refId}
	held := self.refKeyChains[key]
	if held == nil {
		held = &directoryEvsRefChains{versionChains: map[uint64][sha256.Size]byte{}}
		self.refKeyChains[key] = held
	}
	held.versionChains[version] = chain
	// the asked version and the answered one: older ones no read starts from again
	for 2 < len(held.versionChains) {
		oldestVersion := version
		for heldVersion := range held.versionChains {
			oldestVersion = min(oldestVersion, heldVersion)
		}
		delete(held.versionChains, oldestVersion)
	}
	self.chainUseCount += 1
	held.useCount = self.chainUseCount
	for self.settings.ChainRefCount < len(self.refKeyChains) {
		var oldestKey evsRefKey
		var oldest *directoryEvsRefChains
		for heldKey, chains := range self.refKeyChains {
			if oldest == nil || chains.useCount < oldest.useCount {
				oldestKey, oldest = heldKey, chains
			}
		}
		delete(self.refKeyChains, oldestKey)
	}
}

// The ref's chain at version this binding keeps, false for none.
func (self *DirectoryEvsCards) keptChain(repoId Id, refId Id, version uint64) ([sha256.Size]byte, bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	held := self.refKeyChains[evsRefKey{repoId: repoId, refId: refId}]
	if held == nil {
		return [sha256.Size]byte{}, false
	}
	chain, ok := held.versionChains[version]
	if ok {
		self.chainUseCount += 1
		held.useCount = self.chainUseCount
	}
	return chain, ok
}

// C at version of the ref, which a read verifies from: see the file header's chain row.
func (self *DirectoryEvsCards) chainAt(ctx context.Context, repoId Id, refId Id, version uint64) ([sha256.Size]byte, error) {
	if version == 0 {
		return EvsChainStart(repoId, refId), nil
	}
	if chain, ok := self.keptChain(repoId, refId, version); ok {
		return chain, nil
	}
	pin, pinned, err := self.client.pins.Pin(repoId, refId)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	if pinned && pin.Version == version {
		return pin.Chain, nil
	}
	walked, err := self.client.verifier.Walk(ctx, repoId, refId, 0, EvsChainStart(repoId, refId), version)
	if err != nil {
		return [sha256.Size]byte{}, recordEvsRefusal(err)
	}
	if len(walked) == 0 {
		return [sha256.Size]byte{}, fmt.Errorf("%w: no statement up to version %d", ErrEvsChainBroken, version)
	}
	if err := self.client.verifier.checkPinOnWalk(repoId, refId, walked); err != nil {
		return [sha256.Size]byte{}, err
	}
	chain := walked[len(walked)-1].Chain
	self.keepChain(repoId, refId, version, chain)
	return chain, nil
}

// Raises the ref's pin to a verified walk's last statement where the pin stands below it: a verified prefix, which a
// later head below it would contradict (I-16).
func (self *DirectoryEvsCards) raisePin(repoId Id, refId Id, walked []*EvsVerifiedStatement) error {
	if len(walked) == 0 {
		return nil
	}
	last := walked[len(walked)-1]
	pin, pinned, err := self.client.pins.Pin(repoId, refId)
	if err != nil {
		return err
	}
	if pinned && last.Version <= pin.Version {
		return nil
	}
	return self.client.verifier.Pin(&EvsVerifiedHead{RepoId: repoId, RefId: refId, Head: &protocol.EvsHeadSummary{}, Version: last.Version, Chain: last.Chain})
}

// Up to ReadStreamMaxRefCount streams after the versions held: see the file header's streams row.
func (self *DirectoryEvsCards) ReadStreams(ctx context.Context, repoId Id, reads []*DirectoryStreamRead) ([]*DirectoryStreamVersions, error) {
	if len(reads) == 0 || DefaultEvsFormatSettings().ReadStreamMaxRefCount < len(reads) {
		return nil, directoryEvsInvalid()
	}
	repo := self.client.Repo(repoId)
	evsReads := make([]*EvsStreamRead, 0, len(reads))
	for _, read := range reads {
		if read == nil {
			return nil, directoryEvsInvalid()
		}
		refId, err := repo.RefIdOf(ctx, RecordStreamRefName(read.WriterSidecarId))
		if err != nil {
			return nil, err
		}
		chain, err := self.chainAt(ctx, repoId, refId, read.PinVersion)
		if err != nil {
			return nil, err
		}
		// a stream behind the window pages the log from here
		self.keepChain(repoId, refId, read.PinVersion, chain)
		evsReads = append(evsReads, &EvsStreamRead{RefId: refId, PinVersion: read.PinVersion, PinChain: chain})
	}
	answers, err := repo.ReadStreams(ctx, evsReads)
	if err != nil {
		return nil, recordEvsRefusal(err)
	}
	if len(answers) != len(reads) {
		return nil, fmt.Errorf("%w: %d streams answered for %d read", ErrEvsReplyInvalid, len(answers), len(reads))
	}
	keys := newEvsReadKeys(repo)
	streamReads := []*directoryEvsStreamRead{}
	results := make([]*DirectoryStreamVersions, 0, len(answers))
	for i, answer := range answers {
		result := &DirectoryStreamVersions{
			WriterSidecarId: reads[i].WriterSidecarId, HeadVersion: answer.Head.GetVersion(), More: answer.More != 0,
			Behind: answer.Behind, ByteCount: answer.ByteCount,
		}
		for _, version := range answer.Versions {
			slotBodies := map[Id][]byte{}
			for _, slot := range version.Slots {
				slotBodies[slot.Id] = slot.Body
			}
			streamRead := &directoryEvsStreamRead{
				refId: evsReads[i].RefId, statement: version.Statement, payload: version.Payload, files: version.Files,
				slotBodies: slotBodies, result: result,
			}
			streamReads = append(streamReads, streamRead)
		}
		results = append(results, result)
	}
	if err := self.streamVersions(ctx, repo, keys, streamReads); err != nil {
		return nil, err
	}
	for i, result := range results {
		if 0 < len(result.Versions) {
			last := result.Versions[len(result.Versions)-1].Version
			self.keepChain(repoId, evsReads[i].RefId, last.Version, [sha256.Size]byte(last.Chain))
		}
	}
	return results, nil
}

// One version of a stream as a read carried it, and the answer it joins.
type directoryEvsStreamRead struct {
	refId     Id
	statement *EvsVerifiedStatement
	payload   *EvsCheckedPayload
	// the files it creates, rebuilt
	files []*EvsStreamFileRead
	// the slot bodies the read carried, by id
	slotBodies map[Id][]byte
	result     *DirectoryStreamVersions
}

// Each read version as the directory keeps it, appended to its answer in order: see the file header's streams row.
// The push's own slots the reads did not carry are read together, ReadObjectCount to a read.
func (self *DirectoryEvsCards) streamVersions(ctx context.Context, repo *EvsRepo, keys *evsReadKeys, streamReads []*directoryEvsStreamRead) error {
	repoId := repo.repoId
	// each stream's counter search, by ref and push epoch
	type countersKey struct {
		refId     Id
		pathEpoch uint64
	}
	keyCounters := map[countersKey]*recordStreamCounters{}
	versions := make([]*DirectoryStreamVersion, len(streamReads))
	// the push's own slot of each version, and those no read carried
	ownSlotIds := make([]*Id, len(streamReads))
	uncarried := []Id{}
	for i, streamRead := range streamReads {
		statement := streamRead.statement
		push := statement.Statement.Push
		if err := self.client.verifier.VerifyPayloadRefRules(statement.Statement, repoId, streamRead.refId, streamRead.payload.Changes, nil); err != nil {
			// a config or pin this device cannot judge at proves nothing against the signer, as a walk holds it
			quiet := errors.Is(err, ErrEvsNoConfig) || errors.Is(err, ErrGkmAuthAhead) || errors.Is(err, ErrGkmAuthNotRetained)
			if !quiet {
				alarm := SidecarEvsAlarmTamper
				if errors.Is(err, ErrEvsVersionRule) {
					alarm = SidecarEvsAlarmVersionRule
				}
				self.client.alarm(repoId, streamRead.refId, alarm, "", evsSignerOf(statement.Statement.Bytes))
			}
			return err
		}
		pushId, _ := IdFromBytes(push.GetPushId())
		version := &RecordStreamVersion{
			Version: statement.Version, PushId: pushId, TimeMillis: push.GetTimeMs(), Chain: bytes.Clone(statement.Chain[:]),
		}
		if push.GetAuth() != nil {
			version.AuthPin = &bridge.AuthPin{Version: push.GetAuth().GetVersion(), Chain: bytes.Clone(push.GetAuth().GetChain())}
		}
		named := map[Id]bool{}
		for _, file := range streamRead.files {
			for _, slotId := range file.Entry.GetSlotIds() {
				named[recordIdOf(slotId)] = true
			}
			if file.Erased {
				// every slot its chain keeps keys in was emptied by a committed ERASE: nothing to give
				continue
			}
			key := countersKey{refId: streamRead.refId, pathEpoch: push.GetPathEpoch()}
			counters := keyCounters[key]
			if counters == nil {
				pathKey, err := keys.path(ctx, push.GetPathEpoch())
				if err != nil {
					return err
				}
				if counters, err = newRecordStreamCounters(pathKey); err != nil {
					return err
				}
				keyCounters[key] = counters
			}
			n, ok, err := counters.counter(file.TokenPath, self.settings.StreamLevelCount)
			if err != nil {
				return err
			}
			if !ok {
				self.client.alarm(repoId, streamRead.refId, SidecarEvsAlarmTamper, "", evsSignerOf(statement.Statement.Bytes))
				return fmt.Errorf("%w: a stream file at no stream path", ErrEvsEntryRefused)
			}
			path, err := RecordStreamPath(n)
			if err != nil {
				return err
			}
			version.Entries = append(version.Entries, &RecordStreamEntry{Path: path, Entry: file.Content})
		}
		// the push's order is its counters', which the statement's token order is not
		slices.SortFunc(version.Entries, func(a *RecordStreamEntry, b *RecordStreamEntry) int {
			n, _ := RecordStreamPathCounter(a.Path)
			m, _ := RecordStreamPathCounter(b.Path)
			return cmp.Compare(n, m)
		})
		for _, object := range streamRead.payload.NewObjects {
			if object.Kind != protocol.EvsNewObjectKind_EVS_NEW_OBJECT_SLOT || named[recordIdOf(object.Id)] {
				continue
			}
			slotId := recordIdOf(object.Id)
			version.SlotId = slotId
			ownSlotIds[i] = &slotId
			if _, ok := streamRead.slotBodies[slotId]; !ok {
				uncarried = append(uncarried, slotId)
			}
		}
		versions[i] = &DirectoryStreamVersion{Version: version}
	}
	read, err := self.readSlots(ctx, repoId, uncarried)
	if err != nil {
		return err
	}
	for i, streamRead := range streamReads {
		if ownSlotIds[i] != nil {
			slotId := *ownSlotIds[i]
			body, ok := streamRead.slotBodies[slotId]
			if !ok {
				body, ok = read[slotId]
			}
			if ok && 0 < len(body) {
				slot, err := self.openSlot(ctx, repoId, streamRead.refId, keys, slotId, body)
				if err != nil {
					return err
				}
				versions[i].Slot = slot
			}
		}
		streamRead.result.Versions = append(streamRead.result.Versions, versions[i])
	}
	return nil
}

// The bodies evs holds of slotIds, ReadObjectCount to a read on the erasure ref, as a slot read names it: a slot
// emptied or gone is left out.
func (self *DirectoryEvsCards) readSlots(ctx context.Context, repoId Id, slotIds []Id) (map[Id][]byte, error) {
	bodies := map[Id][]byte{}
	count := max(1, self.settings.ReadObjectCount)
	for start := 0; start < len(slotIds); start += count {
		request := &protocol.EvsReadRequest{RefId: EvsErasureRefId(repoId).Bytes()}
		for _, slotId := range slotIds[start:min(len(slotIds), start+count)] {
			request.SlotIds = append(request.SlotIds, slotId.Bytes())
		}
		err := func() error {
			_, objects, err := self.client.postRead(ctx, repoId, request)
			if err != nil {
				return recordEvsRefusal(err)
			}
			defer objects.close()
			for _, slotIdBytes := range request.SlotIds {
				if body, ok := objects.slot(slotIdBytes); ok {
					bodies[recordIdOf(slotIdBytes)] = body
				}
			}
			return nil
		}()
		if err != nil {
			return nil, err
		}
	}
	return bodies, nil
}

// A stream push's own slot, its live rows each opened from its record slot row block under fek of its generation.
// A slot that is no slot object, or a key that does not open, alarms and refuses: no honest writer stores one.
func (self *DirectoryEvsCards) openSlot(ctx context.Context, repoId Id, refId Id, keys *evsReadKeys, slotId Id, body []byte) (*RecordSlot, error) {
	slot, err := EvsDecodeSlotObject(body)
	if err != nil {
		self.client.alarm(repoId, refId, SidecarEvsAlarmTamper, "", nil)
		return nil, err
	}
	// a row is a key: an owner-bound repo's reader that does not write it deposits its receipt first (§16.8)
	if err := self.client.preDecrypt(ctx, repoId, refId, [][]byte{slotId.Bytes()}); err != nil {
		return nil, err
	}
	rows, err := openRecordSlotRows(slot, func(generation uint64) (*EvsFekKey, error) { return keys.fek(ctx, generation) })
	if err != nil {
		if errors.Is(err, ErrEvsSealInvalid) {
			self.client.alarm(repoId, refId, SidecarEvsAlarmTamper, "", nil)
		}
		return nil, err
	}
	return &RecordSlot{SlotId: slotId, Rows: rows}, nil
}

// One GET .../log?ref=&since= page.
func (self *DirectoryEvsCards) logPage(ctx context.Context, repoId Id, refId Id, since uint64) (*protocol.EvsLogReply, error) {
	reply := &protocol.EvsLogReply{}
	err := self.client.http.callMessage(ctx, &evsCall{
		route:  "GET /evs/v1/repos/{repo_id}/log",
		method: http.MethodGet,
		path:   "/evs/v1/repos/" + evsUrlId(repoId) + "/log?ref=" + evsUrlId(refId) + "&since=" + strconv.FormatUint(since, 10),
		repoId: repoId,
		role:   evsScopeRead,
		retry:  true,
	}, reply)
	if err != nil {
		return nil, recordEvsRefusal(err)
	}
	return reply, nil
}

// One page of a stream past the window: see the file header's log row.
func (self *DirectoryEvsCards) ReadStreamLog(ctx context.Context, repoId Id, writerSidecarId Id, afterVersion uint64) (*DirectoryStreamVersions, error) {
	repo := self.client.Repo(repoId)
	refId, err := repo.RefIdOf(ctx, RecordStreamRefName(writerSidecarId))
	if err != nil {
		return nil, err
	}
	fromChain, err := self.chainAt(ctx, repoId, refId, afterVersion)
	if err != nil {
		return nil, err
	}
	page, err := self.logPage(ctx, repoId, refId, afterVersion+1)
	if err != nil {
		return nil, err
	}
	statements := page.GetStatements()
	more := page.GetNextVersion() != 0
	if count := max(1, self.settings.LogPageVersionCount); count < len(statements) {
		statements, more = statements[:count], true
	}
	result := &DirectoryStreamVersions{WriterSidecarId: writerSidecarId, HeadVersion: afterVersion}
	if len(statements) == 0 {
		return result, nil
	}
	through := statements[len(statements)-1].GetVersion()
	walked, err := self.client.verifier.walk(repoId, refId, afterVersion, fromChain, statements, through)
	if err != nil {
		return nil, err
	}
	if err := self.client.verifier.checkPinOnWalk(repoId, refId, walked); err != nil {
		return nil, err
	}
	if err := self.raisePin(repoId, refId, walked); err != nil {
		return nil, err
	}
	head := &EvsVerifiedHead{RepoId: repoId, RefId: refId, Head: &protocol.EvsHeadSummary{RefId: refId.Bytes()}, Version: through}
	payloads, err := self.pushPayloads(ctx, repo, head, walked)
	if err != nil {
		return nil, err
	}
	keys := newEvsReadKeys(repo)
	readResult := &evsReadResult{refId: refId, head: head, keys: keys, objects: newEvsReadObjects(self.client)}
	defer readResult.objects.close()
	streamReads := []*directoryEvsStreamRead{}
	// the page's one judge of emptied slots, which its versions' slot reads, a statement at a time, may pass: a slot
	// read after the ERASEs were is judged on them read again (evs_read_erased.go)
	erasures := evsErasedKeysOf(keys)
	for i, statement := range walked {
		files, err := self.rebuildStreamFiles(ctx, repo, readResult, statement, payloads[i], erasures)
		if err != nil {
			return nil, err
		}
		streamReads = append(streamReads, &directoryEvsStreamRead{
			refId: refId, statement: statement, payload: payloads[i], files: files, slotBodies: map[Id][]byte{}, result: result,
		})
	}
	if err := self.streamVersions(ctx, repo, keys, streamReads); err != nil {
		return nil, err
	}
	result.More = more
	result.HeadVersion = through
	if more {
		// the head lies past this page: its next version at least, which a caller pages on to
		result.HeadVersion = through + 1
	}
	self.keepChain(repoId, refId, through, walked[len(walked)-1].Chain)
	return result, nil
}

// Each file a stream's push creates, rebuilt from the record the page read: as the streams read gives it, a file
// whose every chain slot came back emptied reading as erased only where a committed ERASE names each slot, on the
// ERASEs read after the slots (evs_read_erased.go), and one whose rebuild met a key an ERASE destroyed reading so too.
func (self *DirectoryEvsCards) rebuildStreamFiles(ctx context.Context, repo *EvsRepo, readResult *evsReadResult, statement *EvsVerifiedStatement, payload *EvsCheckedPayload, erasures *evsErasedKeys) ([]*EvsStreamFileRead, error) {
	entries := []*protocol.EvsEntryVersion{}
	changes := []*EvsCheckedChange{}
	for _, change := range payload.Changes {
		if !change.WritesEntry() {
			continue
		}
		entry := &protocol.EvsEntryVersion{}
		if err := proto.Unmarshal(change.EntryVersion, entry); err != nil {
			return nil, fmt.Errorf("%w: a stream entry that does not parse", ErrEvsEntryRefused)
		}
		if entry.GetKind() != uint32(protocol.EvsEntryKind_EVS_ENTRY_FILE) {
			continue
		}
		entries = append(entries, entry)
		changes = append(changes, change)
	}
	if err := self.prefetchVersions(ctx, readResult, entries); err != nil {
		return nil, err
	}
	files := []*EvsStreamFileRead{}
	for i, entry := range entries {
		change := changes[i]
		if evsStreamFileEmptied(readResult.objects, entry) {
			named, err := erasures.namesSlots(ctx, repo, entry)
			if err != nil {
				return nil, recordEvsRefusal(err)
			}
			if !named {
				// evs served the file's slots empty and no committed ERASE names them: a key withheld, no erasure
				self.client.alarm(repo.repoId, readResult.refId, SidecarEvsAlarmTamper, "", nil)
				return nil, fmt.Errorf("%w: a file's slots served empty with no ERASE naming them", ErrEvsSealInvalid)
			}
			files = append(files, &EvsStreamFileRead{TokenPath: change.TokenPath, EntryBytes: change.EntryVersion, Entry: entry, Erased: true})
			continue
		}
		content, err := self.rebuild(ctx, repo, readResult, statement, change, entry, "")
		if errors.Is(err, ErrEvsErased) {
			// a key of its chain a committed ERASE destroyed, in a slot the prefetch did not carry
			files = append(files, &EvsStreamFileRead{TokenPath: change.TokenPath, EntryBytes: change.EntryVersion, Entry: entry, Erased: true})
			continue
		}
		if err != nil {
			return nil, err
		}
		files = append(files, &EvsStreamFileRead{TokenPath: change.TokenPath, EntryBytes: change.EntryVersion, Entry: entry, Content: content})
	}
	return files, nil
}

// One file version's content, rebuilt and checked against its sealed fields. path is the file's plaintext path where
// the binding knows it, a cards ref file's: a versionless version's rounds name its path at that version, which is how
// evs finds a staged segment in its push's record and answers a replaced version collected (§11.7's reads row;
// evs_read_versionless.go), so the read result is given the path the version answers, in its push's epoch. A replaced
// version answers ErrEvsCollected, after the fresh read that shows its replacement.
func (self *DirectoryEvsCards) rebuild(ctx context.Context, repo *EvsRepo, readResult *evsReadResult, statement *EvsVerifiedStatement, change *EvsCheckedChange, entry *protocol.EvsEntryVersion, path string) ([]byte, error) {
	verified := &EvsVerifiedPath{
		TokenPath: change.TokenPath, EntryBytes: change.EntryVersion, Entry: entry, Statement: statement.Statement,
		CommitVersion: statement.Version,
	}
	if entry.GetVersioning() != 0 && path != "" && len(readResult.paths) == len(readResult.replies) {
		readResult.paths = append(readResult.paths, &evsReadPath{
			path:          path,
			version:       entry.GetVersion(),
			commitVersion: statement.Version,
			current:       change.TokenPath,
			epochPaths:    []*protocol.EvsSourcePath{{Epoch: statement.Statement.Push.GetPathEpoch(), TokenPath: change.TokenPath.Components()}},
			verified:      verified,
		})
		readResult.replies = append(readResult.replies, verified)
	}
	spill, _, _, err := repo.reconstructContent(ctx, readResult, verified, nil)
	if err != nil {
		return nil, recordEvsRefusal(err)
	}
	defer spill.close()
	return io.ReadAll(spill.reader())
}

// Reads what the entries' rebuilds need that the read result does not hold yet, together: each format-1 version's
// segment ranges, as EvsRepo.fetchVersionMissing names them (a keyed segment's header and the record's range, a staged
// one's prefix), at most EvsReadMaxRangeCount ranges and EvsReadMaxRangeByteCount bytes a read, and the slots their
// chains keep keys in, ReadObjectCount a read, a versionless version's slots among them, which show a version whose
// key an ERASE destroyed before its rebuild is tried: what each file's rebuild would otherwise ask alone. Anything
// left out, a versionless version's segments above all, its rebuild reads itself.
func (self *DirectoryEvsCards) prefetchVersions(ctx context.Context, readResult *evsReadResult, entries []*protocol.EvsEntryVersion) error {
	ranges := []*protocol.EvsReadRange{}
	slotIds := [][]byte{}
	seen := map[string]bool{}
	wantRange := func(segmentId []byte, offset uint32, length uint32) {
		key := fmt.Sprintf("%x/%d/%d", segmentId, offset, length)
		if _, ok := readResult.objects.segmentRange(segmentId, offset, length); ok || seen[key] {
			return
		}
		seen[key] = true
		ranges = append(ranges, &protocol.EvsReadRange{SegmentId: segmentId, Offset: offset, Length: length})
	}
	for _, entry := range entries {
		for _, slotId := range entry.GetSlotIds() {
			if _, ok := readResult.objects.slot(slotId); ok || seen[string(slotId)] {
				continue
			}
			seen[string(slotId)] = true
			slotIds = append(slotIds, slotId)
		}
		if entry.GetVersioning() != 0 {
			continue
		}
		for _, locator := range entry.GetChain() {
			if protocol.EvsLocatorKind(locator.GetKind()) != protocol.EvsLocatorKind_EVS_LOCATOR_SEGMENT {
				continue
			}
			if locator.GetStaged() {
				through := uint64(locator.GetOffset()) + uint64(locator.GetLength())
				if through <= EvsStagedSegmentMaxByteCount {
					wantRange(locator.GetId(), 0, uint32(through))
				}
				continue
			}
			wantRange(locator.GetId(), 0, evsSegmentKeyedHeaderByteCount)
			wantRange(locator.GetId(), locator.GetOffset(), locator.GetLength())
		}
	}
	requests := []*protocol.EvsReadRequest{}
	var request *protocol.EvsReadRequest
	requestByteCount := uint64(0)
	for _, readRange := range ranges {
		if request == nil || EvsReadMaxRangeCount <= len(request.Ranges) || EvsReadMaxRangeByteCount < requestByteCount+uint64(readRange.GetLength()) {
			request = &protocol.EvsReadRequest{RefId: readResult.refId.Bytes(), PinVersion: readResult.head.Version}
			requests = append(requests, request)
			requestByteCount = 0
		}
		request.Ranges = append(request.Ranges, readRange)
		requestByteCount += uint64(readRange.GetLength())
	}
	count := max(1, self.settings.ReadObjectCount)
	for start, i := 0, 0; start < len(slotIds); start, i = start+count, i+1 {
		if len(requests) <= i {
			requests = append(requests, &protocol.EvsReadRequest{RefId: readResult.refId.Bytes(), PinVersion: readResult.head.Version})
		}
		requests[i].SlotIds = slotIds[start:min(len(slotIds), start+count)]
	}
	for _, request := range requests {
		_, objects, err := self.client.postRead(ctx, readResult.head.RepoId, request)
		if err != nil {
			return recordEvsRefusal(err)
		}
		for key, spill := range objects.objects {
			if held := readResult.objects.objects[key]; held != nil {
				held.close()
			}
			readResult.objects.objects[key] = spill
		}
		for id := range objects.missing {
			readResult.objects.missing[id] = true
		}
	}
	return nil
}

// Each walked statement's checked payload, in order: a one-part push's record read by push id ReadObjectCount to a
// read, each held to its statement as a replaying reader holds it (§11.6's checks row), and a sealed push's parts as
// EvsRepo.pushContent reads them.
func (self *DirectoryEvsCards) pushPayloads(ctx context.Context, repo *EvsRepo, head *EvsVerifiedHead, walked []*EvsVerifiedStatement) ([]*EvsCheckedPayload, error) {
	payloads := make([]*EvsCheckedPayload, len(walked))
	onePart := []int{}
	for i, statement := range walked {
		if 0 < statement.Statement.Push.GetPartCount() {
			payload, err := repo.pushContent(ctx, head, statement)
			if err != nil {
				return nil, recordEvsRefusal(err)
			}
			payloads[i] = payload
			continue
		}
		onePart = append(onePart, i)
	}
	count := max(1, self.settings.ReadObjectCount)
	format2 := self.client.format2Reader() != nil
	for start := 0; start < len(onePart); start += count {
		batch := onePart[start:min(len(onePart), start+count)]
		request := &protocol.EvsReadRequest{RefId: head.RefId.Bytes(), PinVersion: head.Version}
		for _, i := range batch {
			request.Pushes = append(request.Pushes, &protocol.EvsReadPush{PushId: walked[i].Statement.Push.GetPushId(), Version: walked[i].Version})
		}
		err := func() error {
			_, objects, err := self.client.postRead(ctx, repo.repoId, request)
			if err != nil {
				return recordEvsRefusal(err)
			}
			defer objects.close()
			pushIdRecords := map[string][]byte{}
			for key, spill := range objects.objects {
				if key.kind != protocol.EvsReadObjectKind_EVS_READ_OBJECT_BATCH_RECORD || key.number != 0 {
					continue
				}
				record, err := io.ReadAll(spill.reader())
				if err != nil {
					return err
				}
				pushIdRecords[key.id] = record
			}
			for _, i := range batch {
				statement := walked[i]
				record, ok := pushIdRecords[hex.EncodeToString(statement.Statement.Push.GetPushId())]
				if !ok {
					return fmt.Errorf("%w: the push record of version %d", ErrEvsObjectMissing, statement.Version)
				}
				// the batch record as its place holds it, a re-seeded push's under the reseed type (QD-725); a format-2
				// reader takes a format-2 record, its staged tail beside it, as EvsRepo.pushPayload reads one
				var batchRecord *EvsBatchRecord
				var tail *EvsBatchRecordTail
				var err error
				if format2 {
					batchRecord, tail, err = ParseEvsBatchRecordFormat2(record)
				} else {
					batchRecord, err = ParseEvsBatchRecord(record)
				}
				if err != nil || (batchRecord.Type != protocol.EvsBatchRecordType_EVS_BATCH_PUSH && batchRecord.Type != protocol.EvsBatchRecordType_EVS_BATCH_RESEED) {
					return fmt.Errorf("%w: a push record that is not one push's", ErrEvsEntryRefused)
				}
				statementBytes, payloadBytes, err := ParseEvsPushRecordBody(batchRecord.Body)
				if err != nil || !bytes.Equal(statementBytes, statement.Statement.Bytes) {
					return fmt.Errorf("%w: a push record of another statement", ErrEvsEntryRefused)
				}
				var payload *EvsCheckedPayload
				if format2 {
					if payload, err = EvsCheckStoredPayload(statement.Statement, payloadBytes); err != nil {
						return err
					}
					if tail != nil && len(tail.Staged) != 0 {
						segments, err := tail.StagedSegments()
						if err != nil {
							return err
						}
						if payload.Staged, err = evsMatchStaged(statement.Statement.Push, payload.NewObjects, segments); err != nil {
							return err
						}
					}
				} else if payload, err = EvsCheckRecordPayload(statement.Statement, payloadBytes); err != nil {
					// as evs keeps it, with no slot body: keys come from slot reads alone (QD-806)
					return err
				}
				payloads[i] = payload
			}
			return nil
		}()
		if err != nil {
			return nil, err
		}
	}
	return payloads, nil
}

// One directory's cards ref names (the file header's cards row). Guarded by the binding's stateLock.
type directoryEvsNames struct {
	// each known plaintext path's kind, a directory's or a file's, in the order learned
	pathKinds map[string]protocol.EvsEntryKind
	paths     []string
	// the copy's paths were handed over (DirectoryCardsCopyPaths)
	copied bool
	// each epoch's index of the known paths: how many of paths it holds, each path's token path, and the path of each
	// token path by its key form
	epochIndexes map[uint64]*directoryEvsEpochIndex
}

// One epoch's tokens of a directory's known paths.
type directoryEvsEpochIndex struct {
	indexed        int
	pathTokenPaths map[string]EvsTokenPath
	tokenKeyPaths  map[string]string
}

// Names holding the fixed directories alone: d, q and r and their shards, every <h> a byte's two hex digits.
func newDirectoryEvsNames() *directoryEvsNames {
	names := &directoryEvsNames{pathKinds: map[string]protocol.EvsEntryKind{}, epochIndexes: map[uint64]*directoryEvsEpochIndex{}}
	for _, top := range directoryCardsTopNames {
		names.learn(top, protocol.EvsEntryKind_EVS_ENTRY_DIRECTORY)
		for shard := 0; shard <= 0xff; shard += 1 {
			names.learn(top+"/"+hex.EncodeToString([]byte{byte(shard)}), protocol.EvsEntryKind_EVS_ENTRY_DIRECTORY)
		}
	}
	return names
}

// How many paths newDirectoryEvsNames holds: each top-level directory and its 256 shards.
func directoryEvsFixedNameCount() int {
	return len(directoryCardsTopNames) * (1 + 0x100)
}

// Learns path as kind, and each directory above it.
func (self *directoryEvsNames) learn(path string, kind protocol.EvsEntryKind) {
	if path == "" {
		return
	}
	if slash := strings.LastIndexByte(path, '/'); 0 <= slash {
		if parentKind, ok := self.pathKinds[path[:slash]]; !ok || parentKind != protocol.EvsEntryKind_EVS_ENTRY_DIRECTORY {
			self.learn(path[:slash], protocol.EvsEntryKind_EVS_ENTRY_DIRECTORY)
		}
	}
	if _, ok := self.pathKinds[path]; !ok {
		self.paths = append(self.paths, path)
	}
	self.pathKinds[path] = kind
}

// The path tokenPath names in pathKey's epoch, false for none known, the epoch's index brought up to every known path.
func (self *directoryEvsNames) resolve(tokenPath EvsTokenPath, pathKey *EvsPathKey) (string, bool, error) {
	if len(tokenPath) == 0 {
		return "", true, nil
	}
	index := self.epochIndexes[pathKey.epoch]
	if index == nil {
		index = &directoryEvsEpochIndex{pathTokenPaths: map[string]EvsTokenPath{}, tokenKeyPaths: map[string]string{}}
		self.epochIndexes[pathKey.epoch] = index
	}
	for ; index.indexed < len(self.paths); index.indexed += 1 {
		path := self.paths[index.indexed]
		tokens, err := index.tokenPathOf(path, pathKey)
		if err != nil {
			return "", false, err
		}
		index.tokenKeyPaths[tokens.KeyString()] = path
	}
	path, ok := index.tokenKeyPaths[tokenPath.KeyString()]
	return path, ok, nil
}

// path's token path in the index's epoch, its parents' kept on the way.
func (self *directoryEvsEpochIndex) tokenPathOf(path string, pathKey *EvsPathKey) (EvsTokenPath, error) {
	if tokens, ok := self.pathTokenPaths[path]; ok {
		return tokens, nil
	}
	parent := EvsTokenPath{}
	name := path
	if slash := strings.LastIndexByte(path, '/'); 0 <= slash {
		var err error
		if parent, err = self.tokenPathOf(path[:slash], pathKey); err != nil {
			return nil, err
		}
		name = path[slash+1:]
	}
	token, err := EvsPathToken(pathKey, parent.Last(), []byte(name))
	if err != nil {
		return nil, err
	}
	tokens := append(slices.Clone(parent), token)
	self.pathTokenPaths[path] = tokens
	return tokens, nil
}

// The files the names hold below directory.
func (self *directoryEvsNames) filesBelow(directory string) []string {
	files := []string{}
	for _, path := range self.paths {
		if strings.HasPrefix(path, directory+"/") && self.pathKinds[path] == protocol.EvsEntryKind_EVS_ENTRY_FILE {
			files = append(files, path)
		}
	}
	return files
}

// Runs f on repoId's names under stateLock, made on first use and forgotten past CardPathCount.
func (self *DirectoryEvsCards) withNames(repoId Id, f func(names *directoryEvsNames) error) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	names := self.repoIdNames[repoId]
	if names == nil {
		names = newDirectoryEvsNames()
		self.repoIdNames[repoId] = names
	}
	err := f(names)
	if max(0, self.settings.CardPathCount)+directoryEvsFixedNameCount() < len(names.paths) {
		// past the bound: learned again, from the copy's paths and listings
		delete(self.repoIdNames, repoId)
	}
	return err
}

// Whether the copy's paths of repoId were handed over: DirectoryCardsCopyPaths.
func (self *DirectoryEvsCards) CopyPathsKnown(repoId Id) bool {
	known := false
	self.withNames(repoId, func(names *directoryEvsNames) error {
		known = names.copied
		return nil
	})
	return known
}

// Learns the paths the copy holds: DirectoryCardsCopyPaths.
func (self *DirectoryEvsCards) KnowCopyPaths(repoId Id, paths []string) {
	self.withNames(repoId, func(names *directoryEvsNames) error {
		for _, path := range paths {
			if _, err := evsPathNames(path); err == nil {
				names.learn(path, protocol.EvsEntryKind_EVS_ENTRY_FILE)
			}
		}
		names.copied = true
		return nil
	})
}

// One ReadCards call's state: its keys, read result and the directories it listed.
type directoryEvsCardsRead struct {
	repo       *EvsRepo
	refId      Id
	keys       *evsReadKeys
	readResult *evsReadResult
	listed     map[string]bool
}

// The plaintext path tokenPath names in epoch: a known name, else found by listing at the head the directory above it
// that the names place, one level at a time, below a top shard only, since every name above is fixed. False for a
// path no listing shows.
func (self *DirectoryEvsCards) resolvePath(ctx context.Context, read *directoryEvsCardsRead, tokenPath EvsTokenPath, epoch uint64) (string, bool, error) {
	repoId := read.repo.repoId
	pathKey, err := read.keys.path(ctx, epoch)
	if err != nil {
		return "", false, err
	}
	for {
		path := ""
		resolved := false
		parent := ""
		parentDepth := -1
		err := self.withNames(repoId, func(names *directoryEvsNames) error {
			var err error
			if path, resolved, err = names.resolve(tokenPath, pathKey); err != nil || resolved {
				return err
			}
			for depth := len(tokenPath) - 1; 0 <= depth; depth -= 1 {
				held, ok, err := names.resolve(tokenPath[:depth], pathKey)
				if err != nil {
					return err
				}
				if ok {
					parent, parentDepth = held, depth
					return nil
				}
			}
			return nil
		})
		if err != nil || resolved {
			return path, resolved, err
		}
		// at the root and the top shards every name is fixed, so a token they do not place names no file of the
		// directory's: no listing
		if parentDepth < 2 || read.listed[parent] {
			return "", false, nil
		}
		read.listed[parent] = true
		listing, err := read.repo.List(ctx, &EvsReadArgs{RefId: &read.refId, Path: parent})
		if errors.Is(err, ErrEvsPathAbsent) || errors.Is(err, ErrEvsTokenInvalid) {
			// gone by the head, or a file where a directory stood
			return "", false, nil
		}
		if err != nil {
			return "", false, recordEvsRefusal(err)
		}
		self.withNames(repoId, func(names *directoryEvsNames) error {
			for _, entry := range listing.Entries {
				names.learn(parent+"/"+string(entry.Name), entry.Kind)
			}
			return nil
		})
	}
}

// Learns the names a directory's delta adds, its rows opened under their epochs' keys and checked against their
// tokens. A delta whose directory no name places is passed by, its children found later by listing if they stand; one
// whose rows do not open alarms tamper, naming its signer, and teaches nothing.
func (self *DirectoryEvsCards) learnDelta(ctx context.Context, read *directoryEvsCardsRead, change *EvsCheckedChange, entry *protocol.EvsEntryVersion, epoch uint64, signerId *Id) error {
	if entry.GetNames() == nil || len(entry.GetNames().GetNames()) == 0 {
		return nil
	}
	directory, ok, err := self.resolvePath(ctx, read, change.TokenPath, epoch)
	if err != nil || !ok {
		return err
	}
	epochKeys := func(rowEpoch uint64) (*EvsManifestKey, *EvsPathKey, EvsToken, error) {
		manifest, err := read.keys.manifest(ctx, rowEpoch)
		if err != nil {
			return nil, nil, EvsToken{}, err
		}
		pathKey, err := read.keys.path(ctx, rowEpoch)
		if err != nil {
			return nil, nil, EvsToken{}, err
		}
		if rowEpoch == epoch {
			return manifest, pathKey, change.TokenPath.Last(), nil
		}
		// a carried row: its parent's token in its own epoch
		names, err := evsReadPathNames(directory)
		if err != nil {
			return nil, nil, EvsToken{}, err
		}
		tokens, err := EvsPathTokens(pathKey, names)
		if err != nil {
			return nil, nil, EvsToken{}, err
		}
		return manifest, pathKey, tokens.Last(), nil
	}
	opened, err := EvsOpenNameTable(entry.GetNames(), epoch, epochKeys)
	if errors.Is(err, ErrEvsSealInvalid) || errors.Is(err, ErrEvsTokenInvalid) {
		self.client.alarm(read.repo.repoId, read.refId, SidecarEvsAlarmTamper, "", signerId)
		return nil
	}
	if err != nil {
		return err
	}
	return self.withNames(read.repo.repoId, func(names *directoryEvsNames) error {
		for _, row := range opened {
			child := string(row.Name)
			if directory != "" {
				child = directory + "/" + child
			}
			names.learn(child, row.Kind)
		}
		return nil
	})
}

// The cards ref's statements after afterVersion, one page: see the file header's cards row.
func (self *DirectoryEvsCards) ReadCards(ctx context.Context, repoId Id, afterVersion uint64) (*DirectoryCardsChanges, error) {
	repo := self.client.Repo(repoId)
	refId, err := repo.RefIdOf(ctx, DirectoryCardsRefName())
	if err != nil {
		return nil, err
	}
	// the head, and the window's statements after the version held: past evs's head cache when a lease's hint named a
	// newer version (§11.9's cache row)
	fresh := afterVersion < self.client.hintedVersion(repoId, refId)
	reply, objects, err := self.client.postRead(ctx, repoId, &protocol.EvsReadRequest{RefId: refId.Bytes(), PinVersion: afterVersion, Fresh: fresh})
	if err != nil {
		return nil, recordEvsRefusal(err)
	}
	objects.close()
	headVersion := reply.head.GetVersion()
	headChain, err := EvsChainFromBytes(reply.head.GetChain())
	if err != nil {
		return nil, fmt.Errorf("%w: the head's chain", ErrEvsReplyInvalid)
	}
	changes := &DirectoryCardsChanges{HeadVersion: headVersion, ThroughVersion: afterVersion}
	if headVersion < afterVersion {
		// below what the copy holds: the pin rule refuses it, and the copy keeps what it verified (I-16)
		if err := self.client.verifier.checkPin(repoId, refId, headVersion, headChain); err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("%w: the cards ref's head below the version held", ErrEvsHeadForked)
	}
	fromChain, err := self.chainAt(ctx, repoId, refId, afterVersion)
	if err != nil {
		return nil, err
	}
	if headVersion == afterVersion {
		if fromChain != headChain {
			return nil, fmt.Errorf("%w: a head at the version held with another chain", ErrEvsHeadForked)
		}
		return changes, nil
	}
	through := min(headVersion, afterVersion+uint64(max(1, self.settings.CardsPageVersionCount)))
	statements := []*protocol.EvsReadStatement{}
	if reply.behind == 0 {
		for _, statement := range reply.statements {
			if statement.GetVersion() <= through {
				statements = append(statements, statement)
			}
		}
	} else if statements, err = self.client.readLog(ctx, repoId, refId, afterVersion+1, through); err != nil {
		return nil, recordEvsRefusal(err)
	}
	walked, err := self.client.verifier.walk(repoId, refId, afterVersion, fromChain, statements, through)
	if err != nil {
		return nil, err
	}
	if through == headVersion {
		if walked[len(walked)-1].Chain != headChain {
			return nil, fmt.Errorf("%w: the statements do not chain to the head", ErrEvsChainBroken)
		}
		if err := self.client.verifier.checkPin(repoId, refId, headVersion, headChain); err != nil {
			return nil, err
		}
		if err := self.client.verifier.Pin(&EvsVerifiedHead{RepoId: repoId, RefId: refId, Head: reply.head, Version: headVersion, Chain: headChain}); err != nil {
			return nil, err
		}
	} else {
		if err := self.client.verifier.checkPinOnWalk(repoId, refId, walked); err != nil {
			return nil, err
		}
		if err := self.raisePin(repoId, refId, walked); err != nil {
			return nil, err
		}
	}
	head := &EvsVerifiedHead{RepoId: repoId, RefId: refId, Head: reply.head, Version: headVersion, Chain: headChain}
	payloads, err := self.pushPayloads(ctx, repo, head, walked)
	if err != nil {
		return nil, err
	}
	keys := newEvsReadKeys(repo)
	read := &directoryEvsCardsRead{
		repo: repo, refId: refId, keys: keys, listed: map[string]bool{},
		readResult: &evsReadResult{refId: refId, head: head, keys: keys, objects: newEvsReadObjects(self.client)},
	}
	defer read.readResult.objects.close()
	files, err := self.cardFiles(ctx, read, walked, payloads)
	if err != nil {
		return nil, err
	}
	changes.Files = files
	changes.ThroughVersion = through
	changes.More = through < headVersion
	self.keepChain(repoId, refId, through, walked[len(walked)-1].Chain)
	return changes, nil
}

// One change of a cards ref push, its entry parsed, a removal's nil.
type directoryEvsCardChange struct {
	change *EvsCheckedChange
	entry  *protocol.EvsEntryVersion
}

// The files the walked statements wrote and removed, in commit order: see the file header's cards row.
func (self *DirectoryEvsCards) cardFiles(ctx context.Context, read *directoryEvsCardsRead, walked []*EvsVerifiedStatement, payloads []*EvsCheckedPayload) ([]*DirectoryCardFile, error) {
	repoId := read.repo.repoId
	// each statement's file changes, by path, after its deltas taught their names
	type placedChange struct {
		statement *EvsVerifiedStatement
		change    *directoryEvsCardChange
		path      string
	}
	placed := []*placedChange{}
	written := []*protocol.EvsEntryVersion{}
	for i, statement := range walked {
		push := statement.Statement.Push
		var signerId *Id
		if id, err := IdFromBytes(push.GetSignerSidecarId()); err == nil {
			signerId = &id
		}
		deltas := []*directoryEvsCardChange{}
		fileChanges := []*directoryEvsCardChange{}
		for _, change := range payloads[i].Changes {
			if !change.WritesEntry() {
				fileChanges = append(fileChanges, &directoryEvsCardChange{change: change})
				continue
			}
			entry := &protocol.EvsEntryVersion{}
			if err := proto.Unmarshal(change.EntryVersion, entry); err != nil {
				return nil, fmt.Errorf("%w: a cards entry that does not parse", ErrEvsEntryRefused)
			}
			if entry.GetKind() == uint32(protocol.EvsEntryKind_EVS_ENTRY_DIRECTORY) {
				deltas = append(deltas, &directoryEvsCardChange{change: change, entry: entry})
			} else {
				fileChanges = append(fileChanges, &directoryEvsCardChange{change: change, entry: entry})
			}
		}
		// the shallowest first, so each directory is placed before its own rows name its children
		slices.SortStableFunc(deltas, func(a *directoryEvsCardChange, b *directoryEvsCardChange) int {
			return cmp.Compare(len(a.change.TokenPath), len(b.change.TokenPath))
		})
		for _, delta := range deltas {
			if err := self.learnDelta(ctx, read, delta.change, delta.entry, push.GetPathEpoch(), signerId); err != nil {
				return nil, err
			}
		}
		for _, fileChange := range fileChanges {
			path, ok, err := self.resolvePath(ctx, read, fileChange.change.TokenPath, push.GetPathEpoch())
			if err != nil {
				return nil, err
			}
			if !ok {
				continue
			}
			if fileChange.entry != nil {
				self.withNames(repoId, func(names *directoryEvsNames) error {
					names.learn(path, protocol.EvsEntryKind_EVS_ENTRY_FILE)
					return nil
				})
				if !directoryCardPathKept(path) {
					continue
				}
				written = append(written, fileChange.entry)
			}
			placed = append(placed, &placedChange{statement: statement, change: fileChange, path: path})
		}
	}
	if err := self.prefetchVersions(ctx, read.readResult, written); err != nil {
		return nil, err
	}
	files := []*DirectoryCardFile{}
	erasures := evsErasedKeysOf(read.keys)
	for _, placedChange := range placed {
		statement := placedChange.statement
		push := statement.Statement.Push
		stamp := func(file *DirectoryCardFile) *DirectoryCardFile {
			file.PushVersion = statement.Version
			file.SignerSidecarId, _ = IdFromBytes(push.GetSignerSidecarId())
			if push.GetAuth() != nil {
				file.AuthPin = &bridge.AuthPin{Version: push.GetAuth().GetVersion(), Chain: bytes.Clone(push.GetAuth().GetChain())}
			}
			file.TimeMillis = push.GetTimeMs()
			return file
		}
		change := placedChange.change
		if change.entry == nil {
			kind := protocol.EvsEntryKind_EVS_ENTRY_FILE
			below := []string{}
			self.withNames(repoId, func(names *directoryEvsNames) error {
				kind = names.pathKinds[placedChange.path]
				if kind == protocol.EvsEntryKind_EVS_ENTRY_DIRECTORY {
					below = names.filesBelow(placedChange.path)
				}
				return nil
			})
			if kind == protocol.EvsEntryKind_EVS_ENTRY_DIRECTORY {
				// a removed directory: each file below it goes with it, its own version unknown here
				for _, path := range below {
					files = append(files, stamp(&DirectoryCardFile{Path: path, Removed: true}))
				}
				continue
			}
			files = append(files, stamp(&DirectoryCardFile{
				Path: placedChange.path, Version: change.change.Change.GetBaseEntryVersion() + 1, Removed: true,
			}))
			continue
		}
		if evsStreamFileEmptied(read.readResult.objects, change.entry) {
			// the version's slots hold no key. Where a committed ERASE names each slot it is an erased version, as a
			// CLOSURE's ERASE leaves every version the path held before it (§11.12's closure row): the statement
			// stands with no content, as a collected version's does. With no such ERASE the key was withheld, which
			// alarms, and the version is ignored as one that does not open. The ERASEs are read after the slots
			// (evs_read_erased.go)
			named, err := erasures.namesSlots(ctx, read.repo, change.entry)
			if err != nil {
				return nil, recordEvsRefusal(err)
			}
			if named {
				files = append(files, stamp(&DirectoryCardFile{Path: placedChange.path, Version: change.entry.GetVersion()}))
			} else {
				self.client.alarm(repoId, read.readResult.refId, SidecarEvsAlarmTamper, "", nil)
			}
			continue
		}
		content, err := self.rebuild(ctx, read.repo, read.readResult, statement, change.change, change.entry, placedChange.path)
		if errors.Is(err, ErrEvsCollected) || errors.Is(err, ErrEvsErased) {
			// a versionless file's replaced version, its content purged, or a version a key of which a committed ERASE
			// destroyed: the statement stands with no content, which the copy reads as a version it holds nothing of
			// (§16.11's ref cards row)
			files = append(files, stamp(&DirectoryCardFile{Path: placedChange.path, Version: change.entry.GetVersion()}))
			continue
		}
		if err != nil {
			code, refused := RecordStreamRefusalCode(err)
			if errors.Is(err, ErrEvsSealInvalid) || errors.Is(err, ErrEvsObjectMissing) || errors.Is(err, ErrEvsEntryRefused) ||
				(refused && code == protocol.EvsRefusalCode_EVS_REFUSAL_NOT_FOUND) {
				// a version that does not open, alarmed by its rebuild: ignored, so the copy keeps what it last took
				continue
			}
			return nil, err
		}
		files = append(files, stamp(&DirectoryCardFile{Path: placedChange.path, Version: change.entry.GetVersion(), Content: content}))
	}
	return files, nil
}

// A write the binding sends: a directory path, at most once a push, with its pin.
func (self *DirectoryEvsCards) checkWrites(writes []*DirectoryCardWrite) error {
	paths := map[string]bool{}
	for _, write := range writes {
		if write == nil || !directoryCardPathKept(write.Path) || paths[write.Path] || write.AuthPin == nil {
			return directoryEvsInvalid()
		}
		paths[write.Path] = true
	}
	return nil
}

// One push of writes by path CAS on the cards ref: see the file header's writes row. Each write's new path version,
// a removal's the one it removed past.
func (self *DirectoryEvsCards) writeCards(ctx context.Context, repoId Id, writes []*DirectoryCardWrite, removal bool) ([]uint64, error) {
	if len(writes) == 0 {
		return nil, directoryEvsInvalid()
	}
	if err := self.checkWrites(writes); err != nil {
		return nil, err
	}
	state, err := self.client.verifier.config()
	if err != nil {
		return nil, err
	}
	pathWrites := make([]*EvsPathWrite, 0, len(writes))
	for _, write := range writes {
		if state.Pin().GetVersion() < write.AuthPin.GetVersion() || !state.OnChain(write.AuthPin) {
			return nil, ErrEvsStreamPinBehind
		}
		if removal && write.IfVersion == 0 {
			// nothing stands to remove at the version read
			return nil, &RecordStreamRefusal{Code: protocol.EvsRefusalCode_EVS_REFUSAL_PATH_CONFLICT}
		}
		ifVersion := write.IfVersion
		pathWrite := &EvsPathWrite{Path: write.Path, Remove: removal, IfVersion: &ifVersion}
		if !removal {
			if write.Content == nil {
				return nil, directoryEvsInvalid()
			}
			pathWrite.Content = bytes.NewReader(bytes.Clone(write.Content))
			pathWrite.Options = &EvsWriteOptions{Versioning: EvsVersioningKeepSetting, Reserved: EvsReservedDirectory}
		}
		pathWrites = append(pathWrites, pathWrite)
	}
	result, err := self.client.Repo(repoId).WritePaths(ctx, &EvsWritePathsArgs{RefName: DirectoryCardsRefName(), Writes: pathWrites})
	if err != nil {
		return nil, recordEvsRefusal(err)
	}
	return result.PathVersions, nil
}

// Writes a file of the cards ref by path CAS, answering its new version: see the file header's writes row.
func (self *DirectoryEvsCards) PutCard(ctx context.Context, repoId Id, write *DirectoryCardWrite) (uint64, error) {
	versions, err := self.writeCards(ctx, repoId, []*DirectoryCardWrite{write}, false)
	if err != nil {
		return 0, err
	}
	return versions[0], nil
}

// Removes a file of the cards ref by path CAS.
func (self *DirectoryEvsCards) RemoveCard(ctx context.Context, repoId Id, write *DirectoryCardWrite) error {
	_, err := self.writeCards(ctx, repoId, []*DirectoryCardWrite{write}, true)
	return err
}

// Removes several files of the cards ref in one push, each by its path CAS, all or none: DirectoryCardsRemover.
func (self *DirectoryEvsCards) RemoveCards(ctx context.Context, repoId Id, writes []*DirectoryCardWrite) error {
	_, err := self.writeCards(ctx, repoId, writes, true)
	return err
}

// Leases a notice prefix or a notice's path on the cards ref: see the file header's leases row.
func (self *DirectoryEvsCards) Lease(repoId Id, prefix string, callback func(repoId Id)) (func(), error) {
	if !DirectoryLeasePathAllowed(prefix) || callback == nil {
		return nil, ErrDirectoryLeaseRefused
	}
	ctx, cancel := context.WithTimeout(context.Background(), self.settings.LeaseWait)
	defer cancel()
	subscription, err := self.client.Repo(repoId).Subscribe(ctx, &EvsSubscribeArgs{
		RefName: DirectoryCardsRefName(),
		Paths:   []string{strings.TrimSuffix(prefix, "/")},
		Changes: func(change *EvsRepoChange) {
			// on the subscriber's goroutine, which must not block: the callback runs on its own
			go callback(repoId)
		},
	})
	if err != nil {
		return nil, recordEvsRefusal(err)
	}
	var releaseOnce sync.Once
	return func() { releaseOnce.Do(subscription.Close) }, nil
}
