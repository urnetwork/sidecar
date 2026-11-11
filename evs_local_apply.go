//go:build !sidecar_http && !js && !ios && !android && !sdk_mobile_bind

// What the local tier keeps of each git-mode ref it replays, and settle, the one rule that moves a local ref
// (DESIGN-DETAILS 8.2.2's local state, 8.2.7). Everything is in the evs component's sealed directory under
// local/<repo_id>/, beside mirror/ and mounts/, each file rewritten whole:
//
//	ref/<ref_id>          EvsGitRef: name; version and chain; tip; applied_tip; deleted and the last tip; base; stuck_at
//	                      and the spans a refusal stopped; tainted token paths; the source a version waits on
//	tips/<ref_id>/<page>  the version-tip log, 4,096 versions a page, each {version, tip, flags}, appended as versions
//	                      apply; commitless versions are left out (the tip before stands); a DELETE's tip is none
//	tipindex/<oid byte>   commit oid -> (ref_id, version) for every tip a ref version had, 256 files by the first byte
//	held/<ref_id>         an overlay's held paths: path -> file, directory or removed
//	born/<ref_id>         section 9's born journal, fed by replay (8.2.10)
//
// In the bare repository the engine keeps refs/ur/evs/<ref_id hex> at each ref's tip as evs holds it, a deleted ref's
// at its last tip, so what evs's tips reach outlives git gc and later pushes carry none of it.
//
//	settle(r)   E = EvsGitRef.tip (none: deleted); A = applied_tip; L = the local ref, read now, under L_r
//	            Q = r's journal queues updates, LOCAL or SENT, the newest one's new being L (an owned ref's queue)
//	            "ancestor" is of the peeled commits, and none is an ancestor of every commit
//	   L = E                                     -> nothing
//	   E = A and (Q or L = A)                    -> nothing: evs has not moved
//	   L = A, or L is an ancestor of E           -> follow: git update-ref r E L (delete when E is none)
//	   Q, and E is an ancestor of L              -> keep: the queue publishes L on the new tip
//	   else                                      -> conflict (evs_local_conflict.go), then follow
//	   applied_tip = E; journal updates evs's tip now covers are deleted: a new that is E or an ancestor of it, and
//	   a deletion once E is none
//
// It is written in two steps, EvsGitRef {version, tip} first and applied_tip after the update-ref, so a crash between
// them is found by the difference and the rule runs again on the same inputs. A tag differs: a local tag that is not
// evs's is replaced by it, its commit saved on a conflict branch only when no other ref reaches it. A ref with
// ConflictBranchCount conflict branches stops settling, its local ref left alone, until one is deleted.
//
// The replay store is the replay's view of the bare repository: reads through one git cat-file --batch, presence
// through one --batch-check, writes into a pack sink whose flush is git index-pack --stdin, which hashes every object
// again. A commit counts as held by the reader only when evs's tips reach it (refs/ur/evs/*) or this replay wrote
// it: the bare repository also holds a client's unpublished commits and an import's fetched history, which no
// replaying reader holds.
//
// Desktop legs only. Not safe for concurrent use but as each type says.

package sidecar

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"sort"
	"strings"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// A mounted repo's local state in the evs component's sealed store. Safe for concurrent use as the store is.
type evsLocalState struct {
	store  SidecarStore
	repoId Id
}

// The store name of key.
func (self *evsLocalState) name(key EvsLocalKey) (string, error) {
	name, err := key.Name()
	if err != nil {
		return "", err
	}
	return evsLocalStatePrefix(self.repoId) + name, nil
}

// Decodes key's file into value, false when there is none.
func (self *evsLocalState) readJson(key EvsLocalKey, value any) (bool, error) {
	name, err := self.name(key)
	if err != nil {
		return false, err
	}
	reader, err := self.store.Open(name)
	if errors.Is(err, ErrSidecarStoreAbsent) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	data, err := io.ReadAll(reader)
	reader.Close()
	if err != nil {
		return false, err
	}
	if err := json.Unmarshal(data, value); err != nil {
		return false, fmt.Errorf("%w: a local state file that does not parse", ErrSidecarStoreFailed)
	}
	return true, nil
}

// Writes value whole as key's file, durable once it answers.
func (self *evsLocalState) writeJson(key EvsLocalKey, value any) error {
	name, err := self.name(key)
	if err != nil {
		return err
	}
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	writer, err := self.store.Create(name)
	if err != nil {
		return err
	}
	defer writer.Close()
	if _, err := writer.Write(data); err != nil {
		return err
	}
	return writer.Commit()
}

// Removes key's file; none is not an error.
func (self *evsLocalState) remove(key EvsLocalKey) error {
	name, err := self.name(key)
	if err != nil {
		return err
	}
	return self.store.Remove(name)
}

// Every file of a family, by its key.
func (self *evsLocalState) list(family EvsLocalFamily) ([]EvsLocalKey, error) {
	prefix := evsLocalStatePrefix(self.repoId)
	entries, err := self.store.List(prefix + string(family) + "/")
	if err != nil {
		return nil, err
	}
	keys := []EvsLocalKey{}
	for _, entry := range entries {
		key, err := ParseEvsLocalName(strings.TrimPrefix(entry.Name, prefix))
		if err != nil {
			continue
		}
		keys = append(keys, key)
	}
	return keys, nil
}

// What replay applied of one git-mode ref (8.2.2's ref row).
type EvsGitRef struct {
	RefId Id
	// Its name bytes, from its creating push's sealed copy, nil before one is replayed.
	Name []byte
	Kind protocol.EvsRefKind
	// A file-mode ref is recorded and never applied: it has no git ref.
	Mode protocol.EvsRefMode
	// An owned ref's sidecar, from its pushes.
	OwnerSidecarId *Id
	// The version replay passed, and C there.
	Version uint64
	Chain   [32]byte
	// Its tip as evs holds it, nil for none, the commit it peels to, and the version that set it.
	Tip        *EvsGitOid
	Peeled     *EvsGitOid
	TipVersion uint64
	// The tip settle last moved the local ref to, nil for none.
	AppliedTip *EvsGitOid
	// Deleted at its last DELETE, and the tip it had then, which a re-creating push states its net change against.
	Deleted bool
	LastTip *EvsGitOid
	// An overlay's base, nil for none.
	Base *protocol.EvsOverlay
	// The version a check refused, 0 for none: nothing applies past the version before it until a DELETE (8.5).
	StuckAt uint64
	// Each span of versions a refusal stopped, [refused, the DELETE that ended it), 0 while it stands.
	Stopped [][2]uint64
	// The token paths the stopped versions changed, which the re-creating push must write or remove.
	Tainted []EvsTaintedPath
	// The source a version waits on, nil for none, and the version it waits for: no alarm of its own (8.5).
	WaitingSource  *Id
	WaitingVersion uint64
	// The order replay applied this ref's newest version in, among the mount's refs: the higher, the more recent.
	AppliedOrder uint64
	// The epoch state of the head replay last reached, nil before one.
	PathEpoch *protocol.EvsPathEpoch
	// ConflictBranchCount conflict branches stand: settle leaves the local ref alone.
	SettleStopped bool
}

// A token path a stopped version changed: its epoch and its key form.
type EvsTaintedPath struct {
	Epoch uint64 `json:"epoch"`
	Key   string `json:"key"`
}

// EvsGitRef's stored form: ids and oids as hex.
type evsGitRefRecord struct {
	RefId          string           `json:"ref_id"`
	Name           []byte           `json:"name,omitempty"`
	Kind           int32            `json:"kind,omitempty"`
	Mode           int32            `json:"mode,omitempty"`
	OwnerSidecarId string           `json:"owner,omitempty"`
	Version        uint64           `json:"version"`
	Chain          string           `json:"chain"`
	Tip            string           `json:"tip,omitempty"`
	Peeled         string           `json:"peeled,omitempty"`
	TipVersion     uint64           `json:"tip_version,omitempty"`
	AppliedTip     string           `json:"applied_tip,omitempty"`
	Deleted        bool             `json:"deleted,omitempty"`
	LastTip        string           `json:"last_tip,omitempty"`
	BaseRefId      string           `json:"base_ref_id,omitempty"`
	BaseVersion    uint64           `json:"base_version,omitempty"`
	StuckAt        uint64           `json:"stuck_at,omitempty"`
	Stopped        [][2]uint64      `json:"stopped,omitempty"`
	Tainted        []EvsTaintedPath `json:"tainted,omitempty"`
	WaitingSource  string           `json:"waiting_source,omitempty"`
	WaitingVersion uint64           `json:"waiting_version,omitempty"`
	AppliedOrder   uint64           `json:"applied_order,omitempty"`
	PathEpoch      []byte           `json:"path_epoch,omitempty"`
	SettleStopped  bool             `json:"settle_stopped,omitempty"`
}

// A new ref, never applied: version 0 at C_0.
func newEvsGitRef(repoId Id, refId Id) *EvsGitRef {
	return &EvsGitRef{RefId: refId, Chain: EvsChainStart(repoId, refId), Mode: protocol.EvsRefMode_EVS_REF_GIT}
}

// A copy that shares nothing mutable.
func (self *EvsGitRef) clone() *EvsGitRef {
	copied := *self
	copied.Name = bytes.Clone(self.Name)
	copied.Stopped = slices.Clone(self.Stopped)
	copied.Tainted = slices.Clone(self.Tainted)
	if self.Base != nil {
		copied.Base = proto.Clone(self.Base).(*protocol.EvsOverlay)
	}
	if self.PathEpoch != nil {
		copied.PathEpoch = proto.Clone(self.PathEpoch).(*protocol.EvsPathEpoch)
	}
	return &copied
}

// Whether the ref is a tag ref, which holds no path state.
func (self *EvsGitRef) tag() bool {
	return bytes.HasPrefix(self.Name, []byte(evsGitTagRefPrefix))
}

// The record of a ref.
func (self *EvsGitRef) record() *evsGitRefRecord {
	record := &evsGitRefRecord{
		RefId: hex.EncodeToString(self.RefId[:]), Name: self.Name, Kind: int32(self.Kind), Mode: int32(self.Mode),
		Version: self.Version, Chain: hex.EncodeToString(self.Chain[:]), Tip: evsOidText(self.Tip),
		Peeled: evsOidText(self.Peeled), TipVersion: self.TipVersion, AppliedTip: evsOidText(self.AppliedTip),
		Deleted: self.Deleted, LastTip: evsOidText(self.LastTip), StuckAt: self.StuckAt, Stopped: self.Stopped,
		Tainted: self.Tainted, WaitingVersion: self.WaitingVersion, AppliedOrder: self.AppliedOrder,
		SettleStopped: self.SettleStopped,
	}
	if self.OwnerSidecarId != nil {
		record.OwnerSidecarId = hex.EncodeToString(self.OwnerSidecarId[:])
	}
	if self.Base != nil {
		record.BaseRefId = hex.EncodeToString(self.Base.GetRefId())
		record.BaseVersion = self.Base.GetVersion()
	}
	if self.WaitingSource != nil {
		record.WaitingSource = hex.EncodeToString(self.WaitingSource[:])
	}
	if self.PathEpoch != nil {
		record.PathEpoch, _ = proto.MarshalOptions{Deterministic: true}.Marshal(self.PathEpoch)
	}
	return record
}

// The ref a record holds.
func (self *evsGitRefRecord) ref() (*EvsGitRef, error) {
	invalid := fmt.Errorf("%w: a ref record that does not decode", ErrSidecarStoreFailed)
	idOf := func(text string) (*Id, error) {
		if text == "" {
			return nil, nil
		}
		decoded, err := hex.DecodeString(text)
		if err != nil || len(decoded) != 16 {
			return nil, invalid
		}
		id := Id(decoded)
		return &id, nil
	}
	refId, err := idOf(self.RefId)
	if err != nil || refId == nil {
		return nil, invalid
	}
	chain, err := hex.DecodeString(self.Chain)
	if err != nil || len(chain) != 32 {
		return nil, invalid
	}
	ref := &EvsGitRef{
		RefId: *refId, Name: self.Name, Kind: protocol.EvsRefKind(self.Kind), Mode: protocol.EvsRefMode(self.Mode),
		Version: self.Version, Chain: [32]byte(chain), TipVersion: self.TipVersion, Deleted: self.Deleted,
		StuckAt: self.StuckAt, Stopped: self.Stopped, Tainted: self.Tainted, WaitingVersion: self.WaitingVersion,
		AppliedOrder: self.AppliedOrder, SettleStopped: self.SettleStopped,
	}
	for _, field := range []struct {
		text string
		oid  **EvsGitOid
	}{
		{text: self.Tip, oid: &ref.Tip}, {text: self.Peeled, oid: &ref.Peeled}, {text: self.AppliedTip, oid: &ref.AppliedTip},
		{text: self.LastTip, oid: &ref.LastTip},
	} {
		if *field.oid, err = evsOidOfText(field.text); err != nil {
			return nil, invalid
		}
	}
	if ref.OwnerSidecarId, err = idOf(self.OwnerSidecarId); err != nil {
		return nil, invalid
	}
	if ref.WaitingSource, err = idOf(self.WaitingSource); err != nil {
		return nil, invalid
	}
	if self.BaseRefId != "" {
		baseRefId, err := idOf(self.BaseRefId)
		if err != nil {
			return nil, invalid
		}
		ref.Base = &protocol.EvsOverlay{RefId: baseRefId.Bytes(), Version: self.BaseVersion}
	}
	if 0 < len(self.PathEpoch) {
		ref.PathEpoch = &protocol.EvsPathEpoch{}
		if err := proto.Unmarshal(self.PathEpoch, ref.PathEpoch); err != nil {
			return nil, invalid
		}
	}
	return ref, nil
}

// The ref's record, a new ref's when it has none.
func (self *evsLocalState) gitRef(refId Id) (*EvsGitRef, error) {
	record := &evsGitRefRecord{}
	found, err := self.readJson(EvsLocalKey{Family: EvsLocalRefs, RefId: refId}, record)
	if err != nil {
		return nil, err
	}
	if !found {
		return newEvsGitRef(self.repoId, refId), nil
	}
	return record.ref()
}

// Writes the ref's record whole.
func (self *evsLocalState) writeGitRef(ref *EvsGitRef) error {
	return self.writeJson(EvsLocalKey{Family: EvsLocalRefs, RefId: ref.RefId}, ref.record())
}

// Every ref with a record.
func (self *evsLocalState) gitRefs() ([]*EvsGitRef, error) {
	keys, err := self.list(EvsLocalRefs)
	if err != nil {
		return nil, err
	}
	refs := []*EvsGitRef{}
	for _, key := range keys {
		ref, err := self.gitRef(key.RefId)
		if err != nil {
			return nil, err
		}
		refs = append(refs, ref)
	}
	return refs, nil
}

// One entry of the tips log: a version and the tip it left, empty for none (a DELETE).
type evsGitTipEntry struct {
	Version uint64 `json:"v"`
	Tip     string `json:"t,omitempty"`
	Flags   uint32 `json:"f,omitempty"`
}

// The page of the tips log holding version.
func evsGitTipPage(version uint64) uint64 {
	return version / EvsLocalTipsPageVersionCount
}

// One page of the ref's tips log, empty when absent.
func (self *evsLocalState) tipPage(refId Id, page uint64) ([]*evsGitTipEntry, error) {
	entries := []*evsGitTipEntry{}
	if _, err := self.readJson(EvsLocalKey{Family: EvsLocalTips, RefId: refId, Page: page}, &entries); err != nil {
		return nil, err
	}
	return entries, nil
}

// Appends entries to the ref's tips log, each page rewritten whole; an entry at or below one the page holds replaces
// what it holds from there, so a replay run again after a crash appends nothing twice.
func (self *evsLocalState) appendTips(refId Id, entries []*evsGitTipEntry) error {
	for start := 0; start < len(entries); {
		page := evsGitTipPage(entries[start].Version)
		end := start
		for end < len(entries) && evsGitTipPage(entries[end].Version) == page {
			end += 1
		}
		held, err := self.tipPage(refId, page)
		if err != nil {
			return err
		}
		first := entries[start].Version
		held = slices.DeleteFunc(held, func(entry *evsGitTipEntry) bool { return first <= entry.Version })
		held = append(held, entries[start:end]...)
		if err := self.writeJson(EvsLocalKey{Family: EvsLocalTips, RefId: refId, Page: page}, held); err != nil {
			return err
		}
		start = end
	}
	return nil
}

// The tip the ref had at version by its tips log, with ok false for a version past what replay applied or inside a
// span a refusal stopped, and a nil tip for a version that left none (before its creation, after a DELETE).
func (self *evsLocalState) tipAt(ref *EvsGitRef, version uint64) (*EvsGitOid, bool, error) {
	if ref.Version < version || version == 0 {
		return nil, false, nil
	}
	for _, span := range ref.Stopped {
		if span[0] <= version && (span[1] == 0 || version < span[1]) {
			return nil, false, nil
		}
	}
	for page := evsGitTipPage(version); ; page -= 1 {
		entries, err := self.tipPage(ref.RefId, page)
		if err != nil {
			return nil, false, err
		}
		for i := len(entries) - 1; 0 <= i; i -= 1 {
			if entries[i].Version <= version {
				tip, err := evsOidOfText(entries[i].Tip)
				return tip, err == nil, err
			}
		}
		if page == 0 {
			return nil, true, nil
		}
	}
}

// One row of the tip index.
type evsGitTipIndexRow struct {
	Oid     string `json:"o"`
	RefId   string `json:"r"`
	Version uint64 `json:"v"`
}

// The tip index's rows for commit oid.
func (self *evsLocalState) tipIndexRows(oid EvsGitOid) ([]*evsGitTipIndexRow, error) {
	rows := []*evsGitTipIndexRow{}
	if _, err := self.readJson(EvsLocalKey{Family: EvsLocalTipIndex, OidByte: oid[0]}, &rows); err != nil {
		return nil, err
	}
	text := hex.EncodeToString(oid[:])
	found := []*evsGitTipIndexRow{}
	for _, row := range rows {
		if row.Oid == text {
			found = append(found, row)
		}
	}
	return found, nil
}

// Adds rows to the tip index, each file rewritten whole and kept sorted, a row held already not added again.
func (self *evsLocalState) addTipIndexRows(rows []*evsGitTipIndexRow) error {
	byByte := map[byte][]*evsGitTipIndexRow{}
	for _, row := range rows {
		decoded, err := hex.DecodeString(row.Oid)
		if err != nil || len(decoded) == 0 {
			return fmt.Errorf("%w: a tip index row's oid", ErrSidecarStoreFailed)
		}
		byByte[decoded[0]] = append(byByte[decoded[0]], row)
	}
	for oidByte, added := range byByte {
		key := EvsLocalKey{Family: EvsLocalTipIndex, OidByte: oidByte}
		held := []*evsGitTipIndexRow{}
		if _, err := self.readJson(key, &held); err != nil {
			return err
		}
		for _, row := range added {
			if !slices.ContainsFunc(held, func(other *evsGitTipIndexRow) bool { return *other == *row }) {
				held = append(held, row)
			}
		}
		sort.Slice(held, func(i int, j int) bool {
			if held[i].Oid != held[j].Oid {
				return held[i].Oid < held[j].Oid
			}
			if held[i].RefId != held[j].RefId {
				return held[i].RefId < held[j].RefId
			}
			return held[i].Version < held[j].Version
		})
		if err := self.writeJson(key, held); err != nil {
			return err
		}
	}
	return nil
}

// An overlay's held paths: path -> "f" a file, "d" a directory, "r" removed (8.2.4's overlay row).
type evsGitHeldSet map[string]string

// The held kinds.
const (
	evsGitHeldFile      = "f"
	evsGitHeldDirectory = "d"
	evsGitHeldRemoved   = "r"
)

// The ref's held set, empty when it has none.
func (self *evsLocalState) held(refId Id) (evsGitHeldSet, error) {
	held := evsGitHeldSet{}
	if _, err := self.readJson(EvsLocalKey{Family: EvsLocalHeld, RefId: refId}, &held); err != nil {
		return nil, err
	}
	return held, nil
}

// Writes the ref's held set whole.
func (self *evsLocalState) writeHeld(refId Id, held evsGitHeldSet) error {
	return self.writeJson(EvsLocalKey{Family: EvsLocalHeld, RefId: refId}, held)
}

// The ref's born journal, path -> the epoch its creation committed in.
func (self *evsLocalState) born(refId Id) (map[string]uint64, error) {
	born := map[string]uint64{}
	if _, err := self.readJson(EvsLocalKey{Family: EvsLocalBorn, RefId: refId}, &born); err != nil {
		return nil, err
	}
	return born, nil
}

// Writes the ref's born journal whole.
func (self *evsLocalState) writeBorn(refId Id, born map[string]uint64) error {
	return self.writeJson(EvsLocalKey{Family: EvsLocalBorn, RefId: refId}, born)
}

// The replay's view of a mount's bare repository (see the file header): an evsGitReplayStore. Not safe for concurrent
// use: one replay's.
type evsLocalReplayStore struct {
	mount   *EvsLocalRepo
	objects *EvsLocalObjects
	check   *EvsGitProcess
	checked *bufio.Reader
	spool   *os.File
	sink    *EvsGitPackSink
	// commits this replay found reachable from evs's tips, which stay so until a tip moves back
	reachable map[EvsGitOid]bool
}

// The store over mount's bare repository; the caller closes it.
func newEvsLocalReplayStore(ctx context.Context, mount *EvsLocalRepo, chunkByteCount int64) (*evsLocalReplayStore, error) {
	objects, err := mount.Objects(ctx)
	if err != nil {
		return nil, err
	}
	check, err := mount.git.Start(ctx, mount.BareDir, "cat-file", "--batch-check")
	if err != nil {
		objects.Close()
		return nil, err
	}
	spool, err := os.CreateTemp(mount.BareDir, "ur-replay-")
	if err != nil {
		objects.Close()
		check.Close()
		return nil, err
	}
	self := &evsLocalReplayStore{
		mount: mount, objects: objects, check: check, checked: bufio.NewReader(check.Stdout), spool: spool,
		reachable: map[EvsGitOid]bool{},
	}
	self.sink = NewEvsGitPackSink(spool, self.indexPack, self.present, chunkByteCount)
	return self, nil
}

// Ends the readers and drops the spool; what was not flushed is lost, as a crash would lose it.
func (self *evsLocalReplayStore) Close() {
	self.objects.Close()
	self.check.Close()
	self.spool.Close()
	os.Remove(self.spool.Name())
}

// One pack into the bare repository: git index-pack --stdin, which hashes every object again.
func (self *evsLocalReplayStore) indexPack(ctx context.Context, pack io.Reader) error {
	_, err := self.mount.git.RunWith(ctx, &EvsGitRunArgs{Dir: self.mount.BareDir, Input: pack, Args: []string{"index-pack", "--stdin"}})
	return err
}

// Whether the bare repository holds oid, by --batch-check.
func (self *evsLocalReplayStore) present(oid EvsGitOid) bool {
	hexOid := hex.EncodeToString(oid[:])
	if _, err := io.WriteString(self.check.Stdin, hexOid+"\n"); err != nil {
		return false
	}
	line, err := self.checked.ReadString('\n')
	if err != nil {
		return false
	}
	fields := strings.Fields(line)
	return len(fields) == 3 && fields[0] == hexOid
}

// The object's kind and bytes: a pending tree, commit or tag from the sink; a pending blob after a flush, which a
// history diff's base may need; else the repository's.
func (self *evsLocalReplayStore) ReadGitObject(ctx context.Context, oid EvsGitOid) (string, []byte, error) {
	if kind, content, ok := self.sink.PendingGitObject(oid); ok {
		return kind, content, nil
	}
	if _, pending := self.sink.pending[oid]; pending {
		if err := self.sink.Flush(ctx); err != nil {
			return "", nil, err
		}
	}
	return self.objects.ReadGitObject(ctx, oid)
}

// EvsGitObjectSink's, through the pack sink.
func (self *evsLocalReplayStore) WriteGitObject(kind string, content []byte) (EvsGitOid, error) {
	return self.sink.WriteGitObject(kind, content)
}

// A blob streamed into the pack sink.
func (self *evsLocalReplayStore) WriteGitObjectFrom(kind string, content io.Reader, size int64) (EvsGitOid, error) {
	return self.sink.WriteGitObjectFrom(kind, content, size)
}

// Pending in the sink, or present in the bare repository.
func (self *evsLocalReplayStore) HasGitObject(oid EvsGitOid) bool {
	return self.sink.HasGitObject(oid)
}

// A pending tree, commit or tag.
func (self *evsLocalReplayStore) PendingGitObject(oid EvsGitOid) (string, []byte, bool) {
	return self.sink.PendingGitObject(oid)
}

// The pending pack indexed into the bare repository.
func (self *evsLocalReplayStore) Flush(ctx context.Context) error {
	return self.sink.Flush(ctx)
}

// Learns which of oids evs's tips reach, with one rev-list over those the repository holds: what heldCommit answers
// for them afterwards.
func (self *evsLocalReplayStore) learnReachable(ctx context.Context, oids []EvsGitOid) error {
	candidates := []EvsGitOid{}
	for _, oid := range oids {
		if _, known := self.reachable[oid]; known {
			continue
		}
		if _, pending := self.sink.pending[oid]; pending {
			continue
		}
		if !self.present(oid) {
			self.reachable[oid] = false
			continue
		}
		candidates = append(candidates, oid)
	}
	for start := 0; start < len(candidates); start += evsLocalRevListArgCount {
		batch := candidates[start:min(len(candidates), start+evsLocalRevListArgCount)]
		args := append([]string{"rev-list"}, evsGitOidHexes(batch)...)
		args = append(args, "--not", "--glob="+evsLocalEvsRefPrefix+"*")
		out, err := self.mount.Git(ctx, args...)
		if err != nil {
			return err
		}
		unreached := map[string]bool{}
		for _, line := range strings.Fields(string(out)) {
			unreached[line] = true
		}
		for _, oid := range batch {
			self.reachable[oid] = !unreached[hex.EncodeToString(oid[:])]
		}
	}
	return nil
}

// The oids one rev-list names on its command line, well inside every platform's argument bound.
const evsLocalRevListArgCount = 1000

// Whether the reader holds commit oid: written by this replay, or reached by evs's tips (see the file header).
func (self *evsLocalReplayStore) heldCommit(ctx context.Context, oid EvsGitOid) bool {
	if _, pending := self.sink.pending[oid]; pending {
		return true
	}
	if reachable, known := self.reachable[oid]; known {
		return reachable
	}
	if err := self.learnReachable(ctx, []EvsGitOid{oid}); err != nil {
		return false
	}
	return self.reachable[oid]
}

// Forgets what was learned of reachability, once a tip moves back (a FORCE).
func (self *evsLocalReplayStore) forgetReachable() {
	clear(self.reachable)
}

// The local ref of gitRef in the bare repository, nil for none.
func (self *EvsLocalRepo) localRef(ctx context.Context, gitRef string) (*EvsGitOid, error) {
	out, err := self.Git(ctx, "for-each-ref", "--format=%(objectname)", gitRef)
	if err != nil {
		return nil, err
	}
	for _, line := range strings.Fields(string(out)) {
		oid, err := evsGitOidDecodeHex([]byte(line))
		if err != nil {
			return nil, fmt.Errorf("%w: for-each-ref answered no oid", ErrEvsGitFailed)
		}
		return &oid, nil
	}
	return nil, nil
}

// The commit oid peels to, by git: a tag's commit, a commit itself.
func (self *EvsLocalRepo) peel(ctx context.Context, oid EvsGitOid) (EvsGitOid, error) {
	out, err := self.Git(ctx, "rev-parse", "--verify", "--quiet", hex.EncodeToString(oid[:])+"^{commit}")
	if err != nil {
		return EvsGitOid{}, err
	}
	return evsGitOidDecodeHex(bytes.TrimSpace(out))
}

// Whether a is an ancestor of b, or b itself, of the peeled commits: none is an ancestor of every commit, and of
// nothing else.
func (self *EvsLocalRepo) ancestorOf(ctx context.Context, a *EvsGitOid, b *EvsGitOid) (bool, error) {
	switch {
	case a == nil:
		return true, nil
	case b == nil:
		return false, nil
	}
	peeledA, err := self.peel(ctx, *a)
	if err != nil {
		return false, err
	}
	peeledB, err := self.peel(ctx, *b)
	if err != nil {
		return false, err
	}
	return self.reachedBy(ctx, peeledA, []EvsGitOid{peeledB})
}

// One `git update-ref --stdin` transaction of lines, every one or none applied.
func (self *EvsLocalRepo) updateRefs(ctx context.Context, lines []string) error {
	input := strings.Join(lines, "\n") + "\n"
	_, err := self.git.RunWith(ctx, &EvsGitRunArgs{Dir: self.BareDir, Input: strings.NewReader(input), Args: []string{"update-ref", "--stdin"}})
	return err
}

// The update-ref line moving gitRef from old to new: a create, an update or a delete, the old value checked, the
// zero oid standing for none.
func evsUpdateRefLine(gitRef string, new *EvsGitOid, old *EvsGitOid) string {
	zero := strings.Repeat("0", 40)
	oldText := zero
	if old != nil {
		oldText = hex.EncodeToString(old[:])
	}
	if new == nil {
		return "delete " + gitRef + " " + oldText
	}
	return "update " + gitRef + " " + hex.EncodeToString(new[:]) + " " + oldText
}

// What settle did, for the caller's work after L_r: a conflict branch made, which its queue must publish.
type evsGitSettled struct {
	conflictRef    []byte
	conflictCommit *EvsGitOid
}

// The test hook at each of settle's kill points, nil outside tests: an error stops settle there, as a kill would,
// with what it wrote kept. It is given the point's last name: state, ref or done.
var evsLocalApplyKillHook func(point string) error

// The kill points of a replay's flush (DESIGN-DETAILS 8.6), each a barrier keyed <repo>:<ref>.
const (
	evsLocalBarrierApplyState = "evs.local.apply.state"
	evsLocalBarrierApplyRef   = "evs.local.apply.ref"
	evsLocalBarrierApplyDone  = "evs.local.apply.done"
)

// A kill point's hook, past its barrier: nil outside tests.
func evsLocalKilled(hook func(point string) error, point string) error {
	if hook != nil {
		return hook(point)
	}
	return nil
}

// Settle (see the file header), under L_r, on ref as just written. It answers a conflict branch it made.
func (self *EvsGitSyncEngine) settleWithLock(ctx context.Context, ref *EvsGitRef) (*evsGitSettled, error) {
	if ref.Mode != protocol.EvsRefMode_EVS_REF_GIT || len(ref.Name) == 0 {
		return nil, nil
	}
	mount := self.mount
	gitRef := EvsGitRefOfName(ref.Name)
	local, err := mount.localRef(ctx, gitRef)
	if err != nil {
		return nil, err
	}
	evsTip, applied := ref.Tip, ref.AppliedTip
	journal, err := self.state.journal(ref.RefId)
	if err != nil {
		return nil, err
	}
	queued := journal.queued(local)
	settled := &evsGitSettled{}
	follow := func() error {
		if evsOidEqual(local, evsTip) {
			return nil
		}
		return mount.updateRefs(ctx, []string{evsUpdateRefLine(gitRef, evsTip, local)})
	}
	conflict := func() error {
		made, err := self.conflictWithLock(ctx, ref, gitRef, local, evsTip)
		if err != nil {
			return err
		}
		if made == nil {
			// the bound: the local ref is left alone and applied_tip does not move
			return errEvsSettleStopped
		}
		settled.conflictRef, settled.conflictCommit = made.name, made.commit
		return nil
	}
	err = func() error {
		if evsOidEqual(local, evsTip) {
			return nil
		}
		if evsOidEqual(evsTip, applied) && (queued || evsOidEqual(local, applied)) {
			return nil
		}
		if ref.tag() {
			// a local tag that is not evs's is replaced, its commit saved only when no other ref reaches it
			reached, err := mount.reachedElsewhere(ctx, local, gitRef)
			if err != nil {
				return err
			}
			if reached {
				return follow()
			}
			return conflict()
		}
		if evsOidEqual(local, applied) {
			return follow()
		}
		ancestor, err := mount.ancestorOf(ctx, local, evsTip)
		if err != nil {
			return err
		}
		if ancestor {
			return follow()
		}
		if queued {
			kept, err := mount.ancestorOf(ctx, evsTip, local)
			if err != nil {
				return err
			}
			if kept {
				return nil
			}
		}
		return conflict()
	}()
	if errors.Is(err, errEvsSettleStopped) {
		ref.SettleStopped = true
		return nil, self.state.writeGitRef(ref)
	}
	if err != nil {
		return nil, err
	}
	testHookBarrier(evsLocalBarrierApplyRef, self.barrierKey(ref.RefId))
	if err := evsLocalKilled(evsLocalApplyKillHook, "ref"); err != nil {
		return nil, err
	}
	ref.AppliedTip, ref.SettleStopped = evsTip, false
	if err := self.state.writeGitRef(ref); err != nil {
		return nil, err
	}
	if err := self.dropCoveredWithLock(ctx, ref, journal); err != nil {
		return nil, err
	}
	testHookBarrier(evsLocalBarrierApplyDone, self.barrierKey(ref.RefId))
	if err := evsLocalKilled(evsLocalApplyKillHook, "done"); err != nil {
		return nil, err
	}
	if settled.conflictRef == nil {
		return nil, nil
	}
	return settled, nil
}

// Settle stopped at the conflict bound.
var errEvsSettleStopped = errors.New("evs: settle stopped at the conflict bound")

// Deletes the journal's updates evs's tip now covers (see the file header) and writes the journal.
func (self *EvsGitSyncEngine) dropCoveredWithLock(ctx context.Context, ref *EvsGitRef, journal *EvsJournalRef) error {
	changed := false
	for _, update := range slices.Clone(journal.Updates) {
		if update.State == EvsJournalReceived && update.Kind == EvsJournalKindReceive {
			// a receive's own update, which the receive path deletes once it answers
			continue
		}
		newTip, err := evsOidOfText(update.New)
		if err != nil {
			return err
		}
		covered := false
		switch {
		case newTip == nil:
			covered = ref.Tip == nil
		case ref.Tip != nil:
			covered, err = self.mount.ancestorOf(ctx, newTip, ref.Tip)
			if err != nil {
				return err
			}
		}
		if covered {
			journal.deleteUpdate(update.Seq)
			changed = true
		}
	}
	if !changed {
		return nil
	}
	return self.state.writeJournal(ref.RefId, journal)
}

// Whether a ref other than gitRef reaches commit oid: a local tag's commit is then safe to replace.
func (self *EvsLocalRepo) reachedElsewhere(ctx context.Context, oid *EvsGitOid, gitRef string) (bool, error) {
	if oid == nil {
		return true, nil
	}
	peeled, err := self.peel(ctx, *oid)
	if err != nil {
		return false, err
	}
	out, err := self.Git(ctx, "rev-list", "-n", "1", hex.EncodeToString(peeled[:]), "--not", "--exclude="+gitRef, "--all")
	if err != nil {
		return false, err
	}
	return len(bytes.TrimSpace(out)) == 0, nil
}
