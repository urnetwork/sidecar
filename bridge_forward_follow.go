// The Forwarder's follow, its witness and its store's layout (BRIDGE-M8-05; DESIGN-DETAILS 4.2.2, 4.2.5).
//
// A follow reads the projection after the newest stored entry with the forwarding client's token, a page at a time. It
// keeps a page only when its entries are this network's, at consecutive positions and chained onto what the store
// holds, so the store is always one chain from the anchored genesis: a page that breaks the chain is head_alarm fork
// and nothing of it is kept. Rows are stored before the entries that name them. Each kept page goes to the sink's
// ApplyDeltas while it is enforcing, tier 1's chain, base and denial checks, and a compile is wanted when the sink took
// an entry it did not apply as a denial, when it is pending on its anchor, or while narrowing entries wait.
//
// The records, under the component's sealed store (4.2.2's layout):
//
//	genesis                       the Signed Genesis, verbatim, whose hash is the anchor's
//	log/<n, 20 digits>            one AuthEntry, verbatim: from the newest base's retention point on, dropped when a
//	                              newer compiled base's point passes them
//	rows/<rows_sha256 hex>        a base's ProjectionRows, verbatim; the newest compiled base's and any newer kept
//	head/<v, 20 digits>-<sha hex> a verified config head's files, the newest HeadCacheCount kept
//	gen/<g, 20 digits>            RK_g with its Signed GenRotate (bridge_forward_keys.go)
//	compiled                      the newest compile the sink took (bridge_forward_compile.go)
//	bindings.json                 the binding cache (bridge_compile_local.go)
//
// A page's rows are held whole as api answers them, and a head's files whole as its reader answers them: streaming
// both through the store is the review phase's storage-backed compile (QD-641).

package sidecar

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The Forwarder's record names (the file's comment).
const (
	forwarderGenesisName      = "genesis"
	forwarderLogPrefix        = "log/"
	forwarderRowsPrefix       = "rows/"
	forwarderHeadPrefix       = "head/"
	forwarderGenerationPrefix = "gen/"
	forwarderCompiledName     = "compiled"
	// the digits a position, a version or a generation is written in, so names sort in number order
	forwarderNumberDigits = 20
)

// A page api served that is no continuation of this network's log as the store holds it.
var errForwarderPageRefused = errors.New("forwarder: a projection page refused")

// The store's records by what they hold. On the Forwarder's one goroutine, but for generation keys, which RepoKeyAt
// reads from any.
type forwarderRecords struct {
	store ForwarderStore
}

// A number as a record name writes it.
func forwarderNumberName(prefix string, number uint64) string {
	return fmt.Sprintf("%s%0*d", prefix, forwarderNumberDigits, number)
}

// The number a record name writes after prefix, false for a name that is none.
func forwarderNameNumber(prefix string, name string) (uint64, bool) {
	digits, ok := strings.CutPrefix(name, prefix)
	if !ok || len(digits) != forwarderNumberDigits {
		return 0, false
	}
	number, err := strconv.ParseUint(digits, 10, 64)
	if err != nil {
		return 0, false
	}
	return number, true
}

// A record's bytes, read to its end so a cut record keeps nothing. ErrSidecarStoreAbsent for none.
func (self *forwarderRecords) read(name string) ([]byte, error) {
	reader, err := self.store.Open(name)
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	return io.ReadAll(reader)
}

// Replaces a record, whole.
func (self *forwarderRecords) write(name string, data []byte) error {
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

// The positions the log records hold, which must be one run: from and through, both 0 for none.
func (self *forwarderRecords) logRange() (uint64, uint64, error) {
	entries, err := self.store.List(forwarderLogPrefix)
	if err != nil {
		return 0, 0, err
	}
	from, through := uint64(0), uint64(0)
	for _, entry := range entries {
		n, ok := forwarderNameNumber(forwarderLogPrefix, entry.Name)
		if !ok || n == 0 {
			continue
		}
		switch {
		case from == 0:
			from, through = n, n
		case n == through+1:
			through = n
		default:
			return 0, 0, fmt.Errorf("the stored log skips from %d to %d", through, n)
		}
	}
	return from, through, nil
}

// The stored entries in [from, through], verbatim; an error when one is missing.
func (self *forwarderRecords) entries(from uint64, through uint64) ([][]byte, error) {
	entries := [][]byte{}
	for n := from; n <= through && 0 < n; n += 1 {
		entryBytes, err := self.read(forwarderNumberName(forwarderLogPrefix, n))
		if err != nil {
			return nil, fmt.Errorf("stored entry %d: %w", n, err)
		}
		entries = append(entries, entryBytes)
	}
	return entries, nil
}

// Keeps entries at consecutive positions from first, oldest first, so a kill leaves a run.
func (self *forwarderRecords) appendEntries(first uint64, entries [][]byte) error {
	for i, entryBytes := range entries {
		if err := self.write(forwarderNumberName(forwarderLogPrefix, first+uint64(i)), entryBytes); err != nil {
			return err
		}
	}
	return nil
}

// Drops the stored entries before n, oldest first, so a kill leaves a run.
func (self *forwarderRecords) dropEntriesBefore(n uint64) error {
	entries, err := self.store.List(forwarderLogPrefix)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if position, ok := forwarderNameNumber(forwarderLogPrefix, entry.Name); !ok || position < n {
			if err := self.store.Remove(entry.Name); err != nil {
				return err
			}
		}
	}
	return nil
}

// Drops every stored entry, newest first, so a kill leaves a run from the same start: what a follow does before it
// starts again from api's retention point.
func (self *forwarderRecords) resetLog() error {
	entries, err := self.store.List(forwarderLogPrefix)
	if err != nil {
		return err
	}
	for _, entry := range slices.Backward(entries) {
		if err := self.store.Remove(entry.Name); err != nil {
			return err
		}
	}
	return nil
}

// The newest stored entry's pin, nil for none.
func (self *forwarderRecords) tip() (*bridge.AuthPin, error) {
	_, through, err := self.logRange()
	if err != nil || through == 0 {
		return nil, err
	}
	return self.pinAt(through)
}

// (n, A_n) of the stored entry at n.
func (self *forwarderRecords) pinAt(n uint64) (*bridge.AuthPin, error) {
	entryBytes, err := self.read(forwarderNumberName(forwarderLogPrefix, n))
	if err != nil {
		return nil, err
	}
	entry := &bridge.AuthEntry{}
	if err := proto.Unmarshal(entryBytes, entry); err != nil {
		return nil, err
	}
	chain, err := bridge.AuthChainDigest(entry.GetN(), entry.GetPrevChain(), entry.GetKind(), entry.GetTimeMs(), entry.GetBody())
	if err != nil {
		return nil, err
	}
	if entry.GetN() != n {
		return nil, fmt.Errorf("the stored entry at %d names %d", n, entry.GetN())
	}
	return &bridge.AuthPin{Version: n, Chain: chain[:]}, nil
}

// The name of a base's rows.
func forwarderRowsName(rowsSha256 []byte) string {
	return forwarderRowsPrefix + hex.EncodeToString(rowsSha256)
}

// Streams a base's rows, for the sink's verification and the judge's.
func (self *forwarderRecords) openRows(rowsSha256 []byte) (io.ReadCloser, error) {
	if len(rowsSha256) != sha256.Size {
		return nil, fmt.Errorf("rows named by %d bytes", len(rowsSha256))
	}
	return self.store.Open(forwarderRowsName(rowsSha256))
}

// Drops every stored rows record but those named.
func (self *forwarderRecords) keepRows(rowsSha256s [][]byte) error {
	entries, err := self.store.List(forwarderRowsPrefix)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		kept := slices.ContainsFunc(rowsSha256s, func(rowsSha256 []byte) bool { return entry.Name == forwarderRowsName(rowsSha256) })
		if !kept {
			if err := self.store.Remove(entry.Name); err != nil {
				return err
			}
		}
	}
	return nil
}

// The name of a config head's record.
func forwarderHeadName(configVersion uint64, configHeadSha256 []byte) string {
	return forwarderNumberName(forwarderHeadPrefix, configVersion) + "-" + hex.EncodeToString(configHeadSha256)
}

// A head's files as one record: each path and its data, in path order, each a uvarint length and its bytes.
func forwarderEncodeHead(files map[string][]byte) []byte {
	paths := make([]string, 0, len(files))
	for path := range files {
		paths = append(paths, path)
	}
	slices.Sort(paths)
	data := []byte{}
	for _, path := range paths {
		data = binary.AppendUvarint(data, uint64(len(path)))
		data = append(data, path...)
		data = binary.AppendUvarint(data, uint64(len(files[path])))
		data = append(data, files[path]...)
	}
	return data
}

// The files a head record holds.
func forwarderDecodeHead(data []byte) (map[string][]byte, error) {
	files := map[string][]byte{}
	take := func() ([]byte, error) {
		length, read := binary.Uvarint(data)
		if read <= 0 || uint64(len(data)-read) < length {
			return nil, errors.New("a head record cut short")
		}
		field := data[read : read+int(length)]
		data = data[read+int(length):]
		return field, nil
	}
	for 0 < len(data) {
		path, err := take()
		if err != nil {
			return nil, err
		}
		file, err := take()
		if err != nil {
			return nil, err
		}
		files[string(path)] = bytes.Clone(file)
	}
	return files, nil
}

// How many bytes the stored head a base names takes, 0 for one not stored.
func (self *forwarderRecords) headByteCount(configVersion uint64, configHeadSha256 []byte) int64 {
	name := forwarderHeadName(configVersion, configHeadSha256)
	entries, err := self.store.List(name)
	if err != nil {
		return 0
	}
	for _, entry := range entries {
		if entry.Name == name {
			return entry.ByteCount
		}
	}
	return 0
}

// Drops the oldest stored heads past count, by config version.
func (self *forwarderRecords) trimHeads(count int) error {
	entries, err := self.store.List(forwarderHeadPrefix)
	if err != nil {
		return err
	}
	for i := 0; i < len(entries)-count; i += 1 {
		if err := self.store.Remove(entries[i].Name); err != nil {
			return err
		}
	}
	return nil
}

// A message's deterministic encoding.
func forwarderMarshal(message proto.Message) ([]byte, error) {
	return proto.MarshalOptions{Deterministic: true}.Marshal(message)
}

// One entry of a page, parsed, with the digest it gives.
type forwarderPageEntry struct {
	entry *bridge.AuthEntry
	chain [sha256.Size]byte
}

// Follows once and sets when the next follow is due: FollowInterval after one that reached api, FollowRetryInterval
// doubling to FollowInterval after one that did not. On run's goroutine.
func (self *Forwarder) followNow() {
	err := self.follow()
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.followCount += 1
	}()
	now := self.clock.Now()
	if err == nil {
		self.followRetryCount = 0
		self.followAt = now.Add(self.settings.FollowInterval)
		self.clearAlarm(SidecarBridgeAlarm(ForwarderAlarmForwardClientLapsed))
		return
	}
	if self.ctx.Err() != nil {
		return
	}
	self.log.Warningf("[forward]%s the follow stopped: %v", self.args.NetworkId, err)
	if self.args.ClientLapsed != nil && self.args.ClientLapsed() {
		self.raiseAlarm(BridgeAlarm{
			Reason: SidecarBridgeAlarm(ForwarderAlarmForwardClientLapsed),
			Detail: "the forwarding client's credential lapsed: forwarding follows nothing until a new hand-off",
		})
	}
	timeout := self.settings.FollowRetryInterval
	for range self.followRetryCount {
		if self.settings.FollowInterval <= timeout {
			break
		}
		timeout *= 2
	}
	self.followRetryCount += 1
	self.followAt = now.Add(min(timeout, self.settings.FollowInterval))
}

// DESIGN-DETAILS 4.2.5's Follow (the file's comment). On run's goroutine.
func (self *Forwarder) follow() error {
	ctx, cancel := context.WithTimeout(self.ctx, self.settings.FollowTimeout)
	defer cancel()
	from, through, err := self.records.logRange()
	if err != nil {
		// a store that is no run is rebuilt from api's retention point, held to the anchor again
		self.log.Warningf("[forward]%s the stored log is no run and starts again: %v", self.args.NetworkId, err)
		if err := self.records.resetLog(); err != nil {
			return err
		}
		from, through = 0, 0
	}
	var tip *bridge.AuthPin
	if 0 < through {
		if tip, err = self.records.pinAt(through); err != nil {
			return err
		}
	}
	for page := 0; page < self.settings.FollowPageMaxCount; page += 1 {
		testHookBarrier("bridge_forward.follow.read", self.args.NetworkId.String())
		projection, err := self.args.Projection.ReadConfigProjection(ctx, tip.GetVersion())
		if err != nil {
			return err
		}
		if projection == nil {
			return fmt.Errorf("%w: no answer", errForwarderPageRefused)
		}
		if err := self.keepGenesis(projection.SignedGenesis); err != nil {
			return err
		}
		if len(projection.Entries) == 0 {
			break
		}
		entries, err := self.checkPage(tip, projection.Entries)
		if err != nil {
			return err
		}
		first := entries[0].entry.GetN()
		if 0 < through && through+1 < first {
			// api's retention point passed what the store holds: the run starts again there, and the next compile
			// restores at its newest base
			if err := self.records.resetLog(); err != nil {
				return err
			}
			from = 0
		}
		if err := self.keepPageRows(entries, projection.Rows); err != nil {
			return err
		}
		testHookBarrier("bridge_forward.follow.store", self.args.NetworkId.String())
		if err := self.records.appendEntries(first, projection.Entries); err != nil {
			return err
		}
		if from == 0 {
			from = first
		}
		last := entries[len(entries)-1]
		through = last.entry.GetN()
		tip = &bridge.AuthPin{Version: through, Chain: bytes.Clone(last.chain[:])}
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.tip = tip
		}()
		self.handDeltas(from, through)
		if !projection.More {
			break
		}
	}
	// 4.2.5's table: pending on its anchor, or narrowing entries waiting
	decision := self.readDecision()
	if 0 < through && !decision.Fork && (decision.State == BridgeSinkPending || 0 < decision.WaitingCount) {
		self.wantCompile()
	}
	return nil
}

// Holds a served genesis to the anchor and keeps it. None served is no error: api serves it only from position 0.
func (self *Forwarder) keepGenesis(signedGenesis []byte) error {
	if len(signedGenesis) == 0 {
		return nil
	}
	chain := bridge.GenesisChain(signedGenesis)
	if !bytes.Equal(chain[:], self.args.Pending.GetGenesisSha256()) {
		self.emitHeadAlarm(SidecarHeadAlarmFork, &bridge.AuthPin{Chain: bytes.Clone(self.args.Pending.GetGenesisSha256())}, &bridge.AuthPin{Chain: chain[:]})
		return fmt.Errorf("%w: another genesis than the anchor's", errForwarderPageRefused)
	}
	held, err := self.records.read(forwarderGenesisName)
	if err == nil && bytes.Equal(held, signedGenesis) {
		return nil
	}
	if err != nil && !errors.Is(err, ErrSidecarStoreAbsent) {
		return err
	}
	return self.records.write(forwarderGenesisName, signedGenesis)
}

// A page's entries parsed and held to the store's chain: each this network's, at consecutive positions, each chaining
// onto the one before, and the first onto the store's tip where it is the next position, or onto the anchor where it
// is entry 1. A page that starts past the next position is api's retention point having passed the store, which the
// judge holds to the posture's pin at the next compile. A break is head_alarm fork, and nothing of the page is kept.
func (self *Forwarder) checkPage(tip *bridge.AuthPin, pageEntries [][]byte) ([]*forwarderPageEntry, error) {
	entries := make([]*forwarderPageEntry, 0, len(pageEntries))
	for i, entryBytes := range pageEntries {
		entry := &bridge.AuthEntry{}
		if err := proto.Unmarshal(entryBytes, entry); err != nil {
			return nil, fmt.Errorf("%w: entry %d of the page does not decode", errForwarderPageRefused, i)
		}
		if !bytes.Equal(entry.GetNetworkId(), self.args.NetworkId.Bytes()) || len(entry.GetPrevChain()) != sha256.Size {
			return nil, fmt.Errorf("%w: entry %d of the page is another network's or names no prev_chain", errForwarderPageRefused, i)
		}
		chain, err := bridge.AuthChainDigest(entry.GetN(), entry.GetPrevChain(), entry.GetKind(), entry.GetTimeMs(), entry.GetBody())
		if err != nil {
			return nil, fmt.Errorf("%w: entry %d of the page: %w", errForwarderPageRefused, i, err)
		}
		var previous *bridge.AuthPin
		switch {
		case 0 < i:
			previous = &bridge.AuthPin{Version: entries[i-1].entry.GetN(), Chain: entries[i-1].chain[:]}
			if entry.GetN() != previous.GetVersion()+1 {
				return nil, fmt.Errorf("%w: the page skips from %d to %d", errForwarderPageRefused, previous.GetVersion(), entry.GetN())
			}
		case entry.GetN() <= tip.GetVersion():
			return nil, fmt.Errorf("%w: the page starts at %d, at or below the store's %d", errForwarderPageRefused, entry.GetN(), tip.GetVersion())
		case entry.GetN() == tip.GetVersion()+1 && tip != nil:
			previous = tip
		case entry.GetN() == 1:
			previous = &bridge.AuthPin{Chain: self.args.Pending.GetGenesisSha256()}
		}
		if previous != nil && !bytes.Equal(entry.GetPrevChain(), previous.GetChain()) {
			self.emitHeadAlarm(SidecarHeadAlarmFork, previous, &bridge.AuthPin{Version: previous.GetVersion(), Chain: bytes.Clone(entry.GetPrevChain())})
			return nil, fmt.Errorf("%w: entry %d does not chain onto the one before", errForwarderPageRefused, entry.GetN())
		}
		entries = append(entries, &forwarderPageEntry{entry: entry, chain: chain})
	}
	return entries, nil
}

// Keeps the rows each base of a page names, before its entries are kept, each held to the base's rows_sha256. Rows a
// page carries that no base of it names are dropped; a base whose rows the page lacks is kept without them, and the
// sink and the judge then refuse it until a later read brings them.
func (self *Forwarder) keepPageRows(entries []*forwarderPageEntry, pageRows [][]byte) error {
	wanted := [][]byte{}
	for _, entry := range entries {
		if entry.entry.GetKind() != bridge.AuthEntryKindBase {
			continue
		}
		if _, header, err := configParseBase(entry.entry); err == nil && len(header.GetRowsSha256()) == sha256.Size {
			wanted = append(wanted, header.GetRowsSha256())
		}
	}
	for _, rows := range pageRows {
		rowsSha256 := sha256.Sum256(rows)
		if !slices.ContainsFunc(wanted, func(named []byte) bool { return bytes.Equal(named, rowsSha256[:]) }) {
			continue
		}
		if err := self.records.write(forwarderRowsName(rowsSha256[:]), rows); err != nil {
			return err
		}
	}
	return nil
}

// Tier 1: hands the sink, while it is enforcing, every stored entry above its pin, and wants a compile when it took
// one it did not apply as a denial, refused the run, or the store no longer reaches back to its pin. from and through
// are the store's range.
func (self *Forwarder) handDeltas(from uint64, through uint64) {
	decision := self.readDecision()
	if decision.State != BridgeSinkEnforcing {
		return
	}
	next := decision.Pin.GetVersion() + 1
	if through < next {
		return
	}
	if next < from {
		self.wantCompile()
		return
	}
	entries, err := self.records.entries(next, through)
	if err != nil {
		self.log.Warningf("[forward]%s the stored entries from %d did not read: %v", self.args.NetworkId, next, err)
		self.wantCompile()
		return
	}
	testHookBarrier("bridge_forward.deltas.before", self.args.NetworkId.String())
	if err := self.args.Sink.ApplyDeltas(&BridgeStateLog{Entries: entries, OpenRows: self.records.openRows}); err != nil {
		self.log.Warningf("[forward]%s the device role refused entries from %d: %v", self.args.NetworkId, next, err)
		self.wantCompile()
	}
	if self.readDecision().CompileWanted {
		self.wantCompile()
	}
}

// DESIGN-DETAILS 4.2.5's Witness: follows up to the app's pin, raises head_alarm where that pin is off this chain
// (fork, with both pins) or past what api serves (withheld), and sets the sink's fork. On run's goroutine.
func (self *Forwarder) witness(pin *bridge.AuthPin, fork bool) {
	self.followNow()
	if 0 < pin.GetVersion() {
		from, through, err := self.records.logRange()
		switch {
		case err != nil:
			self.log.Warningf("[forward]%s the stored log did not read at a witness: %v", self.args.NetworkId, err)
		case through < pin.GetVersion():
			tip, _ := self.records.tip()
			self.emitHeadAlarm(SidecarHeadAlarmWithheld, tip, pin)
		case from <= pin.GetVersion():
			held, err := self.records.pinAt(pin.GetVersion())
			if err == nil && !bytes.Equal(held.GetChain(), pin.GetChain()) {
				self.emitHeadAlarm(SidecarHeadAlarmFork, held, pin)
			}
		}
	}
	decision := self.readDecision()
	if decision.Fork == fork {
		return
	}
	testHookBarrier("bridge_forward.fork.before", self.args.NetworkId.String())
	if err := self.args.Sink.SetFork(fork); err != nil {
		self.log.Warningf("[forward]%s the device role refused the fork report: %v", self.args.NetworkId, err)
	}
	if decision = self.readDecision(); !decision.Fork {
		// the compile a fork held back
		self.wantCompile()
	}
}
