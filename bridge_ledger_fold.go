// The bridge ledger's fold and its check (DESIGN-DETAILS 12.2.3, QD-667): at each base that folds, the writer freezes
// the body-level verdicts it holds into the head's bridge/ledger/ files, and every full reader standing under the
// previous base computes the same files and forks on a difference.
//
//	fold      FoldBridgeLedger: the previous head's rows and the writer's unfolded statements at or below the fold,
//	          opened as OpenBridgeLedger does at the fold's own position and time, written as rows. A body the writer
//	          cannot open stops the fold below it: a writer never freezes what it may still come to open, and a config
//	          writer holds every generation gkm names, so one it lacks is a broken delivery the caller alarms
//	          (config_key_waiting). The fold then reaches the entry before it, or stays where it was where §7.9's fold
//	          rule (the previous fold, or at least the previous base) does not allow that
//	unformed  the one body a fold freezes that its readers held pending (DESIGN-DETAILS 12.2.3's writer's half,
//	          QD-761): where the writer's plan read gkm whole, FormedThrough G, a body sealed above G whose entry is
//	          UnformedVoidWait before the entry at the fold asked, in the log's time and never a clock, is frozen void
//	          as Refused{no such generation} in both of the fold's opens, and the fold goes on past it
//	          (BridgeLedgerFold.Voided, config_key_void). Every reader that later holds that generation judges the
//	          body void by its grace (bridge_ledger.go), so the frozen row is the one it would have written
//	files     protobuf's deterministic marshal of rows sorted by key; no empty file; the rules in shards of 8 bits, or
//	          16 once the rows hold more than BridgeLedgerSettings.RuleShardRowCount rules; a manifest naming every
//	          file with the SHA-256 of its bytes, and none where the fold holds no bridge statement
//	check     CheckBridgeLedgerFold, inside CheckConfigBase where the reader stands at S(b-1): the head's ledger files
//	          equal the reader's own fold of the previous head's, byte for byte, or the base is a fork; unchecked where
//	          the reader holds a body it could not open at or below the fold, and then it takes the head's rows as a new
//	          device does. A checker voids nothing as unformed: that is the writer's alone, so it folds with no G
//
// Pure: every input is passed, no clock is read, no Go map is ranged over unsorted, so two writers of one fold write
// one set of bytes on every leg. testHookSecret runs inside OpenConfigBody. On every leg, with no connect import.

package sidecar

import (
	"bytes"
	"cmp"
	"crypto/sha256"
	"errors"
	"fmt"
	"maps"
	"math"
	"slices"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// One fold of the ledger.
type BridgeLedgerFold struct {
	// The fold reached: the one asked, or below it where a body the writer could not open stops it.
	FoldedThrough uint64
	// Every ledger file a head folded there holds, the manifest included, by path: none where the fold holds no
	// bridge statement.
	Files map[string][]byte
	// The first statement still waiting at the fold asked, its generation and signer the caller's config_key_waiting
	// line: nil where none is.
	Stopped *BridgeLedgerEntry
	// The statements at or below the fold reached that this fold froze void as unformed, in log order, each with the
	// generation it was sealed to and its signer for the caller's config_key_void line: none where the fold stayed.
	Voided []*BridgeLedgerEntry
}

// The head with the fold's ledger: each of its files set, and every other bridge/ledger/ file removed.
func (self *BridgeLedgerFold) Apply(head *ConfigHead) (*ConfigHead, error) {
	files := head.Files()
	for path := range files {
		if bridgeLedgerPath(path) {
			delete(files, path)
		}
	}
	for path, data := range self.Files {
		files[path] = bytes.Clone(data)
	}
	return NewConfigHead(files)
}

// The time of the entry at n: what the reader answers, else the state's window.
func bridgeLedgerEntryTimeMs(reader *BridgeLedgerReader, n uint64) (int64, bool) {
	if reader.EntryTimeMs != nil {
		if timeMs, ok := reader.EntryTimeMs(n); ok {
			return timeMs, true
		}
	}
	if reader.State != nil {
		return reader.State.aclTimeAt(n)
	}
	return 0, false
}

// DESIGN-DETAILS 12.2.3's fold: the ledger files of a head folded through foldedThrough, from previous, the
// rows of the head being extended, and reader.State's unfolded statements in (previous' fold, foldedThrough], as the top
// of this file says. reader.State is the writer's state at its tip, or a checker's at S(b-1); reader.EntryTimeMs must
// answer the entries the head folds, as a log's kept entries do; reader.FormedThrough is the writer's G, 0 at a
// checker. previous nil is the empty ledger before any fold. Pure: the same inputs fold to the same bytes wherever and
// whenever they are folded, a writer restarted or one whose clock is off included.
func FoldBridgeLedger(previous BridgeLedgerRows, reader *BridgeLedgerReader, foldedThrough uint64) (*BridgeLedgerFold, error) {
	if reader == nil || reader.State == nil {
		return nil, errors.New("bridge ledger fold: no state to fold at")
	}
	state := reader.State
	previousFoldedThrough := uint64(0)
	if previous != nil {
		previousFoldedThrough = previous.FoldedThrough()
	}
	if foldedThrough < previousFoldedThrough || state.n < foldedThrough {
		return nil, fmt.Errorf("bridge ledger fold: through %d from %d at %d", foldedThrough, previousFoldedThrough, state.n)
	}
	if base := state.Base(); base != nil && previousFoldedThrough < base.GetFoldedThrough() {
		return nil, fmt.Errorf("%w: rows through %d under a base folded through %d", ErrBridgeLedgerMalformed, previousFoldedThrough, base.GetFoldedThrough())
	}
	statements := state.Bridge().Statements()
	fold := &BridgeLedgerFold{FoldedThrough: foldedThrough}
	if foldedThrough == previousFoldedThrough {
		files, err := bridgeLedgerRowsFiles(previous)
		if err != nil {
			return nil, err
		}
		fold.Files = files
		return fold, nil
	}
	// the wait for an unformed generation is read against the entry at the fold asked, in both opens, so a fold that
	// stops short voids below its stop exactly what the fold asked would
	askedTimeMs, ok := bridgeLedgerEntryTimeMs(reader, foldedThrough)
	if !ok {
		return nil, fmt.Errorf("bridge ledger fold: the time of entry %d is not held", foldedThrough)
	}
	open := func(through uint64) (*BridgeLedger, error) {
		timeMs, ok := bridgeLedgerEntryTimeMs(reader, through)
		if !ok {
			return nil, fmt.Errorf("bridge ledger fold: the time of entry %d is not held", through)
		}
		return openBridgeLedger(previous, statements, reader, through, timeMs, true, askedTimeMs)
	}
	ledger, err := open(foldedThrough)
	if err != nil {
		return nil, err
	}
	if pending := ledger.Pending(); 0 < len(pending) {
		// the fold stops below the first body still waiting, where §7.9's fold rule lets it
		fold.Stopped = pending[0]
		reached := pending[0].Statement.N - 1
		if base := state.Base(); reached != previousFoldedThrough && (base == nil || reached < base.GetVersion()) {
			reached = previousFoldedThrough
		}
		fold.FoldedThrough = reached
		if reached == previousFoldedThrough {
			files, err := bridgeLedgerRowsFiles(previous)
			if err != nil {
				return nil, err
			}
			fold.Files = files
			return fold, nil
		}
		if ledger, err = open(reached); err != nil {
			return nil, err
		}
		if pending := ledger.Pending(); 0 < len(pending) {
			// the same statements at the same asked time wait alike at any cutoff, so this is a broken invariant, and
			// a fold that froze a waiting body would lose it
			return nil, fmt.Errorf("bridge ledger fold: entry %d waits below the fold reached, %d", pending[0].Statement.N, reached)
		}
	}
	fold.Voided = slices.Clone(ledger.unformed)
	folded := previous != nil && previous.Manifest() != nil
	for _, statement := range statements {
		folded = folded || (previousFoldedThrough < statement.N && statement.N <= fold.FoldedThrough)
	}
	if fold.Files, err = ledger.foldFiles(fold.FoldedThrough, folded); err != nil {
		return nil, err
	}
	if ledger.foldError != nil {
		return nil, fmt.Errorf("bridge ledger fold: %w", ledger.foldError)
	}
	return fold, nil
}

// The ledger files a row source holds as they are, for a fold that does not move.
func bridgeLedgerRowsFiles(rows BridgeLedgerRows) (map[string][]byte, error) {
	files := map[string][]byte{}
	headRows, ok := rows.(*bridgeLedgerHeadRows)
	if rows == nil || (ok && headRows.head == nil) {
		return files, nil
	}
	if !ok {
		return nil, errors.New("bridge ledger fold: a fold that does not move needs the head's own files")
	}
	for _, path := range headRows.head.Paths() {
		if bridgeLedgerPath(path) {
			files[path] = headRows.head.File(path)
		}
	}
	return files, nil
}

// The rows the ledger holds at a fold, by kind, each in its one order: the live addresses and the tombstones still
// holding at its time; every rule, active, void and withdrawn, but a withdrawn one whose retention passed, and every
// reservation; the egress specs; the aliases.
func (self *BridgeLedger) foldRows() ([]*protocol.BridgeLedgerAddressRow, []*protocol.BridgeLedgerRuleRow, []*protocol.BridgeLedgerEgressRow, []*protocol.BridgeLedgerAliasRow) {
	addressRows := []*protocol.BridgeLedgerAddressRow{}
	for _, hostBits := range slices.Sorted(maps.Keys(self.byHostBits)) {
		address := self.byHostBits[hostBits]
		row := &protocol.BridgeLedgerAddressRow{HostBits: hostBits, SidecarId: address.SidecarId.Bytes(), ClaimedAt: address.ClaimedAt}
		if self.bySidecar[address.SidecarId] != address {
			if release := self.addressRelease(address); release != nil {
				row.ReleasedAt, row.ReleasedMs = release.n, release.timeMs
			}
		}
		addressRows = append(addressRows, row)
	}

	withdrawalFields := func(row *protocol.BridgeLedgerRuleRow, withdrawal *BridgeLedgerWithdrawal) {
		row.WithdrawnAt, row.WithdrawnMs, row.WithdrawMode = withdrawal.At, withdrawal.TimeMs, withdrawal.Mode
		row.WithdrawnBy, row.WithdrawnByAdmin = withdrawal.Signer.Bytes(), withdrawal.SignerAdmin
	}
	ruleRows := []*protocol.BridgeLedgerRuleRow{}
	for _, rule := range self.rules {
		if rule.Pending || (rule.Withdrawn != nil && rule.retainUntilMs() < self.timeMs) {
			continue
		}
		row := &protocol.BridgeLedgerRuleRow{
			RuleId: bytes.Clone(rule.RuleId), SignedType: uint32(rule.SignedType), Owner: rule.Owner.Bytes(),
			FirstAt: rule.FirstAt, FirstMs: rule.FirstMs, NewestAt: rule.NewestAt, NewestMs: rule.NewestMs,
			Disposition: protocol.BridgeLedgerDisposition_BRIDGE_LEDGER_DISPOSITION_ACTIVE, Expires: rule.Expires,
		}
		for _, routeRuleId := range rule.RouteRuleIds {
			row.RouteRuleIds = append(row.RouteRuleIds, bytes.Clone(routeRuleId))
		}
		if rule.Void {
			row.Disposition = protocol.BridgeLedgerDisposition_BRIDGE_LEDGER_DISPOSITION_VOID
		} else {
			row.Route, row.Map, row.Standing = rule.Route, rule.Map, rule.Standing
			if !rule.Standing {
				row.ApprovalId, row.ApprovalNotAfterMs, row.ApprovalUses = rule.ApprovalId.Bytes(), rule.ApprovalNotAfterMs, rule.ApprovalUses
			}
			if rule.Withdrawn != nil {
				row.Disposition = protocol.BridgeLedgerDisposition_BRIDGE_LEDGER_DISPOSITION_WITHDRAWN
			}
		}
		if rule.Withdrawn != nil {
			withdrawalFields(row, rule.Withdrawn)
			if retainUntilMs := rule.retainUntilMs(); retainUntilMs != math.MaxInt64 {
				row.RetainUntilMs = retainUntilMs
			}
		}
		ruleRows = append(ruleRows, row)
	}
	for key, withdrawal := range self.reserved {
		if self.rules[key] != nil {
			continue
		}
		row := &protocol.BridgeLedgerRuleRow{RuleId: []byte(key), Disposition: protocol.BridgeLedgerDisposition_BRIDGE_LEDGER_DISPOSITION_RESERVED}
		withdrawalFields(row, withdrawal)
		ruleRows = append(ruleRows, row)
	}
	slices.SortFunc(ruleRows, func(a *protocol.BridgeLedgerRuleRow, b *protocol.BridgeLedgerRuleRow) int {
		return bytes.Compare(a.GetRuleId(), b.GetRuleId())
	})

	egressRows := []*protocol.BridgeLedgerEgressRow{}
	for _, egress := range self.Egress() {
		row := &protocol.BridgeLedgerEgressRow{Subject: egress.Subject.Bytes(), Mode: egress.Mode, ExitTagId: bytes.Clone(egress.ExitTagId), At: egress.At}
		for _, exitId := range egress.ExitSidecarIds {
			row.ExitSidecarIds = append(row.ExitSidecarIds, exitId.Bytes())
		}
		egressRows = append(egressRows, row)
	}

	aliasRows := []*protocol.BridgeLedgerAliasRow{}
	for _, alias := range self.aliases {
		aliasRows = append(aliasRows, &protocol.BridgeLedgerAliasRow{Body: alias.Body, Signer: alias.Signer.Bytes(), At: alias.At})
	}
	slices.SortFunc(aliasRows, func(a *protocol.BridgeLedgerAliasRow, b *protocol.BridgeLedgerAliasRow) int {
		if order := bytes.Compare(a.GetBody().GetShareId(), b.GetBody().GetShareId()); order != 0 {
			return order
		}
		return cmp.Compare(a.GetBody().GetTargetIndex(), b.GetBody().GetTargetIndex())
	})
	return addressRows, ruleRows, egressRows, aliasRows
}

// The ledger's files at a fold through foldedThrough: its rows by kind, each file its one encoding, and the manifest,
// which folded says the head must hold, a bridge statement being at or below the fold. No empty file: a kind with no
// rows has none, and a ledger with no bridge statement folded has no file at all.
func (self *BridgeLedger) foldFiles(foldedThrough uint64, folded bool) (map[string][]byte, error) {
	files := map[string][]byte{}
	if !folded {
		return files, nil
	}
	addressRows, ruleRows, egressRows, aliasRows := self.foldRows()
	shardBits := uint32(bridgeLedgerShardBitsNarrow)
	if 0 < self.settings.RuleShardRowCount && self.settings.RuleShardRowCount < len(ruleRows) {
		shardBits = bridgeLedgerShardBitsWide
	}
	manifest := &protocol.BridgeLedgerManifest{
		Format: bridgeLedgerFormat, FoldedThrough: foldedThrough, TimeMs: self.timeMs, RuleShardBits: shardBits,
	}
	write := func(path string, message proto.Message, rowCount int) error {
		if rowCount == 0 {
			return nil
		}
		data, err := proto.MarshalOptions{Deterministic: true}.Marshal(message)
		if err != nil {
			return err
		}
		digest := sha256.Sum256(data)
		files[path] = data
		manifest.Files = append(manifest.Files, &protocol.BridgeLedgerFile{Path: path, Sha256: digest[:], RowCount: uint64(rowCount)})
		return nil
	}
	if err := write(ConfigHeadBridgeLedgerAddressesPath, &protocol.BridgeLedgerAddresses{Rows: addressRows}, len(addressRows)); err != nil {
		return nil, err
	}
	if err := write(ConfigHeadBridgeLedgerAliasesPath, &protocol.BridgeLedgerAliases{Rows: aliasRows}, len(aliasRows)); err != nil {
		return nil, err
	}
	if err := write(ConfigHeadBridgeLedgerEgressPath, &protocol.BridgeLedgerEgressSpecs{Rows: egressRows}, len(egressRows)); err != nil {
		return nil, err
	}
	for start := 0; start < len(ruleRows); {
		path := BridgeLedgerRulesPath(ruleRows[start].GetRuleId(), shardBits)
		end := start + 1
		for end < len(ruleRows) && BridgeLedgerRulesPath(ruleRows[end].GetRuleId(), shardBits) == path {
			end += 1
		}
		if err := write(path, &protocol.BridgeLedgerRules{Rows: ruleRows[start:end]}, end-start); err != nil {
			return nil, err
		}
		start = end
	}
	slices.SortFunc(manifest.Files, func(a *protocol.BridgeLedgerFile, b *protocol.BridgeLedgerFile) int {
		return cmp.Compare(a.GetPath(), b.GetPath())
	})
	data, err := proto.MarshalOptions{Deterministic: true}.Marshal(manifest)
	if err != nil {
		return nil, err
	}
	files[ConfigHeadBridgeLedgerManifestPath] = data
	return files, nil
}

// DESIGN-DETAILS 12.2.3's fold check: whether head, the config head base b names folding through
// foldedThrough, holds the bridge ledger reader.State, S(b-1), folds from previous, the head the previous base names (nil
// before the first base), as FoldBridgeLedger does. Answers true checked, or false unchecked where the reader holds a
// body it could not open at or below the fold, whatever its age, which then takes the head's rows and so the void a
// writer froze; an error wrapping ErrConfigHeadMismatch is a fork. It folds with FormedThrough 0 whatever reader says:
// a checker never voids as unformed, since one that lacks a formed generation would fork on a row its writer judged
// with the key (BridgeVoidTwin-CheckerVoids).
func CheckBridgeLedgerFold(head *ConfigHead, previous *ConfigHead, reader *BridgeLedgerReader, foldedThrough uint64) (bool, error) {
	if head == nil {
		return false, fmt.Errorf("%w: no head", ErrConfigHeadMismatch)
	}
	checker := &BridgeLedgerReader{}
	if reader != nil {
		copied := *reader
		checker = &copied
	}
	checker.FormedThrough = 0
	previousRows, err := NewBridgeLedgerHeadRows(previous, checker.Settings)
	if err != nil {
		return false, fmt.Errorf("%w: the previous head: %w", ErrConfigHeadMismatch, err)
	}
	fold, err := FoldBridgeLedger(previousRows, checker, foldedThrough)
	if err != nil {
		return false, fmt.Errorf("%w: %w", ErrConfigHeadMismatch, err)
	}
	if fold.FoldedThrough < foldedThrough {
		return false, nil
	}
	held := map[string][]byte{}
	for _, path := range head.Paths() {
		if bridgeLedgerPath(path) {
			held[path] = head.File(path)
		}
	}
	if len(held) != len(fold.Files) {
		return false, fmt.Errorf("%w: the head holds %d bridge ledger files, the reader's fold %d", ErrConfigHeadMismatch, len(held), len(fold.Files))
	}
	for path, data := range fold.Files {
		if !bytes.Equal(held[path], data) {
			return false, fmt.Errorf("%w: the head's %s is not the reader's fold", ErrConfigHeadMismatch, path)
		}
	}
	return true, nil
}

// The time of the entry this log keeps at n, false for one it does not keep: what a fold's releases and its time read,
// and what every full reader standing at a base holds alike for the entries that base folds. For the log's one
// applying goroutine, as Apply.
func (self *ConfigLog) EntryTimeMs(n uint64) (int64, bool) {
	kept := self.keptEntry(n)
	if kept == nil {
		return 0, false
	}
	return kept.entry.GetTimeMs(), true
}

// The bridge ledger's check of the head a base at header names, for a full reader standing at state, S(b-1): the
// previous base's head read through the judge, and CheckBridgeLedgerFold over it. Nil where no judge reads heads, so no
// ledger is checked: a keyless verifier's, or a forwarding role's, which takes rows (DESIGN-DETAILS 4.2.1).
func (self *ConfigLog) bridgeFoldCheck(state *ConfigState, header *bridge.ProjectionHeader) func(head *ConfigHead) error {
	judge := self.settings.BridgeBodyJudge
	if judge == nil || judge.ReadHead == nil {
		return nil
	}
	return func(head *ConfigHead) error {
		var previous *ConfigHead
		if state.base != nil {
			var err error
			previous, err = judge.ReadHead(state.base.header.GetConfigVersion(), state.base.header.GetConfigHeadSha256())
			if err != nil {
				return fmt.Errorf("%w: the previous base's head: %w", ErrConfigHeadUnavailable, err)
			}
		}
		reader := &BridgeLedgerReader{State: state, RepoKeyAt: judge.RepoKeyAt, EntryTimeMs: self.EntryTimeMs, Settings: judge.Settings}
		checked, err := CheckBridgeLedgerFold(head, previous, reader, header.GetFoldedThrough())
		if err != nil {
			return err
		}
		if !checked {
			self.log.Warningf("[config]%s base %d's bridge ledger unchecked: a body at or below its fold is not opened here", self.networkId, header.GetVersion())
		}
		return nil
	}
}

// FoldBridgeLedger with the judge's keys and settings over the head being extended: what ConfigWriterArgs.BridgeFold
// takes. It asks the judge's FormedThrough once, for this plan's G, and folds with 0 where there is none.
func (self *BridgeBodyJudge) Fold(previous *ConfigHead, state *ConfigState, foldedThrough uint64, entryTimeMs func(n uint64) (int64, bool)) (*BridgeLedgerFold, error) {
	rows, err := NewBridgeLedgerHeadRows(previous, self.Settings)
	if err != nil {
		return nil, err
	}
	formedThrough := uint64(0)
	if self.FormedThrough != nil {
		formedThrough = self.FormedThrough()
	}
	return FoldBridgeLedger(rows, &BridgeLedgerReader{
		State: state, RepoKeyAt: self.RepoKeyAt, EntryTimeMs: entryTimeMs, FormedThrough: formedThrough, Settings: self.Settings,
	}, foldedThrough)
}
