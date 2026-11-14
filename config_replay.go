// §7.9's retention row for a reader that did not walk the log from genesis: a new device, one restarting from what it
// kept, or one that fell behind the retention point (DESIGN-DETAILS 5.2.4's StartAtBase). It starts at the newest base
// b it holds: verifies b's signature under a config writer its own rows name, the fold rule against the base before
// it and the tail cap; for a full reader, checks b's config head as its anchor (the head's genesis is the log's, its
// records equal every held entry through folded_through, and the chain recomputed from the genesis through the head's
// records, bases included, reaches the first held entry, the head's pushes judged by descent under b's rows, QD-814);
// then loads b's rows and re-applies the tail folded_through+1..b-1 by b's tail_verdicts, judging nothing, taking every
// verdict there from the base, and applies b+1 on as a long-running reader does. So a new device reaches a long-running
// reader's S(b) without judging a tail it could only judge on b's head (questions team-m2-02-new-device-tail-verdicts
// and the replay ring's, which DESIGN-DETAILS 5.1 answers).
//
// A new device holds no verdict for the entries b's rows fold: it keeps their bytes for the head check and the next
// base's fold, and its replay ring is b's rows' plus the tail's.
//
// Nothing here creates, derives or unwraps a key, so nothing calls testHookSecret.

package sidecar

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A rows source that serves what a ConfigRetained kept before asking the next source, whose head check it always
// uses.
type configRetainedRowsSource struct {
	rows map[[sha256.Size]byte][]byte
	next ConfigRowsSource
}

// The kept rows, else the next source's.
func (self configRetainedRowsSource) Rows(networkId Id, rowsSha256 []byte) ([]byte, error) {
	if len(rowsSha256) == sha256.Size {
		if rows, found := self.rows[[sha256.Size]byte(rowsSha256)]; found {
			return bytes.Clone(rows), nil
		}
	}
	return self.next.Rows(networkId, rowsSha256)
}

// The next source's check.
func (self configRetainedRowsSource) CheckHead(check *ConfigHeadCheck) (*ConfigHeadFacts, error) {
	return self.next.CheckHead(check)
}

// A log from what a device kept, as §7.9's new device starts: at the newest base among retained.Entries, then every
// entry after it. rowsSource serves rows retained does not hold and checks the base's config head. An error when the
// kept entries do not chain or hold no base, or when the base fails its checks.
func RestoreConfigLog(settings *ConfigLogSettings, retained *ConfigRetained, rowsSource ConfigRowsSource) (*ConfigLog, error) {
	return restoreConfigLogAbove(settings, retained, rowsSource, nil)
}

// RestoreConfigLog held to floor, a pin this reader held before, nil for none (DESIGN-DETAILS 5.5's far-behind
// reader): a log ending below it is ErrConfigBelowPin; a run holding another A_n at its position is ErrConfigRunRefused;
// and a floor before what the run holds is checked by the base's head, the chain recomputed through its records, so a
// restart is never a silent move onto another chain.
func restoreConfigLogAbove(settings *ConfigLogSettings, retained *ConfigRetained, rowsSource ConfigRowsSource, floor *bridge.AuthPin) (*ConfigLog, error) {
	self, err := NewConfigLog(settings, retained.SignedGenesis)
	if err != nil {
		return nil, err
	}
	if err := self.restore(retained, rowsSource, floor); err != nil {
		return nil, err
	}
	if err := self.checkFloor(floor); err != nil {
		return nil, err
	}
	return self, nil
}

// Whether this log stands at or above floor and holds floor's A_n where it holds a digest there. Nil floor passes.
func (self *ConfigLog) checkFloor(floor *bridge.AuthPin) error {
	if floor == nil {
		return nil
	}
	state := self.state.Load()
	if state.n < floor.GetVersion() {
		return fmt.Errorf("%w: %d below %d", ErrConfigBelowPin, state.n, floor.GetVersion())
	}
	if chain, ok := state.chainAt(floor.GetVersion()); ok && !bytes.Equal(chain[:], floor.GetChain()) {
		runError := &ConfigRunError{N: floor.GetVersion(), RemoteChain: chain, Reason: "a second A_n at the reader's own pin"}
		if len(floor.GetChain()) == sha256.Size {
			runError.LocalChain, runError.HasLocalChain = [sha256.Size]byte(floor.GetChain()), true
		}
		self.log.Errorf("[config]%s restart refused at %d: %s", self.networkId, floor.GetVersion(), runError.Reason)
		return runError
	}
	return nil
}

// Starts a log at S(0) at the newest base among retained.Entries and applies every entry after it, as
// RestoreConfigLog says, a full reader's or a rows-only one's. floor, nil for none, is a pin this reader held before,
// which a full reader's anchor checks where the entries no longer reach it.
func (self *ConfigLog) restore(retained *ConfigRetained, rowsSource ConfigRowsSource, floor *bridge.AuthPin) error {
	if len(retained.Entries) == 0 {
		return nil
	}
	if rowsSource == nil {
		rowsSource = ConfigNoRowsSource{}
	}
	source := configRetainedRowsSource{rows: retained.Rows, next: rowsSource}

	entries := make([]*bridge.AuthEntry, len(retained.Entries))
	chains := make([][sha256.Size]byte, len(retained.Entries))
	baseIndex := -1
	for i, entryBytes := range retained.Entries {
		entry := &bridge.AuthEntry{}
		if err := proto.Unmarshal(entryBytes, entry); err != nil {
			return fmt.Errorf("%w: kept entry %d: %w", ErrConfigEntryMalformed, i, err)
		}
		if !bytes.Equal(entry.GetNetworkId(), self.networkId.Bytes()) {
			return fmt.Errorf("%w: kept entry %d is another network's", ErrConfigEntryMalformed, i)
		}
		if len(entry.GetPrevChain()) != sha256.Size {
			return fmt.Errorf("%w: kept entry %d has no prev_chain", ErrConfigEntryMalformed, i)
		}
		if 0 < i {
			if entry.GetN() != entries[i-1].GetN()+1 || !bytes.Equal(entry.GetPrevChain(), chains[i-1][:]) {
				return fmt.Errorf("%w: kept entry %d does not chain onto the one before", ErrConfigFork, entry.GetN())
			}
		}
		chain, err := bridge.AuthChainDigest(entry.GetN(), entry.GetPrevChain(), entry.GetKind(), entry.GetTimeMs(), entry.GetBody())
		if err != nil {
			return fmt.Errorf("%w: kept entry %d: %w", ErrConfigEntryMalformed, i, err)
		}
		entries[i], chains[i] = entry, chain
		if entry.GetKind() == bridge.AuthEntryKindBase {
			baseIndex = i
		}
	}
	if baseIndex < 0 {
		return fmt.Errorf("%w: the kept entries hold no base", ErrConfigEntryMalformed)
	}
	if entries[0].GetN() == 1 && !bytes.Equal(entries[0].GetPrevChain(), self.state.Load().chain[:]) {
		return fmt.Errorf("%w: entry 1 does not chain onto the genesis", ErrConfigFork)
	}

	if err := self.startAtBase(entries, chains, retained.Entries, baseIndex, source, floor); err != nil {
		return err
	}
	for i := baseIndex + 1; i < len(entries); i += 1 {
		if _, err := self.Apply(retained.Entries[i], source); err != nil {
			return err
		}
	}
	return nil
}

// Builds S(b) for the base at baseIndex (DESIGN-DETAILS 5.2.4's StartAtBase): its checks and, for a full reader, its
// anchor; its rows; the kept entries before it chained to its prev_chain; the tail among folded_through+1..b-1
// re-applied by its tail_verdicts; and b's own shrinks as its shrunk_repo_ids name them (QD-746). Publishes S(b).
func (self *ConfigLog) startAtBase(entries []*bridge.AuthEntry, chains [][sha256.Size]byte, entryBytes [][]byte, baseIndex int, rowsSource ConfigRowsSource, floor *bridge.AuthPin) error {
	baseEntry := entries[baseIndex]
	baseN := baseEntry.GetN()
	signed, header, err := configParseBase(baseEntry)
	if err != nil {
		return fmt.Errorf("%w: base %d: %w", ErrConfigFork, baseN, err)
	}
	signerId, err := configBaseSigner(signed)
	if err != nil {
		return fmt.Errorf("%w: base %d: %w", ErrConfigFork, baseN, err)
	}
	foldedThrough := header.GetFoldedThrough()
	// S(b) is b's rows with its tail re-applied, so entries that start after the tail's first position would give a
	// state missing what the tail did, a revocation among it: refused, never built short
	if tailFrom := foldedThrough + 1; tailFrom < baseN && tailFrom < entries[0].GetN() {
		return fmt.Errorf("%w: the kept entries start at %d, after base %d's tail from %d", ErrConfigEntryMalformed,
			entries[0].GetN(), baseN, tailFrom)
	}
	rowsBytes, err := rowsSource.Rows(self.networkId, header.GetRowsSha256())
	if err != nil {
		return fmt.Errorf("%w: base %d's rows: %w", ErrConfigFork, baseN, err)
	}

	// the base the kept entries hold before b, whose header bounds b's versions and fold and names the retention point
	var previousBase *configBase
	for i := baseIndex - 1; 0 <= i; i -= 1 {
		if entries[i].GetKind() != bridge.AuthEntryKindBase {
			continue
		}
		_, previousHeader, err := configParseBase(entries[i])
		if err != nil {
			return fmt.Errorf("%w: base %d: %w", ErrConfigFork, entries[i].GetN(), err)
		}
		previousBase = &configBase{n: entries[i].GetN(), chain: chains[i], timeMs: entries[i].GetTimeMs(), header: previousHeader}
		break
	}

	// what b lands on, as far as a reader that starts here knows it: S(0)'s genesis with b's rows, whose config writers
	// vouch for b's signer once its anchor holds
	genesisState := self.state.Load()
	start := &configKeptEntry{n: baseN, chain: chains[baseIndex], entry: baseEntry, entryBytes: bytes.Clone(entryBytes[baseIndex]), verdictHeld: true}
	start.verdict = ConfigVerdict{
		Pin:         &bridge.AuthPin{Version: baseN, Chain: bytes.Clone(chains[baseIndex][:])},
		Kind:        bridge.AuthEntryKindBase,
		SignedType:  bridge.SignedType_SIGNED_PROJECTION_HEADER,
		StatementId: bridge.SignedBytesSha256(bridge.SignedPurposeAuthority, bridge.SignedType_SIGNED_PROJECTION_HEADER, signed.GetBody()),
	}
	next, rows, err := self.stateFromBase(genesisState, start, header, rowsBytes)
	if err != nil {
		return fmt.Errorf("%w: base %d: %w", ErrConfigFork, baseN, err)
	}
	state := next.state
	state.previousBase = previousBase
	if !state.IsConfigWriter(signerId) {
		return fmt.Errorf("%w: base %d's signer is no config writer in its own rows", ErrConfigFork, baseN)
	}
	var previousHeader *bridge.ProjectionHeader
	if previousBase != nil {
		previousHeader = previousBase.header
	}
	if _, err := bridge.VerifyBaseKeyless(baseEntry, state.IdentityKey(signerId), rowsBytes, previousHeader); err != nil {
		return fmt.Errorf("%w: base %d: %w", ErrConfigFork, baseN, err)
	}

	// the kept entries before b, which the tail's re-application and the next base's fold read; those b's rows fold
	// carry no verdict this reader holds
	self.kept = nil
	self.keptFrom = entries[0].GetN()
	for i := 0; i < baseIndex; i += 1 {
		kept := &configKeptEntry{n: entries[i].GetN(), chain: chains[i], entry: entries[i], entryBytes: bytes.Clone(entryBytes[i])}
		kept.verdict = ConfigVerdict{Pin: &bridge.AuthPin{Version: kept.n, Chain: bytes.Clone(chains[i][:])}, Kind: entries[i].GetKind()}
		switch entries[i].GetKind() {
		case bridge.AuthEntryKindBase:
			keptSigned, _, err := configParseBase(entries[i])
			if err != nil {
				return fmt.Errorf("%w: base %d: %w", ErrConfigFork, kept.n, err)
			}
			kept.verdict.SignedType = bridge.SignedType_SIGNED_PROJECTION_HEADER
			kept.verdict.StatementId = bridge.SignedBytesSha256(bridge.SignedPurposeAuthority, bridge.SignedType_SIGNED_PROJECTION_HEADER, keptSigned.GetBody())
			kept.verdictHeld = true
		case bridge.AuthEntryKindStatement:
			kept.verdict.SignedType, kept.verdict.StatementId = configEntryStatementId(entries[i])
		}
		self.keep(kept)
	}
	verdicts, err := self.checkBaseTail(previousBase, header, baseN)
	if err != nil {
		return fmt.Errorf("%w: base %d: %w", ErrConfigFork, baseN, err)
	}

	facts := &ConfigHeadFacts{}
	if !self.rowsOnly {
		folded, _ := self.foldedRecords(entries[0].GetN(), foldedThrough)
		facts, err = rowsSource.CheckHead(&ConfigHeadCheck{
			Header:         header,
			Folded:         folded,
			FoldedKnown:    true,
			Rows:           rowsBytes,
			GenesisChain:   genesisState.genesisChain,
			FoldedFrom:     entries[0].GetN(),
			FirstPrevChain: [sha256.Size]byte(entries[0].GetPrevChain()),
			Floor:          floor,
			// b's rows, the tail not yet re-applied, whose identity keys judge the head's pushes (QD-814); the head
			// reader reads only the genesis and those keys, so no acl part builds before the tail lands
			Anchor: state,
		})
		if errors.Is(err, ErrConfigHeadUnavailable) {
			return err
		}
		if err != nil {
			return fmt.Errorf("%w: base %d's config head: %w", ErrConfigFork, baseN, err)
		}
		if facts == nil {
			facts = &ConfigHeadFacts{}
		}
		if err := CheckServiceSettings(facts.Settings); err != nil {
			return fmt.Errorf("%w: base %d's config head: service_settings: %w", ErrConfigFork, baseN, err)
		}
	}
	if err := self.holdHeadFacts(state, rows, facts); err != nil {
		return fmt.Errorf("%w: base %d: %w", ErrConfigFork, baseN, err)
	}

	// A_k from the first kept entry's prev_chain on, which the tail and the entries after b read; S(b) keeps them from
	// its retention point
	state.chainsFrom = entries[0].GetN() - 1
	state.chains = append([][sha256.Size]byte{[sha256.Size]byte(entries[0].GetPrevChain())}, chains[:baseIndex+1]...)
	if err := self.reapplyTail(next, foldedThrough, baseN, verdicts, true); err != nil {
		return fmt.Errorf("%w: base %d: %w", ErrConfigFork, baseN, err)
	}

	// the state at b itself, with S(b)'s pin and chains, and b's own shrinks as its header carries them, since this
	// reader holds no S(b-1) to compute them from (QD-746)
	state.n, state.chain, state.timeMs = baseN, chains[baseIndex], baseEntry.GetTimeMs()
	if err := configApplyBaseShrinks(nil, next, header); err != nil {
		return fmt.Errorf("%w: base %d: %w", ErrConfigFork, baseN, err)
	}
	result := next.finish()
	self.keep(start)
	self.retainBase(result, rowsBytes)
	testHookBarrier("config.restore", self.networkId.String())
	// StateAt's window starts here: no state before b was built
	self.history.reset(result, start)
	self.state.Store(result)
	return nil
}

// A kept statement's type and id as its Signed gives them, zero when it does not parse as a config statement.
func configEntryStatementId(entry *bridge.AuthEntry) (bridge.SignedType, [sha256.Size]byte) {
	signed := &bridge.Signed{}
	if err := proto.Unmarshal(entry.GetBody(), signed); err != nil {
		return bridge.SignedType_SIGNED_TYPE_NONE, [sha256.Size]byte{}
	}
	signedType := bridge.SignedType(signed.GetType())
	purpose, ok := ConfigStatementPurpose(signedType)
	if !ok {
		return bridge.SignedType_SIGNED_TYPE_NONE, [sha256.Size]byte{}
	}
	return signedType, bridge.SignedBytesSha256(purpose, signedType, signed.GetBody())
}
