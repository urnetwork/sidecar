// §7.9's retention row for a reader that did not walk the log from genesis: a new device, or one restarting from
// what it kept. It starts at the newest base b it holds, verifying b's signature and, through its rows source, its
// config head's chain to genesis rather than the pruned entries; chains A_k back from b's prev_chain through the kept
// entries to the retention point; re-applies the statements and ticks among folded_through+1..b-1 as S(b) says,
// judging each at its own position, so it judges every at as a long-running reader does; then applies b+1 on.
//
// What a new device cannot know it does not judge: entries the base folded are its rows, and their ids join the ring
// as applied, since no state before b is left to judge them by. A statement judged in the tail stands on b's rows
// rather than on the state at its own position, so one whose verdict turns on what b's head changed, a tag owner or a
// setting, can differ from a long-running reader's (question team-m2-02-new-device-tail-verdicts).
//
// Nothing here creates, derives or unwraps a key, so nothing calls testHookSecret.

package sidecar

import (
	"bytes"
	"crypto/sha256"
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
	self, err := NewConfigLog(settings, retained.SignedGenesis)
	if err != nil {
		return nil, err
	}
	if len(retained.Entries) == 0 {
		return self, nil
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
			return nil, fmt.Errorf("%w: kept entry %d: %w", ErrConfigEntryMalformed, i, err)
		}
		if !bytes.Equal(entry.GetNetworkId(), self.networkId.Bytes()) {
			return nil, fmt.Errorf("%w: kept entry %d is another network's", ErrConfigEntryMalformed, i)
		}
		if 0 < i {
			if entry.GetN() != entries[i-1].GetN()+1 || !bytes.Equal(entry.GetPrevChain(), chains[i-1][:]) {
				return nil, fmt.Errorf("%w: kept entry %d does not chain onto the one before", ErrConfigFork, entry.GetN())
			}
		}
		chain, err := bridge.AuthChainDigest(entry.GetN(), entry.GetPrevChain(), entry.GetKind(), entry.GetTimeMs(), entry.GetBody())
		if err != nil {
			return nil, fmt.Errorf("%w: kept entry %d: %w", ErrConfigEntryMalformed, i, err)
		}
		entries[i], chains[i] = entry, chain
		if entry.GetKind() == bridge.AuthEntryKindBase {
			baseIndex = i
		}
	}
	if baseIndex < 0 {
		return nil, fmt.Errorf("%w: the kept entries hold no base", ErrConfigEntryMalformed)
	}
	if entries[0].GetN() == 1 && !bytes.Equal(entries[0].GetPrevChain(), self.state.Load().chain[:]) {
		return nil, fmt.Errorf("%w: entry 1 does not chain onto the genesis", ErrConfigFork)
	}

	if err := self.startAtBase(entries, chains, retained.Entries, baseIndex, source); err != nil {
		return nil, err
	}
	for i := baseIndex + 1; i < len(entries); i += 1 {
		if _, err := self.Apply(retained.Entries[i], source); err != nil {
			return nil, err
		}
	}
	return self, nil
}

// Builds S(b) for the base at baseIndex from its rows, the kept entries before it chained to its prev_chain, and the
// tail among folded_through+1..b-1 judged on its rows. Publishes S(b).
func (self *ConfigLog) startAtBase(entries []*bridge.AuthEntry, chains [][sha256.Size]byte, entryBytes [][]byte, baseIndex int, rowsSource ConfigRowsSource) error {
	baseEntry := entries[baseIndex]
	signed, header, err := configParseBase(baseEntry)
	if err != nil {
		return fmt.Errorf("%w: base %d: %w", ErrConfigFork, baseEntry.GetN(), err)
	}
	signerId, err := configBaseSigner(signed)
	if err != nil {
		return fmt.Errorf("%w: base %d: %w", ErrConfigFork, baseEntry.GetN(), err)
	}
	rowsBytes, err := rowsSource.Rows(self.networkId, header.GetRowsSha256())
	if err != nil {
		return fmt.Errorf("%w: base %d's rows: %w", ErrConfigFork, baseEntry.GetN(), err)
	}

	// the base the kept entries hold before b, whose header bounds b's versions and names the retention point
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

	// what b lands on, as far as a new device knows it: S(0)'s genesis with b's rows, whose config writers vouch for
	// b's signer once its head chains to genesis
	genesisState := self.state.Load()
	start := &configKeptEntry{n: baseEntry.GetN(), chain: chains[baseIndex], entry: baseEntry, entryBytes: bytes.Clone(entryBytes[baseIndex])}
	start.verdict = ConfigVerdict{
		Pin:         &bridge.AuthPin{Version: baseEntry.GetN(), Chain: bytes.Clone(chains[baseIndex][:])},
		Kind:        bridge.AuthEntryKindBase,
		SignedType:  bridge.SignedType_SIGNED_PROJECTION_HEADER,
		StatementId: bridge.SignedBytesSha256(bridge.SignedPurposeAuthority, bridge.SignedType_SIGNED_PROJECTION_HEADER, signed.GetBody()),
	}
	facts := &ConfigHeadFacts{}
	if !self.rowsOnly {
		facts, err = rowsSource.CheckHead(&ConfigHeadCheck{Header: header, Rows: rowsBytes})
		if err != nil {
			return fmt.Errorf("%w: base %d's config head: %w", ErrConfigFork, baseEntry.GetN(), err)
		}
		if facts == nil {
			facts = &ConfigHeadFacts{}
		}
	}
	next, err := self.stateFromBase(genesisState, start, header, rowsBytes, facts)
	if err != nil {
		return fmt.Errorf("%w: base %d: %w", ErrConfigFork, baseEntry.GetN(), err)
	}
	state := next.state
	state.previousBase = previousBase
	if !state.IsConfigWriter(signerId) {
		return fmt.Errorf("%w: base %d's signer is no config writer in its own rows", ErrConfigFork, baseEntry.GetN())
	}
	var previousHeader *bridge.ProjectionHeader
	if previousBase != nil {
		previousHeader = previousBase.header
	}
	if _, err := bridge.VerifyBaseKeyless(baseEntry, state.IdentityKey(signerId), rowsBytes, previousHeader); err != nil {
		return fmt.Errorf("%w: base %d: %w", ErrConfigFork, baseEntry.GetN(), err)
	}

	// A_k from the first kept entry on, which the tail's at reads; S(b) keeps them from its retention point
	state.chainsFrom = entries[0].GetN()
	state.chains = append([][sha256.Size]byte(nil), chains[:baseIndex+1]...)
	if 1 < entries[0].GetN() {
		state.chainsFrom = entries[0].GetN() - 1
		state.chains = append([][sha256.Size]byte{[sha256.Size]byte(entries[0].GetPrevChain())}, state.chains...)
	} else {
		state.chainsFrom = 0
		state.chains = append([][sha256.Size]byte{genesisState.chain}, state.chains...)
	}

	self.kept = nil
	self.keptFrom = entries[0].GetN()
	foldedThrough := header.GetFoldedThrough()
	// the kept bases before b, newest last, which name the retention point of the state each tail entry lands on
	keptBases := []*bridge.ProjectionHeader{}
	keptBasePositions := []uint64{}
	for i := 0; i < baseIndex; i += 1 {
		kept := &configKeptEntry{n: entries[i].GetN(), chain: chains[i], entry: entries[i], entryBytes: bytes.Clone(entryBytes[i])}
		kept.verdict = ConfigVerdict{Pin: &bridge.AuthPin{Version: kept.n, Chain: bytes.Clone(chains[i][:])}, Kind: entries[i].GetKind()}
		switch {
		case entries[i].GetKind() == bridge.AuthEntryKindBase:
			keptSigned, keptHeader, err := configParseBase(entries[i])
			if err != nil {
				return fmt.Errorf("%w: base %d: %w", ErrConfigFork, kept.n, err)
			}
			kept.verdict.SignedType = bridge.SignedType_SIGNED_PROJECTION_HEADER
			kept.verdict.StatementId = bridge.SignedBytesSha256(bridge.SignedPurposeAuthority, bridge.SignedType_SIGNED_PROJECTION_HEADER, keptSigned.GetBody())
			keptBases = append(keptBases, keptHeader)
			keptBasePositions = append(keptBasePositions, kept.n)
		case kept.n <= foldedThrough:
			// folded into b's rows: taken as applied, its id kept so a repeat stays refused
			if entries[i].GetKind() == bridge.AuthEntryKindStatement {
				kept.verdict.SignedType, kept.verdict.StatementId = configEntryStatementId(entries[i])
			}
		default:
			// the tail, judged on b's rows at its own position
			self.judgeTailEntry(next, kept, configTailRetentionPoint(state.chainsFrom, keptBasePositions, keptBases))
		}
		self.keep(kept)
	}

	// the state at b itself, with S(b)'s pin and chains
	state.n, state.chain, state.timeMs = baseEntry.GetN(), chains[baseIndex], baseEntry.GetTimeMs()
	result := next.finish()
	self.keep(start)
	self.retainBase(result, rowsBytes)
	self.state.Store(result)
	return nil
}

// A kept STATEMENT's type and id as its Signed gives them, zero when it does not parse as a config statement.
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

// The retention point of the state a tail entry lands on, as far as a new device can tell: min(the base before the
// newest, the newest's folded_through + 1) when it keeps both, and never below the first position whose A_k it holds,
// since a base before what it keeps lies below that position and an at before it is off what it can check.
func configTailRetentionPoint(chainsFrom uint64, keptBasePositions []uint64, keptBases []*bridge.ProjectionHeader) uint64 {
	point := chainsFrom
	if count := len(keptBases); 2 <= count {
		exact := min(keptBasePositions[count-2], keptBases[count-1].GetFoldedThrough()+1)
		point = max(point, exact)
	}
	return point
}

// Judges one tail entry at its own position on the state next is building, which stands at k-1 for the judgment,
// and applies it to next when it takes effect.
func (self *ConfigLog) judgeTailEntry(next *configStateBuilder, kept *configKeptEntry, retentionPoint uint64) {
	state := next.state
	state.n = kept.n - 1
	state.chain = state.chains[state.n-state.chainsFrom]
	view := next.snapshot()
	switch kept.entry.GetKind() {
	case bridge.AuthEntryKindStatement:
		statement, err := self.judgeStatement(view, kept.entry, retentionPoint)
		if statement != nil {
			kept.verdict.SignedType, kept.verdict.StatementId = statement.signedType, statement.id
		}
		if err == nil {
			err = configApplyStatement(next, statement, false)
		}
		if err != nil {
			kept.verdict.Refusal = err
			return
		}
		kept.statement = statement
		if statement.completes != nil {
			kept.verdict.CompletedProposalId = configCompletedProposalId(statement)
		}
	case bridge.AuthEntryKindTick:
		tick := &bridge.ApiTick{}
		if err := proto.Unmarshal(kept.entry.GetBody(), tick); err != nil {
			kept.verdict.Refusal = fmt.Errorf("%w: tick: %w", ErrConfigRule, err)
			return
		}
		if err := configCheckTick(view, tick); err != nil {
			kept.verdict.Refusal = err
			return
		}
		configApplyTick(next, tick)
		kept.tick = tick
	}
}
