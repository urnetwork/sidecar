// §7.9's apply(e) for the gates: api, evs, gkm and every other gate service hold no config key, so they cannot open a
// config head or recompile one (§8.9). Rows-only mode is ConfigLog's own walk with that one step left out: a base
// applies by bridge.VerifyBaseKeyless (the signature, prev_chain, rows by rows_sha256 and size, and neither version
// below the previous base's, so no base rolls back policy or the fold), its signer a config writer at S(my.n), then
// its rows replace the state's and its tail re-applies keeping each verdict; statements and ticks apply by the
// ordinary rules at S(my.n). So a rows-only verdict is a full reader's, save where a rule reads what only the head
// holds: a ServiceSettings value, which a rows-only state reports unknown and the rule fails closed on (question
// team-m2-02-self-admit-at-rows-only-readers).
//
// Gates read the log from wherever is cheapest: the verified read cache {acl_<networkId>}e when it records {acl_}v's
// current value and holds every position they need, else proj/ on the first metadata cluster (§7.9, ACL-M2-13's
// AclGateDirectSource), or api's read surface for the other gates (plan-SOCK-gate-data). None of those decides
// anything: ApplyRun checks a whole run against the process's own pin before any of it applies, refusing a run whose
// links break or that carries at a position the log holds an A_n other than the one held there, and the log goes on
// from its own pin, so a stale or forged copy costs a re-read and never moves the log, and a stale copy is no lower
// n: nothing here ever lowers a log. A cold start (RestoreConfigLogRowsOnly) is held to a floor, the pin the process
// last held for the network, so a restart of the cache from a stale copy cannot land below it either.
//
// The one fork a run cannot hide: an unsigned TICK chains onto the pin it names, so a copy that forged one at the
// next position moves the log onto a chain proj/ does not hold, and the next run from proj/ is refused as a second
// A_n. Only api writes {acl_}e, so that copy is api's, which can write proj/ too (§7.9's read row).
//
// Rows-only code reads no Postgres (I-12), carries no connect type and runs on every leg, though its callers, the gate
// services, are !sidecar_http. Nothing here creates, derives or unwraps a key, so nothing calls testHookSecret.

package sidecar

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

var (
	// A run of entries refused whole, none of it applied: ConfigRunError says why. The log goes on from its own pin.
	ErrConfigRunRefused = errors.New("config entry run refused")
	// A log a cold start would build ends below the pin the process last held for the network: a lower n (§8.9).
	ErrConfigBelowPin = errors.New("config log below the reader's own pin")
	// A base in a run names rows the source cannot serve now: the run is refused whole and the log goes on, since
	// what a reader cannot fetch is withheld, not forked (§7.9's retain row). The caller reads again later.
	ErrConfigRowsUnavailable = errors.New("config base rows unavailable")
)

// Why a run was refused: the position, what this log holds there and what the run carried there. For a second A_n at
// a position this log holds, both digests are the evidence an alarm carries; for a broken link, RemoteChain is the
// digest the entry before it gave.
type ConfigRunError struct {
	// The position.
	N uint64
	// A_N as this log holds it, when it holds one.
	LocalChain    [sha256.Size]byte
	HasLocalChain bool
	// A_N as the run carries it.
	RemoteChain [sha256.Size]byte
	// What did not hold, ids and positions only (I-13).
	Reason string
}

// The position and both digests.
func (self *ConfigRunError) Error() string {
	return fmt.Sprintf("%s at %d: %s (local %x, run %x)", ErrConfigRunRefused, self.N, self.Reason, self.LocalChain[:8], self.RemoteChain[:8])
}

// ErrConfigRunRefused.
func (self *ConfigRunError) Unwrap() error {
	return ErrConfigRunRefused
}

// A log at S(0) for a reader that holds no config key: NewConfigLog's, whose bases skip the config head's check and
// whose states report ServiceSettings unknown. A gate starts one at the network's newest base with
// RestoreConfigLogRowsOnly instead, since entries before the retention point are gone.
func NewConfigLogRowsOnly(settings *ConfigLogSettings, signedGenesis []byte) (*ConfigLog, error) {
	self, err := NewConfigLog(settings, signedGenesis)
	if err != nil {
		return nil, err
	}
	self.rowsOnly = true
	return self, nil
}

// A rows-only log from a run of entries, as a gate starts cold: at the newest base among retained.Entries, which must
// reach back to that base's tail (folded_through + 1), then every entry after it, as RestoreConfigLog does for a new
// device. The base's signer must be a config writer in its own rows, the one thing a reader that never saw the
// entries before it takes on trust; its chain onward is checked entry by entry.
//
// floor is the pin the process last held for the network, nil for none: a log ending below it is ErrConfigBelowPin,
// and one holding a different A_n at its position is ErrConfigRunRefused, so no restart from a stale copy lands lower
// (§8.9). A floor before what the run holds checks its number alone.
func RestoreConfigLogRowsOnly(settings *ConfigLogSettings, retained *ConfigRetained, rowsSource ConfigRowsSource, floor *bridge.AuthPin) (*ConfigLog, error) {
	self, err := NewConfigLogRowsOnly(settings, retained.SignedGenesis)
	if err != nil {
		return nil, err
	}
	if err := self.restore(retained, rowsSource); err != nil {
		return nil, err
	}
	if floor != nil {
		state := self.state.Load()
		if state.n < floor.GetVersion() {
			return nil, fmt.Errorf("%w: %d below %d", ErrConfigBelowPin, state.n, floor.GetVersion())
		}
		if chain, ok := state.chainAt(floor.GetVersion()); ok && !bytes.Equal(chain[:], floor.GetChain()) {
			runError := &ConfigRunError{N: floor.GetVersion(), RemoteChain: chain, Reason: "a second A_n at the reader's own pin"}
			if len(floor.GetChain()) == sha256.Size {
				runError.LocalChain, runError.HasLocalChain = [sha256.Size]byte(floor.GetChain()), true
			}
			self.log.Errorf("[config]%s cold start refused at %d: %s", self.networkId, floor.GetVersion(), runError.Reason)
			return nil, runError
		}
	}
	return self, nil
}

// Whether this log holds no config key: its bases skip the head check and its states report ServiceSettings unknown.
func (self *ConfigLog) RowsOnly() bool {
	return self.rowsOnly
}

// One entry of a run, parsed, with the digest it gives.
type configRunEntry struct {
	entry      *bridge.AuthEntry
	entryBytes []byte
	chain      [sha256.Size]byte
}

// Applies a run of entries, verbatim and in position order, from wherever a gate read them (§8.9). The run is checked
// whole first, and refused whole with a ConfigRunError when it breaks: each entry is this network's, at the position
// after the one before it and chaining onto that one's digest; the run starts no further on than this log's next
// position; and at each position this log holds, the run carries the A_n held there. Then the entries past this
// log's position apply in order, as Apply does each, and their verdicts come back. A run ending at or below this
// log's position, a stale copy's, applies nothing and lowers nothing. An error from Apply (a fork, or a base whose
// rows rowsSource cannot serve) stops the run where it happened, the entries before it applied.
//
// For the log's one applying goroutine, as Apply is.
func (self *ConfigLog) ApplyRun(entryBytes [][]byte, rowsSource ConfigRowsSource) ([]ConfigVerdict, error) {
	if self.fork != nil {
		return nil, self.fork
	}
	if len(entryBytes) == 0 {
		return nil, nil
	}
	refuse := func(runError *ConfigRunError) error {
		self.log.Errorf("[config]%s run refused at %d: %s", self.networkId, runError.N, runError.Reason)
		return runError
	}

	run := make([]configRunEntry, len(entryBytes))
	for i, oneEntryBytes := range entryBytes {
		entry := &bridge.AuthEntry{}
		if err := proto.Unmarshal(oneEntryBytes, entry); err != nil {
			return nil, refuse(&ConfigRunError{Reason: fmt.Sprintf("entry %d of the run does not parse", i)})
		}
		if !bytes.Equal(entry.GetNetworkId(), self.networkId.Bytes()) {
			return nil, refuse(&ConfigRunError{N: entry.GetN(), Reason: "another network's entry"})
		}
		chain, err := bridge.AuthChainDigest(entry.GetN(), entry.GetPrevChain(), entry.GetKind(), entry.GetTimeMs(), entry.GetBody())
		if err != nil {
			return nil, refuse(&ConfigRunError{N: entry.GetN(), Reason: "an entry with no digest"})
		}
		if 0 < i {
			previous := run[i-1]
			if entry.GetN() != previous.entry.GetN()+1 {
				return nil, refuse(&ConfigRunError{N: entry.GetN(), Reason: fmt.Sprintf("a gap after %d", previous.entry.GetN())})
			}
			if !bytes.Equal(entry.GetPrevChain(), previous.chain[:]) {
				return nil, refuse(&ConfigRunError{N: entry.GetN(), RemoteChain: previous.chain, Reason: "prev_chain is not the run's own A_{n-1}"})
			}
		}
		run[i] = configRunEntry{entry: entry, entryBytes: oneEntryBytes, chain: chain}
	}

	state := self.state.Load()
	first := run[0].entry.GetN()
	if state.n+1 < first {
		return nil, fmt.Errorf("%w: the run starts at %d after %d", ErrConfigEntryAhead, first, state.n)
	}
	// each position this log holds: the run's A_n must be the one held there, and the first held one anchors the
	// rest of the run, which chains on from it
	for _, runEntry := range run {
		n := runEntry.entry.GetN()
		if state.n < n {
			break
		}
		if local, ok := state.chainAt(n); ok && local != runEntry.chain {
			return nil, refuse(&ConfigRunError{N: n, LocalChain: local, HasLocalChain: true, RemoteChain: runEntry.chain,
				Reason: "a second A_n at a position this log holds"})
		}
	}
	if last := run[len(run)-1].entry.GetN(); last <= state.n {
		return nil, nil
	}
	if first == state.n+1 && !bytes.Equal(run[0].entry.GetPrevChain(), state.chain[:]) {
		return nil, refuse(&ConfigRunError{N: first, LocalChain: state.chain, HasLocalChain: true, Reason: "prev_chain is not this log's A_n"})
	}
	// each base's rows before any of the run applies: Apply reads a base whose rows it cannot fetch as a fork, and a
	// store that cannot serve them now has withheld them, so the run is refused whole and read again later
	prefetched := configPrefetchedRowsSource{rows: map[[sha256.Size]byte][]byte{}, next: rowsSource}
	for _, runEntry := range run {
		if runEntry.entry.GetN() <= state.n || runEntry.entry.GetKind() != bridge.AuthEntryKindBase || rowsSource == nil {
			continue
		}
		_, header, err := configParseBase(runEntry.entry)
		if err != nil || len(header.GetRowsSha256()) != sha256.Size {
			// Apply judges it, a fork
			continue
		}
		rows, err := rowsSource.Rows(self.networkId, header.GetRowsSha256())
		if err != nil {
			return nil, fmt.Errorf("%w: base %d: %w", ErrConfigRowsUnavailable, runEntry.entry.GetN(), err)
		}
		prefetched.rows[[sha256.Size]byte(header.GetRowsSha256())] = rows
	}
	testHookBarrier("config.run.checked", self.networkId.String())

	verdicts := []ConfigVerdict{}
	for _, runEntry := range run {
		if runEntry.entry.GetN() <= state.n {
			continue
		}
		verdict, err := self.Apply(runEntry.entryBytes, prefetched)
		if err != nil {
			return verdicts, err
		}
		verdicts = append(verdicts, verdict)
	}
	return verdicts, nil
}

// The rows a run fetched before applying, then the source's own.
type configPrefetchedRowsSource struct {
	rows map[[sha256.Size]byte][]byte
	next ConfigRowsSource
}

// The fetched rows, else the source's.
func (self configPrefetchedRowsSource) Rows(networkId Id, rowsSha256 []byte) ([]byte, error) {
	if len(rowsSha256) == sha256.Size {
		if rows, found := self.rows[[sha256.Size]byte(rowsSha256)]; found {
			return rows, nil
		}
	}
	if self.next == nil {
		return nil, errors.New("no rows source")
	}
	return self.next.Rows(networkId, rowsSha256)
}

// The source's check.
func (self configPrefetchedRowsSource) CheckHead(check *ConfigHeadCheck) (*ConfigHeadFacts, error) {
	if self.next == nil {
		return nil, errors.New("no config head reader")
	}
	return self.next.CheckHead(check)
}

// A rows source for a reader that opens no config head: Rows from the function given, CheckHead refused, which a
// rows-only log never calls.
type ConfigRowsOnlySource func(networkId Id, rowsSha256 []byte) ([]byte, error)

// The function's rows.
func (self ConfigRowsOnlySource) Rows(networkId Id, rowsSha256 []byte) ([]byte, error) {
	return self(networkId, rowsSha256)
}

// Refused: a rows-only reader opens no config head.
func (self ConfigRowsOnlySource) CheckHead(check *ConfigHeadCheck) (*ConfigHeadFacts, error) {
	return nil, errors.New("a rows-only source opens no config head")
}

// §7.9's objects on the first metadata cluster, which api writes and api, evs and gkm read (owner decision 145): entry
// n at proj/<network_id>/<n zero-padded to 20 digits>/_, entry 0 holding the Signed Genesis verbatim
// (plan-TEAM-genesis-custody), and a base's rows content-addressed at projrows/<network_id>/<hex sha256>/_. No key
// prefixes another (§11.8's keys row).
func ConfigEntryKey(networkId Id, n uint64) string {
	return fmt.Sprintf("proj/%s/%020d/_", networkId, n)
}

// The prefix every entry key of the network starts with, for a LIST, which returns them in position order.
func ConfigEntryKeyPrefix(networkId Id) string {
	return fmt.Sprintf("proj/%s/", networkId)
}

// The position an entry key of the network names, false for any other key.
func ParseConfigEntryKey(networkId Id, key string) (uint64, bool) {
	prefix := ConfigEntryKeyPrefix(networkId)
	if !strings.HasPrefix(key, prefix) || !strings.HasSuffix(key, "/_") {
		return 0, false
	}
	digits := key[len(prefix) : len(key)-len("/_")]
	if len(digits) != 20 {
		return 0, false
	}
	n, err := strconv.ParseUint(digits, 10, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}

// A base's rows' key.
func ConfigRowsKey(networkId Id, rowsSha256 []byte) string {
	return fmt.Sprintf("projrows/%s/%s/_", networkId, hex.EncodeToString(rowsSha256))
}

// A base whose version is not the tip's next or whose prev_chain is not A_tip: the tip moved, and its writer re-signs
// at the new tip (§7.9's base row, api's 409).
var ErrConfigTipMoved = errors.New("config tip moved")

// api's verdict on a base before it appends one (§7.9's base row), as Check is for a statement: ErrConfigTipMoved when
// the header's version is not the tip's next or its prev_chain is not A_tip; else what applying it at the next
// position would find, a signer that is no config writer at S(tip), a bad signature, rows that do not hash to
// rows_sha256 or do not build, or either version below the newest base's, as an ErrConfigRefused. Nothing is kept and
// no state changes, so a refused base is no fork here: it never reached the log. A rows-only reader cannot read the
// config head, so its descent is CheckConfigPushes's, from the pushes the base carries
// (plan-TEAM-api-config-head-reach). For the goroutine that applies, as Apply is.
func (self *ConfigLog) CheckBase(signedHeader []byte, rows []byte) error {
	if self.fork != nil {
		return fmt.Errorf("%w: the log stopped at a fork", ErrConfigRefused)
	}
	state := self.state.Load()
	entry := &bridge.AuthEntry{
		NetworkId: self.networkId.Bytes(),
		N:         state.n + 1,
		PrevChain: bytes.Clone(state.chain[:]),
		Kind:      bridge.AuthEntryKindBase,
		TimeMs:    state.timeMs,
		Body:      signedHeader,
	}
	signed, header, err := configParseBase(entry)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrConfigRule, err)
	}
	if header.GetVersion() != entry.GetN() || !bytes.Equal(header.GetPrevChain(), entry.GetPrevChain()) {
		return fmt.Errorf("%w: a base for %d at tip %d", ErrConfigTipMoved, header.GetVersion(), state.n)
	}
	signerId, err := configBaseSigner(signed)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrConfigSigner, err)
	}
	if !state.IsConfigWriter(signerId) {
		return fmt.Errorf("%w: the base's signer is no config writer at %d", ErrConfigAuthority, state.n)
	}
	var previousHeader *bridge.ProjectionHeader
	if state.base != nil {
		previousHeader = state.base.header
	}
	if _, err := bridge.VerifyBaseKeyless(entry, state.IdentityKey(signerId), rows, previousHeader); err != nil {
		return fmt.Errorf("%w: %w", ErrConfigRule, err)
	}
	chain, err := bridge.AuthChainDigest(entry.GetN(), entry.GetPrevChain(), entry.GetKind(), entry.GetTimeMs(), entry.GetBody())
	if err != nil {
		return fmt.Errorf("%w: %w", ErrConfigRule, err)
	}
	scratch := &configKeptEntry{n: entry.GetN(), chain: chain, entry: entry, entryBytes: nil}
	if _, err := self.stateFromBase(state, scratch, header, rows, &ConfigHeadFacts{}); err != nil {
		return fmt.Errorf("%w: %w", ErrConfigRule, err)
	}
	return nil
}
