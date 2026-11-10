// §7.9's authorization log on the fake api: POST /network/config/delta, POST and GET /network/config/projection, on
// proj/ and projrows/ of the first metadata cluster, and the same appends as calls for the shared store suite
// (store_config_log.go), which runs here and on server's real sequencer (TEAM-M2-13), so a schedule relies only on
// what both do.
//
// Verification is the real one: each network's log is a rows-only ConfigLog at this api's tip, which judges a
// statement with ConfigLog.Check and a base with ConfigLog.CheckBase and its config head's descent with
// ConfigLog.CheckConfigPushes, since api holds no config key and never reads the config repo. Sequencing is the copy,
// §7.9's statement, base and uncertain rows:
//
//	verify     the retry identity first: a statement whose id an applied entry among the last 4,096 holds, or a base
//	           this log holds, answers that entry's {n, A_n}; then the verdict at the tip, a refusal answering 403 (a
//	           base whose tip moved 409) with the tip
//	append     PUT proj/<network_id>/<n>/_ If-None-Match at tip+1, the entry's time api's clock
//	412        another appender won the position: read its entry, apply it, and verify again at the new tip
//	unknown    a timeout or lost response: GET the position; the same bytes are success, another entry a loss (apply
//	           it and go on at the next position), 404 repeats the PUT with the same bytes
//	base       its config pushes walk from the newest base's head to its own (plan-TEAM-api-config-head-reach), then
//	           its rows (projrows/, an equal object answering 200), then the entry; base 1 needs the Signed Genesis,
//	           written at position 0 after entry 1, its commit point, and a retry of base 1 repeats a missing step
//	           (plan-TEAM-genesis-custody)
//
// SequenceAnyway appends what api would refuse, as a malicious sequencer does (FS-102, FS-124), and DropEntry withholds
// an entry from reads. Reads come from the store, never from this api's memory, so two fake apis over one cluster
// read alike. An append holds its network's lock across its store requests, serializing this api's appends to one
// network; another api over the same cluster races it at the store, as server's instances race. Safe for concurrent
// use.

package sidecartest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strconv"
	"sync"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// One network's log at this api.
type fakeApiConfigLog struct {
	networkId sidecar.Id

	// serializes this api's loads and appends for the network, and guards what follows
	stateLock sync.Mutex
	// the rows-only verifier at this api's tip, nil until the genesis is known
	log           *sidecar.ConfigLog
	signedGenesis []byte
	// each base this log applied, by its id, for a retry of the same base
	basePins map[[sha256.Size]byte]*bridge.AuthPin
	// positions reads withhold (DropEntry)
	dropped map[uint64]bool
}

// The network's log, made empty on first use.
func (self *FakeApi) configLog(networkId sidecar.Id) *fakeApiConfigLog {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	configLog := self.configLogs[networkId]
	if configLog == nil {
		configLog = &fakeApiConfigLog{networkId: networkId, basePins: map[[sha256.Size]byte]*bridge.AuthPin{}, dropped: map[uint64]bool{}}
		self.configLogs[networkId] = configLog
	}
	return configLog
}

// The first metadata cluster, where proj/ and projrows/ live.
func (self *FakeApi) firstCluster() (sidecar.BlobCluster, error) {
	if self.cluster == nil {
		return nil, sidecar.ErrBlobClusterUnknown
	}
	return self.cluster, nil
}

// A key's bytes, false for none.
func fakeApiGet(ctx context.Context, cluster sidecar.BlobCluster, key string) ([]byte, bool, error) {
	object, err := cluster.Get(ctx, key)
	if errors.Is(err, sidecar.ErrBlobNotFound) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	defer object.Body.Close()
	body, err := io.ReadAll(object.Body)
	if err != nil {
		return nil, false, err
	}
	return body, true, nil
}

// The rows source a rows-only log at this api reads: projrows/ on the first cluster.
func (self *FakeApi) rowsSource(ctx context.Context) sidecar.ConfigRowsOnlySource {
	return func(networkId sidecar.Id, rowsSha256 []byte) ([]byte, error) {
		cluster, err := self.firstCluster()
		if err != nil {
			return nil, err
		}
		rows, found, err := fakeApiGet(ctx, cluster, sidecar.ConfigRowsKey(networkId, rowsSha256))
		if err != nil {
			return nil, err
		}
		if !found {
			return nil, fmt.Errorf("no rows at %x", rowsSha256[:8])
		}
		return rows, nil
	}
}

// Every entry key of the network after position after, in position order, as LIST gives them.
func (self *FakeApi) listEntries(ctx context.Context, networkId sidecar.Id, after uint64, limit int) ([]uint64, bool, error) {
	cluster, err := self.firstCluster()
	if err != nil {
		return nil, false, err
	}
	positions := []uint64{}
	startAfter := sidecar.ConfigEntryKey(networkId, after)
	for {
		infos, more, err := cluster.List(ctx, sidecar.ConfigEntryKeyPrefix(networkId), startAfter, min(limit-len(positions), 999))
		if err != nil {
			return nil, false, err
		}
		for _, info := range infos {
			if n, ok := sidecar.ParseConfigEntryKey(networkId, info.Key); ok && after < n {
				positions = append(positions, n)
			}
			startAfter = info.Key
		}
		if !more || limit <= len(positions) {
			return positions, more, nil
		}
	}
}

// Loads the log from the store when this api holds none: entry 0's genesis, or genesisHint when entry 0 is not
// written yet and the hint is entry 1's prev_chain (a retry of base 1 that lost the step), then the retained entries.
// Nil with no error when the network has no log.
func (self *fakeApiConfigLog) loadWithLock(ctx context.Context, api *FakeApi, genesisHint []byte) (*sidecar.ConfigLog, error) {
	if self.log != nil {
		return self.log, nil
	}
	cluster, err := api.firstCluster()
	if err != nil {
		return nil, err
	}
	signedGenesis, found, err := fakeApiGet(ctx, cluster, sidecar.ConfigEntryKey(self.networkId, 0))
	if err != nil {
		return nil, err
	}
	positions, _, err := api.listEntries(ctx, self.networkId, 0, 1<<30)
	if err != nil {
		return nil, err
	}
	entries := make([][]byte, 0, len(positions))
	for _, n := range positions {
		entryBytes, found, err := fakeApiGet(ctx, cluster, sidecar.ConfigEntryKey(self.networkId, n))
		if err != nil {
			return nil, err
		}
		if !found {
			return nil, fmt.Errorf("entry %d listed and gone", n)
		}
		entries = append(entries, entryBytes)
	}
	if !found {
		if len(entries) == 0 || genesisHint == nil {
			return nil, nil
		}
		first := &bridge.AuthEntry{}
		if err := proto.Unmarshal(entries[0], first); err != nil {
			return nil, err
		}
		genesisChain := bridge.GenesisChain(genesisHint)
		if first.GetN() != 1 || !bytes.Equal(first.GetPrevChain(), genesisChain[:]) {
			return nil, nil
		}
		signedGenesis = genesisHint
	}
	var log *sidecar.ConfigLog
	settings := sidecar.DefaultConfigLogSettings()
	settings.Log = sidecar.NewNoopLogger()
	if len(entries) == 0 || positions[0] == 1 {
		log, err = sidecar.NewConfigLogRowsOnly(settings, signedGenesis)
		if err == nil && 0 < len(entries) {
			_, err = log.ApplyRun(entries, api.rowsSource(ctx))
		}
	} else {
		retained := &sidecar.ConfigRetained{SignedGenesis: signedGenesis, Entries: entries}
		log, err = sidecar.RestoreConfigLogRowsOnly(settings, retained, api.rowsSource(ctx), nil)
	}
	if err != nil {
		return nil, err
	}
	self.log, self.signedGenesis = log, signedGenesis
	for _, entryBytes := range entries {
		self.noteBaseWithLock(entryBytes)
	}
	return log, nil
}

// Remembers a base entry's id and pin, for a retry of the same base.
func (self *fakeApiConfigLog) noteBaseWithLock(entryBytes []byte) {
	entry := &bridge.AuthEntry{}
	if proto.Unmarshal(entryBytes, entry) != nil || entry.GetKind() != bridge.AuthEntryKindBase {
		return
	}
	chain, err := bridge.AuthChainDigest(entry.GetN(), entry.GetPrevChain(), entry.GetKind(), entry.GetTimeMs(), entry.GetBody())
	if err != nil {
		return
	}
	self.basePins[sha256.Sum256(entry.GetBody())] = &bridge.AuthPin{Version: entry.GetN(), Chain: chain[:]}
}

// Applies an entry another appender wrote, or this one did, to the verifier at the tip. An entry that does not apply,
// another genesis's base 1 that won a race or a fork, drops this api's log, which the next request loads again from the
// store, so the store, never this memory, says what the log is.
func (self *fakeApiConfigLog) applyWithLock(ctx context.Context, api *FakeApi, entryBytes []byte) error {
	if _, err := self.log.Apply(entryBytes, api.rowsSource(ctx)); err != nil {
		self.log, self.signedGenesis = nil, nil
		clear(self.basePins)
		return err
	}
	self.noteBaseWithLock(entryBytes)
	return nil
}

// A refusal or failure of an append: 403 refused at the tip, 409 a base whose tip moved, 503 the store's outcome
// unknown or the store unavailable. Tip is the tip the signer re-evaluates at, nil before base 1.
type ConfigLogRefusal struct {
	Status int
	Tip    *bridge.AuthPin
	Err    error
}

// The status and why.
func (self *ConfigLogRefusal) Error() string {
	return fmt.Sprintf("config log append %d: %v", self.Status, self.Err)
}

// Why.
func (self *ConfigLogRefusal) Unwrap() error {
	return self.Err
}

// One append as the sequencer runs it.
type fakeApiAppend struct {
	kind uint32
	body []byte
	// the genesis a base 1 carries
	genesis []byte
	// the entry a retry finds, or the verdict at the tip; nil appends unverified (SequenceAnyway)
	verify func(configLog *fakeApiConfigLog) (*bridge.AuthPin, error)
	// written before the entry (a base's rows) and after it (base 1's genesis), each once more on a retry
	before func(ctx context.Context, cluster sidecar.BlobCluster) error
	after  func(ctx context.Context, cluster sidecar.BlobCluster) error
}

// §7.9's sequencing steps for one entry: verify at the tip, PUT at tip+1, and resolve a 412 or an unknown outcome.
func (self *FakeApi) append(ctx context.Context, networkId sidecar.Id, request *fakeApiAppend) (*bridge.AuthPin, error) {
	configLog := self.configLog(networkId)
	configLog.stateLock.Lock()
	defer configLog.stateLock.Unlock()

	cluster, err := self.firstCluster()
	if err != nil {
		return nil, &ConfigLogRefusal{Status: http.StatusServiceUnavailable, Err: err}
	}
	if _, err := configLog.loadWithLock(ctx, self, request.genesis); err != nil {
		return nil, &ConfigLogRefusal{Status: http.StatusServiceUnavailable, Err: err}
	}
	if configLog.log == nil {
		if request.genesis == nil {
			return nil, &ConfigLogRefusal{Status: http.StatusForbidden, Err: errors.New("the network has no log, and only base 1 with its genesis starts one")}
		}
		settings := sidecar.DefaultConfigLogSettings()
		settings.Log = sidecar.NewNoopLogger()
		log, err := sidecar.NewConfigLogRowsOnly(settings, request.genesis)
		if err != nil {
			return nil, &ConfigLogRefusal{Status: http.StatusForbidden, Err: err}
		}
		if log.State().NetworkId() != networkId {
			return nil, &ConfigLogRefusal{Status: http.StatusForbidden, Err: errors.New("the genesis names another network")}
		}
		configLog.log, configLog.signedGenesis = log, request.genesis
	} else if request.genesis != nil && !bytes.Equal(request.genesis, configLog.signedGenesis) {
		// no network whose log exists takes a new base 1
		return nil, &ConfigLogRefusal{Status: http.StatusConflict, Tip: configLog.log.Pin(), Err: errors.New("the network's log has another genesis")}
	}
	barrierKey := networkId.String()

	finish := func(pin *bridge.AuthPin) (*bridge.AuthPin, error) {
		if request.after != nil {
			if err := request.after(ctx, cluster); err != nil {
				return nil, &ConfigLogRefusal{Status: http.StatusServiceUnavailable, Tip: pin, Err: err}
			}
		}
		return pin, nil
	}
	for range self.settings.AppendAttemptCount {
		if request.verify != nil {
			found, err := request.verify(configLog)
			if err != nil {
				status := http.StatusForbidden
				if errors.Is(err, sidecar.ErrConfigTipMoved) {
					status = http.StatusConflict
				}
				return nil, &ConfigLogRefusal{Status: status, Tip: configLog.log.Pin(), Err: err}
			}
			if found != nil {
				return finish(found)
			}
		}
		tip := configLog.log.Pin()
		entryBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(&bridge.AuthEntry{
			NetworkId: networkId.Bytes(),
			N:         tip.GetVersion() + 1,
			PrevChain: tip.GetChain(),
			Kind:      request.kind,
			TimeMs:    self.clock.Now().UnixMilli(),
			Body:      request.body,
		})
		if err != nil {
			return nil, &ConfigLogRefusal{Status: http.StatusInternalServerError, Err: err}
		}
		if request.before != nil {
			if err := request.before(ctx, cluster); err != nil {
				return nil, &ConfigLogRefusal{Status: http.StatusServiceUnavailable, Tip: tip, Err: err}
			}
		}
		if self.barriers != nil {
			self.barriers.Hit("api.config.verified", barrierKey)
		}
		key := sidecar.ConfigEntryKey(networkId, tip.GetVersion()+1)
		landed, err := func() (*bridge.AuthPin, error) {
			for range self.settings.AppendAttemptCount {
				_, putErr := cluster.PutIfNoneMatch(ctx, key, entryBytes, nil)
				var unknown *sidecar.BlobUnknownError
				switch {
				case putErr == nil:
					if err := configLog.applyWithLock(ctx, self, entryBytes); err != nil {
						return nil, err
					}
					return configLog.log.Pin(), nil
				case errors.Is(putErr, sidecar.ErrBlobPrecondition), errors.As(putErr, &unknown):
					held, found, err := fakeApiGet(ctx, cluster, key)
					switch {
					case err != nil:
						return nil, &ConfigLogRefusal{Status: http.StatusServiceUnavailable, Tip: tip, Err: fmt.Errorf("the outcome is unknown: %w", err)}
					case !found:
						// it never landed and never will, and a 412 over nothing held nothing: the same bytes again
						continue
					case bytes.Equal(held, entryBytes):
						if err := configLog.applyWithLock(ctx, self, held); err != nil {
							return nil, err
						}
						return configLog.log.Pin(), nil
					}
					// another appender's entry: a loss here, applied, and verified again at the next position
					if err := configLog.applyWithLock(ctx, self, held); err != nil {
						return nil, err
					}
					return nil, nil
				default:
					return nil, &ConfigLogRefusal{Status: http.StatusServiceUnavailable, Tip: tip, Err: putErr}
				}
			}
			return nil, &ConfigLogRefusal{Status: http.StatusServiceUnavailable, Tip: tip, Err: errors.New("the store never took the entry")}
		}()
		if self.barriers != nil {
			self.barriers.Hit("api.config.appended", barrierKey)
		}
		if err != nil {
			refusal := &ConfigLogRefusal{}
			if !errors.As(err, &refusal) {
				refusal = &ConfigLogRefusal{Status: http.StatusServiceUnavailable, Tip: tip, Err: err}
			}
			return nil, refusal
		}
		if landed != nil {
			return finish(landed)
		}
	}
	return nil, &ConfigLogRefusal{Status: http.StatusServiceUnavailable, Tip: configLog.log.Pin(), Err: errors.New("too many lost positions")}
}

// §7.9's statement row: the retry identity, then the verdict at the tip, then the append.
func (self *FakeApi) AppendStatement(ctx context.Context, networkId sidecar.Id, signed []byte) (*bridge.AuthPin, error) {
	return self.append(ctx, networkId, &fakeApiAppend{
		kind: bridge.AuthEntryKindStatement,
		body: signed,
		verify: func(configLog *fakeApiConfigLog) (*bridge.AuthPin, error) {
			verdict := configLog.log.Check(signed, self.clock.Now().UnixMilli())
			if pin, found := configLog.log.FindStatement(verdict.StatementId); found {
				return pin, nil
			}
			return nil, verdict.Refusal
		},
	})
}

// §7.9's base row: a retry of the same base answers its entry; else the verdict at the tip and the config head's
// descent from configPushes, the rows, then the entry, and for base 1 the genesis after it (plan-TEAM-genesis-custody).
// genesis is nil but for base 1.
func (self *FakeApi) AppendBase(ctx context.Context, networkId sidecar.Id, signedHeader []byte, rows []byte, genesis []byte, configPushes [][]byte) (*bridge.AuthPin, error) {
	signed := &bridge.Signed{}
	header := &bridge.ProjectionHeader{}
	if err := proto.Unmarshal(signedHeader, signed); err != nil {
		return nil, &ConfigLogRefusal{Status: http.StatusForbidden, Err: err}
	}
	if err := proto.Unmarshal(signed.GetBody(), header); err != nil {
		return nil, &ConfigLogRefusal{Status: http.StatusForbidden, Err: err}
	}
	if (header.GetVersion() == 1) != (genesis != nil) {
		return nil, &ConfigLogRefusal{Status: http.StatusForbidden, Err: errors.New("base 1 comes with its genesis, and no other base does")}
	}
	if genesis != nil {
		genesisChain := bridge.GenesisChain(genesis)
		if !bytes.Equal(header.GetPrevChain(), genesisChain[:]) {
			return nil, &ConfigLogRefusal{Status: http.StatusForbidden, Err: errors.New("base 1's prev_chain is not SHA-256 of its genesis")}
		}
	}
	bodyId := sha256.Sum256(signedHeader)
	request := &fakeApiAppend{
		kind:    bridge.AuthEntryKindBase,
		body:    signedHeader,
		genesis: genesis,
		verify: func(configLog *fakeApiConfigLog) (*bridge.AuthPin, error) {
			if pin := configLog.basePins[bodyId]; pin != nil {
				return pin, nil
			}
			if err := configLog.log.CheckBase(signedHeader, rows); err != nil {
				return nil, err
			}
			return nil, configLog.log.CheckConfigPushes(signedHeader, configPushes)
		},
		before: func(ctx context.Context, cluster sidecar.BlobCluster) error {
			rowsSha256 := sha256.Sum256(rows)
			_, err := sidecar.PutImmutable(ctx, cluster, sidecar.ConfigRowsKey(networkId, rowsSha256[:]), rows, nil)
			return err
		},
	}
	if genesis != nil {
		request.after = func(ctx context.Context, cluster sidecar.BlobCluster) error {
			_, err := sidecar.PutImmutable(ctx, cluster, sidecar.ConfigEntryKey(networkId, 0), genesis, nil)
			return err
		}
	}
	return self.append(ctx, networkId, request)
}

// §7.9's tick row: api's own facts, appended at most once a minute per network by its reaper and window (TEAM-M2-14's
// schedule), checked by readers by content.
func (self *FakeApi) AppendTick(ctx context.Context, networkId sidecar.Id, tick *bridge.ApiTick) (*bridge.AuthPin, error) {
	body, err := proto.MarshalOptions{Deterministic: true}.Marshal(tick)
	if err != nil {
		return nil, err
	}
	return self.append(ctx, networkId, &fakeApiAppend{kind: bridge.AuthEntryKindTick, body: body, verify: func(configLog *fakeApiConfigLog) (*bridge.AuthPin, error) {
		if configLog.log.State().Base() == nil {
			return nil, errors.New("no tick before base 1")
		}
		return nil, nil
	}})
}

// Appends an entry of any kind with any body, unverified, as a malicious sequencer does (FS-102, FS-124): readers
// refuse it at its position, or fork on a base that fails.
func (self *FakeApi) SequenceAnyway(ctx context.Context, networkId sidecar.Id, kind uint32, body []byte) (*bridge.AuthPin, error) {
	return self.append(ctx, networkId, &fakeApiAppend{kind: kind, body: body})
}

// Withholds the entry at n from every later read, as a server hiding it would: a read stops before it, so a reader
// that holds proof of it treats itself as withheld (§7.9's retain row).
func (self *FakeApi) DropEntry(networkId sidecar.Id, n uint64) {
	configLog := self.configLog(networkId)
	configLog.stateLock.Lock()
	defer configLog.stateLock.Unlock()
	configLog.dropped[n] = true
}

// The newest entry's pin as the store holds it, nil before base 1.
func (self *FakeApi) Tip(ctx context.Context, networkId sidecar.Id) (*bridge.AuthPin, error) {
	cluster, err := self.firstCluster()
	if err != nil {
		return nil, err
	}
	positions, _, err := self.listEntries(ctx, networkId, 0, 1<<30)
	if err != nil || len(positions) == 0 {
		return nil, err
	}
	n := positions[len(positions)-1]
	entryBytes, found, err := fakeApiGet(ctx, cluster, sidecar.ConfigEntryKey(networkId, n))
	if err != nil || !found {
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
	return &bridge.AuthPin{Version: n, Chain: chain[:]}, nil
}

// What GET /network/config/projection answers.
type FakeApiProjection struct {
	// The Signed Genesis, verbatim, when the read starts at 0.
	SignedGenesis []byte
	// The entries after the position asked, verbatim and in order, from the retention point when that position is
	// before it; at most a page.
	Entries [][]byte
	// The rows of each base among Entries, by rows_sha256.
	Rows map[[sha256.Size]byte][]byte
	// The store's newest entry, nil before base 1.
	Tip *bridge.AuthPin
	// More entries follow the last one.
	More bool
}

// Reads the log from the store: the entries after after, a page at most, withholding what DropEntry dropped, with the
// rows of their bases and, from 0, the genesis. ErrFakeApiGenesisMissing while entry 1 exists without entry 0.
func (self *FakeApi) ReadProjection(ctx context.Context, networkId sidecar.Id, after uint64, withRows bool) (*FakeApiProjection, error) {
	cluster, err := self.firstCluster()
	if err != nil {
		return nil, err
	}
	configLog := self.configLog(networkId)
	dropped := func() map[uint64]bool {
		configLog.stateLock.Lock()
		defer configLog.stateLock.Unlock()
		dropped := map[uint64]bool{}
		for n := range configLog.dropped {
			dropped[n] = true
		}
		return dropped
	}()
	read := &FakeApiProjection{Rows: map[[sha256.Size]byte][]byte{}}
	positions, more, err := self.listEntries(ctx, networkId, after, self.settings.ProjectionPageCount)
	if err != nil {
		return nil, err
	}
	read.More = more
	if after == 0 {
		signedGenesis, found, err := fakeApiGet(ctx, cluster, sidecar.ConfigEntryKey(networkId, 0))
		if err != nil {
			return nil, err
		}
		if !found && 0 < len(positions) {
			return nil, ErrFakeApiGenesisMissing
		}
		read.SignedGenesis = signedGenesis
	}
	for _, n := range positions {
		if dropped[n] {
			read.More = true
			break
		}
		entryBytes, found, err := fakeApiGet(ctx, cluster, sidecar.ConfigEntryKey(networkId, n))
		if err != nil {
			return nil, err
		}
		if !found {
			break
		}
		entry := &bridge.AuthEntry{}
		if err := proto.Unmarshal(entryBytes, entry); err != nil {
			return nil, err
		}
		chain, err := bridge.AuthChainDigest(entry.GetN(), entry.GetPrevChain(), entry.GetKind(), entry.GetTimeMs(), entry.GetBody())
		if err != nil {
			return nil, err
		}
		read.Entries = append(read.Entries, entryBytes)
		read.Tip = &bridge.AuthPin{Version: n, Chain: chain[:]}
		if withRows && entry.GetKind() == bridge.AuthEntryKindBase {
			signed := &bridge.Signed{}
			header := &bridge.ProjectionHeader{}
			if proto.Unmarshal(entry.GetBody(), signed) == nil && proto.Unmarshal(signed.GetBody(), header) == nil {
				rows, found, err := fakeApiGet(ctx, cluster, sidecar.ConfigRowsKey(networkId, header.GetRowsSha256()))
				if err != nil {
					return nil, err
				}
				if found {
					read.Rows[[sha256.Size]byte(header.GetRowsSha256())] = rows
				}
			}
		}
	}
	return read, nil
}

// Entry 1 exists and entry 0 does not yet: base 1's genesis step has not landed (plan-TEAM-genesis-custody #3, 503).
var ErrFakeApiGenesisMissing = errors.New("entry 1 exists without its genesis")

// The JSON shapes of §7.9's routes, which server's handlers answer alike (TEAM-M2-13, connect/api/bringyour.yml).
type fakeApiConfigPin struct {
	N     uint64 `json:"n"`
	Chain []byte `json:"chain"`
}

func fakeApiPinJson(pin *bridge.AuthPin) *fakeApiConfigPin {
	if pin == nil {
		return nil
	}
	return &fakeApiConfigPin{N: pin.GetVersion(), Chain: pin.GetChain()}
}

type fakeApiConfigDeltaArgs struct {
	Signed []byte `json:"signed"`
}

type fakeApiConfigProjectionPublishArgs struct {
	SignedHeader []byte   `json:"signed_header"`
	Rows         []byte   `json:"rows"`
	Genesis      []byte   `json:"genesis,omitempty"`
	ConfigPushes [][]byte `json:"config_pushes,omitempty"`
}

type fakeApiConfigProjectionResult struct {
	Genesis []byte            `json:"genesis,omitempty"`
	Entries [][]byte          `json:"entries"`
	Rows    [][]byte          `json:"rows"`
	Tip     *fakeApiConfigPin `json:"tip,omitempty"`
	More    bool              `json:"more"`
}

// The routes, on the api's mux.
func (self *FakeApi) addConfigRoutes() {
	self.mux.HandleFunc("POST /network/config/delta", self.handleConfigDelta)
	self.mux.HandleFunc("POST /network/config/projection", self.handleConfigProjectionPublish)
	self.mux.HandleFunc("GET /network/config/projection", self.handleConfigProjection)
}

// Whether the client's bound sidecar stands admitted at the network's tip, as api's admitted rule reads it.
func (self *FakeApi) admitted(ctx context.Context, client *fakeApiClient) bool {
	if client.sidecarId == (sidecar.Id{}) {
		return false
	}
	configLog := self.configLog(client.networkId)
	configLog.stateLock.Lock()
	defer configLog.stateLock.Unlock()
	log, err := configLog.loadWithLock(ctx, self, nil)
	if err != nil || log == nil {
		return false
	}
	row := log.State().SidecarRow(client.sidecarId)
	return row != nil && row.GetRevokedAt() == 0 && row.GetParkedAt() == 0
}

// Writes an append's failure as api answers it: 403 or 409 with the tip, 503 otherwise.
func fakeApiAppendFailure(writer http.ResponseWriter, err error) {
	refusal := &ConfigLogRefusal{}
	if !errors.As(err, &refusal) {
		fakeApiRefuse(writer, http.StatusServiceUnavailable, "unavailable", "The log is unavailable.", nil)
		return
	}
	extra := map[string]any{}
	if refusal.Tip != nil {
		extra["tip"] = fakeApiPinJson(refusal.Tip)
	}
	switch refusal.Status {
	case http.StatusForbidden:
		fakeApiRefuse(writer, refusal.Status, "config_refused", "The statement fails at the tip.", extra)
	case http.StatusConflict:
		fakeApiRefuse(writer, refusal.Status, "config_tip_moved", "The tip moved.", extra)
	default:
		fakeApiRefuse(writer, http.StatusServiceUnavailable, "unavailable", "The log is unavailable.", extra)
	}
}

// POST /network/config/delta {signed}: an admitted client's statement, or an unadmitted client's recovery-signed one.
func (self *FakeApi) handleConfigDelta(writer http.ResponseWriter, request *http.Request) {
	client := self.client(request)
	if client == nil {
		fakeApiRefuse(writer, http.StatusUnauthorized, "unauthorized", "Unauthorized.", nil)
		return
	}
	args := &fakeApiConfigDeltaArgs{}
	if !self.readJson(writer, request, args) {
		return
	}
	if !self.admitted(request.Context(), client) {
		signed := &bridge.Signed{}
		if proto.Unmarshal(args.Signed, signed) != nil || len(signed.GetSignerId()) != len(sidecar.Id{}) || len(signed.GetKeyId()) != sha256.Size {
			fakeApiRefuse(writer, http.StatusForbidden, "config_unadmitted", "An unadmitted client posts a recovery-signed statement only.", nil)
			return
		}
	}
	// what the log's rule cannot judge: a forwarding Delegation's host client (fake_api_forwarding.go)
	if err := self.checkForwardingHost(client.networkId, args.Signed); err != nil {
		fakeApiAppendFailure(writer, err)
		return
	}
	pin, err := self.AppendStatement(request.Context(), client.networkId, args.Signed)
	if err != nil {
		fakeApiAppendFailure(writer, err)
		return
	}
	fakeApiWriteJson(writer, http.StatusOK, fakeApiPinJson(pin))
}

// POST /network/config/projection {signed_header, rows, genesis?, config_pushes}: a config writer's base, its config
// head reached by walking config_pushes (plan-TEAM-api-config-head-reach).
func (self *FakeApi) handleConfigProjectionPublish(writer http.ResponseWriter, request *http.Request) {
	client := self.client(request)
	if client == nil {
		fakeApiRefuse(writer, http.StatusUnauthorized, "unauthorized", "Unauthorized.", nil)
		return
	}
	args := &fakeApiConfigProjectionPublishArgs{}
	if !self.readJson(writer, request, args) {
		return
	}
	if args.Genesis == nil && !self.admitted(request.Context(), client) {
		fakeApiRefuse(writer, http.StatusForbidden, "config_unadmitted", "An unadmitted client publishes no base.", nil)
		return
	}
	pin, err := self.AppendBase(request.Context(), client.networkId, args.SignedHeader, args.Rows, args.Genesis, args.ConfigPushes)
	if err != nil {
		fakeApiAppendFailure(writer, err)
		return
	}
	fakeApiWriteJson(writer, http.StatusOK, fakeApiPinJson(pin))
}

// GET /network/config/projection?after=n: the entries after n, verified by the caller against its own pin.
func (self *FakeApi) handleConfigProjection(writer http.ResponseWriter, request *http.Request) {
	client := self.client(request)
	if client == nil {
		fakeApiRefuse(writer, http.StatusUnauthorized, "unauthorized", "Unauthorized.", nil)
		return
	}
	after := uint64(0)
	if value := request.URL.Query().Get("after"); value != "" {
		parsed, err := strconv.ParseUint(value, 10, 64)
		if err != nil {
			fakeApiRefuse(writer, http.StatusBadRequest, "bad_request", "after is a position.", nil)
			return
		}
		after = parsed
	}
	read, err := self.ReadProjection(request.Context(), client.networkId, after, true)
	if errors.Is(err, ErrFakeApiGenesisMissing) {
		fakeApiRefuse(writer, http.StatusServiceUnavailable, "unavailable", "The log's genesis is not written yet.", nil)
		return
	}
	if err != nil {
		fakeApiRefuse(writer, http.StatusServiceUnavailable, "unavailable", "The log is unavailable.", nil)
		return
	}
	result := &fakeApiConfigProjectionResult{
		Genesis: read.SignedGenesis,
		Entries: read.Entries,
		Rows:    [][]byte{},
		Tip:     fakeApiPinJson(read.Tip),
		More:    read.More,
	}
	if result.Entries == nil {
		result.Entries = [][]byte{}
	}
	rowsShas := make([][sha256.Size]byte, 0, len(read.Rows))
	for rowsSha256 := range read.Rows {
		rowsShas = append(rowsShas, rowsSha256)
	}
	slices.SortFunc(rowsShas, func(a [sha256.Size]byte, b [sha256.Size]byte) int { return bytes.Compare(a[:], b[:]) })
	for _, rowsSha256 := range rowsShas {
		result.Rows = append(result.Rows, read.Rows[rowsSha256])
	}
	fakeApiWriteJson(writer, http.StatusOK, result)
}
