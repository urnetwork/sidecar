// T2's certs world: CertsStore as network_tls_cert in memory, until TLS-M5-16's model.NewCertsStore, and
// the Go twins of certsservice's budget scripts for FakeRedis. Store calls go through hostCall, so a plan
// under FaultOpHost with the key "certs.<Method>" reaches them, and each is counted. Safe for concurrent
// use.
//
// The twins keep a budget key as a hash of member to score where Redis keeps a sorted set: what a script
// answers is the same, which is all a twin promises, and T3 runs the real Lua (fake_redis_script.go).

package sidecartest

import (
	"bytes"
	"context"
	"errors"
	"maps"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/certsservice"
)

var _ certsservice.CertsStore = (*FakeCertsStore)(nil)

// network_tls_cert and network_client_owner's ephemeral flag, in memory.
type FakeCertsStore struct {
	faults *FaultQueue

	stateLock        sync.Mutex
	rows             map[sidecar.Id]*sidecar.TlsCertRecord
	ephemeralClients map[sidecar.Id]bool
	opCounts         map[string]int
}

// A nil faults takes a fresh queue.
func NewFakeCertsStore(faults *FaultQueue) *FakeCertsStore {
	if faults == nil {
		faults = NewFaultQueue()
	}
	return &FakeCertsStore{
		faults:           faults,
		rows:             map[sidecar.Id]*sidecar.TlsCertRecord{},
		ephemeralClients: map[sidecar.Id]bool{},
		opCounts:         map[string]int{},
	}
}

// One call through the fake's fault and count, under its lock.
func (self *FakeCertsStore) call(ctx context.Context, method string, serve func() error) error {
	return hostCall(ctx, self.faults, "certs."+method, func() error {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.opCounts[method] += 1
		return serve()
	})
}

// A copy that shares no slice with the original.
func certsFakeCopy(row *sidecar.TlsCertRecord) *sidecar.TlsCertRecord {
	copied := *row
	copied.IdentifierSetSha256 = bytes.Clone(row.IdentifierSetSha256)
	copied.SpkiSha256 = bytes.Clone(row.SpkiSha256)
	copied.Attestation = bytes.Clone(row.Attestation)
	copied.Csr = bytes.Clone(row.Csr)
	if row.Chain != nil {
		copied.Chain = make([][]byte, 0, len(row.Chain))
		for _, certificate := range row.Chain {
			copied.Chain = append(copied.Chain, bytes.Clone(certificate))
		}
	}
	return &copied
}

// An id's millisecond timestamp, a row's order time.
func certsFakeIdTime(id sidecar.Id) time.Time {
	var ms uint64
	for index := range 6 {
		ms = ms<<8 | uint64(id[index])
	}
	return time.UnixMilli(int64(ms)).UTC()
}

// A random id whose timestamp is at, as certs mints a cert_id on its own clock.
func CertsIdAt(at time.Time) sidecar.Id {
	id := sidecar.NewId()
	ms := uint64(at.UnixMilli())
	for index := range 6 {
		id[index] = byte(ms >> (8 * (5 - index)))
	}
	return id
}

// The rows in id order, as copies, that keep holds.
func (self *FakeCertsStore) sortedWithLock(keep func(row *sidecar.TlsCertRecord) bool) []*sidecar.TlsCertRecord {
	rows := []*sidecar.TlsCertRecord{}
	for _, row := range self.rows {
		if keep(row) {
			rows = append(rows, certsFakeCopy(row))
		}
	}
	slices.SortFunc(rows, func(a *sidecar.TlsCertRecord, b *sidecar.TlsCertRecord) int { return a.CertId.Cmp(b.CertId) })
	return rows
}

func certsFakeInFlight(row *sidecar.TlsCertRecord) bool {
	return row.State == sidecar.TlsCertStateOrdering || row.State == sidecar.TlsCertStateWaitingDns
}

func (self *FakeCertsStore) InsertCert(ctx context.Context, row *sidecar.TlsCertRecord) error {
	return self.call(ctx, "InsertCert", func() error {
		if _, exists := self.rows[row.CertId]; exists {
			return certsservice.ErrCertsConflict
		}
		self.rows[row.CertId] = certsFakeCopy(row)
		return nil
	})
}

func (self *FakeCertsStore) GetCert(ctx context.Context, certId sidecar.Id) (row *sidecar.TlsCertRecord, err error) {
	err = self.call(ctx, "GetCert", func() error {
		stored, ok := self.rows[certId]
		if !ok {
			return certsservice.ErrCertsNotFound
		}
		row = certsFakeCopy(stored)
		return nil
	})
	return
}

func (self *FakeCertsStore) ListNetworkCerts(ctx context.Context, networkId sidecar.Id) (rows []*sidecar.TlsCertRecord, err error) {
	err = self.call(ctx, "ListNetworkCerts", func() error {
		rows = self.sortedWithLock(func(row *sidecar.TlsCertRecord) bool { return row.NetworkId == networkId })
		return nil
	})
	return
}

func (self *FakeCertsStore) FindOpenOrder(ctx context.Context, networkId sidecar.Id, sidecarId sidecar.Id, spkiSha256 []byte, identifierSetSha256 []byte) (found *sidecar.TlsCertRecord, err error) {
	err = self.call(ctx, "FindOpenOrder", func() error {
		rows := self.sortedWithLock(func(row *sidecar.TlsCertRecord) bool {
			open := row.State == sidecar.TlsCertStateQueued || certsFakeInFlight(row)
			return open && row.NetworkId == networkId && row.SidecarId == sidecarId &&
				bytes.Equal(row.SpkiSha256, spkiSha256) && bytes.Equal(row.IdentifierSetSha256, identifierSetSha256)
		})
		if 0 < len(rows) {
			found = rows[len(rows)-1]
		}
		return nil
	})
	return
}

func (self *FakeCertsStore) FindLiveCertBySerial(ctx context.Context, networkId sidecar.Id, serial string, now time.Time) (found *sidecar.TlsCertRecord, err error) {
	err = self.call(ctx, "FindLiveCertBySerial", func() error {
		rows := self.sortedWithLock(func(row *sidecar.TlsCertRecord) bool {
			return row.NetworkId == networkId && serial != "" && row.Serial == serial &&
				row.State == sidecar.TlsCertStateIssued && now.Before(row.NotAfter)
		})
		if 0 < len(rows) {
			found = rows[len(rows)-1]
		}
		return nil
	})
	return
}

func (self *FakeCertsStore) GetPredecessor(ctx context.Context, certId sidecar.Id) (found *sidecar.TlsCertRecord, err error) {
	err = self.call(ctx, "GetPredecessor", func() error {
		rows := self.sortedWithLock(func(row *sidecar.TlsCertRecord) bool { return row.SuccessorCertId == certId })
		if 0 < len(rows) {
			found = rows[0]
		}
		return nil
	})
	return
}

// Whether a row of the set older than beforeCertId has a serial.
func (self *FakeCertsStore) setIssuedBeforeWithLock(identifierSetSha256 []byte, beforeCertId sidecar.Id) bool {
	for _, row := range self.rows {
		if bytes.Equal(row.IdentifierSetSha256, identifierSetSha256) && row.Serial != "" && row.CertId.Cmp(beforeCertId) < 0 {
			return true
		}
	}
	return false
}

func (self *FakeCertsStore) SetIssuedBefore(ctx context.Context, identifierSetSha256 []byte, beforeCertId sidecar.Id) (issued bool, err error) {
	err = self.call(ctx, "SetIssuedBefore", func() error {
		issued = self.setIssuedBeforeWithLock(identifierSetSha256, beforeCertId)
		return nil
	})
	return
}

func (self *FakeCertsStore) ListSetOrders(ctx context.Context, identifierSetSha256 []byte, ca certsservice.CertsCa, since time.Time) (rows []*sidecar.TlsCertRecord, err error) {
	err = self.call(ctx, "ListSetOrders", func() error {
		rows = self.sortedWithLock(func(row *sidecar.TlsCertRecord) bool {
			return bytes.Equal(row.IdentifierSetSha256, identifierSetSha256) && row.Ca == string(ca) &&
				!certsFakeIdTime(row.CertId).Before(since)
		})
		return nil
	})
	return
}

func (self *FakeCertsStore) ListNewSetOrders(ctx context.Context, ca certsservice.CertsCa, since time.Time) (rows []*sidecar.TlsCertRecord, err error) {
	err = self.call(ctx, "ListNewSetOrders", func() error {
		rows = self.sortedWithLock(func(row *sidecar.TlsCertRecord) bool {
			if row.Ca != string(ca) {
				return false
			}
			counted := certsFakeInFlight(row) || (row.Serial != "" && !row.NotBefore.IsZero() && !row.NotBefore.Before(since))
			return counted && !self.setIssuedBeforeWithLock(row.IdentifierSetSha256, row.CertId)
		})
		return nil
	})
	return
}

func (self *FakeCertsStore) ClientEphemeral(ctx context.Context, clientId sidecar.Id) (ephemeral bool, err error) {
	err = self.call(ctx, "ClientEphemeral", func() error {
		ephemeral = self.ephemeralClients[clientId]
		return nil
	})
	return
}

func (self *FakeCertsStore) ListQueued(ctx context.Context, afterCertId sidecar.Id, count int) (rows []*sidecar.TlsCertRecord, err error) {
	err = self.call(ctx, "ListQueued", func() error {
		rows = self.sortedWithLock(func(row *sidecar.TlsCertRecord) bool {
			return row.State == sidecar.TlsCertStateQueued && 0 < row.CertId.Cmp(afterCertId)
		})
		if count < len(rows) {
			rows = rows[:count]
		}
		return nil
	})
	return
}

func (self *FakeCertsStore) ListInStates(ctx context.Context, states []sidecar.TlsCertState, afterCertId sidecar.Id, count int) (rows []*sidecar.TlsCertRecord, err error) {
	err = self.call(ctx, "ListInStates", func() error {
		rows = []*sidecar.TlsCertRecord{}
		if count <= 0 {
			return nil
		}
		rows = self.sortedWithLock(func(row *sidecar.TlsCertRecord) bool {
			return slices.Contains(states, row.State) && 0 < row.CertId.Cmp(afterCertId)
		})
		if count < len(rows) {
			rows = rows[:count]
		}
		return nil
	})
	return
}

func (self *FakeCertsStore) TransitionCert(ctx context.Context, transition *certsservice.CertsTransition) (applied bool, err error) {
	err = self.call(ctx, "TransitionCert", func() error {
		row, ok := self.rows[transition.CertId]
		if !ok || !slices.Contains(transition.From, row.State) {
			return nil
		}
		row.State = transition.To
		if transition.Ca != "" {
			row.Ca = string(transition.Ca)
		}
		if transition.AccountUri != "" {
			row.AccountUri = transition.AccountUri
		}
		if transition.Profile != "" {
			row.Profile = transition.Profile
		}
		if transition.Serial != "" {
			row.Serial = transition.Serial
		}
		if !transition.NotBefore.IsZero() {
			row.NotBefore = transition.NotBefore
		}
		if !transition.NotAfter.IsZero() {
			row.NotAfter = transition.NotAfter
		}
		if !transition.AriWindowStart.IsZero() {
			row.AriWindowStart = transition.AriWindowStart
		}
		if !transition.AriWindowEnd.IsZero() {
			row.AriWindowEnd = transition.AriWindowEnd
		}
		applied = true
		return nil
	})
	return
}

func (self *FakeCertsStore) SetSuccessor(ctx context.Context, certId sidecar.Id, successorCertId sidecar.Id) (linked bool, err error) {
	err = self.call(ctx, "SetSuccessor", func() error {
		row, ok := self.rows[certId]
		if !ok {
			return certsservice.ErrCertsNotFound
		}
		if row.SuccessorCertId != (sidecar.Id{}) {
			return nil
		}
		row.SuccessorCertId = successorCertId
		linked = true
		return nil
	})
	return
}

func (self *FakeCertsStore) PurgeEnded(ctx context.Context, before time.Time) (removedCount int, err error) {
	err = self.call(ctx, "PurgeEnded", func() error {
		for certId, row := range self.rows {
			if !row.NotAfter.IsZero() && row.NotAfter.Before(before) {
				delete(self.rows, certId)
				removedCount += 1
			}
		}
		return nil
	})
	return
}

// Marks clientId as an ephemeral sidecar's, as network_client_owner.ephemeral does.
func (self *FakeCertsStore) SetClientEphemeral(clientId sidecar.Id) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.ephemeralClients[clientId] = true
}

// Every row, in id order, as copies.
func (self *FakeCertsStore) Rows() []*sidecar.TlsCertRecord {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.sortedWithLock(func(row *sidecar.TlsCertRecord) bool { return true })
}

// How often each method ran, by its name.
func (self *FakeCertsStore) OpCounts() map[string]int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return maps.Clone(self.opCounts)
}

// Binds the Go twins of certsservice's budget scripts to redis.
func RegisterCertsBudgetTwins(redis *FakeRedis) {
	redis.RegisterScript(certsservice.CertsBudgetSpendScript.Name, certsBudgetSpendTwin)
	redis.RegisterScript(certsservice.CertsBudgetSeedScript.Name, certsBudgetSeedTwin)
}

// What Lua's tonumber of a malformed ARGV leads Redis to answer.
var errCertsBudgetTwinArgs = errors.New("ERR value is not an integer or out of range")

// certs_budget_spend: 1 spent or spent already, 0 full, -1 no marker.
func certsBudgetSpendTwin(call *FakeRedisScriptCall) (*sidecar.RedisReply, error) {
	key := call.Keys[0]
	members, err := call.HashGetAll(key)
	if err != nil {
		return nil, err
	}
	if _, seeded := members[certsservice.CertsBudgetMarker]; !seeded {
		return RedisIntegerReply(-1), nil
	}
	now, nowErr := strconv.ParseInt(call.Args[0], 10, 64)
	window, windowErr := strconv.ParseInt(call.Args[1], 10, 64)
	budgetCap, capErr := strconv.ParseInt(call.Args[2], 10, 64)
	member := call.Args[3]
	ttl, ttlErr := strconv.ParseInt(call.Args[4], 10, 64)
	if nowErr != nil || windowErr != nil || capErr != nil || ttlErr != nil {
		return nil, errCertsBudgetTwinArgs
	}
	stale := []string{}
	for candidate, scoreBytes := range members {
		score, _ := strconv.ParseInt(string(scoreBytes), 10, 64)
		// ZREMRANGEBYSCORE (0 (now-window: the marker's 0 stays
		if 0 < score && score < now-window {
			stale = append(stale, candidate)
		}
	}
	if 0 < len(stale) {
		if err := call.HashDelete(key, stale); err != nil {
			return nil, err
		}
		for _, candidate := range stale {
			delete(members, candidate)
		}
	}
	if _, spent := members[member]; spent {
		return RedisIntegerReply(1), nil
	}
	if budgetCap <= int64(len(members)-1) {
		return RedisIntegerReply(0), nil
	}
	if err := call.HashSet(key, map[string][]byte{member: []byte(strconv.FormatInt(now, 10))}); err != nil {
		return nil, err
	}
	if _, err := call.Expire(key, time.Duration(ttl)*time.Millisecond); err != nil {
		return nil, err
	}
	return RedisIntegerReply(1), nil
}

// certs_budget_seed: writes the marker and the entries unless the key exists.
func certsBudgetSeedTwin(call *FakeRedisScriptCall) (*sidecar.RedisReply, error) {
	key := call.Keys[0]
	members, err := call.HashGetAll(key)
	if err != nil {
		return nil, err
	}
	if 0 < len(members) {
		return RedisIntegerReply(0), nil
	}
	ttl, err := strconv.ParseInt(call.Args[0], 10, 64)
	if err != nil {
		return nil, err
	}
	fieldValues := map[string][]byte{certsservice.CertsBudgetMarker: []byte("0")}
	for index := 1; index+1 < len(call.Args); index += 2 {
		fieldValues[call.Args[index+1]] = []byte(call.Args[index])
	}
	if err := call.HashSet(key, fieldValues); err != nil {
		return nil, err
	}
	if _, err := call.Expire(key, time.Duration(ttl)*time.Millisecond); err != nil {
		return nil, err
	}
	return RedisIntegerReply(1), nil
}

// The members of a budget key a twin wrote, marker included, for a test's look: member to score in ms.
func CertsBudgetMembers(ctx context.Context, redis *FakeRedis, key string) (map[string]int64, error) {
	fieldValues, err := redis.HashGetAll(InspectContext(ctx), key)
	if err != nil {
		return nil, err
	}
	members := map[string]int64{}
	for member, scoreBytes := range fieldValues {
		score, _ := strconv.ParseInt(string(scoreBytes), 10, 64)
		members[member] = score
	}
	return members, nil
}
