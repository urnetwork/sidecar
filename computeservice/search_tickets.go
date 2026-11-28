// {cmpa}, the open search admissions (DESIGN-COMPUTE §21.5's No shared key and Retries, §14.4, D-SRCH-12, compute-10;
// SRCH-M13-07, SRCH-M13-08): on the admissions instance alone (ComputeEngineDeps.AdmissionsRedis), a Redis of its own
// with persistence off and outside every backup, which the engine checks before it admits a search. Its keys, each
// under the one tag {cmpa}, each a string a single command reads or writes, so every step is one of the interface's
// own atomic operations and none crosses a slot:
//
//	{cmpa}t<ticket>  the 32 random bytes the broker drew for one authorization, in hex, to its record: pending while
//	                 its hold and limits are taken, admitted once they are, then, at the signer's report, only the
//	                 answer the broker gave, with no network, for AnswerLife
//	{cmpa}r<index>   the admission's index, the first 16 bytes of SHA-256 over the network, request id and attempt, to
//	                 its ticket, so a retry of one request id and attempt finds its ticket and asks the signer again with
//	                 it rather than holding or signing anew; dropped at the answer
//	{cmpa}lease      which broker instance pulls the signer's reports (search_reports.go)
//
// A pending or admitted record holds the network, sidecar and agent, the request id and attempt, the operation key, the
// hold, the admitted amount and the authorization's minute: never a payee, a nonce, a query or a transaction. A pending
// claim lives PendingClaimTtl; an admitted one TicketReportGrace past its authorization's window, an unreported
// admission's whole life; an answer AnswerLife after it was given. The ticket lives only here and in the signer's own
// memory, so a join of a search's payment to its network takes both services' memory within that time (§21.5).
//
// Every write that must not lose a race is a compare: a claim is SetIfAbsent, an admission and an answer
// CompareAndSet over the record that stood, an index's drop CompareAndDelete over the ticket it names, so two broker
// instances, or a report and an expiry, never undo each other. Safe for concurrent use.

package computeservice

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// The keys' parts and the record's format: identifiers.
const (
	computeSearchTicketKeyPart = "t"
	computeSearchIndexKeyPart  = "r"
	computeSearchLeaseKeyPart  = "lease"
	computeSearchIndexDomain   = "ur compute search admission v1"
	// The index keeps 16 of SHA-256's bytes: a collision of two admissions would need 2^64 of them.
	computeSearchIndexByteCount = 16
	computeSearchRecordVersion  = 1
)

// A record's state.
type computeSearchTicketState byte

const (
	computeSearchTicketPending  computeSearchTicketState = 1
	computeSearchTicketAdmitted computeSearchTicketState = 2
	computeSearchTicketAnswered computeSearchTicketState = 3
)

// A record that is no record of this format.
var errComputeSearchRecord = errors.New("compute search: a {cmpa} record that does not read")

// One admission's record in {cmpa}.
type computeSearchTicketRecord struct {
	state computeSearchTicketState
	// pending and admitted
	networkId  sidecar.Id
	sidecarId  sidecar.Id
	agentId    *sidecar.Id
	requestId  sidecar.Id
	attempt    uint16
	opKey      sidecar.Id
	hold       int64
	amount     uint64
	minuteUnix int64
	// answered
	answer protocol.SearchReportAnswer
}

// The record in another state, a copy.
func (self *computeSearchTicketRecord) in(state computeSearchTicketState) *computeSearchTicketRecord {
	copied := *self
	copied.state = state
	return &copied
}

// The record's bytes: version, state, then an answer's one byte, or the admission's fields at fixed widths.
func (self *computeSearchTicketRecord) bytes() []byte {
	data := []byte{computeSearchRecordVersion, byte(self.state)}
	if self.state == computeSearchTicketAnswered {
		return append(data, byte(self.answer))
	}
	data = append(data, self.networkId[:]...)
	data = append(data, self.sidecarId[:]...)
	data = append(data, self.requestId[:]...)
	data = append(data, self.opKey[:]...)
	if self.agentId != nil {
		data = append(data, 1)
		data = append(data, self.agentId[:]...)
	} else {
		data = append(data, 0)
	}
	data = binary.BigEndian.AppendUint16(data, self.attempt)
	data = binary.BigEndian.AppendUint64(data, uint64(self.hold))
	data = binary.BigEndian.AppendUint64(data, self.amount)
	return binary.BigEndian.AppendUint64(data, uint64(self.minuteUnix))
}

// A record from its bytes, errComputeSearchRecord for anything else.
func parseComputeSearchTicketRecord(data []byte) (*computeSearchTicketRecord, error) {
	if len(data) < 3 || data[0] != computeSearchRecordVersion {
		return nil, errComputeSearchRecord
	}
	record := &computeSearchTicketRecord{state: computeSearchTicketState(data[1])}
	switch record.state {
	case computeSearchTicketAnswered:
		if len(data) != 3 {
			return nil, errComputeSearchRecord
		}
		record.answer = protocol.SearchReportAnswer(data[2])
		switch record.answer {
		case protocol.SearchReportAnswer_SEARCH_REPORT_ANSWER_CHARGED, protocol.SearchReportAnswer_SEARCH_REPORT_ANSWER_RELEASED,
			protocol.SearchReportAnswer_SEARCH_REPORT_ANSWER_UNKNOWN:
			return record, nil
		}
		return nil, errComputeSearchRecord
	case computeSearchTicketPending, computeSearchTicketAdmitted:
	default:
		return nil, errComputeSearchRecord
	}
	rest := data[2:]
	take := func(count int) []byte {
		if len(rest) < count {
			return nil
		}
		taken := rest[:count]
		rest = rest[count:]
		return taken
	}
	for _, id := range []*sidecar.Id{&record.networkId, &record.sidecarId, &record.requestId, &record.opKey} {
		taken := take(len(sidecar.Id{}))
		if taken == nil {
			return nil, errComputeSearchRecord
		}
		copy(id[:], taken)
	}
	flag := take(1)
	if flag == nil || 1 < flag[0] {
		return nil, errComputeSearchRecord
	}
	if flag[0] == 1 {
		taken := take(len(sidecar.Id{}))
		if taken == nil {
			return nil, errComputeSearchRecord
		}
		agentId := sidecar.Id{}
		copy(agentId[:], taken)
		record.agentId = &agentId
	}
	fixed := take(2 + 8 + 8 + 8)
	if fixed == nil || len(rest) != 0 {
		return nil, errComputeSearchRecord
	}
	record.attempt = binary.BigEndian.Uint16(fixed[0:2])
	record.hold = int64(binary.BigEndian.Uint64(fixed[2:10]))
	record.amount = binary.BigEndian.Uint64(fixed[10:18])
	record.minuteUnix = int64(binary.BigEndian.Uint64(fixed[18:26]))
	if record.hold < 0 {
		return nil, errComputeSearchRecord
	}
	return record, nil
}

// A ticket's key.
func computeSearchTicketKey(ticket []byte) string {
	return ComputeSearchAdmissionsRedisKey() + computeSearchTicketKeyPart + hex.EncodeToString(ticket)
}

// An admission's index key: of its network, request id and attempt.
func computeSearchIndexKey(networkId sidecar.Id, requestId sidecar.Id, attempt uint16) string {
	hash := sha256.New()
	hash.Write([]byte(computeSearchIndexDomain))
	hash.Write([]byte{0})
	hash.Write(networkId[:])
	hash.Write(requestId[:])
	hash.Write(binary.BigEndian.AppendUint16(nil, attempt))
	return ComputeSearchAdmissionsRedisKey() + computeSearchIndexKeyPart + hex.EncodeToString(hash.Sum(nil)[:computeSearchIndexByteCount])
}

// The report loop's lease key.
func computeSearchLeaseKey() string {
	return ComputeSearchAdmissionsRedisKey() + computeSearchLeaseKeyPart
}

// {cmpa} for one engine. Safe for concurrent use.
type computeSearchTickets struct {
	engine   *ComputeEngine
	settings *ComputeSearchSettings
}

// The admissions instance for key, refusing any other family.
func (self *computeSearchTickets) redis(key string) (sidecar.Redis, error) {
	return self.engine.AdmissionsRedis(key)
}

// A fresh ticket.
func (self *computeSearchTickets) draw() ([]byte, error) {
	ticket := make([]byte, self.settings.TicketByteCount)
	if _, err := rand.Read(ticket); err != nil {
		return nil, err
	}
	return ticket, nil
}

// The life of an admission timed to minuteUnix, from now: its window's end plus TicketReportGrace, at least a
// millisecond.
func (self *computeSearchTickets) admittedTtl(minuteUnix int64, now time.Time) time.Duration {
	windowEnd := time.Unix(minuteUnix, 0).Add(self.settings.webSearch().WindowAfter)
	return max(time.Millisecond, windowEnd.Add(self.settings.TicketReportGrace).Sub(now))
}

// What a claim found.
type computeSearchClaim struct {
	// true where this admission claimed the index for its own ticket; false where another holds it, whose ticket and
	// record follow, the record nil for one claimed so recently its record is not yet readable.
	claimed bool
	ticket  []byte
	record  *computeSearchTicketRecord
}

// Claims record's index for a fresh ticket, pending: claimed, or the ticket and record of the admission that holds it.
// An index whose ticket's record has expired is taken over, so a broker stopped mid-admission blocks nothing past
// its claim's life.
func (self *computeSearchTickets) claim(ctx context.Context, record *computeSearchTicketRecord) (*computeSearchClaim, error) {
	ticket, err := self.draw()
	if err != nil {
		return nil, err
	}
	ticketKey := computeSearchTicketKey(ticket)
	indexKey := computeSearchIndexKey(record.networkId, record.requestId, record.attempt)
	redis, err := self.redis(ticketKey)
	if err != nil {
		return nil, err
	}
	pending := record.in(computeSearchTicketPending)
	if err := redis.Set(ctx, ticketKey, pending.bytes(), self.settings.PendingClaimTtl); err != nil {
		return nil, err
	}
	unclaimed := func(claim *computeSearchClaim, err error) (*computeSearchClaim, error) {
		// this admission's own pending record goes: another holds the index, or the claim could not tell
		redis.Delete(ctx, []string{ticketKey})
		return claim, err
	}
	set, err := redis.SetIfAbsent(ctx, indexKey, ticket, self.settings.PendingClaimTtl)
	if err != nil {
		return unclaimed(nil, err)
	}
	if set {
		return &computeSearchClaim{claimed: true, ticket: ticket, record: pending}, nil
	}
	standingTicket, found, err := redis.Get(ctx, indexKey)
	if err != nil {
		return unclaimed(nil, err)
	}
	if !found {
		// the index lapsed between the two reads: the claim is open again
		if set, err := redis.SetIfAbsent(ctx, indexKey, ticket, self.settings.PendingClaimTtl); err != nil || set {
			if err != nil {
				return unclaimed(nil, err)
			}
			return &computeSearchClaim{claimed: true, ticket: ticket, record: pending}, nil
		}
		return unclaimed(&computeSearchClaim{}, nil)
	}
	standing, err := self.read(ctx, standingTicket)
	if err != nil {
		return unclaimed(nil, err)
	}
	if standing == nil {
		// the index names a ticket whose record expired: taken over, unless another took it first
		taken, err := redis.CompareAndSet(ctx, indexKey, standingTicket, ticket, self.settings.PendingClaimTtl)
		if err != nil {
			return unclaimed(nil, err)
		}
		if taken {
			return &computeSearchClaim{claimed: true, ticket: ticket, record: pending}, nil
		}
		return unclaimed(&computeSearchClaim{}, nil)
	}
	return unclaimed(&computeSearchClaim{ticket: standingTicket, record: standing}, nil)
}

// Moves ticket's pending record to admitted, its index with it, for their admitted life. false where the claim was
// lost: its pending record or its index is gone or names another, which the caller answers as capacity after undoing
// what it took.
func (self *computeSearchTickets) admit(ctx context.Context, ticket []byte, pending *computeSearchTicketRecord, now time.Time) (bool, error) {
	ticketKey := computeSearchTicketKey(ticket)
	indexKey := computeSearchIndexKey(pending.networkId, pending.requestId, pending.attempt)
	redis, err := self.redis(ticketKey)
	if err != nil {
		return false, err
	}
	ttl := self.admittedTtl(pending.minuteUnix, now)
	admitted, err := redis.CompareAndSet(ctx, ticketKey, pending.in(computeSearchTicketPending).bytes(), pending.in(computeSearchTicketAdmitted).bytes(), ttl)
	if err != nil || !admitted {
		return false, err
	}
	return redis.CompareAndSet(ctx, indexKey, ticket, ticket, ttl)
}

// Drops ticket's record and, where it still names ticket, record's index: an admission refused, or one whose claim
// was lost.
func (self *computeSearchTickets) drop(ctx context.Context, ticket []byte, record *computeSearchTicketRecord) error {
	ticketKey := computeSearchTicketKey(ticket)
	redis, err := self.redis(ticketKey)
	if err != nil {
		return err
	}
	if err := redis.Delete(ctx, []string{ticketKey}); err != nil {
		return err
	}
	_, err = redis.CompareAndDelete(ctx, computeSearchIndexKey(record.networkId, record.requestId, record.attempt), ticket)
	return err
}

// ticket's record, nil where none stands.
func (self *computeSearchTickets) read(ctx context.Context, ticket []byte) (*computeSearchTicketRecord, error) {
	ticketKey := computeSearchTicketKey(ticket)
	redis, err := self.redis(ticketKey)
	if err != nil {
		return nil, err
	}
	data, found, err := redis.Get(ctx, ticketKey)
	if err != nil || !found {
		return nil, err
	}
	return parseComputeSearchTicketRecord(data)
}

// Keeps answer as ticket's, with no network, for AnswerLife, in place of standing, the record the caller read (nil
// for none): the answer that stands, and whether this call gave it. An answer given first, by another pull or another
// instance, stands and comes back instead. standing's index goes where it still names ticket.
func (self *computeSearchTickets) answer(ctx context.Context, ticket []byte, standing *computeSearchTicketRecord, answer protocol.SearchReportAnswer) (protocol.SearchReportAnswer, bool, error) {
	ticketKey := computeSearchTicketKey(ticket)
	redis, err := self.redis(ticketKey)
	if err != nil {
		return 0, false, err
	}
	answered := &computeSearchTicketRecord{state: computeSearchTicketAnswered, answer: answer}
	var set bool
	if standing == nil {
		set, err = redis.SetIfAbsent(ctx, ticketKey, answered.bytes(), self.settings.AnswerLife)
	} else if standing.state == computeSearchTicketAnswered {
		return standing.answer, false, nil
	} else {
		set, err = redis.CompareAndSet(ctx, ticketKey, standing.bytes(), answered.bytes(), self.settings.AnswerLife)
	}
	if err != nil {
		return 0, false, err
	}
	if !set {
		// another answer, or a record that moved under this one: what stands now is the answer
		now, err := self.read(ctx, ticket)
		if err != nil {
			return 0, false, err
		}
		if now == nil || now.state != computeSearchTicketAnswered {
			return 0, false, errComputeSearchRecord
		}
		return now.answer, false, nil
	}
	if standing != nil {
		indexKey := computeSearchIndexKey(standing.networkId, standing.requestId, standing.attempt)
		if _, err := redis.CompareAndDelete(ctx, indexKey, ticket); err != nil {
			// the answer stands; the index lapses at its own ttl
			return answer, true, nil
		}
	}
	return answer, true, nil
}

// Takes or renews the report loop's lease for holder: true while held.
func (self *computeSearchTickets) lease(ctx context.Context, holder []byte) (bool, error) {
	leaseKey := computeSearchLeaseKey()
	redis, err := self.redis(leaseKey)
	if err != nil {
		return false, err
	}
	taken, err := redis.SetIfAbsent(ctx, leaseKey, holder, self.settings.ReportLeaseTtl)
	if err != nil || taken {
		return taken, err
	}
	return redis.CompareAndSet(ctx, leaseKey, holder, holder, self.settings.ReportLeaseTtl)
}

// Gives the lease up where holder holds it.
func (self *computeSearchTickets) unlease(ctx context.Context, holder []byte) error {
	leaseKey := computeSearchLeaseKey()
	redis, err := self.redis(leaseKey)
	if err != nil {
		return err
	}
	_, err = redis.CompareAndDelete(ctx, leaseKey, holder)
	return err
}
