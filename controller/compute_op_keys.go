// Operation keys (DESIGN-COMPUTE §9.6, §9.7, D-BAL-14; BAL-M12-03): every billable operation's key is its charge's
// charge_id, and its row fixes the charge's start_time, so every delivery of one operation meets one row and one
// partition. A call's key is 16 random bytes the broker draws at admission (ComputeOpKeyForCall), its time the hold's.
// Every other key is the UUIDv5 (RFC 9562 §5.5) of what the operation is, in one fixed namespace, so a repeat of the
// operation derives the same key:
//
//	search       network, request id and attempt, timed to the authorization's minute; no ticket, nonce or payee
//	             (§21.5), so two attempts in one minute are two keys
//	interval     an enclave's running time: enclave, incarnation and its number on the fixed 10-minute grid, timed
//	             to the grid's start
//	egress hour  an enclave's host egress: enclave, incarnation and its hour, timed to the hour's start
//	refund       the charge it returns, so one charge is refunded once; timed to its first booking, which its
//	             writer gives
//	adjustment   its support case and its number in the case
//
// A name is a domain word, a zero byte and the fields as fixed-width big-endian bytes, so no two kinds' names and no
// two values of one kind meet. The namespace and the layouts are identifiers: changing one changes every key, which
// would let an operation already booked be booked again, so they never change. A random key is a version-4 UUID and a
// derived one a version-5 UUID, so the two never meet.
//
// The grid and the hour are UTC-aligned and come from the settings (EnclaveInterval, EnclaveHostEgressInterval,
// OpMinuteGrain), and each counts from the Unix epoch, so a key and its time are a function of the instant alone.

package controller

import (
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	operator "github.com/urnetwork/operator-core"

	"github.com/urnetwork/sidecar/model"
)

// The operation keys' namespace: fixed, an identifier (D-BAL-14).
var computeOpKeyNamespace = operator.Id{
	0x21, 0x37, 0x0d, 0xd4, 0xf1, 0x73, 0x48, 0xb1, 0xa6, 0xfc, 0xb3, 0x51, 0xb6, 0xb5, 0x36, 0x8e,
}

// The domain words that start each kind's name.
const (
	computeOpKeyDomainSearch     = "search"
	computeOpKeyDomainInterval   = "enclave_run"
	computeOpKeyDomainEgressHour = "enclave_host_egress"
	computeOpKeyDomainRefund     = "refund"
	computeOpKeyDomainAdjustment = "adjustment"
)

// A key's input the derivation refuses: a time before the epoch, a negative number, a grid the settings do not give.
var ErrComputeOpKeyArgs = errors.New("compute op key: arguments refused")

// The UUIDv5 of name in namespace (RFC 9562 §5.5): SHA-1 over the namespace's bytes and the name's, its first 16
// bytes with the version and variant set.
func computeUuidV5(namespace operator.Id, name []byte) operator.Id {
	hash := sha1.New()
	hash.Write(namespace[:])
	hash.Write(name)
	sum := hash.Sum(nil)
	var id operator.Id
	copy(id[:], sum[:16])
	id[6] = (id[6] & 0x0f) | 0x50
	id[8] = (id[8] & 0x3f) | 0x80
	return id
}

// One kind's name: its domain word, a zero byte, then its fields.
func computeOpKeyName(domain string, fields ...[]byte) []byte {
	name := append([]byte(domain), 0)
	for _, field := range fields {
		name = append(name, field...)
	}
	return name
}

// A big-endian field.
func computeOpKeyUint64(value uint64) []byte {
	return binary.BigEndian.AppendUint64(nil, value)
}

// The index of the grid slot at falls in, counting slots of grain from the Unix epoch, and the slot's start.
func computeOpKeySlot(at time.Time, grain time.Duration) (int64, time.Time, error) {
	if grain <= 0 || grain%time.Second != 0 {
		return 0, time.Time{}, fmt.Errorf("%w: a grid of %v", ErrComputeOpKeyArgs, grain)
	}
	seconds := at.Unix()
	if seconds < 0 {
		return 0, time.Time{}, fmt.Errorf("%w: a time before the epoch", ErrComputeOpKeyArgs)
	}
	grainSeconds := int64(grain / time.Second)
	index := seconds / grainSeconds
	return index, time.Unix(index*grainSeconds, 0).UTC(), nil
}

// A call's key: 16 random bytes the broker draws at admission (§9.7), as a version-4 UUID, so it never meets a
// derived key.
func ComputeOpKeyForCall() (operator.Id, error) {
	var id operator.Id
	if _, err := rand.Read(id[:]); err != nil {
		return operator.Id{}, err
	}
	id[6] = (id[6] & 0x0f) | 0x40
	id[8] = (id[8] & 0x3f) | 0x80
	return id, nil
}

// A search's key and start (§21.5): of its network, request id and attempt, timed to the minute of authorizedAt. No
// ticket, nonce or payee enters it.
func ComputeOpKeyForSearch(settings *model.ComputeLedgerSettings, networkId operator.Id, requestId operator.Id, attempt int16, authorizedAt time.Time) (operator.Id, time.Time, error) {
	if attempt < 0 {
		return operator.Id{}, time.Time{}, fmt.Errorf("%w: a negative attempt", ErrComputeOpKeyArgs)
	}
	_, minute, err := computeOpKeySlot(authorizedAt, settings.OpMinuteGrain)
	if err != nil {
		return operator.Id{}, time.Time{}, err
	}
	name := computeOpKeyName(computeOpKeyDomainSearch, networkId[:], requestId[:], binary.BigEndian.AppendUint16(nil, uint16(attempt)))
	return computeUuidV5(computeOpKeyNamespace, name), minute, nil
}

// An enclave interval's key and start (§9.6, §9.7): of its enclave, incarnation and number on the fixed grid of the
// settings' EnclaveInterval, the slot at falls in, timed to the slot's start.
func ComputeOpKeyForInterval(settings *model.ComputeLedgerSettings, enclaveId operator.Id, incarnation int64, at time.Time) (operator.Id, time.Time, error) {
	if incarnation < 0 {
		return operator.Id{}, time.Time{}, fmt.Errorf("%w: a negative incarnation", ErrComputeOpKeyArgs)
	}
	number, start, err := computeOpKeySlot(at, settings.EnclaveInterval)
	if err != nil {
		return operator.Id{}, time.Time{}, err
	}
	name := computeOpKeyName(computeOpKeyDomainInterval, enclaveId[:], computeOpKeyUint64(uint64(incarnation)), computeOpKeyUint64(uint64(number)))
	return computeUuidV5(computeOpKeyNamespace, name), start, nil
}

// An enclave's host egress hour's key and start (§9.6): of its enclave, incarnation and the hour at falls in, timed to
// the hour's start.
func ComputeOpKeyForEgressHour(settings *model.ComputeLedgerSettings, enclaveId operator.Id, incarnation int64, at time.Time) (operator.Id, time.Time, error) {
	if incarnation < 0 {
		return operator.Id{}, time.Time{}, fmt.Errorf("%w: a negative incarnation", ErrComputeOpKeyArgs)
	}
	hour, start, err := computeOpKeySlot(at, settings.EnclaveHostEgressInterval)
	if err != nil {
		return operator.Id{}, time.Time{}, err
	}
	name := computeOpKeyName(computeOpKeyDomainEgressHour, enclaveId[:], computeOpKeyUint64(uint64(incarnation)), computeOpKeyUint64(uint64(hour)))
	return computeUuidV5(computeOpKeyNamespace, name), start, nil
}

// A refund's key (§9.6): of the charge it returns alone, so a retry, a dispute's refund racing an operator's, and a
// retry past UTC midnight all meet one row. Its time is its first booking's, which its row keeps.
func ComputeOpKeyForRefund(chargeId operator.Id) operator.Id {
	return computeUuidV5(computeOpKeyNamespace, computeOpKeyName(computeOpKeyDomainRefund, chargeId[:]))
}

// A support adjustment's key (§9.6): of its support case and its number in the case.
func ComputeOpKeyForAdjustment(caseId operator.Id, number uint32) operator.Id {
	return computeUuidV5(computeOpKeyNamespace, computeOpKeyName(computeOpKeyDomainAdjustment, caseId[:], binary.BigEndian.AppendUint32(nil, number)))
}
