// pendingStatements (CORE-M2-02, C-02): §5.9's "statements signed and not yet landed" in keychain.ur, and their posts
// to POST /network/config/delta (§7.9's statement row). A signed statement is kept before it is posted and dropped
// once api answers its entry or refuses it, so a kill, a lost answer or a 503 leaves it here, and
// PostPendingStatements posts the same bytes again until its not_after: api answers a retry of a statement it holds
// with that entry (§7.9's retry identity), and a statement past its not_after can no longer land, so it is dropped.
//
// Each record is the core namespace's pending/<statement id>, the id SHA-256 of the statement's signed bytes as §7.9
// names it, holding not_after_ms (8 bytes, big endian) then the marshalled Signed. A statement an act signed also has
// pending-act/<statement id>, written before it and removed after it: version 1, the act's 16-byte id, its index in
// the act (4 bytes, big endian), a kind byte, 0 for a plain statement and 1 for §7.10's stale revocation, which then
// adds its Worker's and member's ids. PostPendingStatements posts an act's statements in act order, a stale revocation
// re-checked first (identity_act_stale.go), and a statement kept alone in id order. Nothing here creates or unwraps a
// key.
//
// On every leg: root Id, no connect type.

package sidecar

import (
	"bytes"
	"cmp"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The pending records' prefixes in the core namespace.
const (
	sidecarPendingStatementPrefix = "pending/"
	sidecarPendingActPrefix       = "pending-act/"
)

// The act record's values.
const (
	sidecarPendingActVersion     = 1
	sidecarPendingActKindPlain   = 0
	sidecarPendingActKindStale   = 1
	sidecarPendingActByteCount   = 1 + 16 + 4 + 1
	sidecarPendingActStaleLength = sidecarPendingActByteCount + 16 + 16
)

// One statement signed and not yet landed.
type sidecarPendingStatement struct {
	// the marshalled Signed, posted as it is, byte for byte, every time
	signed []byte
	// its header's not_after, past which it can no longer land
	notAfterMs int64
	// the act it was signed in, and its place there; nil for one kept alone
	act *sidecarPendingAct
}

// A pending statement's place in its act.
type sidecarPendingAct struct {
	actId Id
	index uint32
	// set for §7.10's stale revocation, which each post and retry re-checks
	stale *sidecarStaleRevocation
}

// The act record's bytes.
func (self *sidecarPendingAct) encode() []byte {
	record := make([]byte, 0, sidecarPendingActStaleLength)
	record = append(record, sidecarPendingActVersion)
	record = append(record, self.actId[:]...)
	record = binary.BigEndian.AppendUint32(record, self.index)
	if self.stale == nil {
		return append(record, sidecarPendingActKindPlain)
	}
	record = append(record, sidecarPendingActKindStale)
	record = append(record, self.stale.workerId[:]...)
	return append(record, self.stale.memberId[:]...)
}

// An act record's fields, or ErrSidecarStoreFailed for bytes no version of this file writes.
func decodeSidecarPendingAct(record []byte) (*sidecarPendingAct, error) {
	if len(record) < sidecarPendingActByteCount || record[0] != sidecarPendingActVersion {
		return nil, fmt.Errorf("%w: a pending act record", ErrSidecarStoreFailed)
	}
	act := &sidecarPendingAct{index: binary.BigEndian.Uint32(record[17:21])}
	copy(act.actId[:], record[1:17])
	switch record[21] {
	case sidecarPendingActKindPlain:
		if len(record) != sidecarPendingActByteCount {
			return nil, fmt.Errorf("%w: a pending act record", ErrSidecarStoreFailed)
		}
	case sidecarPendingActKindStale:
		if len(record) != sidecarPendingActStaleLength {
			return nil, fmt.Errorf("%w: a pending act record", ErrSidecarStoreFailed)
		}
		stale := &sidecarStaleRevocation{}
		copy(stale.workerId[:], record[22:38])
		copy(stale.memberId[:], record[38:54])
		act.stale = stale
	default:
		return nil, fmt.Errorf("%w: a pending act record", ErrSidecarStoreFailed)
	}
	return act, nil
}

// The statement's id, §7.9's: SHA-256 of its signed bytes, which a retry under another wrapper shares.
func (self *sidecarPendingStatement) id() (string, error) {
	signed := &bridge.Signed{}
	if err := proto.Unmarshal(self.signed, signed); err != nil {
		return "", fmt.Errorf("%w: a pending statement", ErrSidecarStoreFailed)
	}
	signedType := bridge.SignedType(signed.GetType())
	purpose, ok := sidecarIdentitySignedPurpose(signedType)
	if !ok {
		return "", fmt.Errorf("%w: a pending statement of type %#x", ErrSidecarStoreFailed, int32(signedType))
	}
	digest := bridge.SignedBytesSha256(purpose, signedType, signed.GetBody())
	return hex.EncodeToString(digest[:]), nil
}

// Keeps a statement in the pending records, before it is posted: its act record first, so a pending statement an act
// signed always has its place.
func (self *Sidecar) keepPendingStatement(pending *sidecarPendingStatement) error {
	secrets := self.currentCoreSecrets()
	if secrets == nil {
		return ErrSidecarNoIdentity
	}
	id, err := pending.id()
	if err != nil {
		return err
	}
	if pending.act != nil {
		if err := secrets.Put(sidecarPendingActPrefix+id, pending.act.encode()); err != nil {
			return err
		}
	}
	record := binary.BigEndian.AppendUint64(make([]byte, 0, 8+len(pending.signed)), uint64(pending.notAfterMs))
	return secrets.Put(sidecarPendingStatementPrefix+id, append(record, pending.signed...))
}

// Drops a statement from the pending records, then its act record.
func (self *Sidecar) dropPendingStatement(pending *sidecarPendingStatement) error {
	secrets := self.currentCoreSecrets()
	if secrets == nil {
		return ErrSidecarNoIdentity
	}
	id, err := pending.id()
	if err != nil {
		return err
	}
	if err := secrets.Delete(sidecarPendingStatementPrefix + id); err != nil {
		return err
	}
	return secrets.Delete(sidecarPendingActPrefix + id)
}

// Every pending statement, in id order.
func (self *Sidecar) pendingStatements() ([]*sidecarPendingStatement, error) {
	secrets := self.currentCoreSecrets()
	if secrets == nil {
		return nil, ErrSidecarNoIdentity
	}
	names, err := secrets.List(sidecarPendingStatementPrefix)
	if err != nil {
		return nil, err
	}
	pendings := []*sidecarPendingStatement{}
	for _, name := range names {
		record, err := secrets.Get(name)
		if err != nil {
			return nil, err
		}
		if len(record) < 8 {
			return nil, fmt.Errorf("%w: a pending record", ErrSidecarStoreFailed)
		}
		pending := &sidecarPendingStatement{
			notAfterMs: int64(binary.BigEndian.Uint64(record[:8])),
			signed:     record[8:],
		}
		actRecord, err := secrets.Get(sidecarPendingActPrefix + strings.TrimPrefix(name, sidecarPendingStatementPrefix))
		switch {
		case err == nil:
			if pending.act, err = decodeSidecarPendingAct(actRecord); err != nil {
				return nil, err
			}
		case !errors.Is(err, ErrSidecarStoreAbsent):
			return nil, err
		}
		pendings = append(pendings, pending)
	}
	return pendings, nil
}

// Posts one pending statement in its act's order: a stale revocation is re-checked first, and dropped unposted, with a
// nil entry and no error, when its Worker holds a leaf again; one whose re-check cannot run stays pending. Else as
// postPendingStatement.
func (self *Sidecar) postPendingInOrder(ctx context.Context, pending *sidecarPendingStatement) (*bridge.AuthPin, error) {
	if pending.act != nil && pending.act.stale != nil && self.clock.Now().UnixMilli() < pending.notAfterMs {
		post, err := self.recheckStaleRevocation(ctx, pending.act.stale)
		if err != nil {
			return nil, err
		}
		if !post {
			return nil, self.dropPendingStatement(pending)
		}
	}
	return self.postPendingStatement(ctx, pending)
}

// The pending statements as they post: each act's in act order, acts by id, then each statement kept alone, in id
// order.
func sidecarPendingRuns(pendings []*sidecarPendingStatement) [][]*sidecarPendingStatement {
	actRuns := map[Id][]*sidecarPendingStatement{}
	actIds := []Id{}
	runs := [][]*sidecarPendingStatement{}
	alone := [][]*sidecarPendingStatement{}
	for _, pending := range pendings {
		if pending.act == nil {
			alone = append(alone, []*sidecarPendingStatement{pending})
			continue
		}
		if _, ok := actRuns[pending.act.actId]; !ok {
			actIds = append(actIds, pending.act.actId)
		}
		actRuns[pending.act.actId] = append(actRuns[pending.act.actId], pending)
	}
	slices.SortFunc(actIds, func(a Id, b Id) int {
		return bytes.Compare(a[:], b[:])
	})
	for _, actId := range actIds {
		run := actRuns[actId]
		slices.SortStableFunc(run, func(a *sidecarPendingStatement, b *sidecarPendingStatement) int {
			return cmp.Compare(a.act.index, b.act.index)
		})
		runs = append(runs, run)
	}
	return append(runs, alone...)
}

// Posts one pending statement: its entry once api answers one, after which it is dropped; ErrSidecarActRefused, and
// dropped, when api refuses it or its not_after has passed; any other error, a lost answer or api unavailable, and it
// stays to be posted again with the same bytes.
func (self *Sidecar) postPendingStatement(ctx context.Context, pending *sidecarPendingStatement) (*bridge.AuthPin, error) {
	if pending.notAfterMs <= self.clock.Now().UnixMilli() {
		if err := self.dropPendingStatement(pending); err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("%w: its not_after passed before it landed", ErrSidecarActRefused)
	}
	id, err := pending.id()
	if err != nil {
		return nil, err
	}
	testHookBarrier("identity.post.before", id)
	pin, err := self.sidecarApi.PostConfigDelta(ctx, pending.signed)
	testHookBarrier("identity.post.after", id)
	if err != nil {
		apiErr := &SidecarApiError{}
		if errors.As(err, &apiErr) && (apiErr.Status == http.StatusForbidden || apiErr.Status == http.StatusConflict || apiErr.Status == http.StatusBadRequest) {
			if dropErr := self.dropPendingStatement(pending); dropErr != nil {
				return nil, dropErr
			}
			return nil, fmt.Errorf("%w: %w", ErrSidecarActRefused, err)
		}
		return nil, err
	}
	if err := self.dropPendingStatement(pending); err != nil {
		return nil, err
	}
	return pin, nil
}

// Posts every pending statement again, the same bytes: each act's in act order, a stale revocation re-checked first,
// and each statement kept alone in id order. What the daemon runs at each start and after a post's lost answer, until
// each lands, is refused or passes its not_after. An error leaves the rest of its act pending, so an act's order holds,
// and the other acts go on. Answers the first error that left a statement pending; a refusal drops its statement and is
// not returned.
func (self *Sidecar) PostPendingStatements(ctx context.Context) error {
	pendings, err := self.pendingStatements()
	if err != nil {
		return err
	}
	var firstErr error
	for _, run := range sidecarPendingRuns(pendings) {
		for _, pending := range run {
			if _, err := self.postPendingInOrder(ctx, pending); err != nil && !errors.Is(err, ErrSidecarActRefused) {
				if firstErr == nil {
					firstErr = err
				}
				break
			}
		}
	}
	return firstErr
}

// POST /network/config/delta's body (§7.9; sidecartest/fake_api_config.go reads alike).
type sidecarConfigDeltaWire struct {
	Signed []byte `json:"signed"`
}

// Its answer: the entry's (n, A_n).
type sidecarConfigPinReply struct {
	N     uint64 `json:"n"`
	Chain []byte `json:"chain"`
}

// POST /network/config/delta (§7.9's statement row): one Signed statement, its bytes as given. Answers its entry's (n,
// A_n): a new entry, or, for a statement api already holds, that entry. A refusal is a *SidecarApiError: 403
// config_refused with the tip, 409 when the tip moved past a base, 503 while the log is unavailable.
func (self *SidecarApi) PostConfigDelta(ctx context.Context, signed []byte) (*bridge.AuthPin, error) {
	route := "POST /network/config/delta"
	if len(signed) == 0 {
		return nil, fmt.Errorf("sidecar api %s: %w", route, ErrSidecarApiArgs)
	}
	reply := &sidecarConfigPinReply{}
	err := self.sendJson(ctx, &sidecarApiRequest{
		route:     route,
		operation: "config_delta",
		method:    "POST",
		url:       self.settings.ApiUrl + "/network/config/delta",
		bearer:    true,
	}, &sidecarConfigDeltaWire{Signed: signed}, reply)
	if err != nil {
		return nil, err
	}
	if reply.N == 0 || len(reply.Chain) != 32 {
		return nil, fmt.Errorf("sidecar api %s: %w", route, ErrSidecarApiReply)
	}
	return &bridge.AuthPin{Version: reply.N, Chain: reply.Chain}, nil
}
