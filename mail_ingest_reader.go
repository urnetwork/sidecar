//go:build !ios_extension

// What ingest reads (§15.7's Deposit and Ingest; MAIL-M7-15): a deposit's plaintext split into the message and its
// sealed trailer, and the seam over one mail repo's deposit refs.
//
// A deposit's plaintext is the message as received, then the encoded MailDeposit, then u32be of that encoding's
// length (MAIL-FORMAT.md, QD-196). mailSplitDeposit takes the trailer from the tail and refuses, as
// ErrMailDepositInvalid, a plaintext with no trailer, a length past the plaintext or past TrailerMaxByteCount, and
// bytes that do not decode; a trailer of a version this reader does not know is ErrMailDepositVersion, which another
// reader may know, so ingest leaves that deposit standing.
//
// mailIngestRepo is what ingest needs of the repo beyond its main ref's files (mailStore): who deposited, each
// depositor's standing deposits in version order (EvsRepo.ReadDeposits), one CONSUME, the erasure ref's ERASEs, and a
// wake at each change. mailIngestEvsRepo is the seam over EvsRepo; its depositors are the deposit refs evs lists,
// which is only a list of refs to read, each then verified by its own walk, so evs leaving one out withholds mail
// and forges none.
//
// The plaintext is read whole, bounded by DepositMaxByteCount, since mailStore writes a path from bytes: streaming a
// message from the deposit's spill to m/ is the review phase's memory work (QD-641).
//
// On every leg but the extension's. Safe for concurrent use.

package sidecar

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

var (
	// A deposit's plaintext that is not a message and its trailer: no length, a length past the plaintext or the
	// trailer's bound, or a trailer that does not decode. No conforming receiver or member's device makes one.
	ErrMailDepositInvalid = errors.New("mail deposit invalid")
	// A trailer of a version this reader does not know, 0 included (MAIL-FORMAT.md's Numbers), which a newer reader
	// may: nothing is written and the deposit stands.
	ErrMailDepositVersion = errors.New("mail deposit of a version this reader does not know")
	// A deposit past DepositMaxByteCount, which this reader does not open.
	ErrMailDepositTooLarge = errors.New("mail deposit past this reader's bound")
)

// The bytes of the trailer's length at a deposit's tail: a u32be (MAIL-FORMAT.md). A format's field width.
const mailDepositTrailerLengthByteCount = 4

// A deposit's plaintext from body, or ErrMailDepositTooLarge once it passes maxByteCount.
func mailReadDeposit(body io.Reader, maxByteCount int64) ([]byte, error) {
	if maxByteCount < 0 {
		maxByteCount = 0
	}
	plaintext, err := io.ReadAll(io.LimitReader(body, maxByteCount+1))
	if err != nil {
		return nil, err
	}
	if maxByteCount < int64(len(plaintext)) {
		return nil, ErrMailDepositTooLarge
	}
	return plaintext, nil
}

// A deposit's message and trailer: see the file header. The message aliases plaintext.
func mailSplitDeposit(plaintext []byte, trailerMaxByteCount int) ([]byte, *protocol.MailDeposit, error) {
	if len(plaintext) < mailDepositTrailerLengthByteCount {
		return nil, nil, fmt.Errorf("%w: no trailer length", ErrMailDepositInvalid)
	}
	lengthAt := len(plaintext) - mailDepositTrailerLengthByteCount
	trailerByteCount := int64(binary.BigEndian.Uint32(plaintext[lengthAt:]))
	if int64(trailerMaxByteCount) < trailerByteCount || int64(lengthAt) < trailerByteCount {
		return nil, nil, fmt.Errorf("%w: a trailer of %d bytes", ErrMailDepositInvalid, trailerByteCount)
	}
	trailerAt := lengthAt - int(trailerByteCount)
	deposit := &protocol.MailDeposit{}
	if err := proto.Unmarshal(plaintext[trailerAt:lengthAt], deposit); err != nil {
		return nil, nil, fmt.Errorf("%w: a trailer that does not decode", ErrMailDepositInvalid)
	}
	if deposit.GetVersion() != mailFormatVersion {
		return nil, nil, fmt.Errorf("%w: %d", ErrMailDepositVersion, deposit.GetVersion())
	}
	return plaintext[:trailerAt], deposit, nil
}

// A deposit's plaintext from its message and trailer, as a receiver or a member's device seals it (MAIL-FORMAT.md):
// what MAIL-M7-14's and MAIL-M7-18's depositors write, and what tests deposit.
func MailDepositPlaintext(message []byte, deposit *protocol.MailDeposit) ([]byte, error) {
	trailer, err := proto.MarshalOptions{Deterministic: true}.Marshal(deposit)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMailDepositInvalid, err)
	}
	plaintext := make([]byte, 0, len(message)+len(trailer)+mailDepositTrailerLengthByteCount)
	plaintext = append(plaintext, message...)
	plaintext = append(plaintext, trailer...)
	return binary.BigEndian.AppendUint32(plaintext, uint32(len(trailer))), nil
}

// What ingest needs of one mail repo beyond its main ref's files. Implementations are safe for concurrent use.
type mailIngestRepo interface {
	// The sidecars that hold a deposit ref in the repo, in id order.
	Depositors(ctx context.Context) ([]Id, error)
	// A depositor's standing deposits after afterVersion, oldest first, each opened and given to visit with its
	// plaintext; one that does not open ends the read as an *EvsDepositOpenError naming it (EvsRepo.ReadDeposits).
	ReadDeposits(ctx context.Context, depositorId Id, afterVersion uint64, visit func(deposit *EvsDeposit, body io.Reader) error) error
	// One CONSUME of a depositor's deposits, which evs deletes with their slots; one already gone counts consumed.
	Consume(ctx context.Context, depositorId Id, depositIds []Id, consumedThrough uint64) error
	// The committed ERASEs after afterVersion of the repo's erasure ref, oldest first, each with its note.
	Erasures(ctx context.Context, afterVersion uint64) ([]*EvsErasure, error)
	// Calls wake, which never blocks, at each change of the repo's refs until stop; an error where no watch stands,
	// and its caller then ingests on its timer alone.
	Watch(ctx context.Context, wake func()) (stop func(), err error)
}

// mailIngestRepo over EvsRepo. Safe for concurrent use.
type mailIngestEvsRepo struct {
	repo *EvsRepo
}

// The deposit refs evs lists for the repo, each held to the id its owner's deposit ref takes.
func (self *mailIngestEvsRepo) Depositors(ctx context.Context) ([]Id, error) {
	repoId := self.repo.repoId
	reply := &protocol.EvsRefsReply{}
	err := self.repo.client.http.callMessage(ctx, &evsCall{
		route:  "GET /evs/v1/repos/{repo_id}/refs",
		method: http.MethodGet,
		path:   "/evs/v1/repos/" + evsUrlId(repoId) + "/refs",
		repoId: repoId,
		role:   evsScopeRead,
		retry:  true,
	}, reply)
	if err != nil {
		return nil, err
	}
	depositorIds := []Id{}
	for _, head := range reply.GetRefs() {
		if head.GetRefKind() != protocol.EvsRefKind_EVS_REF_DEPOSIT {
			continue
		}
		depositorId, err := IdFromBytes(head.GetOwnerSidecarId())
		if err != nil || !bytes.Equal(head.GetRefId(), EvsDepositRefId(repoId, depositorId).Bytes()) {
			continue
		}
		depositorIds = append(depositorIds, depositorId)
	}
	slices.SortFunc(depositorIds, func(a Id, b Id) int { return a.Cmp(b) })
	return slices.Compact(depositorIds), nil
}

// EvsRepo.ReadDeposits.
func (self *mailIngestEvsRepo) ReadDeposits(ctx context.Context, depositorId Id, afterVersion uint64, visit func(deposit *EvsDeposit, body io.Reader) error) error {
	return self.repo.ReadDeposits(ctx, depositorId, afterVersion, visit)
}

// EvsRepo.Consume on the depositor's ref, a deposit already gone counting consumed.
func (self *mailIngestEvsRepo) Consume(ctx context.Context, depositorId Id, depositIds []Id, consumedThrough uint64) error {
	entryIds := make([]EvsToken, len(depositIds))
	for i, depositId := range depositIds {
		entryIds[i] = EvsToken(depositId)
	}
	_, err := self.repo.Consume(ctx, &EvsConsumeArgs{
		DepositRefId: EvsDepositRefId(self.repo.repoId, depositorId), EntryIds: entryIds, ConsumedThrough: consumedThrough,
	})
	if IsEvsDepositConsumed(err) {
		return nil
	}
	return err
}

// EvsRepo.ReadErasures.
func (self *mailIngestEvsRepo) Erasures(ctx context.Context, afterVersion uint64) ([]*EvsErasure, error) {
	return self.repo.ReadErasures(ctx, afterVersion)
}

// A subscription to every ref of the repo, a deposit ref's among them, whose changes wake the ingestor.
func (self *mailIngestEvsRepo) Watch(ctx context.Context, wake func()) (func(), error) {
	subscription, err := self.repo.Subscribe(ctx, &EvsSubscribeArgs{Changes: func(change *EvsRepoChange) { wake() }})
	if err != nil {
		return nil, err
	}
	return subscription.Close, nil
}
