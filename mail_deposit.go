//go:build !sidecar_http && !ios_extension

// §15.7's deposit, a receiver's side (R-MAIL-2, R-MAIL-12, D-MAIL-5, D-KEYS-17, I-2, I-5, QD-196, QD-208; MAIL-M7-14):
// one message's deposits, one a repo its recipients name, each holding that repo's recipients alone, so a recipient
// of one repo learns nothing of another's, a BCC included.
//
//	plaintext  the message as received, then its MailDeposit, then u32be of that encoding's length (QD-196,
//	           MAIL-FORMAT.md): the trailer goes last, inside the deposit's own stream, since the evidence exists only
//	           once the body has arrived. To evs the trailer is body, sealed under the deposit's object key, whose slot
//	           CONSUME and ERASE destroy
//	trailer    version, the router's MailIngress, the sealed MailAuthEvidence or none ("evidence unavailable"), MAIL
//	           FROM and its REQUIRETLS, this repo's recipients, the TLS version and suite by their IANA values, and this
//	           receiver's sidecar id, which ingest holds to the deposit push's signer
//	seal       EvsRepo.Deposit: the body under a random object key, that key HPKE-wrapped in a slot to the drop key of
//	           the repo's newest GenRotate, taken only under D-KEYS-17's depositor rule, slot ids drawn per statement;
//	           a rebuild after 412 GATE_CLOSED or BASE_STALE seals again under a new object key and new slot ids, and
//	           only a retry of the same statement keeps them (evs_deposit.go)
//	fan-out    each repo's deposit replays the message from the spool, at most DepositConcurrency at once (4, 2 on
//	           mobile, ApplyMobileMailSessionSettings), a group repo counting once (§15.7's group mail)
//	durable    nil only once evs confirmed every deposit: the session answers 250 after it, past the barrier
//	           mail.deposit.durable, and 451 4.3.0 for any failure: a drop key still pending (ErrGkmWait), §11.13's
//	           write-budget refusal, §11.8's closed gate, a reset. A failure leaves the repos that took the message
//	           holding it, and the sender's retry deposits it again there, which QD-208 bounds by
//	           mail_inbound_repos_per_message
//
// The spool is read here and never written. Nothing here logs a recipient, an address or a byte of a message (I-13).
// Safe for concurrent use.

package sidecar

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

var (
	// A deposit could not be made or did not commit: the session answers 451 4.3.0 and the sender retries.
	ErrMailDepositFailed = errors.New("mail deposit failed")
	// What a depositor was given cannot be deposited: no spool, no recipient, or a repo with none.
	ErrMailDepositorInvalid = errors.New("mail depositor: invalid")
)

// Where one repo's deposit goes: EvsRepo.Deposit, or a test's.
type mailDepositRepo interface {
	Deposit(ctx context.Context, args *EvsDepositArgs) (*EvsDepositResult, error)
}

// What NewMailDepositor builds on.
type MailDepositorArgs struct {
	// The repo of an id: EvsClient.Repo.
	Repo func(repoId Id) *EvsRepo
	// This receiver.
	ReceiverSidecarId Id
	// Nil logs nothing.
	Log Logger
	// Nil takes DefaultMailSessionSettings.
	Settings *MailSessionSettings
}

// One repo's recipients, in the order their RCPTs came.
type MailDepositTarget struct {
	RepoId     Id
	Recipients []string
}

// One message's deposits: the spool and what every repo's trailer shares.
type MailDepositInput struct {
	// The message, finished.
	Spool *mailSpool
	// The router's, as the stream opened; nil for none.
	Ingress *protocol.MailIngress
	// The sealed reception-time evidence; nil deposits it as "evidence unavailable".
	Evidence *protocol.MailAuthEvidence
	// MAIL FROM's reverse path as received, empty for <>.
	MailFrom   string
	RequireTls bool
	// The session's TLS version and cipher suite, by their IANA values.
	TlsVersion uint32
	TlsSuite   uint32
	// One target a repo, in the order the repos were first named.
	Targets []*MailDepositTarget
}

// A receiver's depositor. See the file header.
type MailDepositor struct {
	repo              func(repoId Id) mailDepositRepo
	receiverSidecarId Id
	log               Logger
	settings          *MailSessionSettings
}

// A depositor over args.Repo.
func NewMailDepositor(args *MailDepositorArgs) (*MailDepositor, error) {
	if args == nil || args.Repo == nil {
		return nil, fmt.Errorf("%w: no repos", ErrMailDepositorInvalid)
	}
	return newMailDepositor(func(repoId Id) mailDepositRepo {
		repo := args.Repo(repoId)
		if repo == nil {
			return nil
		}
		return repo
	}, args), nil
}

// A depositor over repo.
func newMailDepositor(repo func(repoId Id) mailDepositRepo, args *MailDepositorArgs) *MailDepositor {
	settings := args.Settings
	if settings == nil {
		settings = DefaultMailSessionSettings()
	}
	log := args.Log
	if log == nil {
		log = NewNoopLogger()
	}
	return &MailDepositor{repo: repo, receiverSidecarId: args.ReceiverSidecarId, log: log, settings: settings}
}

// The trailer of target's deposit: what every repo shares, and this repo's recipients alone.
func (self *MailDepositor) trailer(input *MailDepositInput, target *MailDepositTarget) ([]byte, error) {
	deposit := &protocol.MailDeposit{
		Version:           mailFormatVersion,
		Ingress:           proto.CloneOf(input.Ingress),
		Evidence:          proto.CloneOf(input.Evidence),
		MailFrom:          []byte(input.MailFrom),
		RequireTls:        input.RequireTls,
		Recipients:        append([]string(nil), target.Recipients...),
		TlsVersion:        input.TlsVersion,
		TlsSuite:          input.TlsSuite,
		ReceiverSidecarId: self.receiverSidecarId.Bytes(),
	}
	trailer, err := proto.MarshalOptions{Deterministic: true}.Marshal(deposit)
	if err != nil {
		return nil, fmt.Errorf("%w: a trailer that does not encode", ErrMailDepositorInvalid)
	}
	if self.settings.TrailerMaxByteCount < len(trailer) {
		return nil, fmt.Errorf("%w: a trailer past its bound", ErrMailDepositorInvalid)
	}
	return binary.BigEndian.AppendUint32(trailer, uint32(len(trailer))), nil
}

// Deposits the message to every target's repo, at most DepositConcurrency at once: nil only once evs confirmed each,
// else ErrMailDepositFailed with the first failure. See the file header.
func (self *MailDepositor) Deposit(ctx context.Context, input *MailDepositInput) error {
	if input == nil || input.Spool == nil || !input.Spool.finished || len(input.Targets) == 0 {
		return fmt.Errorf("%w: no message or no repo", ErrMailDepositorInvalid)
	}
	trailers := make([][]byte, len(input.Targets))
	for index, target := range input.Targets {
		if len(target.Recipients) == 0 {
			return fmt.Errorf("%w: a repo with no recipient", ErrMailDepositorInvalid)
		}
		trailer, err := self.trailer(input, target)
		if err != nil {
			return err
		}
		trailers[index] = trailer
	}
	concurrency := max(1, self.settings.DepositConcurrency)
	slots := make(chan struct{}, concurrency)
	var group sync.WaitGroup
	var errLock sync.Mutex
	var firstErr error
	for index, target := range input.Targets {
		select {
		case slots <- struct{}{}:
		case <-ctx.Done():
			errLock.Lock()
			if firstErr == nil {
				firstErr = ctx.Err()
			}
			errLock.Unlock()
		}
		if ctx.Err() != nil {
			break
		}
		group.Go(func() {
			defer func() { <-slots }()
			if err := self.depositOne(ctx, input.Spool, target, trailers[index]); err != nil {
				errLock.Lock()
				defer errLock.Unlock()
				if firstErr == nil {
					firstErr = err
				}
			}
		})
	}
	group.Wait()
	if firstErr != nil {
		return fmt.Errorf("%w: %w", ErrMailDepositFailed, firstErr)
	}
	// every deposit is durable at evs: the 250 may follow
	testHookBarrier("mail.deposit.durable", "")
	return nil
}

// One repo's deposit: the message from the spool, then its trailer.
func (self *MailDepositor) depositOne(ctx context.Context, spool *mailSpool, target *MailDepositTarget, trailer []byte) error {
	repo := self.repo(target.RepoId)
	if repo == nil {
		return fmt.Errorf("%w: no handle for a repo", ErrMailDepositorInvalid)
	}
	key := target.RepoId.String()
	testHookBarrier("mail.deposit.repo.before", key)
	_, err := repo.Deposit(ctx, &EvsDepositArgs{
		Body: io.MultiReader(spool.Reader(), bytes.NewReader(trailer)),
		Size: spool.Size() + int64(len(trailer)),
	})
	testHookBarrier("mail.deposit.repo.after", key)
	return err
}
