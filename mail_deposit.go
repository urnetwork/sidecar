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
//	right      a repo this receiver's own newest verified state gives no deposit of mail refuses the message before any
//	           deposit is made, at once (refuses), so the session answers 451 4.3.0 before the body is even spooled.
//	           The rule is the send side's, mailSendMayDeposit itself, so a receiver deposits only where a same-network
//	           sender may: the deposit right the exchange mints repo:<id>:deposit on (§8.5; AclExchangeScopes,
//	           D-ACL-21), on a repo that takes mail, a mailbox or a general repo its RepoCreate marks an inbox, the
//	           only general repos a drop key serves (D-KEYS-17; QD-1173), and never §16.8's receipt deposit, which
//	           ingest takes as no mail. A repo whose client holds no ACL state to judge by is left to the exchange and
//	           evs, which judge every deposit whatever this says
//	never      a repo that state holds as taking no mail, by its kind or its RepoCreate's marker, takes no deposit in
//	           any later state either, since only RepoCreate sets them. gkm serves it no drop key, so a deposit there
//	           waited out ErrGkmWait and answered 451 4.3.0 on every retry, and the sender retried for days. The
//	           session answers such a recipient 550 5.1.1 at RCPT instead (takesNoMail), §15.5's permanent answer for
//	           a recipient no mail reaches, so the sender gives up on that recipient alone at its first try, before
//	           gkm is asked. Deposit refuses a target there at once as well, ErrMailDepositRefused, which a session
//	           answers 451 4.3.0 at DATA, like any failure there: only a state that came to hold the repo after RCPT
//	           took the recipient reaches it, and the sender's retry is then answered 550 5.1.1 at RCPT for that
//	           recipient alone, rather than every recipient of the message bounced
//	bound      the deposits take at most DepositTimeout, past which every one still open is cancelled and the message
//	           answers 451 4.3.0 inside the sender's wait
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
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

var (
	// A deposit could not be made or did not commit: the session answers 451 4.3.0 and the sender retries.
	ErrMailDepositFailed = errors.New("mail deposit failed")
	// A recipient's repo takes no mail, by a kind or marker no later state changes, so no deposit was made and gkm was
	// not asked (the file header's never row). Deposit wraps it in ErrMailDepositFailed.
	ErrMailDepositRefused = errors.New("mail deposit refused: the repo takes no mail")
	// What a depositor was given cannot be deposited: no spool, no recipient, or a repo with none.
	ErrMailDepositorInvalid = errors.New("mail depositor: invalid")
)

// Where one repo's deposit goes: EvsRepo.Deposit, or a test's.
type mailDepositRepo interface {
	Deposit(ctx context.Context, args *EvsDepositArgs) (*EvsDepositResult, error)
}

// A repo that also says, before anything is sent, whether depositorId may deposit mail there now by the depositor's
// own newest verified state; known false where it holds none to judge by (the file header's right row).
type mailDepositRightRepo interface {
	mailDepositRepo
	depositRight(depositorId Id) (allowed bool, known bool)
}

// A repo that also says, before anything is sent, whether it takes mail at all by the depositor's own newest verified
// state; known false where that state does not hold the repo, or there is none to judge by (the file header's never
// row).
type mailDepositTakingRepo interface {
	mailDepositRepo
	takesMail() (takes bool, known bool)
}

// mailDepositRightRepo and mailDepositTakingRepo over EvsRepo: its client's verified state (EvsClientArgs.Config),
// whose ACL rows the exchange reads for repo:<id>:deposit, at its client's clock.
type mailEvsDepositRepo struct {
	*EvsRepo
}

// The ACL state of its client's newest verified state, and its client's now; false where there is none to judge by.
func (self mailEvsDepositRepo) aclState() (*AclState, time.Time, bool) {
	client := self.client
	if client == nil || client.args.Config == nil {
		return nil, time.Time{}, false
	}
	state, ok := client.args.Config().(*ConfigState)
	if !ok || state == nil {
		return nil, time.Time{}, false
	}
	acl, err := state.Acl()
	if err != nil || acl == nil {
		return nil, time.Time{}, false
	}
	return acl, client.clock.Now(), true
}

// See mailDepositRightRepo: the send side's rule, so a receiver deposits mail only where a same-network sender of
// the same rights may, and only where the exchange mints repo:<id>:deposit.
func (self mailEvsDepositRepo) depositRight(depositorId Id) (bool, bool) {
	acl, now, ok := self.aclState()
	if !ok {
		return false, false
	}
	return mailSendMayDeposit(acl, depositorId, self.repoId, now) == MailSendDelivered, true
}

// See mailDepositTakingRepo: a mailbox, or a general repo its RepoCreate marks an inbox, the kinds
// mailSendMayDeposit takes, so both ends agree. A repo's kind and marker are its RepoCreate's, which a repo has
// once (FoldAclRepos), so a repo held here as taking no mail takes none in any later state.
func (self mailEvsDepositRepo) takesMail() (bool, bool) {
	acl, _, ok := self.aclState()
	if !ok {
		return false, false
	}
	repo := acl.Repo(self.repoId)
	if repo == nil {
		// a repo made after this state, which a later state may hold
		return false, false
	}
	switch repo.GetKind() {
	case protocol.RepoKind_REPO_KIND_MAILBOX:
		return true, true
	case protocol.RepoKind_REPO_KIND_GENERAL:
		// a group's or the admin address's repo: no other general repo's generations carry a drop key (D-KEYS-17)
		return gkmRepoTakesDeposits(repo), true
	}
	// every other kind, those whose generations carry a drop key for what they hold among them (the vault, the secret
	// store, the team record), which ingest never reads as mail
	return false, true
}

// What NewMailDepositor builds on.
type MailDepositorArgs struct {
	// The repo of an id: EvsClient.Repo.
	Repo func(repoId Id) *EvsRepo
	// This receiver.
	ReceiverSidecarId Id
	// What DepositTimeout runs on; nil is real time.
	Clock Clock
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
	clock             Clock
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
		return mailEvsDepositRepo{EvsRepo: repo}
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
	return &MailDepositor{repo: repo, receiverSidecarId: args.ReceiverSidecarId, clock: clockOrReal(args.Clock), log: log, settings: settings}
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

// Whether this receiver's own newest verified state already refuses it a deposit into one of targets' repos, so a
// message for them is answered 451 4.3.0 with no deposit made (the file header's right row). False where every repo
// gives it deposit or holds no state to judge by.
func (self *MailDepositor) refuses(targets []*MailDepositTarget) bool {
	for _, target := range targets {
		repo, ok := self.repo(target.RepoId).(mailDepositRightRepo)
		if !ok {
			continue
		}
		if allowed, known := repo.depositRight(self.receiverSidecarId); known && !allowed {
			return true
		}
	}
	return false
}

// Whether this receiver's own newest verified state holds repoId as a repo that takes no mail, so that no deposit
// there could ever land, in this state or any later one: the session answers its recipient 550 5.1.1 at RCPT (the
// file header's never row). False where the state does not hold the repo, or there is none to judge by.
func (self *MailDepositor) takesNoMail(repoId Id) bool {
	repo, ok := self.repo(repoId).(mailDepositTakingRepo)
	if !ok {
		return false
	}
	takes, known := repo.takesMail()
	return known && !takes
}

// Deposits the message to every target's repo, at most DepositConcurrency at once and within DepositTimeout: nil only
// once evs confirmed each, else ErrMailDepositFailed with the first failure, and at once, with none made and gkm not
// asked, where the receiver's own state holds a repo that takes no mail (ErrMailDepositRefused too, takesNoMail) or
// refuses it one (refuses). See the file header.
func (self *MailDepositor) Deposit(ctx context.Context, input *MailDepositInput) error {
	if input == nil || input.Spool == nil || !input.Spool.finished || len(input.Targets) == 0 {
		return fmt.Errorf("%w: no message or no repo", ErrMailDepositorInvalid)
	}
	for _, target := range input.Targets {
		if self.takesNoMail(target.RepoId) {
			return fmt.Errorf("%w: %w", ErrMailDepositFailed, ErrMailDepositRefused)
		}
	}
	if self.refuses(input.Targets) {
		return fmt.Errorf("%w: this receiver may not deposit into a recipient's repo", ErrMailDepositFailed)
	}
	// the bound row: every deposit still open is cancelled at DepositTimeout
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := self.clock.AfterFunc(self.settings.DepositTimeout, cancel)
	defer stop()
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
