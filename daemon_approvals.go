//go:build !js && !ios && !android && !sdk_mobile_bind

// §5.8's two calls (CORE-M8-03; D-CORE-20, D-CORE-13, D-SDK-30, I-4, I-7, FS-98, FS-124): where an act a remote-mode
// app asks for signs a statement §7.9's presence row covers, the check runs where the key is, the app's
// SidecarPresenceSigner, so the app's call takes two. The first, a Confirm method, builds the act on the network's
// Sidecar and answers its countersigned bytes and an act id, signing nothing; the app signs the bytes by
// SignWithPresence; the second, a Confirm method too, sends the evidence back under that id, and only then does the
// daemon sign, each statement carrying the countersignature, which the act verifies against a live presence key of
// this sidecar's before it signs, as api and every member device will. An act the log does not cover answers no bytes
// and signs at the second call on the person's confirmation alone, so a first call never signs.
//
//	devices.revoke.begin, .finish     RevokeDevice of a previewed plan (daemon_devices.go)
//	devices.cosign.begin, .finish     the cosign of an open revocation proposal (daemon_devices.go)
//	approvals.decide.begin, .finish   Decide: an admission, an OwnerConfirm, a RecoveryVeto, an alarm's revoke answer
//	                                  and the cleanup's revoke, each as the core's DecideApproval signs it
//	keys.presence.begin, .prove, .finish
//	                                  the app's own KeyRegister: the first call answers the bytes the app's new key
//	                                  proves itself over (QD-086), the second takes that proof and answers the act's
//	                                  countersigned bytes as a first call does, and the third signs
//
// The act runs on a goroutine of its own, held where the act runner gives a hold (identity_act.go's sidecarActHold):
// built, its bytes known, nothing signed. Every rule of the core runs before the hold as it does for the one confirmed
// call, a plan's re-derivation and the caller's eligibility among them. The act ends unsigned at
// Local.PresenceActTimeout after each hold, when the session that began it ends, when a first call of the same subject
// supersedes it, and when the daemon closes. A next call names the act's network and comes on its session; it is
// single use, and one out of order spends the act unsigned. Where the log covers the act, a next call with no evidence,
// or evidence that does not verify against a live presence key of this sidecar's, signs nothing (REVOKE_CANCELLED).
// The daemon holds at most Local.PresenceActCount acts.
//
// The terminal's path stays the one confirmed call (devices.revoke, devices.cosign, approvals.decide, ur keys
// add-presence) under the daemon's own prompt. ur native-host relays none of these: its allow-list holds no Confirm
// method, and it answers a revocation REVOKE_NOT_CAPABLE itself. Replies carry ids, bytes to sign and positions, never
// a key or a token (I-7).
//
// Safe for concurrent use.

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The methods.
const (
	// Decide's first call: the decision's act built, its countersigned bytes answered.
	DaemonMethodApprovalsDecideBegin = "approvals.decide.begin"
	// Decide's second call: the evidence in, the decision signed.
	DaemonMethodApprovalsDecideFinish = "approvals.decide.finish"
	// The app's KeyRegister, its first call: the bytes the app's new key proves itself over.
	DaemonMethodKeysPresenceBegin = "keys.presence.begin"
	// Its second: the new key's proof in, the act's countersigned bytes out.
	DaemonMethodKeysPresenceProve = "keys.presence.prove"
	// Its third: the countersignature in, the KeyRegister signed.
	DaemonMethodKeysPresenceFinish = "keys.presence.finish"
)

// The families of held acts: a later call takes only an act its own family's first call began.
const (
	daemonPresenceKindDevicesRevoke   = "devices.revoke"
	daemonPresenceKindDevicesCosign   = "devices.cosign"
	daemonPresenceKindApprovalsDecide = "approvals.decide"
	daemonPresenceKindKeysPresence    = "keys.presence"
)

// §16.6's profile names as the keys methods carry a key's algorithm.
const (
	DaemonPresenceAlgWebAuthnEs256   = "webauthn-es256"
	DaemonPresenceAlgEcdsaP256Sha256 = "ecdsa-p256-sha256"
)

var (
	// No held act has that id for this call: it finished, lapsed, was superseded or never began, or another
	// network's, session's or family's call began it. This call signed nothing.
	ErrDaemonPresenceActUnknown = errors.New("no act waits under that id for this call: begin it again")
	// The act waited for another call than this one: a call out of order, which spent it unsigned.
	ErrDaemonPresenceActStage = errors.New("the act waited for another call, so it ended unsigned: begin it again")
	// The daemon holds Local.PresenceActCount acts already.
	ErrDaemonPresenceActCount = errors.New("too many acts wait for their next call")
	// An act of the same subject is being signed: its next call answers first.
	ErrDaemonPresenceActBusy = errors.New("an act of the same subject is being signed")
)

// Why a held act ended unsigned, what its run's hold answers.
var (
	errDaemonPresenceActLapsed     = errors.New("the act waited past its bound for its next call")
	errDaemonPresenceActSuperseded = errors.New("a later call of the same subject superseded the act")
	errDaemonPresenceSessionEnded  = errors.New("the session that began the act ended")
	errDaemonPresenceCallEnded     = errors.New("the call that drove the act ended before the act held or finished")
	errDaemonPresenceActFinished   = errors.New("the act finished")
	errDaemonPresenceHeldTwice     = errors.New("a second act asked a hold that holds one")
	// A covered act's next call sent no evidence (REVOKE_CANCELLED).
	errDaemonPresenceNoEvidence = errors.New("the call sent no presence evidence")
	// The evidence is no §6.9 WebAuthnEvidence naming a key and carrying a signature.
	errDaemonPresenceEvidence = errors.New("the evidence is no WebAuthnEvidence")
)

// A first call's answer.
type DaemonPresenceBeginReply struct {
	// What the next call names the act by. Empty with a refusal.
	ActId *Id `json:"act_id,omitempty"`
	// The act's countersigned bytes (§7.9's presence row), which the app's presence key signs by SignWithPresence:
	// empty for an act the log does not cover, which the next call signs on the person's confirmation alone.
	Countersigned []byte `json:"countersigned,omitempty"`
	// §5.6's refusal before anything was built: nothing was signed and no act waits.
	Refusal *DaemonDeviceRefusal `json:"refusal,omitempty"`
}

// A next call's params.
type DaemonPresenceFinishParams struct {
	Network string `json:"network,omitempty"`
	ActId   Id     `json:"act_id"`
	// §6.9's WebAuthnEvidence, encoded, as SignWithPresence answered it over the bytes the call before answered;
	// empty for none.
	Evidence []byte `json:"evidence,omitempty"`
}

// approvals.decide.begin's params.
type DaemonApprovalsDecideParams struct {
	Network    string `json:"network,omitempty"`
	ApprovalId Id     `json:"approval_id"`
	// approve, deny or revoke.
	Decision string `json:"decision"`
}

// approvals.decide.finish's reply.
type DaemonApprovalsDecideReply struct {
	// The decision's statements are signed and kept, and a post's answer was lost: they go again with the same bytes.
	Pending bool `json:"pending,omitempty"`
	// §5.6's refusal: REVOKE_CANCELLED for a check that failed, was refused or sent no evidence, REVOKE_REFUSED for
	// a statement api refused, and a revoke answer's own codes.
	Refusal *DaemonDeviceRefusal `json:"refusal,omitempty"`
}

// keys.presence.begin's params: the app's new key as its authenticator made it.
type DaemonKeysPresenceBeginParams struct {
	Network string `json:"network,omitempty"`
	// The authenticator's name for it, at most 64 bytes.
	KeyId []byte `json:"key_id"`
	// webauthn-es256 or ecdsa-p256-sha256.
	Alg string `json:"alg"`
	// A SEC 1 uncompressed point, 65 bytes.
	PublicKey []byte `json:"public_key"`
	// For webauthn-es256, the attestation map its client answered (QD-730); empty for none.
	Attestation []byte `json:"attestation,omitempty"`
}

// keys.presence.begin's reply.
type DaemonKeysPresenceBeginReply struct {
	ActId *Id `json:"act_id,omitempty"`
	// The key-proof signed bytes of the KeyRegister before its field 9 (QD-086), which the new key signs by
	// SignWithPresence.
	Proof []byte `json:"proof,omitempty"`
}

// keys.presence.finish's reply.
type DaemonKeysPresenceReply struct {
	KeyId []byte `json:"key_id,omitempty"`
	// The KeyRegister's entry; 0 while its post's answer is lost.
	Position uint64 `json:"position,omitempty"`
	// In milliseconds since the epoch.
	NotAfterMs int64                `json:"not_after_ms,omitempty"`
	Pending    bool                 `json:"pending,omitempty"`
	Refusal    *DaemonDeviceRefusal `json:"refusal,omitempty"`
}

// Where a held act's run waits: the bytes the app signs.
type daemonPresenceHold struct {
	// The act's countersigned bytes, nil where the log does not cover the act; or a new key's proof bytes.
	message []byte
	// A new key's proof rather than the act's check.
	proof bool
}

// What a next call answers a hold.
type daemonPresenceAnswer struct {
	// nil for none
	evidence *bridge.WebAuthnEvidence
	err      error
}

// Where a call left an act: the hold it waits at, or its run's end.
type daemonPresenceStep struct {
	// nil once the run ended
	hold *daemonPresenceHold
	// the run's answer, once it ended
	result any
	err    error
}

// The acts a daemon holds between a remote-mode app's calls.
type daemonPresenceActs struct {
	daemon *Daemon

	stateLock sync.Mutex
	actIdActs map[Id]*daemonPresenceAct
}

// One act a first call began.
type daemonPresenceAct struct {
	acts  *daemonPresenceActs
	actId Id
	// the family whose later calls take it
	kind      string
	networkId Id
	// the session that began it; nil for a call no session reader watches
	session <-chan struct{}
	// what a later first call of the family supersedes it by: a plan, an item, a proposal, a key
	subject string

	// each hold the run reaches, handed to the call waiting for it
	holds chan *daemonPresenceHold
	// the next call's answer to the hold the run waits at
	answers chan daemonPresenceAnswer
	// closed once the act ends; endErr says why, what a hold still to come answers
	ended   chan struct{}
	endOnce sync.Once
	endErr  error
	// closed once the run returned what result and err hold
	done   chan struct{}
	result any
	err    error
	// whether a sidecarAct asked its hold yet
	actHeld atomic.Bool

	// under acts.stateLock: the hold the act waits at for its next call; whether a call drives it; whether its run
	// ended before any hold, kept for its next call; the lapse armed last, its stop, and its generation, which a
	// call taking the act or its end moves on so an older lapse does nothing
	waiting         *daemonPresenceHold
	driving         bool
	completed       bool
	stopLapse       func() bool
	lapseGeneration uint64
}

// The daemon's held acts, made on first use. They end, unsigned, with the daemon.
func (self *Daemon) heldActs() *daemonPresenceActs {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.presenceActs == nil {
		acts := &daemonPresenceActs{daemon: self, actIdActs: map[Id]*daemonPresenceAct{}}
		context.AfterFunc(self.ctx, func() {
			acts.endAll(self.ctx.Err())
		})
		self.presenceActs = acts
	}
	return self.presenceActs
}

// Ends every held act with err.
func (self *daemonPresenceActs) endAll(err error) {
	acts := func() []*daemonPresenceAct {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		acts := make([]*daemonPresenceAct, 0, len(self.actIdActs))
		for _, act := range self.actIdActs {
			acts = append(acts, act)
		}
		return acts
	}()
	for _, act := range acts {
		act.end(err)
	}
}

// Ends the act with err, once: a hold its run reaches or waits at answers err, so nothing more is signed, and it
// leaves the daemon's acts. A run past its last hold goes on: its signing and posts are the act's own.
func (self *daemonPresenceAct) end(err error) {
	// gone before its hold answers, so a call that sees it ended finds no act
	stop := func() func() bool {
		self.acts.stateLock.Lock()
		defer self.acts.stateLock.Unlock()
		if self.acts.actIdActs[self.actId] == self {
			delete(self.acts.actIdActs, self.actId)
		}
		return self.takeLapseWithLock()
	}()
	self.endOnce.Do(func() {
		self.endErr = err
		close(self.ended)
	})
	if stop != nil {
		stop()
	}
}

// Moves the lapse's generation on, so no lapse armed before ends the act, and hands back the last one's stop.
func (self *daemonPresenceAct) takeLapseWithLock() func() bool {
	self.lapseGeneration += 1
	stop := self.stopLapse
	self.stopLapse = nil
	return stop
}

// Starts the act's lapse again: Local.PresenceActTimeout from now it ends unsigned, unless a call drives it then or a
// later start or a call taking it moved the generation on. A non-positive bound ends it at once. Called with no lock
// held, since a clock may call back before it answers.
func (self *daemonPresenceAct) armLapse() {
	acts := self.acts
	generation := func() uint64 {
		acts.stateLock.Lock()
		defer acts.stateLock.Unlock()
		self.lapseGeneration += 1
		return self.lapseGeneration
	}()
	stop := acts.daemon.clock.AfterFunc(acts.daemon.settings.Local.PresenceActTimeout, func() {
		lapsed := func() bool {
			acts.stateLock.Lock()
			defer acts.stateLock.Unlock()
			return acts.actIdActs[self.actId] == self && !self.driving && self.lapseGeneration == generation
		}()
		if lapsed {
			self.end(errDaemonPresenceActLapsed)
		}
	})
	stale := func() func() bool {
		acts.stateLock.Lock()
		defer acts.stateLock.Unlock()
		if self.lapseGeneration != generation || acts.actIdActs[self.actId] != self {
			// a call took the act or it ended meanwhile: this lapse is spent already
			return stop
		}
		previous := self.stopLapse
		self.stopLapse = stop
		return previous
	}()
	if stale != nil {
		stale()
	}
}

// Holds the run at hold until a next call answers it or the act ends.
func (self *daemonPresenceAct) holdAt(hold *daemonPresenceHold) (*bridge.WebAuthnEvidence, error) {
	daemonCtx := self.acts.daemon.ctx
	select {
	case self.holds <- hold:
	case <-self.ended:
		return nil, self.endErr
	case <-daemonCtx.Done():
		return nil, daemonCtx.Err()
	}
	select {
	case answer := <-self.answers:
		return answer.evidence, answer.err
	case <-self.ended:
		return nil, self.endErr
	case <-daemonCtx.Done():
		return nil, daemonCtx.Err()
	}
}

// The hold a sidecarAct asks under the run's context: its countersigned bytes out where the log covers it, none where
// it does not, and the next call's evidence back. One act a run: a second asking signs nothing.
func (self *daemonPresenceAct) actHold(countersignedBytes []byte, presence bool) (*bridge.WebAuthnEvidence, error) {
	if !self.actHeld.CompareAndSwap(false, true) {
		return nil, errDaemonPresenceHeldTwice
	}
	hold := &daemonPresenceHold{}
	if presence {
		hold.message = bytes.Clone(countersignedBytes)
	}
	evidence, err := self.holdAt(hold)
	if err != nil {
		return nil, err
	}
	if presence && evidence == nil {
		return nil, errDaemonPresenceNoEvidence
	}
	return evidence, nil
}

// The check a core call takes beside the hold. The act runner asks the hold first, so this stands in for it where a
// call's own guard wants a check before the act runs, and holds the same way if asked.
func (self *daemonPresenceAct) check() SidecarPresenceCheck {
	return func(countersignedBytes []byte) (*bridge.WebAuthnEvidence, error) {
		return self.actHold(countersignedBytes, true)
	}
}

// Begins run as an act of kind on call's network, of subject, its context holding every sidecarAct it runs, and
// answers where it left the act: at its first hold, waiting for the next call; or its run's end, before any hold, so
// nothing was signed, the act kept for its next call, which answers what the run did, unless the caller drops it. A
// first call of the same kind and subject ends any act of it still waiting, unsigned.
func (self *daemonPresenceActs) begin(ctx context.Context, call *DaemonCall, kind string, subject string,
	run func(ctx context.Context, act *daemonPresenceAct) (any, error)) (*daemonPresenceAct, *daemonPresenceStep, error) {
	act := &daemonPresenceAct{
		acts:      self,
		actId:     NewId(),
		kind:      kind,
		networkId: call.NetworkId,
		session:   call.SessionDone,
		subject:   subject,
		holds:     make(chan *daemonPresenceHold),
		answers:   make(chan daemonPresenceAnswer, 1),
		ended:     make(chan struct{}),
		done:      make(chan struct{}),
		driving:   true,
	}
	superseded, err := func() ([]*daemonPresenceAct, error) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		superseded := []*daemonPresenceAct{}
		for _, held := range self.actIdActs {
			if held.kind == kind && held.networkId == act.networkId && held.subject == subject {
				if held.driving {
					return nil, ErrDaemonPresenceActBusy
				}
				superseded = append(superseded, held)
			}
		}
		if self.daemon.settings.Local.PresenceActCount <= len(self.actIdActs)-len(superseded) {
			return nil, ErrDaemonPresenceActCount
		}
		self.actIdActs[act.actId] = act
		return superseded, nil
	}()
	if err != nil {
		return nil, nil, err
	}
	for _, held := range superseded {
		held.end(errDaemonPresenceActSuperseded)
	}
	runCtx := withSidecarActHold(self.daemon.ctx, act.actHold)
	go func() {
		defer close(act.done)
		act.result, act.err = run(runCtx, act)
	}()
	if act.session != nil {
		go func() {
			select {
			case <-act.session:
				act.end(errDaemonPresenceSessionEnded)
			case <-act.ended:
			}
		}()
	}
	return act, self.await(ctx, act, true), nil
}

// Answers the hold act actId waits at with evidence, encoded, empty for none, as call, a next call of kind, which
// answers a new key's proof where proof is set and the act's check otherwise; then answers where the run left the act
// as begin does. An act whose run ended before any hold answers what it did, its evidence unread. Evidence that does
// not decode signs nothing.
func (self *daemonPresenceActs) next(ctx context.Context, call *DaemonCall, kind string, actId Id, evidence []byte, proof bool) (*daemonPresenceStep, error) {
	var stop func() bool
	act, completed, err := func() (*daemonPresenceAct, bool, error) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		act := self.actIdActs[actId]
		if act == nil || act.kind != kind || act.networkId != call.NetworkId || act.session != call.SessionDone || act.driving {
			return nil, false, ErrDaemonPresenceActUnknown
		}
		if act.completed {
			return act, true, nil
		}
		if act.waiting == nil || act.waiting.proof != proof {
			return act, false, ErrDaemonPresenceActStage
		}
		act.waiting = nil
		act.driving = true
		stop = act.takeLapseWithLock()
		return act, false, nil
	}()
	if stop != nil {
		stop()
	}
	switch {
	case errors.Is(err, ErrDaemonPresenceActStage):
		// a call out of order spends the act: nothing is signed
		act.end(err)
		return nil, err
	case err != nil:
		return nil, err
	case completed:
		act.end(errDaemonPresenceActFinished)
		return &daemonPresenceStep{result: act.result, err: act.err}, nil
	}
	answer := daemonPresenceAnswer{}
	if 0 < len(evidence) {
		answer.evidence = &bridge.WebAuthnEvidence{}
		if err := proto.Unmarshal(evidence, answer.evidence); err != nil || len(answer.evidence.GetKeyId()) == 0 ||
			len(answer.evidence.GetSignature()) == 0 {
			answer = daemonPresenceAnswer{err: errDaemonPresenceEvidence}
		}
	}
	// the run waits at its hold for exactly this, and the buffer holds it
	act.answers <- answer
	return self.await(ctx, act, false), nil
}

// Waits, within ctx, for act's next hold or its run's end. A hold leaves the act waiting for its next call, its lapse
// started again; a run that ended leaves it kept for its next call where keepEnded, a first call's way, else gone.
// ctx's end ends the act: a hold it reaches signs nothing, and a run past its last hold goes on unanswered.
func (self *daemonPresenceActs) await(ctx context.Context, act *daemonPresenceAct, keepEnded bool) *daemonPresenceStep {
	select {
	case hold := <-act.holds:
		kept := func() bool {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			if self.actIdActs[act.actId] != act {
				return false
			}
			act.driving = false
			act.waiting = hold
			return true
		}()
		if !kept {
			// it ended as it reached the hold, which answers why
			return &daemonPresenceStep{err: ErrDaemonPresenceActUnknown}
		}
		act.armLapse()
		return &daemonPresenceStep{hold: hold}
	case <-act.done:
		if !keepEnded {
			act.end(errDaemonPresenceActFinished)
			return &daemonPresenceStep{result: act.result, err: act.err}
		}
		kept := func() bool {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			if self.actIdActs[act.actId] != act {
				return false
			}
			act.driving = false
			act.completed = true
			return true
		}()
		if kept {
			act.armLapse()
		}
		return &daemonPresenceStep{result: act.result, err: act.err}
	case <-ctx.Done():
		act.end(errDaemonPresenceCallEnded)
		return &daemonPresenceStep{err: fmt.Errorf("%w: %w", errDaemonPresenceCallEnded, ctx.Err())}
	}
}

// §5.6's refusal in err, as a next call's reply carries it: a revocation's own code, REVOKE_CANCELLED for a check
// that failed, was refused or sent no evidence, and REVOKE_REFUSED for a statement api refused. Nil for any other
// error.
func daemonPresenceRefusal(err error) *DaemonDeviceRefusal {
	if refusal := daemonDeviceRefusal(err); refusal != nil {
		return refusal
	}
	switch {
	case errors.Is(err, ErrSidecarActPresence):
		return &DaemonDeviceRefusal{Code: DeviceRevokeCodeCancelled}
	case errors.Is(err, ErrSidecarActRefused):
		return &DaemonDeviceRefusal{Code: DeviceRevokeCodeRefused}
	}
	return nil
}

// A first call's answer for act at step, a family whose act holds once at its check: the hold's bytes; or, for a run
// that ended before any hold, signing nothing, §5.6's refusal or the run's error with the act dropped, else the act's
// id, its next call answering what the run did.
func daemonPresenceBeginAnswer(act *daemonPresenceAct, step *daemonPresenceStep) (*DaemonPresenceBeginReply, error) {
	if step.hold != nil {
		if step.hold.proof {
			act.end(ErrDaemonPresenceActStage)
			return nil, ErrDaemonPresenceActStage
		}
		return &DaemonPresenceBeginReply{ActId: &act.actId, Countersigned: bytes.Clone(step.hold.message)}, nil
	}
	if refusal := daemonPresenceRefusal(step.err); refusal != nil {
		act.end(errDaemonPresenceActFinished)
		return &DaemonPresenceBeginReply{Refusal: refusal}, nil
	}
	if step.err != nil {
		act.end(errDaemonPresenceActFinished)
		return nil, step.err
	}
	return &DaemonPresenceBeginReply{ActId: &act.actId}, nil
}

// A call's params into params, refusing a field it does not know; none is an empty object. Shared with the devices
// methods' decoding.
func decodeDaemonPresenceParams(call *DaemonCall, params any) error {
	return decodeDaemonDevicesParams(call, params)
}

// The remote-mode app's authenticator as RegisterPresenceKey asks it: the key the app made, its public half and
// attestation from the first call, and its proof asked of the app between the first and second calls. The key is the
// app's, so nothing here removes it: an app whose registration signed nothing takes its key off itself.
type daemonAppPresenceProvider struct {
	handle *PresenceKeyHandle
	act    *daemonPresenceAct
}

func (self *daemonAppPresenceProvider) Register(ctx context.Context) (*PresenceKeyHandle, error) {
	return &PresenceKeyHandle{
		KeyId:       bytes.Clone(self.handle.KeyId),
		Alg:         self.handle.Alg,
		PublicKey:   bytes.Clone(self.handle.PublicKey),
		Attestation: bytes.Clone(self.handle.Attestation),
	}, nil
}

func (self *daemonAppPresenceProvider) Holds(keyId []byte) bool {
	return bytes.Equal(keyId, self.handle.KeyId)
}

// The app's proof over message, asked at the act's hold: the next call's evidence, which must name the new key.
func (self *daemonAppPresenceProvider) Assert(ctx context.Context, keyId []byte, message []byte) (*bridge.WebAuthnEvidence, error) {
	if !bytes.Equal(keyId, self.handle.KeyId) {
		return nil, fmt.Errorf("%w: the app holds no such key", ErrPresenceNoKey)
	}
	evidence, err := self.act.holdAt(&daemonPresenceHold{message: bytes.Clone(message), proof: true})
	if err != nil {
		return nil, err
	}
	if evidence == nil || !bytes.Equal(evidence.GetKeyId(), self.handle.KeyId) {
		return nil, errDaemonPresenceNoEvidence
	}
	return evidence, nil
}

func (self *daemonAppPresenceProvider) Remove(keyId []byte) error {
	return nil
}

// The key algorithm a keys call names.
func daemonPresenceKeyAlg(name string) (bridge.KeyAlg, bool) {
	switch name {
	case DaemonPresenceAlgWebAuthnEs256:
		return bridge.KeyAlg_KEY_ALG_WEBAUTHN_ES256, true
	case DaemonPresenceAlgEcdsaP256Sha256:
		return bridge.KeyAlg_KEY_ALG_ECDSA_P256_SHA256, true
	}
	return 0, false
}

// A finished KeyRegister as keys.presence.finish answers it.
func newDaemonKeysPresenceReply(result any, err error) (*DaemonKeysPresenceReply, error) {
	reply := &DaemonKeysPresenceReply{}
	if key, ok := result.(*SidecarPresenceKey); ok && key != nil {
		reply.KeyId = bytes.Clone(key.KeyId)
		reply.Position = key.Position
		reply.NotAfterMs = daemonDevicesMs(key.NotAfter)
	}
	switch refusal := daemonPresenceRefusal(err); {
	case errors.Is(err, ErrSidecarActPending):
		reply.Pending = true
	case refusal != nil:
		return &DaemonKeysPresenceReply{Refusal: refusal}, nil
	case err != nil:
		return nil, err
	}
	return reply, nil
}

// A finished decision as approvals.decide.finish answers it.
func newDaemonApprovalsDecideReply(err error) (*DaemonApprovalsDecideReply, error) {
	switch refusal := daemonPresenceRefusal(err); {
	case errors.Is(err, ErrSidecarActPending):
		return &DaemonApprovalsDecideReply{Pending: true}, nil
	case refusal != nil:
		return &DaemonApprovalsDecideReply{Refusal: refusal}, nil
	case err != nil:
		return nil, err
	}
	return &DaemonApprovalsDecideReply{}, nil
}

// The daemon's two-call methods for a remote-mode app's decisions and its own presence key: approvals.decide.begin
// and .finish, keys.presence.begin, .prove and .finish. The devices methods carry the revocation's and the cosign's
// (DaemonDevicesMethods). The daemon's composition registers them with RegisterMethod.
func DaemonApprovalsMethods(daemon *Daemon) []*DaemonMethod {
	return []*DaemonMethod{
		{
			Name:    DaemonMethodApprovalsDecideBegin,
			Network: true,
			Confirm: true,
			Handler: func(ctx context.Context, call *DaemonCall) (any, error) {
				params := &DaemonApprovalsDecideParams{}
				if err := decodeDaemonPresenceParams(call, params); err != nil {
					return nil, err
				}
				if params.ApprovalId == (Id{}) || params.Decision == "" {
					return nil, errDaemonDevicesParams
				}
				running := call.Sidecar
				act, step, err := daemon.heldActs().begin(ctx, call, daemonPresenceKindApprovalsDecide, "approval/"+params.ApprovalId.String(),
					func(ctx context.Context, act *daemonPresenceAct) (any, error) {
						// Confirm let only a confirmed control call here; the origin says so to the act, which checks it again
						return nil, running.DecideApproval(ctx, params.ApprovalId, params.Decision, SidecarActConfirmed, act.check())
					})
				if err != nil {
					return nil, err
				}
				return daemonPresenceBeginAnswer(act, step)
			},
		},
		{
			Name:    DaemonMethodApprovalsDecideFinish,
			Network: true,
			Confirm: true,
			Handler: func(ctx context.Context, call *DaemonCall) (any, error) {
				params := &DaemonPresenceFinishParams{}
				if err := decodeDaemonPresenceParams(call, params); err != nil {
					return nil, err
				}
				step, err := daemon.heldActs().next(ctx, call, daemonPresenceKindApprovalsDecide, params.ActId, params.Evidence, false)
				if err != nil {
					return nil, err
				}
				if step.hold != nil {
					return nil, errDaemonPresenceHeldTwice
				}
				return newDaemonApprovalsDecideReply(step.err)
			},
		},
		{
			Name:    DaemonMethodKeysPresenceBegin,
			Network: true,
			Confirm: true,
			Handler: func(ctx context.Context, call *DaemonCall) (any, error) {
				params := &DaemonKeysPresenceBeginParams{}
				if err := decodeDaemonPresenceParams(call, params); err != nil {
					return nil, err
				}
				alg, ok := daemonPresenceKeyAlg(params.Alg)
				if !ok || len(params.KeyId) == 0 || len(params.PublicKey) == 0 {
					return nil, errDaemonDevicesParams
				}
				handle := &PresenceKeyHandle{
					KeyId:       bytes.Clone(params.KeyId),
					Alg:         alg,
					PublicKey:   bytes.Clone(params.PublicKey),
					Attestation: bytes.Clone(params.Attestation),
				}
				running := call.Sidecar
				act, step, err := daemon.heldActs().begin(ctx, call, daemonPresenceKindKeysPresence, fmt.Sprintf("key/%x", params.KeyId),
					func(ctx context.Context, act *daemonPresenceAct) (any, error) {
						return running.RegisterPresenceKey(ctx, &daemonAppPresenceProvider{handle: handle, act: act}, SidecarActConfirmed, act.check())
					})
				if err != nil {
					return nil, err
				}
				if step.hold == nil || !step.hold.proof {
					// every registration asks the new key's proof first: one that did not refused before it
					act.end(errDaemonPresenceActFinished)
					if step.err != nil {
						return nil, step.err
					}
					return nil, ErrDaemonPresenceActStage
				}
				return &DaemonKeysPresenceBeginReply{ActId: &act.actId, Proof: bytes.Clone(step.hold.message)}, nil
			},
		},
		{
			Name:    DaemonMethodKeysPresenceProve,
			Network: true,
			Confirm: true,
			Handler: func(ctx context.Context, call *DaemonCall) (any, error) {
				params := &DaemonPresenceFinishParams{}
				if err := decodeDaemonPresenceParams(call, params); err != nil {
					return nil, err
				}
				step, err := daemon.heldActs().next(ctx, call, daemonPresenceKindKeysPresence, params.ActId, params.Evidence, true)
				if err != nil {
					return nil, err
				}
				if step.hold != nil {
					if step.hold.proof {
						return nil, errDaemonPresenceHeldTwice
					}
					// the act's own hold, which the third call answers as a second call does
					return &DaemonPresenceBeginReply{ActId: &params.ActId, Countersigned: bytes.Clone(step.hold.message)}, nil
				}
				// a run never signs before its act's hold, so one that ended here refused
				if refusal := daemonPresenceRefusal(step.err); refusal != nil {
					return &DaemonPresenceBeginReply{Refusal: refusal}, nil
				}
				if step.err != nil {
					return nil, step.err
				}
				return nil, ErrDaemonPresenceActStage
			},
		},
		{
			Name:    DaemonMethodKeysPresenceFinish,
			Network: true,
			Confirm: true,
			Handler: func(ctx context.Context, call *DaemonCall) (any, error) {
				params := &DaemonPresenceFinishParams{}
				if err := decodeDaemonPresenceParams(call, params); err != nil {
					return nil, err
				}
				step, err := daemon.heldActs().next(ctx, call, daemonPresenceKindKeysPresence, params.ActId, params.Evidence, false)
				if err != nil {
					return nil, err
				}
				if step.hold != nil {
					return nil, errDaemonPresenceHeldTwice
				}
				return newDaemonKeysPresenceReply(step.result, step.err)
			},
		},
	}
}

// One act by §5.8's two calls on this control session, the caller's side of the file's comment: beginMethod with
// beginParams, confirmed; then, once sign answered §6.9's WebAuthnEvidence, encoded, over the countersigned bytes the
// daemon answered, or with nothing asked for an act the log does not cover, finishMethod with it, confirmed, its
// answer decoded into result. A refusal of the first call is answered with nothing sent after it; an error of sign
// ends it after the first call, and the act the daemon holds lapses unsigned. What the sdk's remote backend does
// (SDK-M8-05), for a Go caller of the daemon.
func (self *DaemonClient) CallPresenceAct(ctx context.Context, network string, beginMethod string, beginParams any, finishMethod string,
	sign func(countersignedBytes []byte) ([]byte, error), result any) (*DaemonDeviceRefusal, error) {
	begin := &DaemonPresenceBeginReply{}
	if err := self.Call(ctx, beginMethod, beginParams, true, begin); err != nil {
		return nil, err
	}
	if begin.Refusal != nil {
		return begin.Refusal, nil
	}
	if begin.ActId == nil {
		return nil, errors.New("the daemon's first call named no act")
	}
	finish := &DaemonPresenceFinishParams{Network: network, ActId: *begin.ActId}
	if 0 < len(begin.Countersigned) {
		evidence, err := sign(bytes.Clone(begin.Countersigned))
		if err != nil {
			return nil, err
		}
		finish.Evidence = evidence
	}
	return nil, self.Call(ctx, finishMethod, finish, true, result)
}
