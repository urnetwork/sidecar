// sidecarAct (CORE-M2-02, D-CORE-13, D-CORE-20, D-TEAM-32, C-02): every act that signs §7.9 or §8.8 statements runs
// through one runner, which owns the order and the rule and nothing of the rule's content:
//
//	build     every statement of the act first, each with its StatementHeader (network, the verified pin, a fresh
//	          16-byte nonce, a not_after inside §7.9's 7 days); Add lets another track join statements to an act, and
//	          AddStaleRevocations puts §7.10's stale revocations first (identity_act_stale.go)
//	presence  if the log says any statement is covered (SidecarAuthority.PresenceRequired, never the caller), one check
//	          over the act's countersigned bytes, PresenceActBytes(signer, m, RFC 9162's root over each statement's
//	          signed bytes); evidence that does not verify against a live key of this sidecar's signs nothing
//	sign      each statement by the identity key (Sidecar.Sign), the countersignature riding each with its own
//	          inclusion path
//	keep      every signed statement in keychain.ur's pending records (identity_pending.go) before any is posted
//	post      each to POST /network/config/delta in act order, testHookBarrier around each, a stale revocation re-checked
//	          first; a statement whose answer is lost stays pending with the rest of its act, and PostPendingStatements
//	          retries the same bytes in the same order until its not_after
//
// The check is the caller's function value: the daemon's presence prompt, §16's, or an app's SidecarPresenceSigner;
// a remote-mode app's takes two calls, CountersignedBytes and Countersign (CORE-M8-03). A sidecar with no live key
// signs on the person's confirmation alone, which the origin carries, and a recovery key's statements are not this
// runner's.
//
// Mode grants nothing (D-CORE-13): an act whose origin is not a person's confirmation, MCP's, a hook's or an
// unconfirmed control call's, signs only §5.8's own-resource filings, a closed list of types (sidecarOwnResourceTypes),
// and an outward one of those only after §5.4's gate (sidecar_gate.go) passed it.
//
// On every leg: root Id, no connect type. An act is used by one goroutine; Run once.

package sidecar

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// Who asked for an act, and whether a person confirmed it.
type SidecarActOrigin int

const (
	// A person confirmed it: a ur command on /dev/tty, an app's UI, or a remote-mode app's control call its host
	// confirmed (§5.8).
	SidecarActConfirmed SidecarActOrigin = iota + 1
	// An MCP session's tool call.
	SidecarActMcp
	// A harness hook's event.
	SidecarActHook
	// A control-mode call no person confirmed.
	SidecarActUnconfirmed
)

// The check an act runs when the log covers it: given the act's countersigned bytes, the presence key's evidence over
// them (§16.6's countersign profile), or an error when the person refused or the key failed.
type SidecarPresenceCheck func(countersignedBytes []byte) (*bridge.WebAuthnEvidence, error)

var (
	// The act's origin is not a person's confirmation, and a statement is not an own-resource filing (D-CORE-13).
	ErrSidecarActMode = errors.New("this statement needs the person's confirmation on /dev/tty or in an app, never MCP, a hook or an unconfirmed call")
	// The log covers the act and no check passed: it failed, was refused, or sent no evidence verifying against a live
	// presence key of this sidecar's. Nothing was signed (REVOKE_CANCELLED).
	ErrSidecarActPresence = errors.New("the presence check failed, was refused or did not verify")
	// No verified config state is installed, so no statement can carry a pin or be judged.
	ErrSidecarActNoAuthority = errors.New("no verified config state")
	// api or a verifier refused a statement at the tip, or none landed by its not_after (REVOKE_REFUSED).
	ErrSidecarActRefused = errors.New("api refused the statement")
	// An act with no statement, or one run twice.
	ErrSidecarActState = errors.New("the act has no statement, or has run")
	// The act signed and kept its statements, and a post's answer was lost or api was unavailable: they stay pending
	// and go again with the same bytes (PostPendingStatements). The decision is made; nothing is to be signed again.
	ErrSidecarActPending = errors.New("the statements are signed and pending: their post goes again")
)

// §5.8's own-resource filings, signed from any mode: a GrantActivate of this sidecar's own approved request, a
// GrantRevoke of a grant whose subject it is, its own BridgeAddress for its first map, and the BridgeRoute, BridgeMap
// and BridgeWithdraw of its own rules. Closed: a type joins only with the design's change. Whether the resource is this
// sidecar's own is the statement's verifier's rule (§8.8, §17), which refuses another's.
var sidecarOwnResourceTypes = map[bridge.SignedType]bool{
	bridge.SignedType_SIGNED_GRANT_ACTIVATE:  true,
	bridge.SignedType_SIGNED_GRANT_REVOKE:    true,
	bridge.SignedType_SIGNED_BRIDGE_ADDRESS:  true,
	bridge.SignedType_SIGNED_BRIDGE_ROUTE:    true,
	bridge.SignedType_SIGNED_BRIDGE_MAP:      true,
	bridge.SignedType_SIGNED_BRIDGE_WITHDRAW: true,
}

// What an act runs on: its tunables.
type sidecarActSettings struct {
	// How long a statement may wait to land: its StatementHeader's not_after, at most §7.9's 7 days.
	statementTimeout time.Duration
}

// One statement of an act.
type sidecarActStatement struct {
	signedType bridge.SignedType
	purpose    string
	// the statement's bytes with its header, as they are signed
	body []byte
	// the header's not_after, ms since the epoch
	notAfterMs int64
	// set on §7.10's stale revocations, which each post and retry re-checks (identity_act_stale.go)
	stale *sidecarStaleRevocation
}

// One act. Construct with Sidecar.newAct.
type sidecarAct struct {
	sidecar   *Sidecar
	authority SidecarAuthority
	origin    SidecarActOrigin
	identity  *SidecarIdentity
	// the verified pin every statement's header carries
	at         *bridge.AuthPin
	random     io.Reader
	statements []*sidecarActStatement
	// set by CountersignedBytes and Countersign
	countersigned []byte
	presence      bool
	evidence      *bridge.WebAuthnEvidence
	ran           bool
}

// A new act of origin's, at the installed authority's pin. ErrSidecarActNoAuthority with none installed and
// ErrSidecarNoIdentity before enrollment.
func (self *Sidecar) newAct(origin SidecarActOrigin) (*sidecarAct, error) {
	authority := self.authority()
	if authority == nil {
		return nil, ErrSidecarActNoAuthority
	}
	identity := self.currentIdentity()
	if identity == nil {
		return nil, ErrSidecarNoIdentity
	}
	pin := authority.Pin()
	if pin == nil {
		return nil, ErrSidecarActNoAuthority
	}
	return &sidecarAct{
		sidecar:   self,
		authority: authority,
		origin:    origin,
		identity:  identity,
		at:        &bridge.AuthPin{Version: pin.GetVersion(), Chain: bytes.Clone(pin.GetChain())},
		random:    rand.Reader,
	}, nil
}

// Adds statement, a §7.9 or §8.8 message whose field 1 is its StatementHeader, which Add sets: this network, the act's
// pin, a fresh nonce and a not_after StatementTimeout from now. Refuses a type the identity key does not sign under a
// statement purpose, and, unless the origin is a person's confirmation, any type but an own-resource filing.
func (self *sidecarAct) Add(signedType bridge.SignedType, statement proto.Message) error {
	return self.AddSealed(signedType, statement, nil)
}

// Add, with seal run on the statement once its StatementHeader is set and before it is encoded, nil for none: what a
// statement with a sealed field needs, since the seal binds the header's network and nonce
// (plan-TEAM-sealed-field-format), as IndexerSet's services (TEAM-M2-18).
func (self *sidecarAct) AddSealed(signedType bridge.SignedType, statement proto.Message, seal func(header *bridge.StatementHeader, statement proto.Message) error) error {
	if self.ran {
		return ErrSidecarActState
	}
	purpose, ok := sidecarIdentitySignedPurpose(signedType)
	if !ok || (purpose != bridge.SignedPurposeAuthority && purpose != bridge.SignedPurposeAcl && !sidecarOwnResourceTypes[signedType]) {
		return fmt.Errorf("%w: type %#x is no statement this act signs", ErrSidecarSignRefused, int32(signedType))
	}
	if self.origin != SidecarActConfirmed && !sidecarOwnResourceTypes[signedType] {
		return ErrSidecarActMode
	}
	headerField := statement.ProtoReflect().Descriptor().Fields().ByNumber(1)
	if headerField == nil || headerField.Kind() != protoreflect.MessageKind ||
		headerField.Message().FullName() != (&bridge.StatementHeader{}).ProtoReflect().Descriptor().FullName() {
		return fmt.Errorf("%w: the statement carries no StatementHeader", ErrSidecarSignRefused)
	}
	nonce := make([]byte, configNonceByteCount)
	if _, err := io.ReadFull(self.random, nonce); err != nil {
		return fmt.Errorf("no randomness for a nonce: %w", err)
	}
	notAfterMs := self.notAfterMs()
	header := &bridge.StatementHeader{
		NetworkId:  self.identity.NetworkId.Bytes(),
		At:         &bridge.AuthPin{Version: self.at.GetVersion(), Chain: bytes.Clone(self.at.GetChain())},
		Nonce:      nonce,
		NotAfterMs: notAfterMs,
	}
	withHeader := proto.Clone(statement)
	withHeader.ProtoReflect().Set(headerField, protoreflect.ValueOfMessage(header.ProtoReflect()))
	if seal != nil {
		if err := seal(header, withHeader); err != nil {
			return err
		}
	}
	body, err := proto.MarshalOptions{Deterministic: true}.Marshal(withHeader)
	if err != nil {
		return err
	}
	self.statements = append(self.statements, &sidecarActStatement{
		signedType: signedType,
		purpose:    purpose,
		body:       body,
		notAfterMs: notAfterMs,
	})
	self.countersigned = nil
	self.evidence = nil
	return nil
}

// A statement's not_after from now, ms since the epoch: StatementTimeout, at most §7.9's 7 days.
func (self *sidecarAct) notAfterMs() int64 {
	timeout := min(self.sidecar.settings.statementTimeout(), time.Duration(configStatementMaxLifetimeMs)*time.Millisecond)
	return self.sidecar.clock.Now().Add(timeout).UnixMilli()
}

// The statement digests in act order, which an act's tree hashes.
func (self *sidecarAct) digests() [][sha256.Size]byte {
	digests := make([][sha256.Size]byte, 0, len(self.statements))
	for _, statement := range self.statements {
		digests = append(digests, bridge.SignedBytesSha256(statement.purpose, statement.signedType, statement.body))
	}
	return digests
}

// The act's countersigned bytes, and whether the log requires a presence check over them: true when §7.9's presence
// row covers any of its statements as this sidecar signs them (SidecarAuthority.PresenceRequired), read here, never
// from a caller. A remote-mode app's first call (CORE-M8-03).
func (self *sidecarAct) CountersignedBytes() ([]byte, bool, error) {
	if len(self.statements) == 0 || self.ran {
		return nil, false, ErrSidecarActState
	}
	presence := false
	for _, statement := range self.statements {
		if self.authority.PresenceRequired(&SidecarStatement{SignerId: self.identity.SidecarId, Type: statement.signedType, Body: statement.body}) {
			presence = true
		}
	}
	root, err := bridge.PresenceActRoot(self.digests())
	if err != nil {
		return nil, false, err
	}
	self.countersigned = bridge.PresenceActBytes(self.identity.SidecarId.Bytes(), uint32(len(self.statements)), root)
	self.presence = presence
	return bytes.Clone(self.countersigned), presence, nil
}

// The verifier's key algorithm of a registered presence key, false for a key that is not one.
func sidecarPresenceKeyAlg(key *bridge.KeyRow) (bridge.SignedKeyAlg, bool) {
	if key.GetPurpose() != bridge.KeyPurpose_KEY_PURPOSE_PRESENCE {
		return 0, false
	}
	switch key.GetAlg() {
	case bridge.KeyAlg_KEY_ALG_WEBAUTHN_ES256:
		return bridge.SignedKeyAlgWebAuthnEs256, true
	case bridge.KeyAlg_KEY_ALG_ECDSA_P256_SHA256:
		return bridge.SignedKeyAlgEcdsaP256, true
	}
	return 0, false
}

// The countersignature statement i carries: evidence with its act fields set.
func (self *sidecarAct) countersignatureAt(evidence *bridge.WebAuthnEvidence, index int) (*bridge.WebAuthnEvidence, error) {
	path, err := bridge.PresenceActPath(self.digests(), uint32(index))
	if err != nil {
		return nil, err
	}
	countersignature := proto.Clone(evidence).(*bridge.WebAuthnEvidence)
	countersignature.ActSize = uint32(len(self.statements))
	countersignature.ActIndex = uint32(index)
	countersignature.ActPath = path
	return countersignature, nil
}

// Takes evidence over the countersigned bytes CountersignedBytes answered, verifying it for every statement against
// the live presence key its key_id names (bridge.VerifyPresenceCountersign), as api and every member device will. A
// remote-mode app's second call (CORE-M8-03). ErrSidecarActPresence when it does not verify.
func (self *sidecarAct) Countersign(evidence *bridge.WebAuthnEvidence) error {
	if self.countersigned == nil || self.ran {
		return ErrSidecarActState
	}
	if evidence == nil || len(evidence.GetKeyId()) == 0 {
		return ErrSidecarActPresence
	}
	var key *bridge.KeyRow
	for _, liveKey := range self.authority.LiveKeys(self.identity.SidecarId) {
		if bytes.Equal(liveKey.GetKeyId(), evidence.GetKeyId()) {
			key = liveKey
		}
	}
	if key == nil {
		return fmt.Errorf("%w: no live presence key of this sidecar's has that key_id", ErrSidecarActPresence)
	}
	keyAlg, ok := sidecarPresenceKeyAlg(key)
	if !ok {
		return fmt.Errorf("%w: the key is no presence key", ErrSidecarActPresence)
	}
	for index, statement := range self.statements {
		countersignature, err := self.countersignatureAt(evidence, index)
		if err != nil {
			return err
		}
		signed := &bridge.Signed{
			Body:     statement.body,
			SignerId: self.identity.SidecarId.Bytes(),
			Type:     uint32(statement.signedType),
			Webauthn: countersignature,
		}
		if err := bridge.VerifyPresenceCountersign(signed, statement.purpose, keyAlg, key.GetPublicKey()); err != nil {
			return fmt.Errorf("%w: %w", ErrSidecarActPresence, err)
		}
	}
	self.evidence = proto.Clone(evidence).(*bridge.WebAuthnEvidence)
	return nil
}

// Runs the act: the presence check where the log requires one, check being called with the countersigned bytes unless
// Countersign already took evidence; then signs every statement, keeps each in the pending records with its place in
// the act, and posts each in act order, re-checking a stale revocation first (identity_act_stale.go). Answers each
// statement's entry (n, A_n), in act order, nil for a stale revocation dropped unposted. A failed, refused or
// non-verifying check signs nothing (ErrSidecarActPresence); an act needing presence with no check is the same. A
// statement api refuses is dropped (ErrSidecarActRefused); one whose answer is lost stays pending with the rest of its
// act, ErrSidecarActPending, and PostPendingStatements retries the same bytes in the same order.
func (self *sidecarAct) Run(ctx context.Context, check SidecarPresenceCheck) ([]*bridge.AuthPin, error) {
	if len(self.statements) == 0 || self.ran {
		return nil, ErrSidecarActState
	}
	if self.countersigned == nil {
		if _, _, err := self.CountersignedBytes(); err != nil {
			return nil, err
		}
	}
	if self.presence && self.evidence == nil {
		if check == nil {
			return nil, fmt.Errorf("%w: the log requires a presence check and none was given", ErrSidecarActPresence)
		}
		evidence, err := check(bytes.Clone(self.countersigned))
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrSidecarActPresence, err)
		}
		if err := self.Countersign(evidence); err != nil {
			return nil, err
		}
	}
	self.ran = true

	// the act's id and each statement's place in it, kept beside each, so a retry posts them in this order
	var actId Id
	if _, err := io.ReadFull(self.random, actId[:]); err != nil {
		return nil, fmt.Errorf("no randomness for an act id: %w", err)
	}
	signedStatements := make([]*sidecarPendingStatement, 0, len(self.statements))
	for index, statement := range self.statements {
		signed, err := self.sidecar.Sign(statement.purpose, statement.signedType, statement.body, nil)
		if err != nil {
			return nil, err
		}
		if self.presence {
			countersignature, err := self.countersignatureAt(self.evidence, index)
			if err != nil {
				return nil, err
			}
			signed.Webauthn = countersignature
		}
		signedBytes, err := proto.Marshal(signed)
		if err != nil {
			return nil, err
		}
		signedStatements = append(signedStatements, &sidecarPendingStatement{
			signed:     signedBytes,
			notAfterMs: statement.notAfterMs,
			act:        &sidecarPendingAct{actId: actId, index: uint32(index), stale: statement.stale},
		})
	}
	// every statement is kept before any is posted, so a kill between two posts retries the rest's same bytes
	for _, pending := range signedStatements {
		if err := self.sidecar.keepPendingStatement(pending); err != nil {
			return nil, err
		}
	}
	pins := make([]*bridge.AuthPin, 0, len(signedStatements))
	for _, pending := range signedStatements {
		pin, err := self.sidecar.postPendingInOrder(ctx, pending)
		if err != nil {
			if errors.Is(err, ErrSidecarActRefused) {
				return pins, err
			}
			return pins, fmt.Errorf("%w: %w", ErrSidecarActPending, err)
		}
		// nil for a stale revocation dropped unposted, its Worker holding a leaf again
		pins = append(pins, pin)
	}
	return pins, nil
}

// A statement's not_after from now: at most §7.9's 7 days.
func (self *SidecarSettings) statementTimeout() time.Duration {
	if self.StatementTimeout <= 0 {
		return time.Duration(configStatementMaxLifetimeMs) * time.Millisecond
	}
	return self.StatementTimeout
}
