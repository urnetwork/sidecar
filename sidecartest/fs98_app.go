//go:build !js && !ios && !android && !sdk_mobile_bind

// FS-98's and FS-124's app-host world (CORE-M8-03; §5.8's two calls, §18.5's SidecarApprovals, D-SDK-30, D-CORE-20):
// what an app host adds to the CLI world (fs98.go). An app's presence key is a FixtureAppSigner, its
// SidecarPresenceSigner: SignWithPresence over a message after the person's check, "" when the person refuses.
//
//	phone    an app in local mode (sdk.NewSidecarLocal): it runs a host's Sidecar in process and calls the core as
//	         SidecarApprovals' local backend does, a person's confirmation in the app's UI, each act's check its
//	         signer's SignWithPresence over the act's countersigned bytes (the sdk's sidecarPresenceCheckOf), its own
//	         key registered from that signer
//	desktop  an app in remote mode (sdk.NewSidecarRemote) paired to a host's daemon: each call goes over §5.8's control
//	         mode on a session of the app's own, its acts by the two calls, the app signing each first call's bytes by
//	         its SignWithPresence (DaemonClient.CallPresenceAct), and its own KeyRegister by three, the first answering
//	         the bytes the new key proves itself over
//
// A refusal the app's signer makes ends its act where the sdk does: in process, the act's check fails; over the
// daemon, no further call is sent and the session closes, which ends the act the daemon holds unsigned. The sdk's own
// adapters, gomobile's, the C ABI's and js's, are §18's T4 rows (SDK-M8-15), which this world does not run.

package sidecartest

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The person refused an app's presence check: its SignWithPresence answered "".
var ErrFixtureAppRefused = errors.New("the person refused the app's presence check")

// An app's SidecarPresenceSigner (§18.5) as a test holds it: one fixture key, which signs a message after the person's
// check, and the refusal a test sets. Safe for concurrent use.
type FixtureAppSigner struct {
	stateLock sync.Mutex
	key       *FixturePresenceKey
	refuse    bool
	asked     [][]byte
}

// A signer whose key is seed's of alg, webauthn-es256 or ecdsa-p256-sha256.
func NewFixtureAppSigner(seed string, alg bridge.KeyAlg) *FixtureAppSigner {
	return &FixtureAppSigner{key: NewFixturePresenceKey(seed, alg)}
}

// The key as the app's GetAttestation hands it over: its id, profile and public half, with no attestation (QD-137's
// none conveyance).
func (self *FixtureAppSigner) Handle() *sidecar.PresenceKeyHandle {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return &sidecar.PresenceKeyHandle{KeyId: bytes.Clone(self.key.KeyId), Alg: self.key.Alg, PublicKey: bytes.Clone(self.key.PublicKey)}
}

// The key's id.
func (self *FixtureAppSigner) KeyId() []byte {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return bytes.Clone(self.key.KeyId)
}

// Whether every SignWithPresence from now on is refused, the person cancelling the check.
func (self *FixtureAppSigner) Refuse(refuse bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.refuse = refuse
}

// The messages SignWithPresence was asked over, refused ones among them, in order.
func (self *FixtureAppSigner) Asked() [][]byte {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	asked := make([][]byte, 0, len(self.asked))
	for _, message := range self.asked {
		asked = append(asked, bytes.Clone(message))
	}
	return asked
}

// §18.5's SignWithPresence: standard base64 of the message in; standard base64 of §6.9's WebAuthnEvidence, encoded,
// out, its key_id and DER signature, with the assertion beside them for webauthn-es256; "" when refused.
func (self *FixtureAppSigner) SignWithPresence(messageBase64 string) string {
	message, err := base64.StdEncoding.DecodeString(messageBase64)
	if err != nil {
		return ""
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.asked = append(self.asked, bytes.Clone(message))
	if self.refuse {
		return ""
	}
	evidence, signature := self.key.Assert(message)
	if evidence == nil {
		evidence = &bridge.WebAuthnEvidence{}
	}
	evidence.KeyId = bytes.Clone(self.key.KeyId)
	evidence.Signature = signature
	encoded, err := proto.Marshal(evidence)
	if err != nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(encoded)
}

// SignWithPresence over message, its answer decoded: the evidence's bytes, or ErrFixtureAppRefused.
func (self *FixtureAppSigner) Sign(message []byte) ([]byte, error) {
	answer := self.SignWithPresence(base64.StdEncoding.EncodeToString(message))
	if answer == "" {
		return nil, ErrFixtureAppRefused
	}
	return base64.StdEncoding.DecodeString(answer)
}

// The check an app in local mode hands the core, as the sdk's sidecarPresenceCheckOf makes it: the act's bytes
// through SignWithPresence, its answer decoded, a refusal the check's error.
func (self *FixtureAppSigner) Check() sidecar.SidecarPresenceCheck {
	return func(countersignedBytes []byte) (*bridge.WebAuthnEvidence, error) {
		encoded, err := self.Sign(countersignedBytes)
		if err != nil {
			return nil, err
		}
		evidence := &bridge.WebAuthnEvidence{}
		if err := proto.Unmarshal(encoded, evidence); err != nil {
			return nil, err
		}
		return evidence, nil
	}
}

// The authenticator an app in local mode registers its key from: its one key, whose proof SignWithPresence makes. It
// takes nothing off the app's authenticator.
func (self *FixtureAppSigner) Provider() sidecar.PresenceProvider {
	return &fixtureAppProvider{signer: self}
}

type fixtureAppProvider struct {
	signer *FixtureAppSigner
}

func (self *fixtureAppProvider) Register(ctx context.Context) (*sidecar.PresenceKeyHandle, error) {
	return self.signer.Handle(), nil
}

func (self *fixtureAppProvider) Holds(keyId []byte) bool {
	return bytes.Equal(keyId, self.signer.KeyId())
}

func (self *fixtureAppProvider) Assert(ctx context.Context, keyId []byte, message []byte) (*bridge.WebAuthnEvidence, error) {
	if !self.Holds(keyId) {
		return nil, errors.New("the app holds no such key")
	}
	return self.signer.Check()(message)
}

func (self *fixtureAppProvider) Remove(keyId []byte) error {
	return nil
}

// An app on a host of the world.
type Fs98AppHost struct {
	Name string
	// The host whose Sidecar the app runs in process, or whose daemon it reaches.
	Host *Fs98Host
	// The app's presence key.
	Signer *FixtureAppSigner
	// The app reaches its host's daemon over control mode, as a desktop app in remote mode does; else it runs the
	// host's Sidecar in process, as a phone's does.
	Remote bool

	world *Fs98World
}

// Adds an app named name on host: a phone's in local mode, running host's Sidecar in process, or with remote a desktop
// app's, paired to host's daemon. Its signer's key is of alg, from a seed of the network and name.
func (self *Fs98World) AddApp(name string, host *Fs98Host, remote bool, alg bridge.KeyAlg) *Fs98AppHost {
	self.t.Helper()
	return &Fs98AppHost{
		Name:   name,
		Host:   host,
		Signer: NewFixtureAppSigner(self.admission.NetworkId().String()+" app "+name, alg),
		Remote: remote,
		world:  self,
	}
}

// A control session of the app's own on its host's daemon, as the sdk's remote backend holds one.
func (self *Fs98AppHost) dial() *sidecar.DaemonClient {
	self.world.t.Helper()
	hello := &sidecar.DaemonHello{Mode: sidecar.DaemonModeControl, Version: sidecar.Version, Pid: int64(os.Getpid())}
	client, err := sidecar.DialDaemon(self.world.admission.ctx, self.Host.SocketPath, hello)
	if err != nil {
		self.world.t.Fatalf("%s: the daemon: %v", self.Name, err)
	}
	return client
}

// One call on a session of the app's own, its reply decoded into reply. The rpc's error is answered.
func (self *Fs98AppHost) call(method string, params any, confirmed bool, reply any) error {
	client := self.dial()
	defer client.Close()
	return client.Call(self.world.admission.ctx, method, params, confirmed, reply)
}

// A time as a reply carries it, 0 for none.
func fs98AppMs(at time.Time) int64 {
	if at.IsZero() {
		return 0
	}
	return at.UnixMilli()
}

// GetDevices: the member's devices, this one first.
func (self *Fs98AppHost) Devices() []*sidecar.DaemonDevice {
	self.world.t.Helper()
	self.world.catchUp()
	if self.Remote {
		reply := &sidecar.DaemonDevicesListReply{}
		if err := self.call(sidecar.DaemonMethodDevicesList, &sidecar.DaemonDevicesListParams{}, false, reply); err != nil {
			self.world.t.Fatalf("%s: GetDevices: %v", self.Name, err)
		}
		return reply.Devices
	}
	devices, err := self.Host.Sidecar.Sidecar().Devices()
	if err != nil {
		self.world.t.Fatalf("%s: GetDevices: %v", self.Name, err)
	}
	listed := []*sidecar.DaemonDevice{}
	for _, device := range devices {
		listed = append(listed, &sidecar.DaemonDevice{
			SidecarId:    device.SidecarId,
			Name:         device.Name,
			This:         device.This,
			ReadOnly:     device.ReadOnly,
			Ephemeral:    device.Ephemeral,
			State:        device.State,
			AdmittedAtMs: fs98AppMs(device.AdmittedAt),
			LastChangeMs: fs98AppMs(device.LastChange),
		})
	}
	return listed
}

// PreviewRevokeDevice: the plan the app shows the person, or §5.6's refusal.
func (self *Fs98AppHost) Preview(device sidecar.Id, reason string, sinceN uint64, lostAt time.Time) *sidecar.DaemonDevicesPreviewReply {
	self.world.t.Helper()
	self.world.catchUp()
	if self.Remote {
		params := &sidecar.DaemonDevicesPreviewParams{Device: device.String(), Reason: reason, SinceN: sinceN, LostAtMs: fs98AppMs(lostAt)}
		reply := &sidecar.DaemonDevicesPreviewReply{}
		if err := self.call(sidecar.DaemonMethodDevicesPreview, params, false, reply); err != nil {
			self.world.t.Fatalf("%s: PreviewRevokeDevice: %v", self.Name, err)
		}
		return reply
	}
	plan, err := self.Host.Sidecar.Sidecar().PreviewDeviceRevoke(self.world.admission.ctx, device, reason, lostAt, sinceN)
	var revokeError *sidecar.DeviceRevokeError
	if errors.As(err, &revokeError) {
		return &sidecar.DaemonDevicesPreviewReply{Refusal: &sidecar.DaemonDeviceRefusal{Code: revokeError.Code, Position: revokeError.Position}}
	}
	if err != nil {
		self.world.t.Fatalf("%s: PreviewRevokeDevice: %v", self.Name, err)
	}
	return &sidecar.DaemonDevicesPreviewReply{Plan: sidecar.NewDaemonDeviceRevokePlan(plan)}
}

// RevokeDevice of plan after the person confirmed it in the app, with the key items they left selected: in process
// the core's under the signer's check; over the daemon by the two calls, the signer signing the first call's bytes. A
// refused check is REVOKE_CANCELLED either way, the remote app sending no second call. What landed is applied at every
// reader.
func (self *Fs98AppHost) Revoke(plan *sidecar.DaemonDeviceRevokePlan, revokeKeyIds ...[]byte) *sidecar.DaemonDevicesRevokeReply {
	self.world.t.Helper()
	self.world.catchUp()
	defer self.world.Settle()
	if !self.Remote {
		revocation, err := self.Host.Sidecar.Sidecar().RevokeDevicePlan(self.world.admission.ctx, plan.PlanId, revokeKeyIds, sidecar.SidecarActConfirmed, self.Signer.Check())
		reply, err := sidecar.NewDaemonDevicesRevokeReply(revocation, err)
		if err != nil {
			self.world.t.Fatalf("%s: RevokeDevice: %v", self.Name, err)
		}
		return reply
	}
	params := &sidecar.DaemonDevicesRevokeParams{PlanId: plan.PlanId, RevokeKeyIds: []string{}}
	for _, keyId := range revokeKeyIds {
		params.RevokeKeyIds = append(params.RevokeKeyIds, hex.EncodeToString(keyId))
	}
	client := self.dial()
	// the session's end ends an act the app left unanswered
	defer client.Close()
	reply := &sidecar.DaemonDevicesRevokeReply{}
	refusal, err := client.CallPresenceAct(self.world.admission.ctx, "", sidecar.DaemonMethodDevicesRevokeBegin, params,
		sidecar.DaemonMethodDevicesRevokeFinish, self.Signer.Sign, reply)
	switch {
	case errors.Is(err, ErrFixtureAppRefused):
		// the sdk answers the refusal itself and sends no second call
		return &sidecar.DaemonDevicesRevokeReply{Refusal: &sidecar.DaemonDeviceRefusal{Code: sidecar.DeviceRevokeCodeCancelled}}
	case err != nil:
		self.world.t.Fatalf("%s: RevokeDevice: %v", self.Name, err)
	case refusal != nil:
		return &sidecar.DaemonDevicesRevokeReply{Refusal: refusal}
	}
	return reply
}

// A remote app's RevokeDevice whose second call carries what evidenceOf makes of the first call's bytes, nil for no
// evidence: what a broken or a hostile caller of control mode sends. Answers the second call's reply.
func (self *Fs98AppHost) RevokeSending(plan *sidecar.DaemonDeviceRevokePlan, evidenceOf func(countersigned []byte) []byte) *sidecar.DaemonDevicesRevokeReply {
	self.world.t.Helper()
	if !self.Remote {
		self.world.t.Fatalf("%s runs its Sidecar in process: it makes no calls", self.Name)
	}
	self.world.catchUp()
	defer self.world.Settle()
	client := self.dial()
	defer client.Close()
	begin := &sidecar.DaemonPresenceBeginReply{}
	if err := client.Call(self.world.admission.ctx, sidecar.DaemonMethodDevicesRevokeBegin, &sidecar.DaemonDevicesRevokeParams{PlanId: plan.PlanId}, true, begin); err != nil ||
		begin.Refusal != nil || begin.ActId == nil {
		self.world.t.Fatalf("%s: the first call: %+v, %v", self.Name, begin, err)
	}
	reply := &sidecar.DaemonDevicesRevokeReply{}
	finish := &sidecar.DaemonPresenceFinishParams{ActId: *begin.ActId, Evidence: evidenceOf(begin.Countersigned)}
	if err := client.Call(self.world.admission.ctx, sidecar.DaemonMethodDevicesRevokeFinish, finish, true, reply); err != nil {
		self.world.t.Fatalf("%s: the second call: %v", self.Name, err)
	}
	return reply
}

// A first call of plan's revocation from a session of mode, control, hook or mcp, with its confirmation flag: the
// daemon's error, a *sidecar.DaemonRpcError or a *sidecar.DaemonHelloRefusal, or nil and the reply.
func (self *Fs98AppHost) BeginFrom(mode string, confirmed bool, plan *sidecar.DaemonDeviceRevokePlan) (*sidecar.DaemonPresenceBeginReply, error) {
	self.world.t.Helper()
	self.world.catchUp()
	defer self.world.Settle()
	hello := &sidecar.DaemonHello{Mode: mode, Version: sidecar.Version, Pid: int64(os.Getpid())}
	if mode == sidecar.DaemonModeHook {
		hello.Harness = "claude-code"
	}
	client, err := sidecar.DialDaemon(self.world.admission.ctx, self.Host.SocketPath, hello)
	if err != nil {
		return nil, err
	}
	defer client.Close()
	begin := &sidecar.DaemonPresenceBeginReply{}
	err = client.Call(self.world.admission.ctx, sidecar.DaemonMethodDevicesRevokeBegin, &sidecar.DaemonDevicesRevokeParams{PlanId: plan.PlanId}, confirmed, begin)
	return begin, err
}

// The app's own presence key registered for its member after the person's confirmation: in process its signer's key
// under its check, a first key needing none; over the daemon by three calls, the signer proving the new key over the
// first call's bytes and countersigning the act's where the second call answers any. What landed is applied at every
// reader. Answers the error of whatever refused it.
func (self *Fs98AppHost) RegisterPresenceKey() error {
	self.world.t.Helper()
	self.world.catchUp()
	defer self.world.Settle()
	if !self.Remote {
		running := self.Host.Sidecar.Sidecar()
		_, err := running.RegisterPresenceKey(self.world.admission.ctx, self.Signer.Provider(), sidecar.SidecarActConfirmed, self.Signer.Check())
		return err
	}
	handle := self.Signer.Handle()
	alg := sidecar.DaemonPresenceAlgWebAuthnEs256
	if handle.Alg == bridge.KeyAlg_KEY_ALG_ECDSA_P256_SHA256 {
		alg = sidecar.DaemonPresenceAlgEcdsaP256Sha256
	}
	ctx := self.world.admission.ctx
	client := self.dial()
	defer client.Close()
	begin := &sidecar.DaemonKeysPresenceBeginReply{}
	if err := client.Call(ctx, sidecar.DaemonMethodKeysPresenceBegin, &sidecar.DaemonKeysPresenceBeginParams{
		KeyId: handle.KeyId, Alg: alg, PublicKey: handle.PublicKey,
	}, true, begin); err != nil {
		return err
	}
	if begin.ActId == nil {
		return errors.New("the first call named no act")
	}
	proof, err := self.Signer.Sign(begin.Proof)
	if err != nil {
		return err
	}
	proved := &sidecar.DaemonPresenceBeginReply{}
	if err := client.Call(ctx, sidecar.DaemonMethodKeysPresenceProve, &sidecar.DaemonPresenceFinishParams{ActId: *begin.ActId, Evidence: proof}, true, proved); err != nil {
		return err
	}
	if proved.Refusal != nil {
		return &sidecar.DeviceRevokeError{Code: proved.Refusal.Code, Position: proved.Refusal.Position}
	}
	finish := &sidecar.DaemonPresenceFinishParams{ActId: *begin.ActId}
	if 0 < len(proved.Countersigned) {
		countersignature, err := self.Signer.Sign(proved.Countersigned)
		if err != nil {
			return err
		}
		finish.Evidence = countersignature
	}
	reply := &sidecar.DaemonKeysPresenceReply{}
	if err := client.Call(ctx, sidecar.DaemonMethodKeysPresenceFinish, finish, true, reply); err != nil {
		return err
	}
	if reply.Refusal != nil {
		return &sidecar.DeviceRevokeError{Code: reply.Refusal.Code, Position: reply.Refusal.Position}
	}
	if !bytes.Equal(reply.KeyId, handle.KeyId) {
		return fmt.Errorf("the KeyRegister names key %x, not the app's", reply.KeyId)
	}
	return nil
}

// GetPending's items, as the core lists them on the app's host.
func (self *Fs98AppHost) Pending() []*sidecar.SidecarApprovalItem {
	self.world.t.Helper()
	self.world.catchUp()
	items, err := self.Host.Sidecar.Sidecar().PendingApprovals()
	if err != nil {
		self.world.t.Fatalf("%s: the pending approvals: %v", self.Name, err)
	}
	return items
}

// Decide of an item after the person's confirmation in the app: in process the core's DecideApproval under the
// signer's check; over the daemon by the two calls, the signer signing the first call's bytes. What landed is applied
// at every reader. Answers the error of whatever refused it, §5.6's refusals as a *sidecar.DeviceRevokeError.
func (self *Fs98AppHost) Decide(approvalId sidecar.Id, decision string) error {
	self.world.t.Helper()
	self.world.catchUp()
	defer self.world.Settle()
	if !self.Remote {
		return self.Host.Sidecar.Sidecar().DecideApproval(self.world.admission.ctx, approvalId, decision, sidecar.SidecarActConfirmed, self.Signer.Check())
	}
	client := self.dial()
	defer client.Close()
	reply := &sidecar.DaemonApprovalsDecideReply{}
	refusal, err := client.CallPresenceAct(self.world.admission.ctx, "", sidecar.DaemonMethodApprovalsDecideBegin,
		&sidecar.DaemonApprovalsDecideParams{ApprovalId: approvalId, Decision: decision}, sidecar.DaemonMethodApprovalsDecideFinish, self.Signer.Sign, reply)
	switch {
	case err != nil:
		return err
	case refusal != nil:
		return &sidecar.DeviceRevokeError{Code: refusal.Code, Position: refusal.Position}
	case reply.Refusal != nil:
		return &sidecar.DeviceRevokeError{Code: reply.Refusal.Code, Position: reply.Refusal.Position}
	}
	return nil
}

// A remote app's Decide whose second call carries what evidenceOf makes of the first call's bytes, no evidence where
// evidenceOf is nil: what a broken or a hostile caller of control mode sends. Answers the error of whatever refused
// it, as Decide does.
func (self *Fs98AppHost) DecideSending(approvalId sidecar.Id, decision string, evidenceOf func(countersigned []byte) []byte) error {
	self.world.t.Helper()
	if !self.Remote {
		self.world.t.Fatalf("%s runs its Sidecar in process: it makes no calls", self.Name)
	}
	self.world.catchUp()
	defer self.world.Settle()
	client := self.dial()
	defer client.Close()
	begin := &sidecar.DaemonPresenceBeginReply{}
	if err := client.Call(self.world.admission.ctx, sidecar.DaemonMethodApprovalsDecideBegin,
		&sidecar.DaemonApprovalsDecideParams{ApprovalId: approvalId, Decision: decision}, true, begin); err != nil {
		return err
	}
	if begin.Refusal != nil {
		return &sidecar.DeviceRevokeError{Code: begin.Refusal.Code, Position: begin.Refusal.Position}
	}
	if begin.ActId == nil {
		return errors.New("the first call named no act")
	}
	finish := &sidecar.DaemonPresenceFinishParams{ActId: *begin.ActId}
	if evidenceOf != nil {
		finish.Evidence = evidenceOf(begin.Countersigned)
	}
	reply := &sidecar.DaemonApprovalsDecideReply{}
	if err := client.Call(self.world.admission.ctx, sidecar.DaemonMethodApprovalsDecideFinish, finish, true, reply); err != nil {
		return err
	}
	if reply.Refusal != nil {
		return &sidecar.DeviceRevokeError{Code: reply.Refusal.Code, Position: reply.Refusal.Position}
	}
	return nil
}
