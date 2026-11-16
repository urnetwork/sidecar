//go:build !js && !ios && !android && !sdk_mobile_bind

package sidecar

// §5.8's two calls (CORE-M8-03; D-CORE-20, D-SDK-30, FS-98, FS-124) on the devices tests' world: the dispatcher with
// no socket, each call on a session whose end the test controls, a scripted delta route, and the remote-mode app's
// presence key on a fake authenticator that is not the daemon's, registered as a live key of this sidecar's. The first
// call answers the act's bytes and signs nothing; only the second, with the app's evidence over exactly those bytes,
// signs; no evidence, evidence of another key or bytes that do not decode sign nothing; and a held act ends unsigned
// at its bound, with its session, when a later first call supersedes it, and when a call comes out of order.

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A clock a test moves by hand, firing each timer it passes outside its lock, in time order.
type presenceActTestClock struct {
	stateLock sync.Mutex
	now       time.Time
	timers    []*presenceActTestTimer
}

type presenceActTestTimer struct {
	at       time.Time
	function func()
	// stopped or fired
	spent bool
}

func newPresenceActTestClock() *presenceActTestClock {
	return &presenceActTestClock{now: time.Date(2026, time.November, 15, 9, 0, 0, 0, time.UTC)}
}

func (self *presenceActTestClock) Now() time.Time {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.now
}

func (self *presenceActTestClock) After(timeout time.Duration) <-chan time.Time {
	fired := make(chan time.Time, 1)
	self.AfterFunc(timeout, func() {
		fired <- self.Now()
	})
	return fired
}

func (self *presenceActTestClock) AfterFunc(timeout time.Duration, function func()) func() bool {
	timer := func() *presenceActTestTimer {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		timer := &presenceActTestTimer{at: self.now.Add(timeout), function: function}
		self.timers = append(self.timers, timer)
		return timer
	}()
	return func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if timer.spent {
			return false
		}
		timer.spent = true
		return true
	}
}

// Moves the clock on by timeout, firing every timer it passes.
func (self *presenceActTestClock) advance(timeout time.Duration) {
	due := func() []*presenceActTestTimer {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.now = self.now.Add(timeout)
		due := []*presenceActTestTimer{}
		for _, timer := range self.timers {
			if !timer.spent && !timer.at.After(self.now) {
				timer.spent = true
				due = append(due, timer)
			}
		}
		slices.SortFunc(due, func(a *presenceActTestTimer, b *presenceActTestTimer) int { return a.at.Compare(b.at) })
		return due
	}()
	for _, timer := range due {
		timer.function()
	}
}

// The devices world with the two-call methods registered, a clock the test moves on the daemon, and the app's presence
// key as a live key of this sidecar's, its statements covered.
type presenceActTestWorld struct {
	*devicesTestWorld
	clock *presenceActTestClock
	// the remote-mode app's authenticator, never the daemon's
	app      *testPresenceProvider
	appKeyId []byte
	// the app's control session
	session chan struct{}
}

func newPresenceActTestWorld(t *testing.T) *presenceActTestWorld {
	t.Helper()
	world := newDevicesTestWorld(t)
	clock := newPresenceActTestClock()
	world.daemon.clock = clock
	for _, method := range DaemonApprovalsMethods(world.daemon) {
		if err := world.daemon.RegisterMethod(method); err != nil {
			t.Fatal(err)
		}
	}
	// held acts end with the daemon
	t.Cleanup(world.daemon.cancel)
	return &presenceActTestWorld{devicesTestWorld: world, clock: clock, session: make(chan struct{})}
}

// The app's presence key, made on its own authenticator and live for this sidecar, with types covered.
func (self *presenceActTestWorld) addAppKey(t *testing.T, signedTypes ...bridge.SignedType) {
	t.Helper()
	self.app = newTestPresenceProvider(t, bridge.KeyAlg_KEY_ALG_WEBAUTHN_ES256)
	handle, err := self.app.Register(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	self.appKeyId = handle.KeyId
	row := self.app.row(handle.KeyId, self.memberId, self.selfId)
	self.authority.edit(func() {
		self.authority.liveKeys = append(self.authority.liveKeys, row)
		for _, signedType := range signedTypes {
			self.authority.covered[signedType] = true
		}
	})
}

// What the app's SignWithPresence answers over message: §6.9's evidence, encoded.
func (self *presenceActTestWorld) appSign(t *testing.T, message []byte) []byte {
	t.Helper()
	evidence, err := self.app.Assert(t.Context(), self.appKeyId, message)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := proto.Marshal(evidence)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

// One confirmed control call on done's session, its reply decoded into reply, or the rpc's error.
func (self *presenceActTestWorld) callOn(t *testing.T, done <-chan struct{}, method string, params any, reply any) *DaemonRpcError {
	t.Helper()
	encoded, err := json.Marshal(params)
	if err != nil {
		t.Fatal(err)
	}
	line, err := json.Marshal(&daemonRpcRequest{JsonRpc: "2.0", Id: json.RawMessage("1"), Method: method, Params: encoded, UrConfirmed: true})
	if err != nil {
		t.Fatal(err)
	}
	session := &daemonSession{hello: &DaemonHello{UrLocal: 1, Mode: DaemonModeControl, Version: "synthetic-version"}, done: done}
	response := self.daemon.dispatch(line, session, runUnbounded)
	if response.Error != nil {
		return response.Error
	}
	if reply != nil {
		if err := json.Unmarshal(response.Result, reply); err != nil {
			t.Fatal(err)
		}
	}
	return nil
}

// A confirmed control call on the app's session.
func (self *presenceActTestWorld) appCall(t *testing.T, method string, params any, reply any) *DaemonRpcError {
	t.Helper()
	return self.callOn(t, self.session, method, params, reply)
}

// A previewed lost revocation of the other device.
func (self *presenceActTestWorld) previewOther(t *testing.T) *DaemonDeviceRevokePlan {
	t.Helper()
	reply := &DaemonDevicesPreviewReply{}
	if rpcErr := self.call(t, DaemonModeControl, DaemonMethodDevicesPreview,
		&DaemonDevicesPreviewParams{Device: self.otherId.String(), Reason: DeviceRevokeLost}, false, reply); rpcErr != nil || reply.Plan == nil {
		t.Fatalf("the preview: %+v, %v", reply, rpcErr)
	}
	return reply.Plan
}

// The first call of the other device's revocation: an act waiting, with its bytes.
func (self *presenceActTestWorld) beginRevoke(t *testing.T, plan *DaemonDeviceRevokePlan, revokeKeyIds ...[]byte) *DaemonPresenceBeginReply {
	t.Helper()
	params := &DaemonDevicesRevokeParams{PlanId: plan.PlanId}
	for _, keyId := range revokeKeyIds {
		params.RevokeKeyIds = append(params.RevokeKeyIds, hex.EncodeToString(keyId))
	}
	begin := &DaemonPresenceBeginReply{}
	if rpcErr := self.appCall(t, DaemonMethodDevicesRevokeBegin, params, begin); rpcErr != nil || begin.Refusal != nil || begin.ActId == nil {
		t.Fatalf("the first call: %+v, %v", begin, rpcErr)
	}
	return begin
}

// The held act of actId, nil for none.
func (self *presenceActTestWorld) heldAct(actId Id) *daemonPresenceAct {
	acts := self.daemon.heldActs()
	acts.stateLock.Lock()
	defer acts.stateLock.Unlock()
	return acts.actIdActs[actId]
}

// How many acts the daemon holds.
func (self *presenceActTestWorld) heldCount() int {
	acts := self.daemon.heldActs()
	acts.stateLock.Lock()
	defer acts.stateLock.Unlock()
	return len(acts.actIdActs)
}

// Whether a webauthn assertion's client data names message's SHA-256 as its challenge.
func presenceActTestChallengeIs(evidence *bridge.WebAuthnEvidence, message []byte) bool {
	digest := sha256.Sum256(message)
	return bytes.Contains(evidence.GetClientDataJson(), []byte(base64.RawURLEncoding.EncodeToString(digest[:])))
}

// TestSecondCallRequired: under Presence the first call answers the act's countersigned bytes and an act id and signs
// nothing; the app signs exactly those bytes, and only the second call, carrying that evidence, signs, each statement
// with the app key's countersignature, which verifies against its live row. An act the log does not cover answers no
// bytes at the first call and still signs nothing until the second, on the person's confirmation alone.
func TestSecondCallRequired(t *testing.T) {
	world := newPresenceActTestWorld(t)
	world.addAppKey(t, bridge.SignedType_SIGNED_SIDECAR_REVOKE, bridge.SignedType_SIGNED_KEY_REVOKE)
	otherKeyId := countingBytes(0x40, 32)
	world.authority.edit(func() {
		world.authority.keys[world.otherId] = []*bridge.KeyRow{{KeyId: otherKeyId, Purpose: bridge.KeyPurpose_KEY_PURPOSE_PRESENCE, Signer: world.otherId.Bytes(), At: 8}}
	})
	plan := world.previewOther(t)
	if !plan.Presence {
		t.Fatalf("the plan sets no Presence: %+v", plan)
	}
	begin := world.beginRevoke(t, plan, otherKeyId)
	if len(begin.Countersigned) == 0 {
		t.Fatal("the first call answered no bytes under Presence")
	}
	if posts := world.deltaApi.postsSoFar(); len(posts) != 0 {
		t.Fatalf("the first call posted %d statements", len(posts))
	}
	if world.heldAct(*begin.ActId) == nil {
		t.Fatal("no act waits for the second call")
	}

	reply := &DaemonDevicesRevokeReply{}
	finish := &DaemonPresenceFinishParams{ActId: *begin.ActId, Evidence: world.appSign(t, begin.Countersigned)}
	if rpcErr := world.appCall(t, DaemonMethodDevicesRevokeFinish, finish, reply); rpcErr != nil || reply.Refusal != nil || reply.Position == 0 {
		t.Fatalf("the second call: %+v, %v", reply, rpcErr)
	}
	if len(reply.RevokedKeyIds) != 1 || reply.RevokedKeyIds[0] != hex.EncodeToString(otherKeyId) {
		t.Errorf("the keys revoked: %v", reply.RevokedKeyIds)
	}
	posts := world.posted(t)
	if len(posts) != 2 || bridge.SignedType(posts[0].GetType()) != bridge.SignedType_SIGNED_SIDECAR_REVOKE ||
		bridge.SignedType(posts[1].GetType()) != bridge.SignedType_SIGNED_KEY_REVOKE {
		t.Fatalf("posted %d statements", len(posts))
	}
	liveKey := world.authority.LiveKeys(world.selfId)[0]
	for index, signed := range posts {
		if err := VerifyPresenceCountersignature(signed, bridge.SignedPurposeAuthority, liveKey); err != nil {
			t.Errorf("statement %d's countersignature: %v", index, err)
		}
		// the one check covers exactly the bytes the first call answered
		if !presenceActTestChallengeIs(signed.GetWebauthn(), begin.Countersigned) || !bytes.Equal(signed.GetWebauthn().GetKeyId(), world.appKeyId) {
			t.Errorf("statement %d's countersignature is over other bytes or another key", index)
		}
	}
	if world.heldCount() != 0 {
		t.Errorf("%d acts held after the second call", world.heldCount())
	}
	// the daemon's own authenticator asked nothing: the key is the app's
	if world.daemon.PresenceProvider() != nil {
		t.Error("the daemon has an authenticator in this world")
	}

	// a statement the log does not cover: no bytes, and still nothing signed before the second call
	world.authority.edit(func() { world.authority.covered = map[bridge.SignedType]bool{} })
	thirdId := NewId()
	world.admit(thirdId, world.memberId, 9)
	preview := &DaemonDevicesPreviewReply{}
	if rpcErr := world.call(t, DaemonModeControl, DaemonMethodDevicesPreview,
		&DaemonDevicesPreviewParams{Device: thirdId.String(), Reason: DeviceRevokeLost}, false, preview); rpcErr != nil || preview.Plan == nil || preview.Plan.Presence {
		t.Fatalf("an uncovered plan: %+v, %v", preview, rpcErr)
	}
	uncovered := world.beginRevoke(t, preview.Plan)
	if len(uncovered.Countersigned) != 0 {
		t.Fatal("an act the log does not cover answered bytes to sign")
	}
	if posts := world.deltaApi.postsSoFar(); len(posts) != 2 {
		t.Fatalf("the first call of an uncovered act posted: %d statements in all", len(posts))
	}
	confirmed := &DaemonDevicesRevokeReply{}
	if rpcErr := world.appCall(t, DaemonMethodDevicesRevokeFinish, &DaemonPresenceFinishParams{ActId: *uncovered.ActId}, confirmed); rpcErr != nil ||
		confirmed.Refusal != nil || confirmed.Position == 0 {
		t.Fatalf("the uncovered act's second call: %+v, %v", confirmed, rpcErr)
	}
	posts = world.posted(t)
	if len(posts) != 3 || posts[2].GetWebauthn() != nil {
		t.Fatalf("posted %d statements, the last with a countersignature %v", len(posts), posts[len(posts)-1].GetWebauthn() != nil)
	}
}

// TestNoEvidenceCancels: under Presence a second call with no evidence answers REVOKE_CANCELLED with nothing signed,
// and so do evidence of a key that is not live for this sidecar and evidence that does not decode; each spends its act,
// whose id then names nothing, and the plan stands for the next first call.
func TestNoEvidenceCancels(t *testing.T) {
	world := newPresenceActTestWorld(t)
	world.addAppKey(t, bridge.SignedType_SIGNED_SIDECAR_REVOKE)
	// a provider's keys follow one seed sequence: its second key is none of the app's
	stranger := newTestPresenceProvider(t, bridge.KeyAlg_KEY_ALG_WEBAUTHN_ES256)
	if _, err := stranger.Register(t.Context()); err != nil {
		t.Fatal(err)
	}
	strangerHandle, err := stranger.Register(t.Context())
	if err != nil || bytes.Equal(strangerHandle.KeyId, world.appKeyId) {
		t.Fatalf("a stranger's key: %v", err)
	}
	plan := world.previewOther(t)
	strangerEvidence := func(message []byte) []byte {
		evidence, err := stranger.Assert(t.Context(), strangerHandle.KeyId, message)
		if err != nil {
			t.Fatal(err)
		}
		encoded, _ := proto.Marshal(evidence)
		return encoded
	}
	for name, evidenceOf := range map[string]func(message []byte) []byte{
		"no evidence":       func(message []byte) []byte { return nil },
		"another key's":     strangerEvidence,
		"bytes that do not": func(message []byte) []byte { return []byte("not a WebAuthnEvidence") },
		// the app's key over other bytes than the first call's
		"over other bytes": func(message []byte) []byte { return world.appSign(t, append(bytes.Clone(message), 0)) },
	} {
		begin := world.beginRevoke(t, plan)
		reply := &DaemonDevicesRevokeReply{}
		if rpcErr := world.appCall(t, DaemonMethodDevicesRevokeFinish, &DaemonPresenceFinishParams{ActId: *begin.ActId, Evidence: evidenceOf(begin.Countersigned)}, reply); rpcErr != nil ||
			reply.Refusal == nil || reply.Refusal.Code != DeviceRevokeCodeCancelled {
			t.Fatalf("%s: %+v, %v", name, reply, rpcErr)
		}
		// spent: its id names nothing now
		again := &DaemonDevicesRevokeReply{}
		if rpcErr := world.appCall(t, DaemonMethodDevicesRevokeFinish, &DaemonPresenceFinishParams{ActId: *begin.ActId, Evidence: world.appSign(t, begin.Countersigned)}, again); rpcErr == nil ||
			!strings.Contains(rpcErr.Message, ErrDaemonPresenceActUnknown.Error()) {
			t.Fatalf("%s: a second answer of a spent act: %+v, %v", name, again, rpcErr)
		}
	}
	if posts := world.deltaApi.postsSoFar(); len(posts) != 0 {
		t.Fatalf("%d statements posted with no verifying evidence", len(posts))
	}
	// the plan stands for the person's next try
	begin := world.beginRevoke(t, plan)
	reply := &DaemonDevicesRevokeReply{}
	if rpcErr := world.appCall(t, DaemonMethodDevicesRevokeFinish, &DaemonPresenceFinishParams{ActId: *begin.ActId, Evidence: world.appSign(t, begin.Countersigned)}, reply); rpcErr != nil ||
		reply.Refusal != nil || reply.Position == 0 {
		t.Fatalf("the next try: %+v, %v", reply, rpcErr)
	}
}

// D-CORE-13: every two-call method is a Confirm method, refused before its handler from an MCP session, a harness
// hook's and an unconfirmed control call, whatever their flag says, with nothing held or signed; what ur native-host
// sends, never confirmed, is refused alike.
func TestTwoCallMethodsNeedTheConfirmation(t *testing.T) {
	world := newPresenceActTestWorld(t)
	world.addAppKey(t, bridge.SignedType_SIGNED_SIDECAR_REVOKE)
	plan := world.previewOther(t)
	twoCall := []string{
		DaemonMethodDevicesRevokeBegin, DaemonMethodDevicesRevokeFinish, DaemonMethodDevicesCosignBegin, DaemonMethodDevicesCosignFinish,
		DaemonMethodApprovalsDecideBegin, DaemonMethodApprovalsDecideFinish,
		DaemonMethodKeysPresenceBegin, DaemonMethodKeysPresenceProve, DaemonMethodKeysPresenceFinish,
	}
	methods := append(DaemonDevicesMethods(world.daemon), DaemonApprovalsMethods(world.daemon)...)
	for _, name := range twoCall {
		index := slices.IndexFunc(methods, func(method *DaemonMethod) bool { return method.Name == name })
		if index < 0 || !methods[index].Confirm || !methods[index].Network {
			t.Errorf("%s is not a registered network Confirm method", name)
		}
	}
	for _, name := range twoCall {
		for _, c := range []struct {
			mode      string
			confirmed bool
		}{
			{mode: DaemonModeMcp, confirmed: true},
			{mode: DaemonModeHook, confirmed: true},
			{mode: DaemonModeHook, confirmed: false},
			{mode: DaemonModeControl, confirmed: false},
		} {
			rpcErr := world.call(t, c.mode, name, &DaemonDevicesRevokeParams{PlanId: plan.PlanId}, c.confirmed, nil)
			if rpcErr == nil || rpcErr.Code != DaemonRpcConfirmationRequired {
				t.Errorf("%s from %s, confirmed %t: %v", name, c.mode, c.confirmed, rpcErr)
			}
		}
	}
	if world.heldCount() != 0 || len(world.deltaApi.postsSoFar()) != 0 {
		t.Fatalf("refused calls held %d acts and posted %d statements", world.heldCount(), len(world.deltaApi.postsSoFar()))
	}
}

// A held act ends unsigned at Local.PresenceActTimeout: its second call then names nothing, and nothing is posted.
func TestTwoCallActLapses(t *testing.T) {
	world := newPresenceActTestWorld(t)
	world.addAppKey(t, bridge.SignedType_SIGNED_SIDECAR_REVOKE)
	begin := world.beginRevoke(t, world.previewOther(t))
	act := world.heldAct(*begin.ActId)
	world.clock.advance(world.daemon.settings.Local.PresenceActTimeout - time.Second)
	if world.heldAct(*begin.ActId) == nil {
		t.Fatal("the act ended before its bound")
	}
	world.clock.advance(time.Second)
	<-act.done
	if world.heldCount() != 0 {
		t.Fatal("the act stands past its bound")
	}
	reply := &DaemonDevicesRevokeReply{}
	if rpcErr := world.appCall(t, DaemonMethodDevicesRevokeFinish, &DaemonPresenceFinishParams{ActId: *begin.ActId, Evidence: world.appSign(t, begin.Countersigned)}, reply); rpcErr == nil ||
		!strings.Contains(rpcErr.Message, ErrDaemonPresenceActUnknown.Error()) {
		t.Fatalf("the second call past the bound: %+v, %v", reply, rpcErr)
	}
	if revokeCode(act.err) != DeviceRevokeCodeCancelled {
		t.Errorf("the lapsed act's run answered %v", act.err)
	}
	if posts := world.deltaApi.postsSoFar(); len(posts) != 0 {
		t.Fatalf("%d statements posted by a lapsed act", len(posts))
	}
}

// A held act belongs to the session that began it: another session's second call names nothing and leaves it, and the
// session's end ends it unsigned.
func TestTwoCallActEndsWithItsSession(t *testing.T) {
	world := newPresenceActTestWorld(t)
	world.addAppKey(t, bridge.SignedType_SIGNED_SIDECAR_REVOKE)
	plan := world.previewOther(t)
	begin := world.beginRevoke(t, plan)
	evidence := world.appSign(t, begin.Countersigned)
	other := make(chan struct{})
	reply := &DaemonDevicesRevokeReply{}
	if rpcErr := world.callOn(t, other, DaemonMethodDevicesRevokeFinish, &DaemonPresenceFinishParams{ActId: *begin.ActId, Evidence: evidence}, reply); rpcErr == nil ||
		!strings.Contains(rpcErr.Message, ErrDaemonPresenceActUnknown.Error()) {
		t.Fatalf("another session's second call: %+v, %v", reply, rpcErr)
	}
	act := world.heldAct(*begin.ActId)
	if act == nil {
		t.Fatal("another session's call ended the act")
	}
	close(world.session)
	<-act.ended
	<-act.done
	if rpcErr := world.callOn(t, world.session, DaemonMethodDevicesRevokeFinish, &DaemonPresenceFinishParams{ActId: *begin.ActId, Evidence: evidence}, reply); rpcErr == nil {
		t.Fatalf("a second call after the session ended: %+v", reply)
	}
	if posts := world.deltaApi.postsSoFar(); len(posts) != 0 {
		t.Fatalf("%d statements posted after the session ended", len(posts))
	}
}

// A later first call of the same plan supersedes a held act, which ends unsigned; the daemon holds at most
// Local.PresenceActCount acts and refuses a first call past it.
func TestTwoCallActSupersededAndBounded(t *testing.T) {
	world := newPresenceActTestWorld(t)
	world.addAppKey(t, bridge.SignedType_SIGNED_SIDECAR_REVOKE)
	plan := world.previewOther(t)
	first := world.beginRevoke(t, plan)
	firstAct := world.heldAct(*first.ActId)
	second := world.beginRevoke(t, plan)
	<-firstAct.done
	if world.heldAct(*first.ActId) != nil || world.heldAct(*second.ActId) == nil || world.heldCount() != 1 {
		t.Fatalf("the superseded act stands, or the new one does not: %d held", world.heldCount())
	}
	reply := &DaemonDevicesRevokeReply{}
	if rpcErr := world.appCall(t, DaemonMethodDevicesRevokeFinish, &DaemonPresenceFinishParams{ActId: *first.ActId, Evidence: world.appSign(t, first.Countersigned)}, reply); rpcErr == nil {
		t.Fatalf("the superseded act's second call: %+v", reply)
	}

	// the bound: each other device's plan holds one act
	world.daemon.settings.Local.PresenceActCount = 2
	thirdId := NewId()
	world.admit(thirdId, world.memberId, 9)
	preview := &DaemonDevicesPreviewReply{}
	if rpcErr := world.call(t, DaemonModeControl, DaemonMethodDevicesPreview,
		&DaemonDevicesPreviewParams{Device: thirdId.String(), Reason: DeviceRevokeLost}, false, preview); rpcErr != nil || preview.Plan == nil {
		t.Fatalf("the third device's plan: %+v, %v", preview, rpcErr)
	}
	world.beginRevoke(t, preview.Plan)
	fourthId := NewId()
	world.admit(fourthId, world.memberId, 10)
	if rpcErr := world.call(t, DaemonModeControl, DaemonMethodDevicesPreview,
		&DaemonDevicesPreviewParams{Device: fourthId.String(), Reason: DeviceRevokeLost}, false, preview); rpcErr != nil || preview.Plan == nil {
		t.Fatalf("the fourth device's plan: %+v, %v", preview, rpcErr)
	}
	begin := &DaemonPresenceBeginReply{}
	if rpcErr := world.appCall(t, DaemonMethodDevicesRevokeBegin, &DaemonDevicesRevokeParams{PlanId: preview.Plan.PlanId}, begin); rpcErr == nil ||
		!strings.Contains(rpcErr.Message, ErrDaemonPresenceActCount.Error()) {
		t.Fatalf("a first call past the bound: %+v, %v", begin, rpcErr)
	}
	if posts := world.deltaApi.postsSoFar(); len(posts) != 0 {
		t.Fatalf("%d statements posted", len(posts))
	}
}

// A first call of a plan this Sidecar never previewed is §5.6's refusal, answered with nothing held, and a second call
// of another family's act names nothing.
func TestTwoCallFirstCallRefusesAndFamiliesStayApart(t *testing.T) {
	world := newPresenceActTestWorld(t)
	world.addAppKey(t, bridge.SignedType_SIGNED_SIDECAR_REVOKE)
	stale := &DaemonPresenceBeginReply{}
	if rpcErr := world.appCall(t, DaemonMethodDevicesRevokeBegin, &DaemonDevicesRevokeParams{PlanId: NewId()}, stale); rpcErr != nil ||
		stale.Refusal == nil || stale.Refusal.Code != DeviceRevokeCodeStale || stale.ActId != nil {
		t.Fatalf("a plan never previewed: %+v, %v", stale, rpcErr)
	}
	if world.heldCount() != 0 {
		t.Fatal("a refused first call holds an act")
	}
	begin := world.beginRevoke(t, world.previewOther(t))
	reply := &DaemonApprovalsDecideReply{}
	if rpcErr := world.appCall(t, DaemonMethodApprovalsDecideFinish, &DaemonPresenceFinishParams{ActId: *begin.ActId, Evidence: world.appSign(t, begin.Countersigned)}, reply); rpcErr == nil ||
		!strings.Contains(rpcErr.Message, ErrDaemonPresenceActUnknown.Error()) {
		t.Fatalf("a decision's second call of a revocation's act: %+v, %v", reply, rpcErr)
	}
	if world.heldAct(*begin.ActId) == nil {
		t.Fatal("another family's call ended the act")
	}
}

// Decide by two calls: an admission's SidecarAdmit, covered, signs only with the app's evidence over the first call's
// bytes; a refused check (no evidence) cancels it and leaves the item open; and a deny, which signs nothing, answers
// no bytes and closes the item at its second call.
func TestDecideByTwoCalls(t *testing.T) {
	world := newPresenceActTestWorld(t)
	world.addAppKey(t, bridge.SignedType_SIGNED_SIDECAR_ADMIT)
	newDevice := NewId()
	approvalId, err := world.sidecar.OpenAdmission(&SidecarAdmissionRequest{SidecarId: newDevice, MemberId: world.memberId, IdentityPublicKey: bytes.Repeat([]byte{9}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	beginDecide := func(decision string) *DaemonPresenceBeginReply {
		begin := &DaemonPresenceBeginReply{}
		if rpcErr := world.appCall(t, DaemonMethodApprovalsDecideBegin, &DaemonApprovalsDecideParams{ApprovalId: approvalId, Decision: decision}, begin); rpcErr != nil ||
			begin.Refusal != nil || begin.ActId == nil {
			t.Fatalf("the first call: %+v, %v", begin, rpcErr)
		}
		return begin
	}
	begin := beginDecide(SidecarDecisionApprove)
	if len(begin.Countersigned) == 0 || len(world.deltaApi.postsSoFar()) != 0 {
		t.Fatalf("the first call answered %d bytes and posted %d statements", len(begin.Countersigned), len(world.deltaApi.postsSoFar()))
	}
	cancelled := &DaemonApprovalsDecideReply{}
	if rpcErr := world.appCall(t, DaemonMethodApprovalsDecideFinish, &DaemonPresenceFinishParams{ActId: *begin.ActId}, cancelled); rpcErr != nil ||
		cancelled.Refusal == nil || cancelled.Refusal.Code != DeviceRevokeCodeCancelled {
		t.Fatalf("no evidence: %+v, %v", cancelled, rpcErr)
	}
	items, err := world.sidecar.PendingApprovals()
	if err != nil || !slices.ContainsFunc(items, func(item *SidecarApprovalItem) bool { return item.ApprovalId == approvalId }) {
		t.Fatalf("a cancelled admission closed its item: %+v %v", items, err)
	}

	begin = beginDecide(SidecarDecisionApprove)
	reply := &DaemonApprovalsDecideReply{}
	if rpcErr := world.appCall(t, DaemonMethodApprovalsDecideFinish, &DaemonPresenceFinishParams{ActId: *begin.ActId, Evidence: world.appSign(t, begin.Countersigned)}, reply); rpcErr != nil ||
		reply.Refusal != nil || reply.Pending {
		t.Fatalf("the admission: %+v, %v", reply, rpcErr)
	}
	posts := world.posted(t)
	if len(posts) != 1 || bridge.SignedType(posts[0].GetType()) != bridge.SignedType_SIGNED_SIDECAR_ADMIT {
		t.Fatalf("posted %d statements", len(posts))
	}
	if err := VerifyPresenceCountersignature(posts[0], bridge.SignedPurposeAuthority, world.authority.LiveKeys(world.selfId)[0]); err != nil ||
		!presenceActTestChallengeIs(posts[0].GetWebauthn(), begin.Countersigned) {
		t.Errorf("the admission's countersignature: %v", err)
	}
	admit := &protocol.SidecarAdmit{}
	postedBody(t, posts[0], admit)
	if !bytes.Equal(admit.GetSidecarId(), newDevice.Bytes()) {
		t.Errorf("the admission: %+v", admit)
	}

	// a deny of another admission signs nothing: no bytes, and the item closes at the second call
	otherApprovalId, err := world.sidecar.OpenAdmission(&SidecarAdmissionRequest{SidecarId: NewId(), MemberId: world.memberId, IdentityPublicKey: bytes.Repeat([]byte{8}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	approvalId = otherApprovalId
	deny := beginDecide(SidecarDecisionDeny)
	if len(deny.Countersigned) != 0 {
		t.Fatal("a deny answered bytes to sign")
	}
	denied := &DaemonApprovalsDecideReply{}
	if rpcErr := world.appCall(t, DaemonMethodApprovalsDecideFinish, &DaemonPresenceFinishParams{ActId: *deny.ActId}, denied); rpcErr != nil || denied.Refusal != nil {
		t.Fatalf("the deny: %+v, %v", denied, rpcErr)
	}
	items, err = world.sidecar.PendingApprovals()
	if err != nil || slices.ContainsFunc(items, func(item *SidecarApprovalItem) bool { return item.ApprovalId == otherApprovalId }) {
		t.Fatalf("the denied item is open: %+v %v", items, err)
	}
	if posts := world.deltaApi.postsSoFar(); len(posts) != 1 {
		t.Errorf("%d statements posted, want the one admission", len(posts))
	}
}

// A cosign by two calls: devices.cosign.begin answers the act's bytes, and the second call's evidence becomes the
// cosign's countersignature.
func TestCosignByTwoCalls(t *testing.T) {
	world := newPresenceActTestWorld(t)
	world.addAppKey(t, bridge.SignedType_SIGNED_AUTHORITY_COSIGN)
	world.authority.edit(func() { world.authority.suspended[world.otherId] = true })
	proposalId := world.propose(world.otherId, NewId(), bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST, 0)
	params := &DaemonDevicesProposalParams{ProposalId: hex.EncodeToString(proposalId)}
	begin := &DaemonPresenceBeginReply{}
	if rpcErr := world.appCall(t, DaemonMethodDevicesCosignBegin, params, begin); rpcErr != nil || begin.ActId == nil || len(begin.Countersigned) == 0 {
		t.Fatalf("the first call: %+v, %v", begin, rpcErr)
	}
	if len(world.deltaApi.postsSoFar()) != 0 {
		t.Fatal("the first call posted")
	}
	reply := &DaemonDevicesCosignReply{}
	if rpcErr := world.appCall(t, DaemonMethodDevicesCosignFinish, &DaemonPresenceFinishParams{ActId: *begin.ActId, Evidence: world.appSign(t, begin.Countersigned)}, reply); rpcErr != nil ||
		reply.Refusal != nil || reply.Position == 0 {
		t.Fatalf("the second call: %+v, %v", reply, rpcErr)
	}
	posts := world.posted(t)
	if len(posts) != 1 || bridge.SignedType(posts[0].GetType()) != bridge.SignedType_SIGNED_AUTHORITY_COSIGN {
		t.Fatalf("posted %d statements", len(posts))
	}
	if err := VerifyPresenceCountersignature(posts[0], bridge.SignedPurposeAuthority, world.authority.LiveKeys(world.selfId)[0]); err != nil {
		t.Errorf("the cosign's countersignature: %v", err)
	}
	// a proposal that is not open refuses at the first call with nothing held
	unknown := &DaemonPresenceBeginReply{}
	if rpcErr := world.appCall(t, DaemonMethodDevicesCosignBegin, &DaemonDevicesProposalParams{ProposalId: hex.EncodeToString(countingBytes(0x77, 32))}, unknown); rpcErr == nil ||
		!strings.Contains(rpcErr.Message, ErrSidecarRevokeProposalUnknown.Error()) || world.heldCount() != 0 {
		t.Fatalf("an unknown proposal: %+v, %v", unknown, rpcErr)
	}
}

// The app's KeyRegister by three calls: the first answers the bytes the new key proves itself over, the second takes
// the proof and answers the act's bytes, none for a first key, which the log does not cover, and the third signs the
// KeyRegister carrying that proof. A second key, covered by the app's live one, carries its countersignature. A proof
// that does not verify, and a call out of order, sign nothing.
func TestAppKeyRegisterByThreeCalls(t *testing.T) {
	world := newPresenceActTestWorld(t)
	world.authority.edit(func() { world.authority.covered[bridge.SignedType_SIGNED_KEY_REGISTER] = true })
	app := newTestPresenceProvider(t, bridge.KeyAlg_KEY_ALG_WEBAUTHN_ES256)
	register := func(handle *PresenceKeyHandle, prove func(message []byte) []byte, countersign func(message []byte) []byte) (*DaemonKeysPresenceReply, *DaemonPresenceBeginReply) {
		t.Helper()
		begin := &DaemonKeysPresenceBeginReply{}
		if rpcErr := world.appCall(t, DaemonMethodKeysPresenceBegin, &DaemonKeysPresenceBeginParams{
			KeyId: handle.KeyId, Alg: DaemonPresenceAlgWebAuthnEs256, PublicKey: handle.PublicKey,
		}, begin); rpcErr != nil || begin.ActId == nil || len(begin.Proof) == 0 {
			t.Fatalf("the first call: %+v, %v", begin, rpcErr)
		}
		proved := &DaemonPresenceBeginReply{}
		if rpcErr := world.appCall(t, DaemonMethodKeysPresenceProve, &DaemonPresenceFinishParams{ActId: *begin.ActId, Evidence: prove(begin.Proof)}, proved); rpcErr != nil {
			t.Fatalf("the second call: %v", rpcErr)
		}
		if proved.Refusal != nil {
			return nil, proved
		}
		reply := &DaemonKeysPresenceReply{}
		if rpcErr := world.appCall(t, DaemonMethodKeysPresenceFinish, &DaemonPresenceFinishParams{ActId: *begin.ActId, Evidence: countersign(proved.Countersigned)}, reply); rpcErr != nil {
			t.Fatalf("the third call: %v", rpcErr)
		}
		return reply, proved
	}
	assertWith := func(keyId []byte) func(message []byte) []byte {
		return func(message []byte) []byte {
			if len(message) == 0 {
				return nil
			}
			evidence, err := app.Assert(t.Context(), keyId, message)
			if err != nil {
				t.Fatal(err)
			}
			encoded, _ := proto.Marshal(evidence)
			return encoded
		}
	}

	// a first key: proved, uncovered, signed at the third call
	first, err := app.Register(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	reply, proved := register(first, assertWith(first.KeyId), assertWith(first.KeyId))
	if len(proved.Countersigned) != 0 || reply.Refusal != nil || reply.Position == 0 || !bytes.Equal(reply.KeyId, first.KeyId) {
		t.Fatalf("the first key: %+v, %+v", proved, reply)
	}
	posts := world.posted(t)
	if len(posts) != 1 || bridge.SignedType(posts[0].GetType()) != bridge.SignedType_SIGNED_KEY_REGISTER || posts[0].GetWebauthn() != nil {
		t.Fatalf("posted %d statements", len(posts))
	}
	registered := &protocol.KeyRegister{}
	postedBody(t, posts[0], registered)
	if err := VerifyPresenceRegistration(registered, posts[0]); err != nil || !bytes.Equal(registered.GetKeyId(), first.KeyId) {
		t.Fatalf("the KeyRegister's proof: %v", err)
	}
	// the key is live now: the app's second key is covered, and the first one countersigns it
	world.authority.edit(func() {
		world.authority.liveKeys = append(world.authority.liveKeys, app.row(first.KeyId, world.memberId, world.selfId))
	})
	second, err := app.Register(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	reply, proved = register(second, assertWith(second.KeyId), assertWith(first.KeyId))
	if len(proved.Countersigned) == 0 || reply.Refusal != nil || reply.Position == 0 {
		t.Fatalf("the second key: %+v, %+v", proved, reply)
	}
	posts = world.posted(t)
	if len(posts) != 2 || VerifyPresenceCountersignature(posts[1], bridge.SignedPurposeAuthority, app.row(first.KeyId, world.memberId, world.selfId)) != nil {
		t.Fatalf("the second key's countersignature: %d posts", len(posts))
	}

	// a proof by another key cancels at the second call; nothing posted
	third, err := app.Register(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, refused := register(third, assertWith(first.KeyId), assertWith(first.KeyId)); refused.Refusal == nil || refused.Refusal.Code != DeviceRevokeCodeCancelled {
		t.Fatalf("a proof by another key: %+v", refused)
	}
	// the third call before the second spends the act
	begin := &DaemonKeysPresenceBeginReply{}
	if rpcErr := world.appCall(t, DaemonMethodKeysPresenceBegin, &DaemonKeysPresenceBeginParams{
		KeyId: third.KeyId, Alg: DaemonPresenceAlgWebAuthnEs256, PublicKey: third.PublicKey,
	}, begin); rpcErr != nil || begin.ActId == nil {
		t.Fatalf("the first call: %+v, %v", begin, rpcErr)
	}
	outOfOrder := &DaemonKeysPresenceReply{}
	if rpcErr := world.appCall(t, DaemonMethodKeysPresenceFinish, &DaemonPresenceFinishParams{ActId: *begin.ActId}, outOfOrder); rpcErr == nil ||
		!strings.Contains(rpcErr.Message, ErrDaemonPresenceActStage.Error()) {
		t.Fatalf("the third call first: %+v, %v", outOfOrder, rpcErr)
	}
	if world.heldAct(*begin.ActId) != nil {
		t.Fatal("an act out of order stands")
	}
	if posts := world.deltaApi.postsSoFar(); len(posts) != 2 {
		t.Fatalf("%d statements posted, want the two keys", len(posts))
	}
	// an algorithm no profile names refuses at the first call
	if rpcErr := world.appCall(t, DaemonMethodKeysPresenceBegin, &DaemonKeysPresenceBeginParams{
		KeyId: third.KeyId, Alg: "rsa", PublicKey: third.PublicKey,
	}, begin); rpcErr == nil {
		t.Fatal("an algorithm no profile names began an act")
	}
}

// The daemon's close ends every held act unsigned.
func TestTwoCallActsEndWithTheDaemon(t *testing.T) {
	world := newPresenceActTestWorld(t)
	world.addAppKey(t, bridge.SignedType_SIGNED_SIDECAR_REVOKE)
	begin := world.beginRevoke(t, world.previewOther(t))
	act := world.heldAct(*begin.ActId)
	world.daemon.cancel()
	<-act.ended
	<-act.done
	if world.heldCount() != 0 || len(world.deltaApi.postsSoFar()) != 0 {
		t.Fatalf("after the daemon closed: %d held, %d posted", world.heldCount(), len(world.deltaApi.postsSoFar()))
	}
	if revokeCode(act.err) != DeviceRevokeCodeCancelled {
		t.Errorf("the act's run answered %v", act.err)
	}
}
