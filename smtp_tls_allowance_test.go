//go:build !sidecar_http && !ios_extension

// §14.4's TL4 allowance on §16.6's real gate (QD-729), over the approval world's ledger, inbox and
// store (record_approval_state_test.go): the allowance is its own request, which an approver's device
// renders with its sentence; an approval of a mail_send to the domain, found or handed over, spends
// nothing on it; the phone's approval of the request keeps the allowance for that domain alone; a kill
// after the Reserve, and one after the effect, reconcile through SmtpTlsPolicy.Lookup. Then the store
// on its own: its file round-trips, a malformed one is a store failure and never no allowance, a later
// allowance replaces the domain's, and a full store refuses a new domain rather than dropping one.
//
// Names are .example. The sends themselves are smtp_tls_policy_test.go's.

package sidecar

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// A sender's directory of an instance's store, as its host hands it over.
func testSmtpSenderStore(t *testing.T, store SidecarStore) SidecarStore {
	t.Helper()
	senderStore, err := store.Directory("smtp", "smtp")
	if err != nil {
		t.Fatal(err)
	}
	return senderStore
}

// The approval world's policy: its allowances in the world's store, its gate the world's real one, and
// its Lookup registered for the kind, as the sender's host does. Built afresh each call, as after a
// restart, once the world's gate has been.
func (self *testApprovalWorld) tlsPolicy() *SmtpTlsPolicy {
	allowances := NewSmtpTlsAllowanceStore(testSmtpSenderStore(self.t, self.store), DefaultSmtpSenderSettings(), self.clock)
	policy := &SmtpTlsPolicy{allowances: allowances, authorizer: self.gate, clock: self.clock}
	self.lookups[SidecarActionMailTlsUnauthenticated] = policy.Lookup
	return policy
}

// The phone approves request, and the requester's inbox takes the decision.
func (self *testApprovalWorld) phoneApproves(request *StoredApprovalRequest) []byte {
	self.t.Helper()
	decision := self.approve(request)
	self.log.putDecision(request.ApprovalId(), decision)
	if err := self.inbox.Poll(self.t.Context()); err != nil {
		self.t.Fatal(err)
	}
	return decision
}

// A mail_send to recipient in no run, as an app's own send, approved by the phone and spent.
func (self *testApprovalWorld) spentMail(recipient string) (*StoredApprovalRequest, []byte) {
	self.t.Helper()
	bodySha256 := sha256.Sum256([]byte("body for " + recipient))
	stored, err := NewCanonicalAction(&protocol.CanonicalAction{
		Kind: uint32(SidecarActionMail), Recipients: []string{recipient}, BodySha256: bodySha256[:], Alias: "me",
	})
	if err != nil {
		self.t.Fatal(err)
	}
	action := func() *SidecarAction {
		return &SidecarAction{Kind: SidecarActionMail, Canonical: stored.Bytes, Risk: SidecarRiskNormal, Effect: self.effect}
	}
	request := self.pendingRequest(self.gate.Authorize(self.t.Context(), action(), nil))
	decision := self.phoneApproves(request)
	spent := action()
	testGateExpectOutcome(self.t, "the mail_send", self.gate.Authorize(self.t.Context(), spent, nil), spent, ApprovalOutcomeDone)
	return request, decision
}

// The allowance is its own action on the real gate: an approved, spent mail_send to the domain, and a
// second one's unspent approval handed over as the decision, keep nothing; the request filed is
// mail_tls_unauthenticated for the domain, rendered with its sentence; the phone's approval of it keeps
// the allowance, for that domain alone, under the approval's id.
func TestSmtpTlsAllowancePassesTheRealGate(t *testing.T) {
	world := newTestApprovalWorld(t)
	policy := world.tlsPolicy()
	world.spentMail("someone@mail.example")

	request := world.pendingRequest(policy.AllowUnauthenticated(t.Context(), "Mail.Example.", time.Time{}, nil))
	action := request.Action.Action
	if SidecarActionKind(action.GetKind()) != SidecarActionMailTlsUnauthenticated || action.GetHost() != "mail.example" ||
		action.GetExpiresMillis() != 0 || action.GetScope() || len(request.Request.GetRunId()) != 0 || request.Request.GetTainted() {
		t.Fatalf("the request filed: %+v", request.Request)
	}
	render := RenderApprovalRequest(request)
	wantMeaning := "Send mail to mail.example through a mail server that cannot be authenticated: an active URnetwork edge could read it"
	if render.Meaning != wantMeaning || render.KindName != "mail_tls_unauthenticated" || !strings.Contains(render.Text(), wantMeaning) ||
		len(render.Fields) != 1 || render.Fields[0].Name != "host" || render.Fields[0].Value != "mail.example" {
		t.Errorf("the render: %+v\n%s", render, render.Text())
	}
	if allowance, err := policy.UnauthenticatedAllowance("mail.example"); err != nil || allowance != nil {
		t.Errorf("a waiting request kept an allowance: %+v %v", allowance, err)
	}
	// the same allowance asked again finds its request and files no other
	if again := world.pendingRequest(policy.AllowUnauthenticated(t.Context(), "mail.example", time.Time{}, nil)); again.ApprovalId() != request.ApprovalId() {
		t.Error("the same allowance filed a second request")
	}

	// an approval of another mail_send to the domain, handed over as the allowance's decision
	mailBodySha256 := sha256.Sum256([]byte("another body"))
	otherMail, err := NewCanonicalAction(&protocol.CanonicalAction{
		Kind: uint32(SidecarActionMail), Recipients: []string{"other@mail.example"}, BodySha256: mailBodySha256[:], Alias: "me",
	})
	if err != nil {
		t.Fatal(err)
	}
	mailRequest := world.pendingRequest(world.gate.Authorize(t.Context(),
		&SidecarAction{Kind: SidecarActionMail, Canonical: otherMail.Bytes, Risk: SidecarRiskNormal, Effect: world.effect}, nil))
	mailDecision := world.phoneApproves(mailRequest)
	err = policy.AllowUnauthenticated(t.Context(), "mail.example", time.Time{}, testGateSigned(t, mailDecision))
	if !errors.Is(err, ErrApprovalRefused) {
		t.Errorf("a mail_send's decision as the allowance's: %v", err)
	}
	if allowance, err := policy.UnauthenticatedAllowance("mail.example"); err != nil || allowance != nil {
		t.Fatalf("a mail_send's approval kept an allowance: %+v %v", allowance, err)
	}
	if reserves := world.state(mailRequest.ApprovalId()).Reserves; len(reserves) != 0 {
		t.Errorf("the allowance took %d uses of the mail_send's approval", len(reserves))
	}

	world.phoneApproves(request)
	if err := policy.AllowUnauthenticated(t.Context(), "mail.example", time.Time{}, nil); err != nil {
		t.Fatal(err)
	}
	allowance, err := policy.UnauthenticatedAllowance("MAIL.example")
	if err != nil || allowance == nil || allowance.RecipientDomain != "mail.example" || !allowance.ExpireTime.IsZero() ||
		allowance.ApprovalId == nil || *allowance.ApprovalId != request.ApprovalId() {
		t.Fatalf("the allowance: %+v %v", allowance, err)
	}
	if got := world.status(request.ApprovalId()); got != ApprovalStatusSpent {
		t.Errorf("status %s", got)
	}
	for _, domain := range []string{"other.example", "sub.mail.example", "example"} {
		if other, err := policy.UnauthenticatedAllowance(domain); err != nil || other != nil {
			t.Errorf("%s is allowed by another domain's allowance: %+v %v", domain, other, err)
		}
	}
	// AU4: the same allowance again answers its outcome, and the store's allowance is the one made
	if err := policy.AllowUnauthenticated(t.Context(), "mail.example", time.Time{}, nil); err != nil {
		t.Errorf("the same allowance again: %v", err)
	}
	// a restart: the store's file gives the allowance back
	world.open()
	if again, err := world.tlsPolicy().UnauthenticatedAllowance("mail.example"); err != nil || again == nil ||
		!again.AllowTime.Equal(allowance.AllowTime) || again.ApprovalId == nil || *again.ApprovalId != request.ApprovalId() {
		t.Errorf("the allowance after a restart: %+v %v", again, err)
	}
	// another domain's allowance is another request
	if other := world.pendingRequest(world.tlsPolicy().AllowUnauthenticated(t.Context(), "other.example", time.Time{}, nil)); other.ApprovalId() == request.ApprovalId() {
		t.Error("another domain's allowance found this domain's approval")
	}
}

// A denial stops the allowance rather than asking again, and nothing is kept.
func TestSmtpTlsAllowanceDeniedKeepsNothing(t *testing.T) {
	world := newTestApprovalWorld(t)
	policy := world.tlsPolicy()
	request := world.pendingRequest(policy.AllowUnauthenticated(t.Context(), "mail.example", time.Time{}, nil))
	world.log.putDecision(request.ApprovalId(), world.decision(request, world.spend.phone, protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE,
		protocol.ApprovalVerdict_APPROVAL_VERDICT_DENY, 1))
	if err := world.inbox.Poll(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := policy.AllowUnauthenticated(t.Context(), "mail.example", time.Time{}, nil); !errors.Is(err, ErrApprovalDenied) {
		t.Errorf("a denied allowance: %v", err)
	}
	if allowance, err := policy.UnauthenticatedAllowance("mail.example"); err != nil || allowance != nil {
		t.Errorf("a denied allowance was kept: %+v %v", allowance, err)
	}
}

// A kill after the Reserve and before the effect: the restart's reconcile finds no allowance under the
// key and leaves the use uncertain, and the same allowance asked again completes it under that key. A
// kill after the effect and before its Outcome: the reconcile finds the allowance and records done.
func TestSmtpTlsAllowanceReconcilesAfterAKill(t *testing.T) {
	for _, effectDone := range []bool{false, true} {
		world := newTestApprovalWorld(t)
		policy := world.tlsPolicy()
		request := world.pendingRequest(policy.AllowUnauthenticated(t.Context(), "mail.example", time.Time{}, nil))
		world.phoneApproves(request)
		effectKey := world.reserveDirect(request, request.Action)
		approvalId := request.ApprovalId()
		if effectDone {
			if _, err := policy.allowances.allow("mail.example", time.Time{}, effectKey, &approvalId); err != nil {
				t.Fatal(err)
			}
		}
		// the restart: a gate and a policy built afresh, the gate reconciling before it serves
		world.open()
		policy = world.tlsPolicy()
		recordedCount, err := world.gate.Reconcile(t.Context())
		if err != nil || recordedCount != 1 {
			t.Fatalf("effect done %t: reconcile recorded %d, %v", effectDone, recordedCount, err)
		}
		want := ApprovalOutcomeUncertain
		if effectDone {
			want = ApprovalOutcomeDone
		}
		actionId := request.Action.ActionId(approvalId)
		if outcome := world.state(approvalId).Outcome(actionId[:]); outcome == nil || outcome.State != want {
			t.Fatalf("effect done %t: reconciled %+v", effectDone, outcome)
		}
		if allowance, err := policy.UnauthenticatedAllowance("mail.example"); err != nil || (allowance != nil) != effectDone {
			t.Fatalf("effect done %t: the allowance after the restart: %+v %v", effectDone, allowance, err)
		}
		if err := policy.AllowUnauthenticated(t.Context(), "mail.example", time.Time{}, nil); err != nil {
			t.Fatalf("effect done %t: the allowance asked again: %v", effectDone, err)
		}
		allowance, err := policy.UnauthenticatedAllowance("mail.example")
		if err != nil || allowance == nil || !bytes.Equal(allowance.effectKey, effectKey) || *allowance.ApprovalId != approvalId {
			t.Errorf("effect done %t: the allowance: %+v %v", effectDone, allowance, err)
		}
		if outcome := world.state(approvalId).Outcome(actionId[:]); outcome == nil || outcome.State != ApprovalOutcomeDone {
			t.Errorf("effect done %t: the use's outcome %+v", effectDone, outcome)
		}
	}
}

// The Lookup answers only for its own kind and key: an allowance made under another key, or for
// another domain than the action's, is not this use's effect.
func TestSmtpTlsAllowanceLookupIsHeldToItsKindAndKey(t *testing.T) {
	world := newTestApprovalWorld(t)
	policy := world.tlsPolicy()
	stored, err := NewCanonicalAction(&protocol.CanonicalAction{Kind: uint32(SidecarActionMailTlsUnauthenticated), Host: "mail.example"})
	if err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{0x11}, sha256.Size)
	otherKey := bytes.Repeat([]byte{0x22}, sha256.Size)
	if outcome, err := policy.Lookup(t.Context(), stored.Bytes, key); err != nil || outcome.State != ApprovalOutcomeUncertain {
		t.Errorf("no allowance: %+v %v", outcome, err)
	}
	allowance, err := policy.allowances.allow("mail.example", time.Time{}, key, nil)
	if err != nil {
		t.Fatal(err)
	}
	if outcome, err := policy.Lookup(t.Context(), stored.Bytes, key); err != nil || outcome.State != ApprovalOutcomeDone || !bytes.Equal(outcome.EffectRef, allowance.effectRef()) {
		t.Errorf("the allowance's key: %+v %v", outcome, err)
	}
	if outcome, err := policy.Lookup(t.Context(), stored.Bytes, otherKey); err != nil || outcome.State != ApprovalOutcomeUncertain {
		t.Errorf("another key: %+v %v", outcome, err)
	}
	other, err := NewCanonicalAction(&protocol.CanonicalAction{Kind: uint32(SidecarActionMailTlsUnauthenticated), Host: "other.example"})
	if err != nil {
		t.Fatal(err)
	}
	if outcome, err := policy.Lookup(t.Context(), other.Bytes, key); err != nil || outcome.State != ApprovalOutcomeUncertain {
		t.Errorf("another domain's action under the key: %+v %v", outcome, err)
	}
	if _, err := policy.Lookup(t.Context(), world.mailAction("someone@mail.example").Bytes, key); !errors.Is(err, ErrSidecarActionInvalid) {
		t.Errorf("a mail_send: %v", err)
	}
	if _, err := policy.Lookup(t.Context(), []byte{0xff}, key); err == nil {
		t.Error("bytes that are no action")
	}
}

// The store on its own: an allowance holds until its end, a later one replaces the domain's, the file
// gives both back after a restart, and a call under the key an allowance was made under writes nothing.
func TestSmtpTlsAllowanceStoreKeepsOneADomain(t *testing.T) {
	instance, _, _ := enrolledInstance(t)
	store := testSmtpSenderStore(t, instance.Store(&testNetworkId))
	clock := newRecordTestClock()
	settings := DefaultSmtpSenderSettings()
	allowances := NewSmtpTlsAllowanceStore(store, settings, clock)
	start := clock.Now()
	key := bytes.Repeat([]byte{0x31}, sha256.Size)
	approvalId := testConfigId("tls allowance approval")

	first, err := allowances.allow("mail.example", start.Add(time.Hour), key, &approvalId)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := allowances.allow("other.example", time.Time{}, nil, nil); err != nil {
		t.Fatal(err)
	}
	clock.advance(time.Minute)
	if again, err := allowances.allow("mail.example", start.Add(time.Hour), key, &approvalId); err != nil || !again.AllowTime.Equal(first.AllowTime) {
		t.Errorf("the same key again: %+v %v", again, err)
	}
	listed, err := allowances.Allowances()
	if err != nil || len(listed) != 2 || listed[0].RecipientDomain != "mail.example" || listed[1].RecipientDomain != "other.example" ||
		listed[1].ApprovalId != nil || !listed[1].ExpireTime.IsZero() {
		t.Fatalf("the allowances: %+v %v", listed, err)
	}

	// a restart
	allowances = NewSmtpTlsAllowanceStore(store, settings, clock)
	held, err := allowances.Allowance("mail.example")
	if err != nil || held == nil || !held.ExpireTime.Equal(start.Add(time.Hour)) || !held.AllowTime.Equal(first.AllowTime) ||
		!bytes.Equal(held.effectKey, key) || held.ApprovalId == nil || *held.ApprovalId != approvalId {
		t.Fatalf("the allowance after a restart: %+v %v", held, err)
	}
	// a later allowance replaces the domain's, and its key is the one found from then on
	laterKey := bytes.Repeat([]byte{0x32}, sha256.Size)
	if _, err := allowances.allow("mail.example", start.Add(2*time.Hour), laterKey, nil); err != nil {
		t.Fatal(err)
	}
	if replaced, err := allowances.effect(key); err != nil || replaced != nil {
		t.Errorf("the replaced allowance's key: %+v %v", replaced, err)
	}
	clock.advance(time.Hour)
	if held, err := allowances.Allowance("mail.example"); err != nil || held == nil || !held.ExpireTime.Equal(start.Add(2*time.Hour)) {
		t.Errorf("the later allowance: %+v %v", held, err)
	}
	clock.advance(time.Hour)
	if held, err := allowances.Allowance("mail.example"); err != nil || held != nil {
		t.Errorf("an ended allowance: %+v %v", held, err)
	}
	if _, err := allowances.allow("mail.example", clock.Now(), nil, nil); !errors.Is(err, ErrSmtpTlsAllowanceEnded) {
		t.Errorf("an allowance that ends now: %v", err)
	}
	if listed, err := allowances.Allowances(); err != nil || len(listed) != 1 || listed[0].RecipientDomain != "other.example" {
		t.Errorf("the allowances that hold: %+v %v", listed, err)
	}
	for _, name := range []string{"", "not a domain", "mail..example"} {
		if _, err := allowances.Allowance(name); !errors.Is(err, ErrSmtpTlsRequest) {
			t.Errorf("%q: %v", name, err)
		}
	}
	if _, err := allowances.allow("mail.example", time.Time{}, []byte{1, 2, 3}, nil); !errors.Is(err, ErrSmtpTlsRequest) {
		t.Errorf("a short effect key: %v", err)
	}
}

// A full store refuses a new domain's allowance, before the gate is asked and again in the effect,
// rather than dropping another's; a domain it already holds is still replaced, and an allowance that
// ended makes room.
func TestSmtpTlsAllowanceStoreRefusesPastItsCount(t *testing.T) {
	world := newTestApprovalWorld(t)
	settings := DefaultSmtpSenderSettings()
	settings.TlsAllowanceMaxCount = 2
	allowances := NewSmtpTlsAllowanceStore(testSmtpSenderStore(t, world.store), settings, world.clock)
	policy := &SmtpTlsPolicy{allowances: allowances, authorizer: world.gate, clock: world.clock}
	world.lookups[SidecarActionMailTlsUnauthenticated] = policy.Lookup
	start := world.clock.Now()

	if _, err := allowances.allow("first.example", start.Add(time.Hour), nil, nil); err != nil {
		t.Fatal(err)
	}
	// a request filed while there was room, approved once there is none
	request := world.pendingRequest(policy.AllowUnauthenticated(t.Context(), "third.example", time.Time{}, nil))
	world.phoneApproves(request)
	if _, err := allowances.allow("second.example", time.Time{}, nil, nil); err != nil {
		t.Fatal(err)
	}
	filedCount := world.log.filedCount()
	if err := policy.AllowUnauthenticated(t.Context(), "fourth.example", time.Time{}, nil); !errors.Is(err, ErrSmtpTlsAllowanceFull) {
		t.Errorf("a new domain past the count: %v", err)
	}
	if world.log.filedCount() != filedCount {
		t.Error("a request was filed for an allowance the store has no room for")
	}
	effect := &smtpTlsAllowanceEffect{allowances: allowances, domain: "third.example"}
	if _, err := effect.Run(t.Context(), bytes.Repeat([]byte{0x41}, sha256.Size)); !errors.Is(err, ErrSidecarEffectNotDone) || !errors.Is(err, ErrSmtpTlsAllowanceFull) {
		t.Errorf("the effect past the count: %v", err)
	}
	if _, err := allowances.allow("second.example", start.Add(3*time.Hour), nil, nil); err != nil {
		t.Errorf("a held domain's allowance replaced: %v", err)
	}
	if listed, err := allowances.Allowances(); err != nil || len(listed) != 2 {
		t.Errorf("the allowances: %+v %v", listed, err)
	}
	// first.example's ends, which makes room for the approved third
	world.clock.advance(time.Hour)
	if err := policy.AllowUnauthenticated(t.Context(), "third.example", time.Time{}, nil); err != nil {
		t.Errorf("an allowance once one ended: %v", err)
	}
	listed, err := allowances.Allowances()
	if err != nil || len(listed) != 2 || listed[0].RecipientDomain != "second.example" || listed[1].RecipientDomain != "third.example" {
		t.Errorf("the allowances: %+v %v", listed, err)
	}
}

// A file that is not this version's well-formed records is a store failure, never read as no
// allowances, and nothing is written over it.
func TestSmtpTlsAllowanceFileIsHeldToItsFormat(t *testing.T) {
	for name, contents := range map[string]string{
		"not json":         "not json",
		"another version":  `{"version":2,"allowances":[]}`,
		"a null record":    `{"version":1,"allowances":[null]}`,
		"a capital":        `{"version":1,"allowances":[{"domain":"Mail.example","allow_time_ms":5}]}`,
		"a trailing dot":   `{"version":1,"allowances":[{"domain":"mail.example.","allow_time_ms":5}]}`,
		"no allow time":    `{"version":1,"allowances":[{"domain":"mail.example"}]}`,
		"a negative end":   `{"version":1,"allowances":[{"domain":"mail.example","allow_time_ms":5,"expire_time_ms":-1}]}`,
		"a short key":      `{"version":1,"allowances":[{"domain":"mail.example","allow_time_ms":5,"effect_key":"AQID"}]}`,
		"a short approval": `{"version":1,"allowances":[{"domain":"mail.example","allow_time_ms":5,"approval_id":"AQID"}]}`,
		"a domain twice":   `{"version":1,"allowances":[{"domain":"mail.example","allow_time_ms":5},{"domain":"mail.example","allow_time_ms":6}]}`,
	} {
		instance, _, _ := enrolledInstance(t)
		store := testSmtpSenderStore(t, instance.Store(&testNetworkId))
		if err := smtpWriteStoreFile(store, smtpTlsAllowanceFileName, []byte(contents)); err != nil {
			t.Fatal(err)
		}
		allowances := NewSmtpTlsAllowanceStore(store, DefaultSmtpSenderSettings(), newRecordTestClock())
		if _, err := allowances.Allowance("mail.example"); !errors.Is(err, ErrSidecarStoreFailed) {
			t.Errorf("%s: %v", name, err)
		}
		if _, err := allowances.allow("mail.example", time.Time{}, nil, nil); !errors.Is(err, ErrSidecarStoreFailed) {
			t.Errorf("%s: an allowance over it: %v", name, err)
		}
		if data, found, err := smtpReadStoreFile(store, smtpTlsAllowanceFileName); err != nil || !found || string(data) != contents {
			t.Errorf("%s: the file was written over: %q %v", name, data, err)
		}
	}
	instance, _, _ := enrolledInstance(t)
	store := testSmtpSenderStore(t, instance.Store(&testNetworkId))
	if err := smtpWriteStoreFile(store, smtpTlsAllowanceFileName, []byte(`{"version":1,"allowances":[{"domain":"mail.example","allow_time_ms":5}]}`)); err != nil {
		t.Fatal(err)
	}
	allowance, err := NewSmtpTlsAllowanceStore(store, DefaultSmtpSenderSettings(), newRecordTestClock()).Allowance("mail.example")
	if err != nil || allowance == nil || !allowance.ExpireTime.IsZero() || allowance.ApprovalId != nil || len(allowance.effectKey) != 0 {
		t.Errorf("a well-formed file: %+v %v", allowance, err)
	}
}
