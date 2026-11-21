//go:build !js && !ios && !android && !sdk_mobile_bind

// MCP-M9-01's internet mail_send (R-MCP-9, D-MCP-11, I-8, AU1-AU4) on tools_mail_test.go's env: the approval world's
// mail sink stands in for MAIL's outbox, o/<h>/<effect_key> created only if absent (MailOutbox.Queue), and its
// Lookup for MailOutbox.Lookup, so AU1 counts objects, never SMTP sends, which claim no exactly-once. The tests hold
// one object per effect key across a crash between the Reserve and the object and a daemon restart, and across a
// crash after the object and before its Outcome, a retry through a new session answering the first's message id; and
// internet recipients that each hold an approval record going at once in a clean run and outward in a tainted one
// (TS1). MAIL's outbox itself, its standing and its or/ outcomes are MAIL's tests (mail_outbox_test.go,
// mail_send_result_test.go); S6's mail_send path through SMTP's scenario is the review phase's.

package mcp

import (
	"errors"
	"testing"

	"github.com/urnetwork/sidecar"
)

// An internet send's arguments.
func testMailOutboxSend() map[string]any {
	return map[string]any{
		"from_alias": testMailAddress("me"), "to": []string{"buyer@outside.example"}, "bcc": []string{"files@outside.example"},
		"subject": "your order", "text": "it ships monday",
	}
}

// The world's one Reserve of approvalId, its effect key.
func (self *testMailToolEnv) reservedKey(approvalId sidecar.Id) []byte {
	self.t.Helper()
	state, err := self.world.LedgerState(approvalId)
	if err != nil {
		self.t.Fatal(err)
	}
	if len(state.Reserves) != 1 {
		self.t.Fatalf("%d Reserves of approval %s", len(state.Reserves), approvalId)
	}
	return state.Reserves[0].EffectKey
}

// Kills the world's daemon and starts it again, its gate reconciling every unresolved use before it serves.
func (self *testMailToolEnv) restartDaemon() {
	self.t.Helper()
	if err := self.net.Kill("daemon"); err != nil {
		self.t.Fatal(err)
	}
	if err := self.net.Restart("daemon", "restarted"); err != nil {
		self.t.Fatal(err)
	}
}

// One outbox object per effect key: a crash between the Reserve and the object leaves the use uncertain, the call
// answering that it may go again; the daemon restarts and its reconcile leaves it so, nothing proving the object; the
// same call again, through a new session, completes the use under the Reserve's own key, and later calls answer that
// send's message id with no second object (AU1, AU3, AU4).
func TestOutboxObjectOncePerEffectKey(t *testing.T) {
	env := newTestMailToolEnv(t)
	conn := env.conn("2025-11-25")
	pending, _ := testMailData[mcpMailSendOut](t, env.callTool(conn, "2025-11-25", "mail_send", testMailOutboxSend()))
	if pending.Status != mcpMailStatusApprovalPending {
		t.Fatalf("an internet send: %+v", pending)
	}
	approvalId := env.approve(pending.ApprovalId, 1)
	outbox := env.world.Sink(sidecar.SidecarActionMail)
	outbox.SetAnswer(errors.New("the process died before the object"))
	wantMcpError(t, env.callTool(conn, "2025-11-25", "mail_send", testMailOutboxSend()), McpCodeFailed, "sends nothing twice")
	key := env.reservedKey(approvalId)
	if outbox.EffectCount() != 0 {
		t.Fatal("an object before the crash's retry")
	}

	env.restartDaemon()
	outbox.SetAnswer(nil)
	retry, _ := env.cleanRun("after the restart")
	sent, _ := testMailData[mcpMailSendOut](t, env.callTool(retry, "2025-11-25", "mail_send", testMailOutboxSend()))
	if sent.Status != mcpMailStatusSent || sent.MessageId == "" || len(sent.Recipients) != 2 || sent.Recipients[1].Outcome != "queued" {
		t.Fatalf("the retry: %+v", sent)
	}
	keys := outbox.EffectKeys()
	if outbox.EffectCount() != 1 || len(keys) != 1 || string(keys[0]) != string(key) {
		t.Fatalf("%d objects, under %d keys", outbox.EffectCount(), len(keys))
	}
	again, _ := testMailData[mcpMailSendOut](t, env.callTool(conn, "2025-11-25", "mail_send", testMailOutboxSend()))
	if again.Status != mcpMailStatusSent || again.MessageId != sent.MessageId || outbox.EffectCount() != 1 {
		t.Fatalf("a later call: %+v, %d objects", again, outbox.EffectCount())
	}
	if env.reservedKey(approvalId) == nil {
		t.Fatal("the use's Reserve went")
	}
	if err := env.world.CheckEffects(true); err != nil {
		t.Fatal(err)
	}
}

// A crash after the object and before its Outcome: the restart's reconcile finds the object by the outbox's Lookup and
// records the use done, so the call again answers it, and no second object is queued.
func TestOutboxObjectFoundAfterACrashBeforeItsOutcome(t *testing.T) {
	env := newTestMailToolEnv(t)
	conn := env.conn("2025-11-25")
	pending, _ := testMailData[mcpMailSendOut](t, env.callTool(conn, "2025-11-25", "mail_send", testMailOutboxSend()))
	approvalId := env.approve(pending.ApprovalId, 1)
	outbox := env.world.Sink(sidecar.SidecarActionMail)
	outbox.SetAnswer(errors.New("the answer was lost"))
	wantMcpError(t, env.callTool(conn, "2025-11-25", "mail_send", testMailOutboxSend()), McpCodeFailed, "sends nothing twice")
	// the object did land before the process died
	ref := outbox.DoneUnder(env.reservedKey(approvalId))
	outbox.SetAnswer(nil)

	env.restartDaemon()
	state, err := env.world.LedgerState(approvalId)
	if err != nil {
		t.Fatal(err)
	}
	if outcome := state.Outcome(state.Reserves[0].ActionId); outcome == nil || outcome.State != sidecar.ApprovalOutcomeDone {
		t.Fatalf("the restart's reconcile: %+v", outcome)
	}
	sent, _ := testMailData[mcpMailSendOut](t, env.callTool(conn, "2025-11-25", "mail_send", testMailOutboxSend()))
	if sent.Status != mcpMailStatusSent || sent.MessageId != testMailSendId(ref).String() || outbox.EffectCount() != 1 || outbox.RunCount() != 1 {
		t.Fatalf("the call again: %+v, %d objects in %d runs", sent, outbox.EffectCount(), outbox.RunCount())
	}
	if err := env.world.CheckEffects(true); err != nil {
		t.Fatal(err)
	}
}

// Internet recipients that each hold an approval record (owner decision 280) go at once in a clean run, queued with
// no action handed to the gate; in a tainted run the records are ignored and the same send waits on a decision (TS1).
func TestApprovedRecipientsQueueAtOnceInACleanRunAlone(t *testing.T) {
	env := newTestMailToolEnv(t)
	env.mail.approved["buyer@outside.example"] = true
	env.mail.approved["files@outside.example"] = true
	conn := env.conn("2025-11-25")
	sent, _ := testMailData[mcpMailSendOut](t, env.callTool(conn, "2025-11-25", "mail_send", testMailOutboxSend()))
	if sent.Status != mcpMailStatusSent || len(sent.Recipients) != 2 || sent.Recipients[0].Outcome != "queued" || len(env.mail.gated()) != 0 {
		t.Fatalf("a clean run's send to approved recipients: %+v, %d gated", sent, len(env.mail.gated()))
	}
	_, outside := env.message("someone@outside.example", "note", "outside words", false)
	testEnvelopeOf(t, env.callTool(conn, "2025-11-25", "mail_read", map[string]any{"id": testMailIdOf(outside)}))
	held, _ := testMailData[mcpMailSendOut](t, env.callTool(conn, "2025-11-25", "mail_send", testMailOutboxSend()))
	if held.Status != mcpMailStatusApprovalPending || len(env.mail.gated()) != 1 {
		t.Fatalf("a tainted run's send to approved recipients: %+v", held)
	}
}
