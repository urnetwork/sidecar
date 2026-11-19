//go:build !js && !ios && !android && !sdk_mobile_bind && !sidecar_http && !ios_extension

package sidecar

// mail.check_send, mail.send_result and mail.send (QD-853, owner decision 288) on the dispatcher with no socket, over a
// Sidecar holding an identity and the test's backends: three network methods, none a Confirm one; check_send answering
// a draft's domains as JSON in the root's numbers; send_result answering a known send and refusing an unknown or a
// missing id; both reads answering ErrMailSendUnavailable while their calls are not on MailClient; params read
// strictly; and mail.send over MAIL-M7-18's send world answering the approval the gate holds it for, nothing kept or
// deposited, then the send_id once a decision passes it.

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"
)

// A daemon hosting one network's Sidecar, the send methods over backends registered.
type mailSendDaemonTestWorld struct {
	daemon    *Daemon
	networkId Id
}

func newMailSendDaemonTestWorld(t *testing.T, backends *DaemonMailSendBackends) *mailSendDaemonTestWorld {
	t.Helper()
	sidecar, _, _ := newIdentityTestSidecar(t)
	identity := sidecar.Identity()
	daemon := newDispatchTestDaemon(t)
	if err := daemon.AddSidecar(identity.NetworkId, sidecar); err != nil {
		t.Fatal(err)
	}
	for _, method := range DaemonMailSendMethods(backends) {
		if err := daemon.RegisterMethod(method); err != nil {
			t.Fatal(err)
		}
	}
	return &mailSendDaemonTestWorld{daemon: daemon, networkId: identity.NetworkId}
}

// One control request for method, its params params encoded, or as given where they are a string; its response.
func (self *mailSendDaemonTestWorld) call(t *testing.T, method string, params any) *daemonRpcResponse {
	t.Helper()
	request := &daemonRpcRequest{JsonRpc: "2.0", Id: json.RawMessage("1"), Method: method}
	switch params := params.(type) {
	case nil:
	case string:
		request.Params = json.RawMessage(params)
	default:
		encoded, err := json.Marshal(params)
		if err != nil {
			t.Fatal(err)
		}
		request.Params = encoded
	}
	line, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	return dispatchTest(self.daemon, DaemonModeControl, string(line))
}

// Fails unless response is a handler's refusal whose text names want.
func testMailSendDaemonRefused(t *testing.T, when string, response *daemonRpcResponse, want error) {
	t.Helper()
	if response.Error == nil || response.Error.Code != DaemonRpcFailed || !strings.Contains(response.Error.Message, want.Error()) {
		t.Errorf("%s: %+v, %s", when, response.Error, response.Result)
	}
}

// Three methods on a network, none a Confirm one: two reads and a submission the gate holds.
func TestDaemonMailSendMethodsAreReadsAndASubmission(t *testing.T) {
	names := []string{}
	for _, method := range DaemonMailSendMethods(nil) {
		names = append(names, method.Name)
		if !method.Network || method.Confirm || method.Handler == nil {
			t.Errorf("%s: network %t, confirm %t", method.Name, method.Network, method.Confirm)
		}
	}
	if !slices.Equal(names, []string{"mail.check_send", "mail.send_result", "mail.send"}) {
		t.Errorf("the methods %v", names)
	}
}

// check_send hands the draft whole to the check and answers its domains in order, as JSON with the root's numbers and
// the delay in ms; a draft with no From or no recipient, or a field the method does not know, is refused before the
// check runs, and a check that answers nothing is no empty answer.
func TestDaemonMailCheckSendAnswersADraftsDomains(t *testing.T) {
	checked := []*MailSendArgs{}
	answerNothing := false
	world := newMailSendDaemonTestWorld(t, &DaemonMailSendBackends{
		Check: func(ctx context.Context, sidecar *Sidecar, args *MailSendArgs) (*SmtpSendCheck, error) {
			checked = append(checked, args)
			if answerNothing {
				return nil, nil
			}
			return &SmtpSendCheck{Domains: []*SmtpDomainCheck{
				{Domain: "chunking.example", Mode: SmtpModeBdat, ByteCount: 2048, CapByteCount: 1024, ExpectedDelay: 30 * time.Second, Prediction: SmtpCheckOk},
				nil,
				{Domain: "plain.example", Mode: SmtpModeData, ByteCount: 2048, CapByteCount: 1024, ExpectedDelay: 40 * time.Minute, Prediction: SmtpCheckTooLarge},
				{Domain: "new.example", ByteCount: 2048, Prediction: SmtpCheckUnknown},
			}}, nil
		},
	})
	params := &DaemonMailDraftParams{
		Network: world.networkId.String(),
		From:    "ann@acme.root.example",
		To:      []string{"a@chunking.example"},
		Cc:      []string{"b@plain.example"},
		Bcc:     []string{"c@new.example"},
		Subject: "Plans",
		Text:    "Dinner at eight.",
	}
	response := world.call(t, DaemonMethodMailCheckSend, params)
	if response.Error != nil {
		t.Fatal(response.Error.Message)
	}
	want := `{"domains":[` +
		`{"domain":"chunking.example","mode":1,"byte_count":2048,"cap_byte_count":1024,"expected_delay_ms":30000,"prediction":1},` +
		`{"domain":"plain.example","mode":2,"byte_count":2048,"cap_byte_count":1024,"expected_delay_ms":2400000,"prediction":2},` +
		`{"domain":"new.example","mode":0,"byte_count":2048,"cap_byte_count":0,"expected_delay_ms":0,"prediction":3}]}`
	if string(response.Result) != want {
		t.Errorf("the check answered %s", response.Result)
	}
	if len(checked) != 1 || checked[0].From != params.From || !slices.Equal(checked[0].To, params.To) || !slices.Equal(checked[0].Cc, params.Cc) ||
		!slices.Equal(checked[0].Bcc, params.Bcc) || checked[0].Subject != params.Subject || checked[0].Text != params.Text {
		t.Fatalf("the check took %+v", checked)
	}

	for name, bad := range map[string]any{
		"no recipient":             &DaemonMailDraftParams{From: "ann@acme.root.example"},
		"no From":                  &DaemonMailDraftParams{To: []string{"a@chunking.example"}},
		"a field it does not know": `{"from":"ann@acme.root.example","to":["a@chunking.example"],"body":"t"}`,
	} {
		testMailSendDaemonRefused(t, name, world.call(t, DaemonMethodMailCheckSend, bad), ErrMailSendInvalid)
	}
	if len(checked) != 1 {
		t.Fatalf("a refused draft reached the check: %d", len(checked))
	}
	answerNothing = true
	testMailSendDaemonRefused(t, "an empty check", world.call(t, DaemonMethodMailCheckSend, params), ErrMailSendUnavailable)
}

// send_result answers a known send's outcomes in order, as JSON in or/'s names and numbers, with no effect key; an
// unknown id is refused naming no id, and no send_id, the zero id or a field the method does not know is refused
// before the read runs.
func TestDaemonMailSendResultAnswersAKnownSendAndRefusesAnUnknownId(t *testing.T) {
	known := NewId()
	read := []Id{}
	updateTime := time.UnixMilli(1_700_000_000_000)
	world := newMailSendDaemonTestWorld(t, &DaemonMailSendBackends{
		Result: func(ctx context.Context, sidecar *Sidecar, sendId Id) (*SmtpSendResult, error) {
			read = append(read, sendId)
			if sendId != known {
				return nil, ErrMailSendUnknown
			}
			return &SmtpSendResult{EffectKey: []byte("synthetic effect key"), Domains: []*SmtpDomainOutcome{
				{Domain: "a.example", Mode: SmtpModeBdat, Outcome: SmtpOutcomeSent, TlsLevel: SmtpTlsLevelUnauthenticated, UpdateTime: updateTime},
				{Domain: "b.example", Mode: SmtpModeData, Outcome: SmtpOutcomeDeferred, RetryAfter: 90 * time.Second, UpdateTime: updateTime},
				nil,
				{Domain: "c.example", Outcome: SmtpOutcomeRefused, ReplyCode: 550},
				{Domain: "d.example", Mode: SmtpModeData, Outcome: SmtpOutcomeTooLarge, ByteCount: 2048, CapByteCount: 1024, TlsLevel: SmtpTlsLevelDane},
			}}, nil
		},
	})
	response := world.call(t, DaemonMethodMailSendResult, &DaemonMailSendResultParams{Network: world.networkId.String(), SendId: &known})
	if response.Error != nil {
		t.Fatal(response.Error.Message)
	}
	want := `{"domains":[` +
		`{"domain":"a.example","mode":1,"byte_count":0,"cap_byte_count":0,"outcome":1,"reply_code":0,"retry_after_ms":0,"update_time_ms":1700000000000,"tls_level":4},` +
		`{"domain":"b.example","mode":2,"byte_count":0,"cap_byte_count":0,"outcome":3,"reply_code":0,"retry_after_ms":90000,"update_time_ms":1700000000000,"tls_level":0},` +
		`{"domain":"c.example","mode":0,"byte_count":0,"cap_byte_count":0,"outcome":5,"reply_code":550,"retry_after_ms":0,"update_time_ms":0,"tls_level":0},` +
		`{"domain":"d.example","mode":2,"byte_count":2048,"cap_byte_count":1024,"outcome":4,"reply_code":0,"retry_after_ms":0,"update_time_ms":0,"tls_level":1}]}`
	if string(response.Result) != want {
		t.Errorf("the result answered %s", response.Result)
	}

	unknown := NewId()
	refused := world.call(t, DaemonMethodMailSendResult, &DaemonMailSendResultParams{SendId: &unknown})
	testMailSendDaemonRefused(t, "an unknown send", refused, ErrMailSendUnknown)
	if refused.Error != nil && strings.Contains(refused.Error.Message, unknown.String()) {
		t.Error("the refusal names the id")
	}
	if len(read) != 2 || read[1] != unknown {
		t.Fatalf("the reads took %v", read)
	}

	extra, err := json.Marshal(map[string]any{"send_id": known, "extra": 1})
	if err != nil {
		t.Fatal(err)
	}
	for name, bad := range map[string]any{
		"no send_id":               &DaemonMailSendResultParams{},
		"the zero id":              &DaemonMailSendResultParams{SendId: &Id{}},
		"a field it does not know": string(extra),
	} {
		testMailSendDaemonRefused(t, name, world.call(t, DaemonMethodMailSendResult, bad), ErrMailSendInvalid)
	}
	if len(read) != 2 {
		t.Fatalf("a refused call reached the read: %d", len(read))
	}
}

// With the composition's backends, both reads answer ErrMailSendUnavailable naming what they wait on, which an app
// reads as MAIL_UNAVAILABLE, and mail.send on a Sidecar whose mail is bound to nothing is unbound, unavailable too.
func TestDaemonMailReadsAnswerUnavailableUntilTheirCallsLand(t *testing.T) {
	world := newMailSendDaemonTestWorld(t, nil)
	draft := &DaemonMailDraftParams{From: "ann@acme.root.example", To: []string{"a@outside.example"}, Text: "t"}
	check := world.call(t, DaemonMethodMailCheckSend, draft)
	testMailSendDaemonRefused(t, "check_send", check, ErrMailSendUnavailable)
	if check.Error == nil || !strings.Contains(check.Error.Message, "check a send") {
		t.Errorf("check_send names nothing it waits on: %+v", check.Error)
	}
	sendId := NewId()
	result := world.call(t, DaemonMethodMailSendResult, &DaemonMailSendResultParams{SendId: &sendId})
	testMailSendDaemonRefused(t, "send_result", result, ErrMailSendUnavailable)
	if result.Error == nil || !strings.Contains(result.Error.Message, "result") {
		t.Errorf("send_result names nothing it waits on: %+v", result.Error)
	}
	testMailSendDaemonRefused(t, "send", world.call(t, DaemonMethodMailSend, draft), ErrMailUnbound)
}

// mail.send of a draft naming an outside recipient answers the approval the gate holds it for, and nothing is kept or
// deposited; once a decision passes it, the same draft answers its send_id and each recipient's outcome. Mail to the
// network's own addresses alone goes at once.
func TestDaemonMailSendWaitsOnTheGateAndSendsNothingWithoutIt(t *testing.T) {
	mail, parts, mailboxId := newMailSendTestWorld(t)
	world := newMailSendDaemonTestWorld(t, &DaemonMailSendBackends{
		Send: func(ctx context.Context, sidecar *Sidecar, args *MailSendArgs) (*MailSendResult, error) {
			return mail.client.SubmitSend(ctx, args)
		},
	})
	params := &DaemonMailDraftParams{
		Network: world.networkId.String(),
		From:    testMailSendFrom,
		To:      []string{testMailIngestRecipient, "someone@outside.example"},
		Bcc:     []string{"hidden@elsewhere.example"},
		Subject: "Plans",
		Text:    "Dinner at eight.",
	}

	testMailSubmitHold(mail.gate, true)
	held := world.call(t, DaemonMethodMailSend, params)
	if held.Error != nil {
		t.Fatal(held.Error.Message)
	}
	if want := `{"approval_id":` + string(mustJsonId(t, evsTestId("pending approval"))) + `}`; string(held.Result) != want {
		t.Fatalf("a held send answered %s", held.Result)
	}
	if len(parts.snapshot()) != 0 || testMailSendRead(t, mail, MailFolderSent, "Plans") != nil {
		t.Fatal("a held send deposited or kept a copy")
	}

	testMailSubmitHold(mail.gate, false)
	defer mail.gate.RegisterEffectLookup(SidecarActionMail, testMailSubmitLookup)()
	sent := world.call(t, DaemonMethodMailSend, params)
	if sent.Error != nil {
		t.Fatal(sent.Error.Message)
	}
	reply := &DaemonMailSendReply{}
	if err := json.Unmarshal(sent.Result, reply); err != nil {
		t.Fatal(err)
	}
	if reply.SendId == nil || reply.ApprovalId != nil || !reply.SentCopy {
		t.Fatalf("a passed send answered %s", sent.Result)
	}
	outcomes := []string{}
	for _, recipient := range reply.Recipients {
		outcomes = append(outcomes, recipient.Address+" "+recipient.Outcome)
	}
	if !slices.Equal(outcomes, []string{
		testMailIngestRecipient + " delivered", "someone@outside.example queued", "hidden@elsewhere.example queued",
	}) {
		t.Fatalf("outcomes %v", outcomes)
	}
	if deposits := parts.snapshot(); len(deposits) != 1 || deposits[0].repoId != mailboxId {
		t.Fatalf("%d deposits", len(deposits))
	}
	if sentCopy := testMailSendRead(t, mail, MailFolderSent, "Plans"); sentCopy == nil || mailEntryId(sentCopy.Entry) != *reply.SendId {
		t.Fatal("the send_id is not the sent copy's")
	}

	testMailSubmitHold(mail.gate, true)
	members := world.call(t, DaemonMethodMailSend, &DaemonMailDraftParams{From: testMailSendFrom, To: []string{testMailIngestRecipient}, Subject: "Lunch", Text: "x"})
	membersReply := &DaemonMailSendReply{}
	if members.Error != nil || json.Unmarshal(members.Result, membersReply) != nil || membersReply.SendId == nil || membersReply.ApprovalId != nil {
		t.Fatalf("mail to members answered %+v, %s", members.Error, members.Result)
	}
	if len(parts.snapshot()) != 2 {
		t.Fatal("mail to members waited on the gate")
	}
}

// id as JSON encodes it.
func mustJsonId(t *testing.T, id Id) []byte {
	t.Helper()
	encoded, err := json.Marshal(id)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
