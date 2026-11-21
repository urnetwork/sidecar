//go:build !sidecar_http && !js && !ios_extension

// Interrupted mixed sends through the normal client and its approval gate. All stores and transports are private.
package sidecar

import (
	"bytes"
	"context"
	"crypto/hpke"
	"errors"
	"io"
	"net/http"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The same device reopened over its persistent mail state and delivery bindings.
func reopenMailSendClient(t *testing.T, world *mailClientTestWorld, parts mailClientParts, binding *MailBinding) *MailClient {
	t.Helper()
	client := world.newClient()
	client.partsOverride = parts
	client.Bind(binding)
	return client
}

// Failure immediately before the queue commit leaves the accepted member deposit and sent copy intact. A restart
// the following month must queue the original bytes and preserve the original copy, date and delivery order.
func TestMailSendResumesAnAcceptedDepositBeforeQueue(t *testing.T) {
	ctx := t.Context()
	world, parts, _ := newMailSendTestWorld(t)
	firstTime := time.Date(2026, time.January, 31, 23, 59, 50, 0, time.UTC)
	world.client.clock = &mailTestClock{now: firstTime}
	original, _, err := world.client.bound()
	if err != nil {
		t.Fatal(err)
	}
	interrupted := *original
	interrupted.Sign = func(string, bridge.SignedType, []byte) (*bridge.Signed, error) {
		return nil, ErrMailSendUncertain
	}
	world.client.Bind(&interrupted)
	draft := testMailSubmitDraft()
	if _, err := world.client.Send(ctx, draft); !errors.Is(err, ErrMailSendUncertain) {
		t.Fatalf("interrupted submission: %v", err)
	}
	action := world.gate.lastAction()
	key := mailConfigTestEffectKey(action.Canonical)
	deposits := parts.snapshot()
	sent := testMailSendRead(t, world, MailFolderSent, draft.Subject)
	if sent == nil || len(deposits) != 1 || len(testMailSendOutbox(t, world)) != 0 {
		t.Fatal("the interrupted send did not stop between its member deposit and queue")
	}
	checkpoint, err := world.client.readSendCheckpoint(mailSendCheckpointName(key))
	if err != nil || checkpoint == nil || checkpoint.Complete || len(checkpoint.Deposits) != 1 || checkpoint.Deposits[0] != MailSendDelivered {
		t.Fatalf("committed local deposit has no checkpoint: %v", err)
	}
	outcome, err := world.client.outboxLookup(ctx, action.Canonical, key)
	if err != nil || outcome.State != ApprovalOutcomeUncertain {
		t.Fatalf("a partially delivered use reconciled as %+v: %v", outcome, err)
	}
	world.client = reopenMailSendClient(t, world, parts, original)
	world.client.clock = &mailTestClock{now: firstTime.Add(24 * time.Hour)}

	// The same canonical action can arrange its display headers differently. It cannot replace the original send.
	changed := *draft
	changed.Cc, changed.Bcc = append(append([]string{}, draft.Cc...), draft.Bcc...), nil
	if _, err := world.client.Send(ctx, &changed); !errors.Is(err, ErrMailSendUncertain) {
		t.Fatalf("changed headers on retry: %v", err)
	}
	result, err := world.client.Send(ctx, draft)
	if err != nil || result.SendId != mailEntryId(sent.Entry) || len(result.Recipients) != 3 ||
		result.Recipients[0].Outcome != MailSendDelivered || result.Recipients[1].Outcome != MailSendQueued || result.Recipients[2].Outcome != MailSendQueued {
		t.Fatalf("resumed send %+v: %v", result, err)
	}
	queued := testMailSendOutbox(t, world)
	if len(parts.snapshot()) != 1 || len(queued) != 1 {
		t.Fatalf("resumed send left %d deposits and %d queue entries", len(parts.snapshot()), len(queued))
	}
	for _, file := range queued {
		if !bytes.Equal(file.Message, deposits[0].message) {
			t.Fatal("the member and internet recipients got different bytes")
		}
	}
	page, err := world.client.List(ctx, &MailListArgs{Folder: MailFolderSent})
	if err != nil || len(page.Entries) != 1 || mailEntryId(page.Entries[0].Entry) != result.SendId {
		t.Fatalf("resumed sent folder %+v: %v", page, err)
	}
	checkpoint, err = world.client.readSendCheckpoint(mailSendCheckpointName(key))
	if err != nil || checkpoint == nil || !checkpoint.Complete || !checkpoint.Queued || checkpoint.EffectRef != result.SendId || checkpoint.Pending != nil {
		t.Fatalf("completed use has no durable receipt: %v", err)
	}
	if err := world.client.sweepSendCheckpoints(ctx, checkpoint.Expires.Add(time.Nanosecond)); err != nil {
		t.Fatal(err)
	}
	if expired, err := world.client.readSendCheckpoint(mailSendCheckpointName(key)); err != nil || expired != nil {
		t.Fatalf("expired checkpoint survived its approval's retention: %v", err)
	}
}

// A live queue receipt left by an older writer already owns the send, including its id. The normal composing
// path must adopt it before creating a sent copy or delivering the member part.
func TestMailSendAdoptsAQueueCommittedBeforeTheSend(t *testing.T) {
	ctx := t.Context()
	world, parts, _ := newMailSendTestWorld(t)
	draft := testMailSubmitDraft()
	testMailSubmitHold(world.gate, true)
	if _, err := world.client.Send(ctx, draft); err == nil {
		t.Fatal("the approval should be pending")
	}
	effectKey := mailConfigTestEffectKey(world.gate.lastAction().Canonical)
	testMailSubmitHold(world.gate, false)
	outbox, err := world.client.memberOutbox(testMailOutboxStanding(AbuseStandingStandard, true))
	if err != nil {
		t.Fatal(err)
	}
	id := newMailOutboxSendId()
	if queued, err := outbox.Queue(ctx, testMailOutboxQueueArgs(effectKey, testMailOutboxMessage(id))); err != nil || !queued.Created {
		t.Fatalf("prior queue %+v: %v", queued, err)
	}
	result, err := world.client.Send(ctx, draft)
	if err != nil || result.SendId != id || len(result.Recipients) != 0 || !bytes.Equal(result.EffectKey, effectKey) ||
		len(parts.snapshot()) != 0 || testMailSendRead(t, world, MailFolderSent, draft.Subject) != nil {
		t.Fatalf("send with a prior queue %+v: %v", result, err)
	}
}

// A normal mail world with a real EVS deposit client, a private upload transport and a generated drop key.
type mailSendCheckpointEvsParts struct {
	*mailSendTestParts
	repo *EvsRepo
}

func (self *mailSendCheckpointEvsParts) depositRepo(repoId Id) mailSendDepositRepo {
	if repoId == self.repo.RepoId() {
		return self.repo
	}
	return nil
}

type mailSendCheckpointGkm struct {
	GkmClient
	drop *GkmDropKey
}

func (self *mailSendCheckpointGkm) DropKey(context.Context, Id) (*GkmDropKey, error) {
	return self.drop, nil
}

// An acknowledgement lost after EVS accepted the deposit must replay the exact signed push, even if the recipient
// has already consumed it. A second sealing would create different segments, slot and push id.
func TestMailSendReplaysTheOriginalDepositAfterALostAcknowledgement(t *testing.T) {
	testMailSendLostDeposit(t, false)
}

// Once EVS has forgotten an accepted and consumed push it can reject a replay against the new head. Starting a
// different push at that head could deliver the same mail again.
func TestMailSendKeepsAnUnprovableOriginalDepositUncertain(t *testing.T) {
	testMailSendLostDeposit(t, true)
}

func testMailSendLostDeposit(t *testing.T, forgot bool) {
	t.Helper()
	ctx := t.Context()
	world, parts, mailboxId := newMailSendTestWorld(t)
	writer := newEvsTestWriter(t)
	writer.world.repoId = mailboxId
	writer.repo = writer.test.client.Repo(mailboxId)
	key, err := hpke.MLKEM768X25519().GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	writer.test.client.args.Gkm = &mailSendCheckpointGkm{GkmClient: writer.gkm, drop: &GkmDropKey{
		RepoId: mailboxId, GroupId: evsTestId("mail deposit group"), Generation: 1,
		Commitment: evsTestBytes("mail deposit commitment", 32), PublicKey: key.PublicKey().Bytes(), NotAfter: writer.test.clock.Now().Add(time.Hour),
	}}
	var posts [][]byte
	handler := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method == http.MethodPut {
			writer.server.serveSegment(response, request)
			return
		}
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Error(err)
		}
		posts = append(posts, body)
		if len(posts) == 1 {
			// The receiver committed, but its response was cut.
			response.Write([]byte{0xff})
			return
		}
		if forgot {
			refusal, _ := proto.Marshal(&protocol.EvsRefusalReply{
				Code: protocol.EvsRefusalCode_EVS_REFUSAL_BASE_STALE, Recorded: true,
				DepositHead: &protocol.EvsDepositHead{Version: 2, ConsumedThrough: 1, Chain: evsTestBytes("consumed deposit head", 32)},
			})
			response.WriteHeader(http.StatusConflict)
			response.Write(refusal)
			return
		}
		reply, _ := proto.Marshal(&protocol.EvsPushReply{Version: 1, DepositHead: &protocol.EvsDepositHead{
			Version: 2, ConsumedThrough: 1, Chain: evsTestBytes("consumed deposit head", 32),
		}})
		response.Write(reply)
	})
	writer.test.client.http.transport = wrapSidecarApiTransport(&evsTestTransport{handler: handler})
	evsParts := &mailSendCheckpointEvsParts{mailSendTestParts: parts, repo: writer.repo}
	world.client.partsOverride = evsParts
	draft := testMailSubmitDraft()
	if _, err := world.client.Send(ctx, draft); !errors.Is(err, ErrMailSendUncertain) || len(posts) != 1 || len(testMailSendOutbox(t, world)) != 0 {
		t.Fatalf("lost acknowledgement left %d posts: %v", len(posts), err)
	}
	binding, _, err := world.client.bound()
	if err != nil {
		t.Fatal(err)
	}
	world.client = reopenMailSendClient(t, world, evsParts, binding)
	result, err := world.client.Send(ctx, draft)
	if len(posts) != 2 || !bytes.Equal(posts[0], posts[1]) || len(writer.server.uploads) != 1 {
		t.Fatalf("resumed send %+v, %d posts and %d uploads: %v", result, len(posts), len(writer.server.uploads), err)
	}
	if forgot {
		if !errors.Is(err, ErrMailSendUncertain) || len(testMailSendOutbox(t, world)) != 0 {
			t.Fatalf("forgotten deposit on replay %+v: %v", result, err)
		}
	} else if err != nil || len(result.Delivered()) != 1 || len(testMailSendOutbox(t, world)) != 1 {
		t.Fatalf("acknowledged deposit on replay %+v: %v", result, err)
	}
}
