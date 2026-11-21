//go:build sidecar_testhooks && !sidecar_http && !js && !ios_extension

package sidecar

import (
	"bytes"
	"sync"
	"testing"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// Two active clients of the same requester reach the same approval use while its first submitter has already
// deposited but has yet to queue. Only that submitter can publish its copy, local deposit and internet message.
func TestMailSendConcurrentPresentationsOfOneMixedUse(t *testing.T) {
	ctx := t.Context()
	world, parts, _ := newMailSendTestWorld(t)
	binding, _, err := world.client.bound()
	if err != nil {
		t.Fatal(err)
	}
	atQueue, resume := make(chan struct{}), make(chan struct{})
	var stopOnce, resumeOnce sync.Once
	pause := *binding
	pause.Sign = func(purpose string, signedType bridge.SignedType, body []byte) (*bridge.Signed, error) {
		stopOnce.Do(func() {
			close(atQueue)
			<-resume
		})
		return binding.Sign(purpose, signedType, body)
	}
	world.client.Bind(&pause)
	second := reopenMailSendClient(t, world, parts, binding)
	waiting := make(chan struct{})
	var waitOnce sync.Once
	SetTestHooks(&TestHooks{Barrier: func(name string, key string) {
		if name == "mail.send.use.wait" {
			waitOnce.Do(func() { close(waiting) })
		}
	}})
	var sends sync.WaitGroup
	defer func() {
		resumeOnce.Do(func() { close(resume) })
		sends.Wait()
		SetTestHooks(nil)
	}()
	type answer struct {
		result *MailSendResult
		err    error
	}
	send := func(client *MailClient) <-chan answer {
		answers := make(chan answer, 1)
		sends.Add(1)
		go func() {
			defer sends.Done()
			result, err := client.Send(ctx, testMailSubmitDraft())
			answers <- answer{result: result, err: err}
		}()
		return answers
	}
	firstAnswer := send(world.client)
	select {
	case <-atQueue:
	case out := <-firstAnswer:
		t.Fatalf("first send ended before its queue: %+v", out)
	}
	secondAnswer := send(second)
	select {
	case <-waiting:
	case out := <-secondAnswer:
		t.Fatalf("second send passed an active use: %+v", out)
	}
	action := world.gate.lastAction()
	key := mailConfigTestEffectKey(action.Canonical)
	outcome, err := second.outboxLookup(ctx, action.Canonical, key)
	if err != nil || outcome.State != ApprovalOutcomeUncertain || len(parts.snapshot()) != 1 || len(testMailSendOutbox(t, world)) != 0 {
		t.Fatalf("active claim %+v with %d member deposits: %v", outcome, len(parts.snapshot()), err)
	}
	resumeOnce.Do(func() { close(resume) })
	first, again := <-firstAnswer, <-secondAnswer
	if first.err != nil || again.err != nil || first.result.SendId == (Id{}) || first.result.SendId != again.result.SendId ||
		len(parts.snapshot()) != 1 || !bytes.Equal(first.result.EffectKey, again.result.EffectKey) {
		t.Fatalf("concurrent sends %+v, %+v with %d member deposits", first, again, len(parts.snapshot()))
	}
	seen, err := second.List(ctx, &MailListArgs{Folder: MailFolderSent})
	if err != nil || len(seen.Entries) != 1 || mailEntryId(seen.Entries[0].Entry) != first.result.SendId ||
		len(testMailSendOutbox(t, world)) != 1 {
		t.Fatalf("sent copies %+v: %v", seen, err)
	}
}
