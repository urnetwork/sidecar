//go:build !sidecar_http && !js && !ios && !android && !sdk_mobile_bind && !windows

// An owned ref's queue holds on the token exchange's refusal for good of its push's scope as it holds on evs's 403
// SCOPE (DESIGN-DETAILS 8.2.8's queue rows; the brief's fourth item), with stock git pushing to a mount as
// evs_local_receive_test.go's tests do; and goes again at QueueInterval on what can change, the exchange's answers.

package sidecar

import (
	"context"
	"errors"
	"net/http"
	"testing"
)

// An owned ref whose push's write scope the exchange refuses for good, invalid_grant or the plain 403 of a bearer it
// does not take, holds its queue: ur evs status's journal shows the exchange's refusal, the commits stay on the local
// ref, and a queue run while the local ref stands asks the exchange nothing; `ur evs retry` releases it, and with the
// scope granted again the next push lands. Before, the queue asked again every QueueInterval for as long as the
// exchange refused, holding nothing.
func TestEvsLocalReceiveQueueHeldOnAnExchangeRefusalForGood(t *testing.T) {
	cases := []struct {
		name   string
		answer *evsTestExchangeAnswer
		code   string
	}{
		{name: "invalid_grant", answer: evsTestExchangeRefusedForGood(http.StatusBadRequest, "invalid_grant"), code: "token exchange invalid_grant"},
		{name: "plain 403", answer: &evsTestExchangeAnswer{status: http.StatusForbidden, body: "A sidecar token cannot call this route.", repeats: true},
			code: "token exchange 403"},
	}
	ctx := context.Background()
	for _, c := range cases {
		publisher := newEvsTestPublisher(t)
		receiver := newEvsTestReceiver(t, publisher)
		sidecarId := publisher.writer.test.client.args.Identity().SidecarId
		owned := string(EvsOwnedRefName(sidecarId, "held"))
		dir := receiver.clone()
		c1 := receiver.commit(dir, map[string]string{"a.txt": "held by the exchange\n"})
		if out, ok := receiver.push(dir, "origin", "HEAD:refs/heads/"+owned); !ok {
			t.Fatalf("%s: the push: %s", c.name, out)
		}
		refId := publisher.ref(owned).refId
		exchange := newEvsTestExchange(t, publisher.writer.test.client, evsTestWriteScope(publisher.writer), c.answer)
		if err := receiver.mount.receiver.publishQueued(ctx, refId); err != nil {
			t.Errorf("%s: the queue answered %v, not a hold", c.name, err)
			continue
		}
		statuses, _ := receiver.mount.receiver.JournalStatus()
		if len(statuses) != 1 || statuses[0].HoldCode != c.code {
			t.Errorf("%s: the hold %+v", c.name, statuses)
			continue
		}
		if local := receiver.local("refs/heads/" + owned); local == nil || *local != c1 {
			t.Errorf("%s: the held commits left the local ref: %v", c.name, local)
		}
		asks := exchange.count()
		posted := publisher.posted()
		if err := receiver.mount.receiver.publishQueued(ctx, refId); err != nil || exchange.count() != asks || publisher.posted() != posted {
			t.Errorf("%s: a held queue asked %d more times and posted %d: %v", c.name, exchange.count()-asks, publisher.posted()-posted, err)
		}
		func() {
			exchange.stateLock.Lock()
			defer exchange.stateLock.Unlock()
			exchange.answers = nil
		}()
		released, err := receiver.mount.receiver.Retry(ctx, nil)
		if err != nil || len(released) != 1 || string(released[0]) != owned {
			t.Errorf("%s: retry released %q %v", c.name, released, err)
			continue
		}
		if err := receiver.mount.receiver.publishQueued(ctx, refId); err != nil {
			t.Errorf("%s: the retried queue: %v", c.name, err)
			continue
		}
		if version := receiver.headVersion(owned); version != 1 {
			t.Errorf("%s: the retried queue's push: %d", c.name, version)
		}
		if statuses, _ := receiver.mount.receiver.JournalStatus(); len(statuses) != 0 {
			t.Errorf("%s: the journal after the retry %+v", c.name, statuses)
		}
	}
}

// What can change holds nothing: the exchange's 503 past the call's bound ends the push with its error and leaves the
// journal unheld, the queue to go again at QueueInterval. No enrolled client, the sidecar's own state, holds offline
// until a reconnect since service-token-refusal-classify (evs_local_receive_offline_hold_test.go).
func TestEvsLocalReceiveQueueNotHeldOnWhatCanChange(t *testing.T) {
	cases := []struct {
		name    string
		install func(t *testing.T, writer *evsTestWriter)
		check   func(err error) bool
	}{
		{name: "exchange 503", install: func(t *testing.T, writer *evsTestWriter) {
			writer.test.client.settings.PushRetryCount = 1
			newEvsTestExchange(t, writer.test.client, evsTestWriteScope(writer), &evsTestExchangeAnswer{status: http.StatusServiceUnavailable,
				body: `{"error":"temporarily_unavailable"}`, repeats: true})
		}, check: func(err error) bool {
			var apiErr *SidecarApiError
			return errors.As(err, &apiErr) && apiErr.Status == http.StatusServiceUnavailable
		}},
	}
	ctx := context.Background()
	for _, c := range cases {
		publisher := newEvsTestPublisher(t)
		receiver := newEvsTestReceiver(t, publisher)
		sidecarId := publisher.writer.test.client.args.Identity().SidecarId
		owned := string(EvsOwnedRefName(sidecarId, "unheld"))
		dir := receiver.clone()
		receiver.commit(dir, map[string]string{"a.txt": "not held\n"})
		if out, ok := receiver.push(dir, "origin", "HEAD:refs/heads/"+owned); !ok {
			t.Fatalf("%s: the push: %s", c.name, out)
		}
		c.install(t, publisher.writer)
		err := receiver.mount.receiver.publishQueued(ctx, publisher.ref(owned).refId)
		if !c.check(err) {
			t.Errorf("%s: the queue answered %v", c.name, err)
		}
		statuses, _ := receiver.mount.receiver.JournalStatus()
		for _, status := range statuses {
			if status.HoldCode != "" {
				t.Errorf("%s: held %q", c.name, status.HoldCode)
			}
		}
	}
}
