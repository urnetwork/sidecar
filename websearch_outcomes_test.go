//go:build !ios_extension && !sidecar_http

package sidecar_test

// A device's search outcomes (SRCH-M13-02; §21.8, compute-11): counts by class alone, riding the next authorization,
// else the daily report, and kept across a restart.

import (
	"context"
	"errors"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest/computetest"
)

// Outcomes ride the next authorization and leave the log; a device that searches no more sends them in the daily
// report once its interval passes, and not before; what is kept is counts alone, and it survives a restart.
func TestWebSearchOutcomeLogReported(t *testing.T) {
	world := newTestWebSearchWorld(t, nil)
	ctx := context.Background()
	world.parallel.Script(&computetest.FakeParallelStep{Outcome: computetest.FakeParallelUpstreamFailure})
	if _, err := world.client.Search(ctx, testWebSearchQuery()); sidecar.WebSearchErrorCode(err) != sidecar.WebSearchCodeProviderError {
		t.Fatal(err)
	}
	if received := world.broker.received(t); len(received) != 1 || received[0].Outcomes != nil {
		t.Fatal("the first authorization carried outcomes")
	}
	// the next search carries the provider error and leaves only its own ok behind
	if _, err := world.client.Search(ctx, testWebSearchQuery()); err != nil {
		t.Fatal(err)
	}
	received := world.broker.received(t)
	if len(received) != 2 || !proto.Equal(received[1].Outcomes, &protocol.SearchOutcomes{ProviderError: 1}) {
		t.Fatalf("the second authorization carried %v", received[1].Outcomes)
	}
	unreported, err := world.outcomes.Unreported()
	if err != nil || !proto.Equal(unreported, &protocol.SearchOutcomes{Ok: 1}) {
		t.Fatalf("unreported %v, %v", unreported, err)
	}
	// the file holds counts and a time, nothing of a search
	for _, path := range world.store.Paths() {
		contents, _ := world.store.Contents(path)
		for _, word := range []string{"synthetic", "request", "nonce", "query", "result"} {
			if strings.Contains(string(contents), word) {
				t.Fatalf("%s holds %q: %s", path, word, contents)
			}
		}
	}
	// a restart keeps them
	restarted, err := sidecar.NewWebSearchOutcomeLog(&sidecar.WebSearchOutcomeLogArgs{Store: world.store.Root(), Settings: world.settings, Clock: world.clock})
	if err != nil {
		t.Fatal(err)
	}
	if kept, err := restarted.Unreported(); err != nil || !proto.Equal(kept, &protocol.SearchOutcomes{Ok: 1}) {
		t.Fatalf("after a restart: %v, %v", kept, err)
	}
	world.outcomes = restarted
	world.client = world.newClient()
	// not due within the day of the last report
	if err := world.client.ReportOutcomes(ctx); err != nil || len(world.broker.reports) != 0 {
		t.Fatalf("reported within the day: %v", err)
	}
	world.clock.Advance(world.settings.OutcomesReportInterval)
	if err := world.client.ReportOutcomes(ctx); err != nil {
		t.Fatal(err)
	}
	if len(world.broker.reports) != 1 || !proto.Equal(world.broker.reports[0], &protocol.SearchOutcomes{Ok: 1}) {
		t.Fatalf("the daily report %v", world.broker.reports)
	}
	if left, _ := restarted.Unreported(); left != nil {
		t.Fatalf("left after the report: %v", left)
	}
	// nothing left: nothing sent
	world.clock.Advance(world.settings.OutcomesReportInterval)
	if err := world.client.ReportOutcomes(ctx); err != nil || len(world.broker.reports) != 1 {
		t.Fatalf("an empty report was sent: %v", err)
	}
}

// Only the four classes count, each saturating rather than wrapping; a write that fails fails the count.
func TestWebSearchOutcomeLogClasses(t *testing.T) {
	world := newTestWebSearchWorld(t, nil)
	for _, class := range []string{sidecar.WebSearchOutcomeOk, sidecar.WebSearchOutcomeProviderError, sidecar.WebSearchOutcomeTimeout, sidecar.WebSearchOutcomeRefused, sidecar.WebSearchOutcomeRefused} {
		if err := world.outcomes.Add(class); err != nil {
			t.Fatal(err)
		}
	}
	if err := world.outcomes.Add("cancelled"); !errors.Is(err, sidecar.ErrWebSearchOutcomeClass) {
		t.Fatalf("an unknown class: %v", err)
	}
	unreported, err := world.outcomes.Unreported()
	if err != nil || !proto.Equal(unreported, &protocol.SearchOutcomes{Ok: 1, ProviderError: 1, Timeout: 1, Refused: 2}) {
		t.Fatalf("counts %v, %v", unreported, err)
	}
	// a part reported: what came since stays
	if err := world.outcomes.Reported(&protocol.SearchOutcomes{Ok: 1, Refused: 1}); err != nil {
		t.Fatal(err)
	}
	if left, _ := world.outcomes.Unreported(); !proto.Equal(left, &protocol.SearchOutcomes{ProviderError: 1, Timeout: 1, Refused: 1}) {
		t.Fatalf("left %v", left)
	}
	world.store.FailWritesAfter(0)
	if err := world.outcomes.Add(sidecar.WebSearchOutcomeOk); err == nil {
		t.Fatal("a count whose write failed answered nil")
	}
}
