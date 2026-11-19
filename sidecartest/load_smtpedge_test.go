//go:build !sidecar_http

package sidecartest

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/smtpedgeservice"
)

// §22.8's smtpedge row at a small size on a fake clock: Team networks at a day of 12 connections and 3 at once,
// each trying 20 across 3 edges sharing a FakeRedis, every connection the quota passes running its pre-TLS
// dialog with a ScriptedMx first. No network passes a limit, and 4 networks halted by a store row midway are
// refused by every edge within 60 s and accept nothing after.
func TestLoadSmtpEdgeHoldsTeamQuotaAndHaltsWithinAMinute(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	clock := NewFakeClock(DefaultClockStart())
	faults := NewFaultQueue()
	redis := NewFakeRedis(ctx, clock, faults, nil, nil)
	RegisterSmtpQuotaScripts(redis)
	store := NewFakeSmtpEdgeStore(clock, faults)
	mx, err := NewScriptedMx("mx.dest.example", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	var mxConnections sync.WaitGroup
	dial := func(ctx context.Context) (net.Conn, error) {
		edgeEnd, mxEnd := NewMxPipe(nil, nil)
		mxConnections.Add(1)
		go func() {
			defer mxConnections.Done()
			mx.ServeMx(mxEnd)
		}()
		return edgeEnd, nil
	}
	limits := DefaultSmtpEdgeLoadTeamLimits()
	limits.Limits[smtpedgeservice.SmtpLimitConnectionsPerDay] = 12
	limits.Limits[smtpedgeservice.SmtpLimitBurst] = 1000
	limits.Limits[smtpedgeservice.SmtpLimitConcurrentConnections] = 3
	settings := DefaultSmtpEdgeLoadSettings()
	settings.NetworkCount = 24
	settings.EdgeCount = 3
	settings.AttemptsPerNetwork = 20
	settings.OpenConcurrency = 32
	settings.HaltedNetworkCount = 4
	report, err := LoadSmtpEdge(ctx, &SmtpEdgeLoadArgs{
		Redis:    redis,
		Store:    store,
		Clock:    clock,
		Limits:   limits,
		DialMx:   dial,
		HeloName: "o1.out.relay.example",
		Settings: settings,
	})
	mxConnections.Wait()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%d attempts, %d accepted, %d released, refusals %v, %d of one network open at once, %d of %d halts reached in %v",
		report.Attempts, report.Accepted, report.Released, report.Refusals, report.MaxOpenAtOnce, report.HaltsReached, report.HaltCount, report.HaltReach)
	if report.Failed != 0 {
		t.Errorf("%d connections failed: %v", report.Failed, report.Errors)
	}
	if len(report.Overruns) != 0 {
		t.Errorf("overruns: %v", report.Overruns)
	}
	if report.Attempts != 24*20 || report.Accepted == 0 || 24*12 < report.Accepted {
		t.Errorf("%d attempts, %d accepted", report.Attempts, report.Accepted)
	}
	// every attempt past a network's day is refused, and nothing but the quota and the concurrency refuse
	if report.Refusals[protocol.SmtpPreambleCode_SMTP_PREAMBLE_QUOTA] < 24*(20-12) {
		t.Errorf("refusals %v", report.Refusals)
	}
	for code := range report.Refusals {
		if code != protocol.SmtpPreambleCode_SMTP_PREAMBLE_QUOTA && code != protocol.SmtpPreambleCode_SMTP_PREAMBLE_TRY_LATER {
			t.Errorf("a refusal %v in the load", code)
		}
	}
	if 3 < report.MaxOpenAtOnce {
		t.Errorf("%d of one network open at once", report.MaxOpenAtOnce)
	}
	if report.HaltCount != 4 || report.HaltsReached != 4 || 60*time.Second < report.HaltReach || report.AcceptedAfterHalt != 0 {
		t.Errorf("halts %d, reached %d in %v, %d accepted after", report.HaltCount, report.HaltsReached, report.HaltReach, report.AcceptedAfterHalt)
	}
	if 2*time.Minute < report.Elapsed {
		t.Errorf("the run took %v on its fake clock", report.Elapsed)
	}
}

// A day too short for the load: with a concurrency of 1 and no MX, no network ever has two open, and each
// takes its whole day and no more.
func TestLoadSmtpEdgeTakesEachNetworksDayAndNoMore(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	clock := NewFakeClock(DefaultClockStart())
	faults := NewFaultQueue()
	redis := NewFakeRedis(ctx, clock, faults, nil, nil)
	RegisterSmtpQuotaScripts(redis)
	limits := DefaultSmtpEdgeLoadTeamLimits()
	limits.Limits[smtpedgeservice.SmtpLimitConnectionsPerDay] = 5
	limits.Limits[smtpedgeservice.SmtpLimitBurst] = 1000
	limits.Limits[smtpedgeservice.SmtpLimitConcurrentConnections] = 1
	settings := DefaultSmtpEdgeLoadSettings()
	settings.NetworkCount = 6
	settings.EdgeCount = 2
	settings.AttemptsPerNetwork = 9
	settings.OpenConcurrency = 1
	settings.HaltedNetworkCount = 0
	report, err := LoadSmtpEdge(ctx, &SmtpEdgeLoadArgs{Redis: redis, Store: NewFakeSmtpEdgeStore(clock, faults), Clock: clock, Limits: limits, Settings: settings})
	if err != nil {
		t.Fatal(err)
	}
	// one at a time, every network's first five pass and its last four meet its day
	if report.Accepted != 6*5 || report.Refusals[protocol.SmtpPreambleCode_SMTP_PREAMBLE_QUOTA] != 6*4 || len(report.Overruns) != 0 || report.MaxOpenAtOnce != 1 {
		t.Errorf("%+v", report)
	}
}
