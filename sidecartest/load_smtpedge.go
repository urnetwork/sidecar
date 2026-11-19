// §22.8's smtpedge load harness (SMTP-M9-32): Team quota on many networks, halts within 60 s, no overrun. A
// driver opens connections for many networks at once across several edges that share one Redis, as smtpedge's
// processes share theirs, each edge admitting a preamble through smtpedgeservice's own quota (SmtpQuota's
// Reserve, then DebitMail where the edge forwards MAIL, then Close) and keeping its halts as the engine does
// (halt_reload.go: each HaltReloadInterval, the store's ActiveHalts into ReplaceHalts). Each connection the
// quota passes runs its pre-TLS dialog with a fake MX before its unit is debited, so a connection the MX ends
// first is released and costs nothing. Every network attempts more connections than its day holds, and the run
// holds each network to its limits: no more debited connections or recipients than its day allows, and never
// more open at once than its concurrency, counted at the driver. Midway, the store gains a halt row for some
// networks, with no flag in Redis, and the run moves the clock until every edge refuses each of them; that
// takes at most §14.8's 60 s, after which no connection of a halted network is accepted.
//
// sidecartest's own test runs it on a fake clock over FakeRedis, the quota's scripts as their twins. Given a
// real Redis with the scripts loaded it drives the Lua the same way, on real time, its clock moving as time
// does. What it does not drive is a deployed smtpedge: a T5 run reaches the engine through ur/smtpedge streams
// from ticketed sidecars, which this driver does not open.
//
// The driver holds no address or name but synthetic ones and writes nothing but its own connections' bytes.

package sidecartest

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/smtpedgeservice"
)

// What a load run drives.
type SmtpEdgeLoadSettings struct {
	// Networks, each held to the run's limits.
	NetworkCount int
	// Edges, each a quota and a reload of its own over the one Redis.
	EdgeCount int
	// Connections each network attempts, past its day's connections to try an overrun.
	AttemptsPerNetwork int
	// Connections in flight at once across the run, so that a network's open at once press on its
	// concurrency.
	OpenConcurrency int
	// Each preamble's recipient domain, recipients and octets.
	RecipientDomain  string
	RecipientCount   uint32
	MessageByteCount uint64
	// The networks halted midway, the first of them, by a store row alone.
	HaltedNetworkCount int
	// How long a halt may take to reach every edge: §14.8's 60 s.
	HaltReachTimeout time.Duration
	// The step a fake clock takes while the run waits for the halts to land.
	ClockStep time.Duration
	// How many failures' errors a report keeps, to say why.
	ErrorKeepCount int
}

// §22.8's run at its scale: 1,000 Team networks over 4 edges, each trying 25 connections more than its day
// holds, 256 at once, with 10 networks halted midway.
func DefaultSmtpEdgeLoadSettings() *SmtpEdgeLoadSettings {
	limits := DefaultSmtpEdgeLoadTeamLimits()
	return &SmtpEdgeLoadSettings{
		NetworkCount:       1000,
		EdgeCount:          4,
		AttemptsPerNetwork: int(limits.Limits[smtpedgeservice.SmtpLimitConnectionsPerDay]) + 25,
		OpenConcurrency:    256,
		RecipientDomain:    "dest.example",
		RecipientCount:     5,
		MessageByteCount:   64 * 1024,
		HaltedNetworkCount: 10,
		HaltReachTimeout:   60 * time.Second,
		ClockStep:          time.Second,
		ErrorKeepCount:     8,
	}
}

// §20.4's Team column: 20,000 connections a day, 100 recipients a message and 100,000 a day, 35 MiB a message
// and 20 GiB a day, a burst of 2,000 an hour, 32 at once.
func DefaultSmtpEdgeLoadTeamLimits() *sidecar.QuotaLimits {
	return &sidecar.QuotaLimits{Tier: "team", Limits: map[string]int64{
		smtpedgeservice.SmtpLimitConnectionsPerDay:     20000,
		smtpedgeservice.SmtpLimitBytesPerDay:           20 * 1024 * 1024 * 1024,
		smtpedgeservice.SmtpLimitRecipientsPerMessage:  100,
		smtpedgeservice.SmtpLimitRecipientsPerDay:      100000,
		smtpedgeservice.SmtpLimitMessageBytes:          35 * 1024 * 1024,
		smtpedgeservice.SmtpLimitBurst:                 2000,
		smtpedgeservice.SmtpLimitBurstWindow:           time.Hour.Milliseconds(),
		smtpedgeservice.SmtpLimitConcurrentConnections: 32,
	}}
}

// One run's world.
type SmtpEdgeLoadArgs struct {
	// The Redis every edge shares, the quota's scripts on it: RegisterSmtpQuotaScripts on a FakeRedis.
	Redis sidecar.Redis
	// The store halt rows go to and every edge's reload reads.
	Store smtpedgeservice.SmtpEdgeStore
	// The clock every edge reads. A FakeClock moves only when the run moves it; nil is real time.
	Clock sidecar.Clock
	// Each edge's settings. Nil is DefaultSmtpEdgeSettings.
	Edge *smtpedgeservice.SmtpEdgeSettings
	// What every network is held to. Nil is DefaultSmtpEdgeLoadTeamLimits.
	Limits *sidecar.QuotaLimits
	// Opens a connection to the fake MX the edge dials for a connection the quota passed. Nil dials none,
	// and the unit is debited at once.
	DialMx func(ctx context.Context) (net.Conn, error)
	// The EHLO name the edge's pre-TLS dialog gives the MX.
	HeloName string
	// Nil takes DefaultSmtpEdgeLoadSettings.
	Settings *SmtpEdgeLoadSettings
}

// What a run saw.
type SmtpEdgeLoadReport struct {
	Attempts int
	// Connections the quota passed and whose unit was debited, and those it passed that the MX ended first.
	Accepted int
	Released int
	// Refusals by preamble code: QUOTA, TRY_LATER, HALTED.
	Refusals map[protocol.SmtpPreambleCode]int
	// Connections that ended in an error, with the first ErrorKeepCount errors.
	Failed int
	Errors []string
	// The most connections of one network open at once.
	MaxOpenAtOnce int64
	// Networks held past a limit, each with what it passed: none, in a run that holds.
	Overruns []string
	// Halts written midway, how many reached every edge, the longest that took, and connections of a halted
	// network accepted after every edge refused it: none, in a run that holds.
	HaltCount         int
	HaltsReached      int
	HaltReach         time.Duration
	AcceptedAfterHalt int
	Elapsed           time.Duration
}

// One network's counts at the driver.
type smtpEdgeLoadNetwork struct {
	networkId sidecar.Id

	stateLock  sync.Mutex
	debited    int64
	recipients int64
	open       int64
	maxOpen    int64
}

// Runs the load, then the halts. An error is the run's own: a quota that could not start, or a context that
// ended.
func LoadSmtpEdge(ctx context.Context, args *SmtpEdgeLoadArgs) (*SmtpEdgeLoadReport, error) {
	settings := args.Settings
	if settings == nil {
		settings = DefaultSmtpEdgeLoadSettings()
	}
	edgeSettings := args.Edge
	if edgeSettings == nil {
		edgeSettings = smtpedgeservice.DefaultSmtpEdgeSettings()
	}
	limits := args.Limits
	if limits == nil {
		limits = DefaultSmtpEdgeLoadTeamLimits()
	}
	clock := args.Clock
	if clock == nil {
		clock = sidecar.RealClock{}
	}
	if args.Redis == nil || args.Store == nil || settings.EdgeCount <= 0 || settings.NetworkCount <= 0 {
		return nil, errors.New("smtpedge load: a run needs a Redis, a store, an edge and a network")
	}
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	quotas := make([]*smtpedgeservice.SmtpQuota, 0, settings.EdgeCount)
	for range settings.EdgeCount {
		host := &sidecar.ServiceHost{Redis: args.Redis, Metrics: NewFakeMetrics(nil), Clock: clock}
		quota, err := smtpedgeservice.NewSmtpQuota(runCtx, host, edgeSettings)
		if err != nil {
			return nil, err
		}
		quotas = append(quotas, quota)
	}
	networks := make([]*smtpEdgeLoadNetwork, 0, settings.NetworkCount)
	for range settings.NetworkCount {
		networks = append(networks, &smtpEdgeLoadNetwork{networkId: sidecar.NewId()})
	}
	report := &SmtpEdgeLoadReport{Refusals: map[protocol.SmtpPreambleCode]int{}}
	var reportLock sync.Mutex
	fail := func(err error) {
		reportLock.Lock()
		defer reportLock.Unlock()
		report.Failed += 1
		if len(report.Errors) < settings.ErrorKeepCount {
			report.Errors = append(report.Errors, err.Error())
		}
	}
	start := clock.Now()

	// one connection's life on an edge: the preamble's admission, the MX's pre-TLS dialog, MAIL's unit, the close
	connect := func(edge *smtpedgeservice.SmtpQuota, network *smtpEdgeLoadNetwork) (protocol.SmtpPreambleCode, error) {
		decision, err := edge.Reserve(runCtx, &smtpedgeservice.SmtpQuotaRequest{
			NetworkId:        network.networkId,
			RecipientCount:   settings.RecipientCount,
			MessageByteCount: settings.MessageByteCount,
			RecipientDomain:  settings.RecipientDomain,
			Limits:           limits,
		})
		if err != nil {
			return 0, err
		}
		if decision.Code != protocol.SmtpPreambleCode_SMTP_PREAMBLE_OK {
			return decision.Code, nil
		}
		reservation := decision.Reservation
		// counted open from the reservation until just before its slot returns, so that the count is never
		// below the quota's own: a slot freed is a slot another connection may take at once
		func() {
			network.stateLock.Lock()
			defer network.stateLock.Unlock()
			network.open += 1
			network.maxOpen = max(network.maxOpen, network.open)
		}()
		closed := func() {
			network.stateLock.Lock()
			defer network.stateLock.Unlock()
			network.open -= 1
		}
		if args.DialMx != nil {
			if err := smtpEdgeLoadPreTls(runCtx, args.DialMx, args.HeloName); err != nil {
				// the MX ended it before MAIL: nothing is charged
				closed()
				edge.Release(runCtx, reservation)
				reportLock.Lock()
				report.Released += 1
				reportLock.Unlock()
				return decision.Code, nil
			}
		}
		if err := edge.DebitMail(runCtx, reservation); err != nil {
			closed()
			edge.Release(runCtx, reservation)
			return 0, err
		}
		func() {
			network.stateLock.Lock()
			defer network.stateLock.Unlock()
			network.debited += 1
			network.recipients += int64(settings.RecipientCount)
		}()
		closed()
		return decision.Code, edge.Close(runCtx, reservation, settings.MessageByteCount)
	}
	record := func(code protocol.SmtpPreambleCode, err error) {
		if err != nil {
			fail(err)
			return
		}
		reportLock.Lock()
		defer reportLock.Unlock()
		if code == protocol.SmtpPreambleCode_SMTP_PREAMBLE_OK {
			report.Accepted += 1
		} else {
			report.Refusals[code] += 1
		}
	}

	// the load: every network's attempts, interleaved by network and spread over the edges, so that a
	// network's connections are open on several edges at once
	attempts := make(chan int)
	var workers sync.WaitGroup
	for range max(settings.OpenConcurrency, 1) {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for attempt := range attempts {
				network := networks[attempt%len(networks)]
				edge := quotas[(attempt/len(networks)+attempt)%len(quotas)]
				record(connect(edge, network))
			}
		}()
	}
	total := settings.NetworkCount * settings.AttemptsPerNetwork
	sent := 0
	func() {
		defer close(attempts)
		for ; sent < total; sent += 1 {
			select {
			case attempts <- sent:
			case <-runCtx.Done():
				return
			}
		}
	}()
	workers.Wait()
	report.Attempts = sent
	if err := runCtx.Err(); err != nil {
		return report, err
	}
	connectionsPerDay := limits.Limits[smtpedgeservice.SmtpLimitConnectionsPerDay]
	recipientsPerDay := limits.Limits[smtpedgeservice.SmtpLimitRecipientsPerDay]
	concurrent := limits.Limits[smtpedgeservice.SmtpLimitConcurrentConnections]
	for i, network := range networks {
		network.stateLock.Lock()
		debited, recipients, maxOpen := network.debited, network.recipients, network.maxOpen
		network.stateLock.Unlock()
		report.MaxOpenAtOnce = max(report.MaxOpenAtOnce, maxOpen)
		over := []string{}
		if 0 <= connectionsPerDay && connectionsPerDay < debited {
			over = append(over, fmt.Sprintf("%d connections of %d", debited, connectionsPerDay))
		}
		if 0 <= recipientsPerDay && recipientsPerDay < recipients {
			over = append(over, fmt.Sprintf("%d recipients of %d", recipients, recipientsPerDay))
		}
		if 0 <= concurrent && concurrent < maxOpen {
			over = append(over, fmt.Sprintf("%d open at once of %d", maxOpen, concurrent))
		}
		if 0 < len(over) {
			report.Overruns = append(report.Overruns, fmt.Sprintf("network %d: %s", i, strings.Join(over, ", ")))
		}
	}

	// the halts: a store row each, as the intake writes it, which each edge's reload alone carries to its
	// quota, the edges' reloads spread over the interval as independent processes' are
	halted := networks[:min(settings.HaltedNetworkCount, len(networks))]
	report.HaltCount = len(halted)
	haltTime := clock.Now()
	for _, network := range halted {
		if err := args.Store.SetHalt(runCtx, &smtpedgeservice.SmtpHalt{
			HaltId:    sidecar.NewId(),
			NetworkId: network.networkId,
			Trigger:   smtpedgeservice.SmtpHaltTriggerFraud,
			StartTime: haltTime,
		}); err != nil {
			return report, err
		}
	}
	interval := edgeSettings.HaltReloadInterval
	nextReloads := make([]time.Time, len(quotas))
	for i := range quotas {
		phase := time.Duration(i) * interval / time.Duration(len(quotas))
		nextReloads[i] = start.Add(phase)
		for !haltTime.Before(nextReloads[i]) {
			nextReloads[i] = nextReloads[i].Add(interval)
		}
	}
	// a probe of every edge for every halted network: reached once all answer HALTED; one that passes is
	// released, and counted against the run only once the halt has reached every edge
	probe := func() (bool, error) {
		reached := true
		for _, edge := range quotas {
			for _, network := range halted {
				decision, err := edge.Reserve(runCtx, &smtpedgeservice.SmtpQuotaRequest{
					NetworkId:        network.networkId,
					RecipientCount:   settings.RecipientCount,
					MessageByteCount: settings.MessageByteCount,
					RecipientDomain:  settings.RecipientDomain,
					Limits:           limits,
				})
				if err != nil {
					return false, err
				}
				if decision.Code == protocol.SmtpPreambleCode_SMTP_PREAMBLE_OK {
					edge.Release(runCtx, decision.Reservation)
				}
				if decision.Code != protocol.SmtpPreambleCode_SMTP_PREAMBLE_HALTED {
					reached = false
				}
			}
		}
		return reached, nil
	}
	fakeClock, fake := clock.(*FakeClock)
	for {
		now := clock.Now()
		for i, edge := range quotas {
			if now.Before(nextReloads[i]) {
				continue
			}
			nextReloads[i] = nextReloads[i].Add(interval)
			halts, err := args.Store.ActiveHalts(runCtx)
			if err != nil {
				fail(err)
				continue
			}
			edge.ReplaceHalts(runCtx, halts)
		}
		reached, err := probe()
		if err != nil {
			return report, err
		}
		if reached {
			report.HaltsReached = len(halted)
			report.HaltReach = now.Sub(haltTime)
			break
		}
		if settings.HaltReachTimeout < now.Sub(haltTime) {
			break
		}
		if fake {
			fakeClock.Advance(settings.ClockStep)
			continue
		}
		select {
		case <-clock.After(settings.ClockStep):
		case <-runCtx.Done():
			return report, runCtx.Err()
		}
	}
	// once a halt has reached every edge, no connection of its network goes
	for _, network := range halted {
		for _, edge := range quotas {
			code, err := connect(edge, network)
			if err != nil {
				fail(err)
				continue
			}
			if code == protocol.SmtpPreambleCode_SMTP_PREAMBLE_OK {
				report.AcceptedAfterHalt += 1
			}
		}
	}
	report.Elapsed = clock.Now().Sub(start)
	slices.Sort(report.Overruns)
	return report, nil
}

// The edge's pre-TLS dialog with the MX, as far as this driver takes it: the banner, EHLO and its reply, then
// QUIT, where the edge would go on to STARTTLS and the splice.
func smtpEdgeLoadPreTls(ctx context.Context, dial func(ctx context.Context) (net.Conn, error), heloName string) error {
	conn, err := dial(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	reader := bufio.NewReader(conn)
	expect := func(code string) error {
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return err
			}
			if !strings.HasPrefix(line, code) {
				return fmt.Errorf("the MX answered %q", strings.TrimSpace(line))
			}
			if len(line) < 4 || line[3] != '-' {
				return nil
			}
		}
	}
	if err := expect("220"); err != nil {
		return err
	}
	if _, err := conn.Write([]byte("EHLO " + heloName + "\r\n")); err != nil {
		return err
	}
	if err := expect("250"); err != nil {
		return err
	}
	if _, err := conn.Write([]byte("QUIT\r\n")); err != nil {
		return err
	}
	return expect("221")
}
