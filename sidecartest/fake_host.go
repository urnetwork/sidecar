// A fake of every interface ServiceHost holds, gathered into one host (§22.4's AddEngines). Each file
// beside this one keeps its interface's promises as host_*.go states them and reads the shared clock
// and fault queue. A call goes through hostCall, so a schedule can drop an answer, fail a call or crash
// its caller, by FaultOpHost and the method's name as key, such as "quota.ReportUsage".
//
// A fake declares each call that writes by making it through hostWrite (QD-1155): the Quota's ReportUsage,
// CountRate, a Lease that draws and a lease's settling Close (fake_quota.go), Tasks' Schedule (fake_tasks.go)
// and Push's Hint and HintSidecars (fake_push.go). The queue counts those among the host's writes, so a WritesOnly plan
// names one by its place among them, and §22.8's unknown rule loses each one's answer in turn on T2
// (fault.EveryWrite), as it does a store's writes. Every other call reads, and is never counted as a write.

package sidecartest

import (
	"context"
	"errors"

	"github.com/urnetwork/sidecar"
)

// What a client sees when a fault plan drops a call to a host service.
var errHostTransport = errors.New("host call dropped by the fault plan")

// One call that reads through a fake's fault: serve runs on the caller's goroutine, under whatever lock it
// takes.
func hostCall(ctx context.Context, faults *FaultQueue, method string, serve func() error) error {
	return hostCallWriting(ctx, faults, method, false, serve)
}

// One call that writes through a fake's fault, as hostCall: the queue counts it among the host's writes. See the
// file header.
func hostWrite(ctx context.Context, faults *FaultQueue, method string, serve func() error) error {
	return hostCallWriting(ctx, faults, method, true, serve)
}

// hostWrite where write, hostCall otherwise: for a call whose fake knows only as it is made whether it writes, as a
// Lease that may or may not draw.
func hostCallWriting(ctx context.Context, faults *FaultQueue, method string, write bool, serve func() error) error {
	stopIfDead(ctx)
	if isInspecting(ctx) {
		return serve()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	plan := faults.take(ctx, FaultOpHost, "", method, write)
	result := FaultResult(0)
	if plan != nil {
		result = plan.Result
	}
	switch result {
	case FailBeforeApply:
		return errHostTransport
	case CrashBeforeApply:
		crashCaller(ctx)
	}
	err := serve()
	switch result {
	case ApplyThenDrop:
		return errHostTransport
	case CrashAfterApply:
		crashCaller(ctx)
	}
	return err
}

type FakeHostSettings struct {
	Blobs         *FakeBlobsSettings
	ClockCheck    *FakeClockCheckSettings
	Redis         *FakeRedisSettings
	Tasks         *FakeTasksSettings
	Quota         *FakeQuotaSettings
	Push          *FakePushSettings
	Metrics       *FakeMetricsSettings
	ServiceClient *FakeServiceClientSettings
	Gates         *FakeServiceGatesSettings
	Budget        *FakeWriteBudgetSettings
}

func DefaultFakeHostSettings() *FakeHostSettings {
	return &FakeHostSettings{
		Blobs:         DefaultFakeBlobsSettings(),
		ClockCheck:    DefaultFakeClockCheckSettings(),
		Redis:         DefaultFakeRedisSettings(),
		Tasks:         DefaultFakeTasksSettings(),
		Quota:         DefaultFakeQuotaSettings(),
		Push:          DefaultFakePushSettings(),
		Metrics:       DefaultFakeMetricsSettings(),
		ServiceClient: DefaultFakeServiceClientSettings(),
		Gates:         DefaultFakeServiceGatesSettings(),
		Budget:        DefaultFakeWriteBudgetSettings(),
	}
}

// Every fake, by its type, beside the ServiceHost built from them, so a test can reach behind an
// interface: moving a balance, losing Redis, reading what was hinted.
type FakeHost struct {
	Authenticator *FakeAuthenticator
	Quota         *FakeQuota
	Metrics       *FakeMetrics
	Tasks         *FakeTasks
	Redis         *FakeRedis
	Blobs         *FakeBlobs
	ClockCheck    *FakeClockCheck
	Push          *FakePush
	ServiceClient *FakeServiceClientSource
	// Every gate closed until a test sets the file's text.
	Gates *FakeServiceGates
	// Admits every write until a test refuses one.
	Budget *FakeWriteBudget
	// No network loaded, so every gate reading it refuses, until a test loads one.
	Abuse *FakeAbuseGate
	// The clock this host's engines read: the shared one, or a view of it with an offset.
	Clock Clock
}

// Everything shares clock, faults and barriers. A nil settings takes the defaults, and a nil barriers
// suits a test outside a schedule. The Redis fake's goroutine ends with ctx.
func NewFakeHost(ctx context.Context, clock Clock, faults *FaultQueue, barriers *BarrierDriver, settings *FakeHostSettings) *FakeHost {
	if clock == nil {
		clock = NewFakeClock(DefaultClockStart())
	}
	if faults == nil {
		faults = NewFaultQueue()
	}
	if settings == nil {
		settings = DefaultFakeHostSettings()
	}
	return &FakeHost{
		Authenticator: NewFakeAuthenticator(clock, faults),
		Quota:         NewFakeQuota(clock, faults, settings.Quota),
		Metrics:       NewFakeMetrics(settings.Metrics),
		Tasks:         NewFakeTasks(clock, faults, settings.Tasks),
		Redis:         NewFakeRedis(ctx, clock, faults, barriers, settings.Redis),
		Blobs:         NewFakeBlobs(clock, faults, barriers, settings.Blobs),
		ClockCheck:    NewFakeClockCheck(settings.ClockCheck),
		Push:          NewFakePushWithSettings(faults, settings.Push),
		ServiceClient: NewFakeServiceClientSource(faults, settings.ServiceClient),
		Gates:         NewFakeServiceGates(settings.Gates),
		Budget:        NewFakeWriteBudget(settings.Budget),
		Abuse:         NewFakeAbuseGate(),
		Clock:         clock,
	}
}

// The host an engine's constructor takes.
func (self *FakeHost) ServiceHost() *sidecar.ServiceHost {
	return &sidecar.ServiceHost{
		Authenticator: self.Authenticator,
		Quota:         self.Quota,
		Metrics:       self.Metrics,
		Tasks:         self.Tasks,
		Redis:         self.Redis,
		Blobs:         self.Blobs,
		ClockCheck:    self.ClockCheck,
		Push:          self.Push,
		ServiceClient: self.ServiceClient,
		Clock:         self.Clock,
		Gates:         self.Gates,
		Budget:        self.Budget,
		Abuse:         self.Abuse,
	}
}

// CC3 and CC4 as far as the fakes hold them: every Redis value, object, metric, hint, usage event and
// task request.
func (self *FakeHost) privacyItems() []*PrivacyItem {
	items := []*PrivacyItem{}
	for key, value := range self.Redis.Dump() {
		items = append(items, &PrivacyItem{Class: PrivacyClassRedis, Name: "redis " + key, Body: append([]byte(key+"\x00"), value...)})
	}
	for name, body := range self.Blobs.Dump() {
		items = append(items, &PrivacyItem{Class: PrivacyClassObject, Name: "object " + name, Body: body})
	}
	for _, line := range self.Metrics.Dump() {
		items = append(items, &PrivacyItem{Class: PrivacyClassMetric, Name: "metric", Body: []byte(line)})
	}
	for _, hint := range self.Push.AllHints() {
		items = append(items, &PrivacyItem{
			Class: PrivacyClassHint,
			Name:  "hint to " + hint.ClientId.String(),
			Body:  append([]byte(hint.Hint.Topic+"\x00"), hint.Hint.Body...),
		})
	}
	// every batch that reached the host, a refused one too: api read it before it refused it
	for _, batch := range self.Quota.SentBatches() {
		for _, event := range batch.Events {
			items = append(items, &PrivacyItem{Class: PrivacyClassUsage, Name: "usage from " + batch.Producer, Body: []byte(event.Meter)})
		}
	}
	for _, request := range self.Tasks.AllRequests() {
		items = append(items, &PrivacyItem{
			Class: PrivacyClassTask,
			Name:  "task " + request.Name,
			Body:  append([]byte(request.OnceKey+"\x00"), request.Args...),
		})
	}
	return items
}
