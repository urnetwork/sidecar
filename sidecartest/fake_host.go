// A fake of every interface ServiceHost holds, gathered into one host (§22.4's AddEngines). Each file
// beside this one keeps its interface's promises as host_*.go states them and reads the shared clock
// and fault queue. A call goes through hostCall, so a schedule can drop an answer, fail a call or crash
// its caller, by FaultOpHost and the method's name as key, such as "quota.ReportUsage".

package sidecartest

import (
	"context"
	"errors"

	"github.com/urnetwork/sidecar"
)

// What a client sees when a fault plan drops a call to a host service.
var errHostTransport = errors.New("host call dropped by the fault plan")

// One call through a fake's fault: serve runs on the caller's goroutine, under whatever lock it takes.
func hostCall(ctx context.Context, faults *FaultQueue, method string, serve func() error) error {
	stopIfDead(ctx)
	if isInspecting(ctx) {
		return serve()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	plan := faults.take(ctx, FaultOpHost, "", method)
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
	Redis         *FakeRedisSettings
	Tasks         *FakeTasksSettings
	Quota         *FakeQuotaSettings
	Metrics       *FakeMetricsSettings
	ServiceClient *FakeServiceClientSettings
}

func DefaultFakeHostSettings() *FakeHostSettings {
	return &FakeHostSettings{
		Blobs:         DefaultFakeBlobsSettings(),
		Redis:         DefaultFakeRedisSettings(),
		Tasks:         DefaultFakeTasksSettings(),
		Quota:         DefaultFakeQuotaSettings(),
		Metrics:       DefaultFakeMetricsSettings(),
		ServiceClient: DefaultFakeServiceClientSettings(),
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
	Push          *FakePush
	ServiceClient *FakeServiceClientSource
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
		Quota:         NewFakeQuota(faults, settings.Quota),
		Metrics:       NewFakeMetrics(settings.Metrics),
		Tasks:         NewFakeTasks(clock, faults, settings.Tasks),
		Redis:         NewFakeRedis(ctx, clock, faults, barriers, settings.Redis),
		Blobs:         NewFakeBlobs(clock, faults, barriers, settings.Blobs),
		Push:          NewFakePush(faults),
		ServiceClient: NewFakeServiceClientSource(faults, settings.ServiceClient),
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
		Push:          self.Push,
		ServiceClient: self.ServiceClient,
	}
}

// CC3 and CC4 as far as the fakes hold them: every Redis value, object, metric, hint and usage event.
func (self *FakeHost) privacyItems() []*PrivacyItem {
	items := []*PrivacyItem{}
	for key, value := range self.Redis.Dump() {
		items = append(items, &PrivacyItem{Class: "CC3", Name: "redis " + key, Body: append([]byte(key+"\x00"), value...)})
	}
	for name, body := range self.Blobs.Dump() {
		items = append(items, &PrivacyItem{Class: "CC3", Name: "object " + name, Body: body})
	}
	for _, line := range self.Metrics.Dump() {
		items = append(items, &PrivacyItem{Class: "CC4", Name: "metric", Body: []byte(line)})
	}
	for _, hint := range self.Push.AllHints() {
		items = append(items, &PrivacyItem{
			Class: "CC4",
			Name:  "hint to " + hint.ClientId.String(),
			Body:  append([]byte(hint.Hint.Topic+"\x00"), hint.Hint.Body...),
		})
	}
	return items
}
