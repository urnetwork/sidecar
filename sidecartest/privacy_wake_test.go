// §22.7's wake row and CC4's fake APNs and FCM source (TEST-M8-01; owner decision 88, WK4): "wake payloads carry only
// a topic class and version". The wakes here take the path a real one does: a hint through pushservice's waking hint
// writer, whose script answers the client's token, the enqueue into the wake queue, the push sender reading the queue
// and submitting to a vendor, on FakeRedis and a fake clock, the vendors sidecartest's fakes, which record the body the
// real vendor would have been sent. Each hint carries what a wake must not: a topic that names a repo, a kind and a
// body of ids. The capture (privacy_wake.go) scans what the vendors were sent, and WakeSubmissionErrors holds each
// body to its exact shape. The mutants are a wake whose payload carries an id and a vendor body that gained a field.

package sidecartest_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/pushservice"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The bound on a wake's settlement, a guard that fails the test: the sender settles on the fake clock.
const privacyWakeTimeout = 30 * time.Second

// A waking writer and a push sender over one FakeRedis, with an APNs and an FCM fake the capture reads.
type privacyWakeWorld struct {
	t       *testing.T
	redis   *sidecartest.FakeRedis
	clock   *sidecartest.FakeClock
	capture *sidecartest.PrivacyCapture
	apns    *sidecartest.FakeWakeVendor
	fcm     *sidecartest.FakeWakeVendor
	writer  *pushservice.HintWriter
	settled chan *pushservice.WakeSettled
}

func newPrivacyWakeWorld(t *testing.T) *privacyWakeWorld {
	t.Helper()
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	redis := sidecartest.NewFakeRedis(t.Context(), clock, nil, nil, nil)
	t.Cleanup(redis.Close)
	sidecartest.RegisterPushScripts(redis)
	world := &privacyWakeWorld{
		t:       t,
		redis:   redis,
		clock:   clock,
		capture: sidecartest.NewPrivacyCapture(),
		apns:    sidecartest.NewFakeWakeVendor(pushservice.WakePlatformApns, clock),
		fcm:     sidecartest.NewFakeWakeVendor(pushservice.WakePlatformFcm, clock),
		settled: make(chan *pushservice.WakeSettled, 64),
	}
	world.capture.AddWakeVendor(world.apns)
	world.capture.AddWakeVendor(world.fcm)
	metrics := sidecartest.NewFakeMetrics(nil)
	queueSettings := pushservice.DefaultWakeQueueSettings()
	enqueuer, err := pushservice.NewWakeEnqueuer(redis, queueSettings, clock, func() bool { return true }, metrics)
	if err != nil {
		t.Fatal(err)
	}
	if world.writer, err = pushservice.NewWakingHintWriter(redis, nil, nil, nil, enqueuer); err != nil {
		t.Fatal(err)
	}
	// reads and claims block long on the fake clock, so the sender moves only when an entry arrives
	senderSettings := pushservice.DefaultWakeSenderSettings()
	senderSettings.ReadBlock = 100 * time.Hour
	senderSettings.ClaimInterval = 100 * time.Hour
	senderSettings.GateInterval = 100 * time.Hour
	// the group stands before any entry, as it does in production from the first sender's start
	for shard := range queueSettings.ShardCount {
		if err := redis.StreamGroupCreate(t.Context(), pushservice.WakeQueueKey(shard), senderSettings.ConsumerGroup); err != nil {
			t.Fatal(err)
		}
	}
	sender, err := pushservice.NewWakeSender(t.Context(), &pushservice.WakeSenderArgs{
		Redis:    redis,
		Vendors:  []pushservice.WakeVendor{world.apns, world.fcm},
		Consumer: "privacy-wake",
		Enabled:  func() bool { return true },
		Clock:    clock,
		Metrics:  metrics,
		Log:      world.capture.Logger("push sender"),
		Settings: senderSettings,
		Settled: func(settled *pushservice.WakeSettled) {
			world.settled <- settled
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sender.Close)
	t.Cleanup(func() {
		if violations := redis.Violations(); len(violations) != 0 {
			t.Errorf("violations %v", violations)
		}
	})
	return world
}

// Gives a fresh client a synthetic token on platform, as §18.7's step 0 leaves it.
func (self *privacyWakeWorld) client(platform string) (connect.Id, string) {
	self.t.Helper()
	clientId := connect.NewId()
	token := "synthetic-" + platform + "-token-" + clientId.String()[:8]
	if err := self.redis.Set(self.t.Context(), pushservice.HintTokenKey(clientId), pushservice.WakeTokenValue(platform, token), 0); err != nil {
		self.t.Fatal(err)
	}
	if err := self.redis.Set(self.t.Context(), pushservice.WakeTokenRevisionKey(clientId), []byte("1"), 0); err != nil {
		self.t.Fatal(err)
	}
	return clientId, token
}

// Hints clientId, whose resident is gone, so its wake is due now, and returns once the sender settled it sent.
func (self *privacyWakeWorld) wake(clientId connect.Id, hint *sidecar.ClientHint) {
	self.t.Helper()
	result, err := self.writer.HintClient(self.t.Context(), clientId, hint)
	if err != nil {
		self.t.Fatal(err)
	}
	if result.Wake != pushservice.WakeEnqueueDue {
		self.t.Fatalf("the hint on %s queued no wake due now: %d", hint.Topic, result.Wake)
	}
	select {
	case settled := <-self.settled:
		if settled.ClientId != clientId || settled.Result != pushservice.WakeSettledSent {
			self.t.Fatalf("the wake on %s settled %+v", hint.Topic, settled)
		}
	case <-time.After(privacyWakeTimeout):
		self.t.Fatalf("the wake on %s never settled", hint.Topic)
	}
}

// Every wake class through each vendor, each hint carrying a repo's id in its topic and ids in its body: the vendors
// are sent a topic class and a version and nothing else, no id of the hint is in anything a vendor took, and the scan
// read both vendors' submissions.
func TestWakePayloadsCarryOnlyATopicClassAndVersion(t *testing.T) {
	world := newPrivacyWakeWorld(t)
	repoId := sidecar.NewId()
	requestId := sidecar.NewId()
	runId := world.capture.CanaryText("a run id in a hint's body")
	world.capture.Forbid("the repo id of an evs topic", []byte(repoId.String()))
	world.capture.Forbid("the request id in a hint's body", []byte(requestId.String()))
	body := []byte(requestId.String() + " " + runId)
	classes := map[string]string{
		sidecar.PushTopicCore:        "core",
		sidecar.PushTopicTeam:        "team",
		sidecar.PushTopicMail:        "mail",
		sidecar.PushTopicEvs(repoId): "evs",
	}
	version := uint64(1) << 60
	for _, platform := range []string{pushservice.WakePlatformApns, pushservice.WakePlatformFcm} {
		for topic := range classes {
			clientId, _ := world.client(platform)
			version += 1
			world.wake(clientId, &sidecar.ClientHint{Topic: topic, Version: version, Kind: 0x0A01, Body: body})
		}
	}
	for _, vendor := range []*sidecartest.FakeWakeVendor{world.apns, world.fcm} {
		for _, err := range sidecartest.WakeVendorErrors(vendor) {
			t.Error(err)
		}
		sent := []string{}
		for _, submission := range vendor.Submissions() {
			sent = append(sent, submission.Payload.TopicClass)
			if submission.Payload.Version <= uint64(1)<<60 {
				t.Errorf("a wake to %s at version %d, which lost its high digits", vendor.Platform(), submission.Payload.Version)
			}
		}
		slices.Sort(sent)
		if !slices.Equal(sent, []string{"core", "evs", "mail", "team"}) {
			t.Errorf("the %s vendor was sent the classes %v", vendor.Platform(), sent)
		}
	}
	if count := world.capture.ItemCount(sidecartest.PrivacyClassWake); count != 3*2*len(classes) {
		t.Fatalf("the scan read %d wake items", count)
	}
	for _, finding := range world.capture.Scan() {
		t.Errorf("%s", finding)
	}
}

// A wake whose payload carries an id fails: as its topic class, the scan finds the id and the shape refuses the class;
// beside its class and version in the vendor's body, the shape refuses the field, whatever it is called.
func TestAWakePayloadCarryingAnIdFails(t *testing.T) {
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	runId := sidecar.NewId()
	for _, platform := range []string{pushservice.WakePlatformApns, pushservice.WakePlatformFcm} {
		// a capture for each vendor, so one's finding is never the other's
		capture := sidecartest.NewPrivacyCapture()
		capture.Forbid("a run id", []byte(runId.String()))
		vendor := sidecartest.NewFakeWakeVendor(platform, clock)
		capture.AddWakeVendor(vendor)
		// the control: a wake as the sender builds it passes
		vendor.Send(t.Context(), "synthetic-"+platform+"-token-control", &pushservice.WakePayload{TopicClass: "mail", Version: 7})
		if errs := sidecartest.WakeVendorErrors(vendor); len(errs) != 0 {
			t.Fatalf("%s: a wake of a class and a version fails: %v", platform, errs)
		}
		if findings := capture.Scan(); len(findings) != 0 {
			t.Fatalf("%s: a wake of a class and a version is found: %v", platform, findings)
		}

		// an id where the class belongs
		vendor.Send(t.Context(), "synthetic-"+platform+"-token-id", &pushservice.WakePayload{TopicClass: "evs:" + runId.String(), Version: 8})
		errs := sidecartest.WakeVendorErrors(vendor)
		if len(errs) == 0 || !strings.Contains(fmt.Sprint(errs), "is none of") {
			t.Errorf("%s: an id as the topic class passed the shape: %v", platform, errs)
		}
		found := false
		for _, finding := range capture.Scan() {
			found = found || (finding.Class == sidecartest.PrivacyClassWake && finding.Needle == "a run id")
		}
		if !found {
			t.Errorf("%s: the scan missed an id in a wake's body", platform)
		}

		// a version of 0, which no topic's state has
		zero := &sidecartest.FakeWakeSubmission{Platform: platform, Token: "synthetic-token-zero", Payload: pushservice.WakePayload{TopicClass: "core"}}
		zero.Body = privacyWakeBody(platform, zero.Token, &zero.Payload)
		if errs := sidecartest.WakeSubmissionErrors(zero); len(errs) == 0 {
			t.Errorf("%s: a wake at version 0 passed the shape", platform)
		}
	}

	// a field beside the class and the version, in each body's each object
	for _, mutant := range []struct {
		platform string
		body     string
	}{
		{pushservice.WakePlatformApns, `{"aps":{"content-available":1},"t":"mail","v":7,"run_id":"` + runId.String() + `"}`},
		{pushservice.WakePlatformApns, `{"aps":{"content-available":1,"alert":"new mail from ann"},"t":"mail","v":7}`},
		{pushservice.WakePlatformApns, `{"aps":{"content-available":1},"t":"mail","v":"7"}`},
		{pushservice.WakePlatformApns, `{"aps":{"content-available":1},"t":"mail","v":7.0}`},
		{pushservice.WakePlatformFcm, `{"message":{"token":"synthetic-token","data":{"t":"mail","v":"7","client_id":"` + runId.String() + `"},"android":{"priority":"high"}}}`},
		{pushservice.WakePlatformFcm, `{"message":{"token":"synthetic-token","data":{"t":"mail","v":"7"},"android":{"priority":"high"},"notification":{"title":"new mail"}}}`},
		{pushservice.WakePlatformFcm, `{"message":{"token":"another-token","data":{"t":"mail","v":"7"},"android":{"priority":"high"}}}`},
		{pushservice.WakePlatformFcm, `{"message":{"token":"synthetic-token","data":{"t":"mail","v":"7"},"android":{"priority":"high"}},"validate_only":false}`},
	} {
		submission := &sidecartest.FakeWakeSubmission{
			Platform: mutant.platform, Token: "synthetic-token", Payload: pushservice.WakePayload{TopicClass: "mail", Version: 7}, Body: []byte(mutant.body),
		}
		if errs := sidecartest.WakeSubmissionErrors(submission); len(errs) == 0 {
			t.Errorf("a %s body that carries more than a class and a version passed: %s", mutant.platform, mutant.body)
		}
	}
	// and each mutant's twin, the body the sender builds, passes, so the refusals above are the fields'
	for _, platform := range []string{pushservice.WakePlatformApns, pushservice.WakePlatformFcm} {
		submission := &sidecartest.FakeWakeSubmission{Platform: platform, Token: "synthetic-token", Payload: pushservice.WakePayload{TopicClass: "mail", Version: 7}}
		submission.Body = privacyWakeBody(platform, submission.Token, &submission.Payload)
		if errs := sidecartest.WakeSubmissionErrors(submission); len(errs) != 0 {
			t.Errorf("the %s body the sender builds fails: %v", platform, errs)
		}
		if !json.Valid(submission.Body) || bytes.Contains(submission.Body, []byte(runId.String())) {
			t.Errorf("the %s body the sender builds: %s", platform, submission.Body)
		}
	}
	// a vendor that took nothing shows nothing
	if errs := sidecartest.WakeVendorErrors(sidecartest.NewFakeWakeVendor(pushservice.WakePlatformApns, clock)); len(errs) != 1 {
		t.Errorf("a vendor that took no wake reads %v", errs)
	}
}

// The body pushservice builds for platform.
func privacyWakeBody(platform string, token string, payload *pushservice.WakePayload) []byte {
	if platform == pushservice.WakePlatformFcm {
		return pushservice.FcmWakeMessage(token, payload)
	}
	return pushservice.ApnsWakeBody(payload)
}
