//go:build sidecar_testhooks && !sidecar_http && !js && !ios_extension

// QD-1130's lookup under the test hooks: it sits between its two barriers, the linearization point where a custom
// domain's awaiting selector goes into use, and no log line names the domain, only the selector (I-13).

package sidecar_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A Logger keeping every line, every level enabled.
type testDkimAnswerLogger struct {
	stateLock sync.Mutex
	lines     []string
}

func (self *testDkimAnswerLogger) add(line string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.lines = append(self.lines, line)
}

func (self *testDkimAnswerLogger) Info(args ...any) { self.add(fmt.Sprint(args...)) }
func (self *testDkimAnswerLogger) Infof(format string, args ...any) {
	self.add(fmt.Sprintf(format, args...))
}
func (self *testDkimAnswerLogger) Warningf(format string, args ...any) {
	self.add(fmt.Sprintf(format, args...))
}
func (self *testDkimAnswerLogger) Errorf(format string, args ...any) {
	self.add(fmt.Sprintf(format, args...))
}
func (self *testDkimAnswerLogger) V(level int32) sidecar.Verbose {
	return testDkimAnswerVerbose{logger: self}
}

func (self *testDkimAnswerLogger) lineList() []string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return append([]string{}, self.lines...)
}

type testDkimAnswerVerbose struct {
	logger *testDkimAnswerLogger
}

func (self testDkimAnswerVerbose) Enabled() bool    { return true }
func (self testDkimAnswerVerbose) Info(args ...any) { self.logger.Info(args...) }
func (self testDkimAnswerVerbose) Infof(format string, args ...any) {
	self.logger.Infof(format, args...)
}

func TestSmtpDkimAnswerSitsBetweenItsBarriersAndLogsNoDomain(t *testing.T) {
	barrierLock := sync.Mutex{}
	barriers := []string{}
	sidecar.SetTestHooks(&sidecar.TestHooks{
		Barrier: func(name string, key string) {
			if strings.HasPrefix(name, "smtp.dkim_answer.") {
				barrierLock.Lock()
				defer barrierLock.Unlock()
				barriers = append(barriers, name+" "+key)
			}
		},
	})
	t.Cleanup(func() { sidecar.SetTestHooks(nil) })

	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	zone := sidecartest.NewFakeMailZone(clock)
	publisher := newTestDkimAnswerPublisher()
	settings := sidecar.DefaultSmtpSenderSettings()
	logger := &testDkimAnswerLogger{}
	keys := sidecar.NewSmtpDkimKeys(&testCustomDomainSecrets{values: map[string][]byte{}}, publisher, settings, clock, logger)
	keys.SetDomainAnswers(&sidecar.SmtpDkimDomainAnswers{Doh: zone, Root: testDkimAnswerRoot})

	if _, err := keys.Current(context.Background(), testCustomDomainName); !errors.Is(err, sidecar.ErrSmtpDkimSelectorUnanswered) {
		t.Fatal(err)
	}
	selector := publisher.callList()[0].Publish[0].Selector
	zone.AddTxt(sidecar.SmtpDkimKeyName(selector, testCustomDomainName), publisher.record(t, selector))
	clock.Advance(settings.DkimAnswerRetryInterval)
	current, err := keys.Current(context.Background(), testCustomDomainName)
	if err != nil {
		t.Fatal(err)
	}
	current.Release()

	barrierLock.Lock()
	seen := append([]string{}, barriers...)
	barrierLock.Unlock()
	want := []string{
		"smtp.dkim_answer.before " + selector, "smtp.dkim_answer.after " + selector,
		"smtp.dkim_answer.before " + selector, "smtp.dkim_answer.after " + selector,
	}
	if strings.Join(seen, "\n") != strings.Join(want, "\n") {
		t.Fatalf("barriers %q", seen)
	}
	lines := logger.lineList()
	if len(lines) == 0 {
		t.Fatal("the unanswered lookup logged nothing")
	}
	for _, line := range lines {
		if strings.Contains(line, testCustomDomainName) {
			t.Errorf("a log names the domain: %s", line)
		}
	}
}
