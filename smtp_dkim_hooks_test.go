//go:build sidecar_testhooks && !sidecar_http

package sidecar

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

// A Logger keeping every line, so a test can scan what reached the log.
type smtpDkimTestLogger struct {
	stateLock sync.Mutex
	lines     []string
}

func (self *smtpDkimTestLogger) add(line string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.lines = append(self.lines, line)
}

func (self *smtpDkimTestLogger) Info(args ...any) { self.add(fmt.Sprint(args...)) }
func (self *smtpDkimTestLogger) Infof(format string, args ...any) {
	self.add(fmt.Sprintf(format, args...))
}
func (self *smtpDkimTestLogger) Warningf(format string, args ...any) {
	self.add(fmt.Sprintf(format, args...))
}
func (self *smtpDkimTestLogger) Errorf(format string, args ...any) {
	self.add(fmt.Sprintf(format, args...))
}
func (self *smtpDkimTestLogger) V(level int32) Verbose { return smtpDkimTestVerbose{logger: self} }

type smtpDkimTestVerbose struct {
	logger *smtpDkimTestLogger
}

func (self smtpDkimTestVerbose) Enabled() bool                    { return true }
func (self smtpDkimTestVerbose) Info(args ...any)                 { self.logger.Info(args...) }
func (self smtpDkimTestVerbose) Infof(format string, args ...any) { self.logger.Infof(format, args...) }

// Every DKIM key reaches the privacy harness when made and each time it is read to sign, and none of
// them, nor a signing domain, reaches the log or the published bodies (I-7, I-13), across a first
// publish, a failed rotation, a rotation and a burn.
func TestSmtpDkimKeysReachTheSecretHookAndNoLog(t *testing.T) {
	recorder := recordHooks(t)
	_, secrets := newSmtpDkimTestSecrets(t)
	publisher := &smtpDkimTestPublisher{}
	clock := newSmtpDkimTestClock()
	logger := &smtpDkimTestLogger{}
	keys := NewSmtpDkimKeys(secrets, publisher, DefaultSmtpSenderSettings(), clock, logger)
	ctx := context.Background()

	selector, err := keys.Current(ctx, testDkimBurnerDomain)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("synthetic"))
	if _, err := selector.SignDkim(digest[:]); err != nil {
		t.Fatal(err)
	}
	selector.Release()
	clock.advance(91 * 24 * time.Hour)
	publisher.setErr(errors.New("synthetic transport failure"))
	failed, err := keys.Current(ctx, testDkimBurnerDomain)
	if err != nil {
		t.Fatal(err)
	}
	failed.Release()
	publisher.setErr(nil)
	if err := keys.Rotate(ctx, testDkimBurnerDomain); err != nil {
		t.Fatal(err)
	}
	if err := keys.Retire(ctx, testDkimBurnerDomain); err != nil {
		t.Fatal(err)
	}

	recorder.stateLock.Lock()
	defer recorder.stateLock.Unlock()
	if !recorder.kinds["dkim_private_key"] {
		t.Fatal("no dkim key reached the hook")
	}
	// one key made by the first publish, one read to sign, one made by the failed rotation and one by
	// the rotation
	keyCount := 0
	for _, secret := range recorder.secrets {
		if 1000 < len(secret) {
			keyCount += 1
		}
	}
	if keyCount < 4 {
		t.Errorf("%d keys reached the hook", keyCount)
	}
	for _, barrier := range []string{"smtp.dkim_publish.before", "smtp.dkim_publish.after", "smtp.dkim_retire.before", "smtp.dkim_retire.after"} {
		if !recorder.barriers[barrier] {
			t.Errorf("no %s barrier", barrier)
		}
	}
	var published bytes.Buffer
	for _, call := range publisher.calls {
		fmt.Fprintf(&published, "%+v", call)
		for _, publish := range call.Publish {
			published.Write(publish.PublicKey)
		}
	}
	logger.stateLock.Lock()
	defer logger.stateLock.Unlock()
	if len(logger.lines) == 0 {
		t.Fatal("the failed rotation logged nothing")
	}
	for _, line := range logger.lines {
		if bytes.Contains([]byte(line), []byte(testDkimBurnerDomain)) {
			t.Errorf("a log names the domain: %s", line)
		}
		for _, secret := range recorder.secrets {
			if bytes.Contains([]byte(line), secret) {
				t.Errorf("a log holds a key: %s", line)
			}
		}
	}
	for _, secret := range recorder.secrets {
		if bytes.Contains(published.Bytes(), secret) {
			t.Error("a published body holds a key")
		}
	}
}
