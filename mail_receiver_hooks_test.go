//go:build sidecar_testhooks && !sidecar_http && !js && !ios_extension

// MAIL-M7-13's hook sites: the mail host key reaches testHookSecret where the keychain makes it, the key record's
// post sits between barriers a fault schedule holds, and nothing the receiver logs names its host, names or key.

package sidecar

import (
	"bytes"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
)

// A Logger that keeps every line, safe for concurrent use.
type mailTestLogger struct {
	stateLock sync.Mutex
	lines     []string
}

func (self *mailTestLogger) add(line string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.lines = append(self.lines, line)
}

func (self *mailTestLogger) Info(args ...any)                 { self.add(fmt.Sprint(args...)) }
func (self *mailTestLogger) Infof(format string, args ...any) { self.add(fmt.Sprintf(format, args...)) }
func (self *mailTestLogger) Warningf(format string, args ...any) {
	self.add(fmt.Sprintf(format, args...))
}
func (self *mailTestLogger) Errorf(format string, args ...any) {
	self.add(fmt.Sprintf(format, args...))
}
func (self *mailTestLogger) V(level int32) Verbose { return &mailTestVerbose{log: self} }

// Every level enabled, so a guarded line is kept too.
type mailTestVerbose struct {
	log *mailTestLogger
}

func (self *mailTestVerbose) Enabled() bool    { return true }
func (self *mailTestVerbose) Info(args ...any) { self.log.add(fmt.Sprint(args...)) }
func (self *mailTestVerbose) Infof(format string, args ...any) {
	self.log.add(fmt.Sprintf(format, args...))
}

// The lines so far.
func (self *mailTestLogger) snapshot() []string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.lines)
}

// The device key's scalar reaches the hook as the keychain makes it, the key record's post passes its barriers, and no
// line the receiver logs, through a listen that ends and one the gate refuses, names a host, a name or the key.
func TestMailReceiverKeyReachesTheSecretHookAndNoLog(t *testing.T) {
	recorder := recordHooks(t)
	log := &mailTestLogger{}
	world := newMailReceiverTestWorld(t, nil)
	world.newReceiver(func(args *MailReceiverArgs) {
		args.Log = log
	})
	world.startServing()
	if _, err := world.handshake(world.edgeNetworkId); err != nil {
		t.Fatal(err)
	}
	world.listenAnswers = []func() (MailReceiverListener, error){
		func() (MailReceiverListener, error) { return nil, ErrSidecarGateDenied },
	}
	ended := world.clock.Now()
	world.listener.Close()
	world.clock.awaitWaitAt(ended.Add(world.receiver.settings.ListenRetryInterval))

	current, _, _ := world.keys.TlsKeys()
	scalar := current.privateKey.D.FillBytes(make([]byte, tlsDeviceKeyScalarSize))
	recorder.stateLock.Lock()
	hooked := slices.ContainsFunc(recorder.secrets, func(secret []byte) bool { return bytes.Contains(secret, scalar) })
	barriers := map[string]bool{}
	for name := range recorder.barriers {
		barriers[name] = true
	}
	recorder.stateLock.Unlock()
	if !hooked {
		t.Fatal("the mail host key never reached testHookSecret")
	}
	for _, barrier := range []string{"mail.receiver.publish.before", "mail.receiver.publish.after"} {
		if !barriers[barrier] {
			t.Errorf("barrier %s never fired", barrier)
		}
	}
	lines := log.snapshot()
	if len(lines) == 0 {
		t.Fatal("the listen's end logged nothing")
	}
	spkiSha256 := current.SpkiSha256()
	for _, line := range lines {
		for _, name := range append(slices.Clone(testMailReceiverNames), testMailReceiverServerName, "smtp/25/mx") {
			if strings.Contains(line, name) {
				t.Errorf("a line names %q: %q", name, line)
			}
		}
		if strings.Contains(line, fmt.Sprintf("%x", spkiSha256[:])) || bytes.Contains([]byte(line), scalar) {
			t.Errorf("a line names the key: %q", line)
		}
	}
}
