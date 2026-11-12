package main

// ur login --device (cmd_login_device.go; RFC 8628): against a fake issuer and api on loopback TLS, the device
// authorization carries v0's command and the consent code the terminal shows, the polls wait as RFC 8628 says and each
// carries a fresh proof by the key the authorization named, the token runs the one command, and it is dropped before
// the daemon is reached; nothing ur prints holds the token or the device code.

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
)

// The fake's synthetic device code, user code and token.
const (
	testUrcliDeviceCode = "synthetic-device-code"
	testUrcliUserCode   = "WDJB-MJHT"
)

// A fake issuer and api speaking the device grant, on testUrcliServer's checks.
type testUrcliDeviceServer struct {
	*testUrcliServer

	deviceStateLock sync.Mutex
	consentCode     string
	// the poll answers in order, after which every poll gets the token; "" is the token
	pollAnswers []string
	pollCount   int
	// what the device authorization omits: "endpoint" leaves it out of the metadata
	omit string
}

func newTestUrcliDeviceServer(t *testing.T, pollAnswers ...string) *testUrcliDeviceServer {
	base := &testUrcliServer{t: t, proofJtis: map[string]bool{}, authKey: newTestUrcliAuthKey(t)}
	fake := &testUrcliDeviceServer{testUrcliServer: base, pollAnswers: pollAnswers}
	base.server = httptest.NewTLSServer(http.HandlerFunc(fake.serveDevice))
	t.Cleanup(base.server.Close)
	return fake
}

// The polls answered so far.
func (self *testUrcliDeviceServer) polls() int {
	self.deviceStateLock.Lock()
	defer self.deviceStateLock.Unlock()
	return self.pollCount
}

// The commands run so far.
func (self *testUrcliDeviceServer) commands() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.commandCount
}

func (self *testUrcliDeviceServer) serveDevice(w http.ResponseWriter, r *http.Request) {
	origin := self.server.URL
	switch r.URL.Path {
	case "/.well-known/oauth-authorization-server":
		metadata := map[string]string{
			"issuer":                 origin,
			"authorization_endpoint": origin + "/authorize",
			"token_endpoint":         origin + "/oauth/token",
		}
		if self.omit != "endpoint" {
			metadata["device_authorization_endpoint"] = origin + "/oauth/device_authorization"
		}
		json.NewEncoder(w).Encode(metadata)
	case "/oauth/device_authorization":
		r.ParseForm()
		details, err := sidecar.ParseAdminCommandDetails(r.PostFormValue("authorization_details"))
		if err != nil || r.PostFormValue("client_id") != urcliClientId || r.PostFormValue("scope") != "auth_keys" ||
			r.PostFormValue("resource") != origin || details.Method != "POST" || details.Path != "/network/auth-keys" {
			self.t.Errorf("the device authorization %v: %v", r.PostForm, err)
			http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
			return
		}
		func() {
			self.deviceStateLock.Lock()
			defer self.deviceStateLock.Unlock()
			self.consentCode = details.ConsentCode
		}()
		self.stateLock.Lock()
		self.jkt = r.PostFormValue("dpop_jkt")
		self.stateLock.Unlock()
		json.NewEncoder(w).Encode(map[string]any{
			"device_code":      testUrcliDeviceCode,
			"user_code":        testUrcliUserCode,
			"verification_uri": "https://auth.example/device",
			"expires_in":       600,
			"interval":         5,
		})
	case "/oauth/token":
		r.ParseForm()
		if r.PostFormValue("grant_type") != urcliDeviceCodeGrantType || r.PostFormValue("client_id") != urcliClientId ||
			r.PostFormValue("device_code") != testUrcliDeviceCode || r.PostFormValue("resource") != origin {
			self.t.Errorf("the poll's form %v", r.PostForm)
			http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
			return
		}
		self.stateLock.Lock()
		proofErr := self.checkProof(r.Header.Get("DPoP"), "POST", origin+"/oauth/token", testUrcliDeviceCode)
		self.stateLock.Unlock()
		if proofErr != nil {
			self.t.Errorf("the poll's proof: %v", proofErr)
			http.Error(w, `{"error":"invalid_dpop_proof"}`, http.StatusBadRequest)
			return
		}
		answer := ""
		func() {
			self.deviceStateLock.Lock()
			defer self.deviceStateLock.Unlock()
			if self.pollCount < len(self.pollAnswers) {
				answer = self.pollAnswers[self.pollCount]
			}
			self.pollCount += 1
		}()
		if answer != "" {
			http.Error(w, `{"error":"`+answer+`"}`, http.StatusBadRequest)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"access_token": testUrcliAccessToken, "token_type": "DPoP", "expires_in": 3600, "scope": "auth_keys"})
	default:
		self.serve(w, r)
	}
}

// Installs a device env of the fake, recording each wait instead of waiting.
func installTestUrcliDeviceEnv(t *testing.T, fake *testUrcliDeviceServer) (*strings.Builder, *[]time.Duration) {
	terminal := &strings.Builder{}
	waits := &[]time.Duration{}
	var waitsLock sync.Mutex
	previous := newUrcliDeviceEnv
	newUrcliDeviceEnv = func(cli *urCli) (*urcliDeviceEnv, error) {
		return &urcliDeviceEnv{
			urcliEnv: &urcliEnv{
				settings:    defaultUrcliSettings(),
				issuer:      fake.server.URL,
				apiOrigin:   fake.server.URL,
				httpClient:  fake.server.Client(),
				openBrowser: func(string) error { return errors.New("no browser on this host") },
				random:      rand.Reader,
				now:         time.Now,
				out:         terminal,
			},
			device: defaultUrcliDeviceSettings(),
			wait: func(ctx context.Context, timeout time.Duration) error {
				waitsLock.Lock()
				defer waitsLock.Unlock()
				*waits = append(*waits, timeout)
				return ctx.Err()
			},
		}, nil
	}
	t.Cleanup(func() { newUrcliDeviceEnv = previous })
	return terminal, waits
}

// ur login --device gets a single-use key through the device grant and one admin command, polling as RFC 8628 says,
// and drops the token before the daemon is reached: the daemon gets the key alone, the dropped grant can neither show
// its token nor prove its key again, and the terminal shows the codes the person needs and no secret.
func TestDeviceGrantDropsToken(t *testing.T) {
	fake := newTestUrcliDeviceServer(t, urcliDeviceAuthorizationPending, urcliDeviceSlowDown, urcliDeviceAuthorizationPending)
	terminal, waits := installTestUrcliDeviceEnv(t, fake)

	// the grant itself: polls, the command, and an erase that leaves nothing usable
	env, err := newUrcliDeviceEnv(&urCli{})
	if err != nil {
		t.Fatal(err)
	}
	command, err := urcliLoginCommand()
	if err != nil {
		t.Fatal(err)
	}
	grant, err := urcliDeviceToken(context.Background(), env, command)
	if err != nil {
		t.Fatal(err)
	}
	if want := []time.Duration{5 * time.Second, 5 * time.Second, 10 * time.Second, 10 * time.Second}; len(*waits) != len(want) {
		t.Fatalf("waits %v, want %v", *waits, want)
	} else {
		for i := range want {
			if (*waits)[i] != want[i] {
				t.Fatalf("waits %v, want %v", *waits, want)
			}
		}
	}
	if _, err := urcliRunCommand(context.Background(), env.urcliEnv, grant); err != nil {
		t.Fatal(err)
	}
	grant.erase()
	if grant.accessToken != "" {
		t.Fatal("the dropped grant still holds its token")
	}
	if _, err := grant.dpopKey.Sign(http.MethodPost, fake.server.URL+"/network/auth-keys", "anything"); err == nil {
		t.Fatal("the dropped grant's DPoP key still proves")
	}
	text := terminal.String()
	fake.deviceStateLock.Lock()
	consentCode := fake.consentCode
	fake.deviceStateLock.Unlock()
	if !strings.Contains(text, testUrcliUserCode) || !strings.Contains(text, consentCode) || !strings.Contains(text, "https://auth.example/device") {
		t.Fatalf("the terminal lacks the page, the user code or the consent code:\n%s", text)
	}

	// through ur login --device and the daemon: the token is dropped before the daemon is dialed
	func() {
		fake.deviceStateLock.Lock()
		defer fake.deviceStateLock.Unlock()
		fake.pollCount = 0
	}()
	target := &testUrDaemonTarget{}
	daemon := startTestControlDaemon(t, target, nil)
	cli, stdout, stderr := newTestUrCli(daemon.socketPath)
	dropped := false
	calledBeforeDrop := false
	dial := cli.dialDaemon
	cli.dialDaemon = func(ctx context.Context, socketPath string, hello *sidecar.DaemonHello) (*sidecar.DaemonClient, error) {
		if !dropped {
			calledBeforeDrop = true
		}
		return dial(ctx, socketPath, hello)
	}
	cli.login = func(ctx context.Context, cli *urCli, invite string) (string, func(), error) {
		t.Error("ur login --device ran the browser login")
		return "", nil, errors.New("not this login")
	}
	cli.loginDevice = func(ctx context.Context, cli *urCli, invite string) (string, func(), error) {
		authKey, drop, err := urcliDeviceLogin(ctx, cli, invite)
		return authKey, func() {
			if drop != nil {
				drop()
			}
			dropped = true
		}, err
	}
	if code := cli.main(context.Background(), []string{"ur", "login", "--device"}); code != urExitOk {
		t.Fatalf("exit %d: %q", code, stderr.String())
	}
	if !dropped || calledBeforeDrop {
		t.Fatal("the token outlived the key's mint")
	}
	if len(target.authKeys) != 1 || target.authKeys[0] != fake.authKey {
		t.Fatalf("the daemon got %v", target.authKeys)
	}
	for _, secret := range []string{fake.authKey, testUrcliAccessToken, testUrcliDeviceCode} {
		for _, out := range []string{terminal.String(), stdout.String(), stderr.String()} {
			if strings.Contains(out, secret) {
				t.Fatal("ur prints a secret")
			}
		}
	}
}

// A denied or expired device code ends the login with no command run, and an issuer offering no device sign-in is
// refused before anything is sent.
func TestDeviceGrantRefusals(t *testing.T) {
	for _, code := range []string{"access_denied", "expired_token"} {
		fake := newTestUrcliDeviceServer(t, urcliDeviceAuthorizationPending, code)
		installTestUrcliDeviceEnv(t, fake)
		_, drop, err := urcliDeviceLogin(context.Background(), &urCli{}, "")
		if drop != nil {
			drop()
		}
		var httpErr *urcliHttpError
		if !errors.As(err, &httpErr) || httpErr.Code != code || fake.commands() != 0 {
			t.Errorf("%s: %v after %d commands", code, err, fake.commands())
		}
	}

	none := newTestUrcliDeviceServer(t)
	none.omit = "endpoint"
	installTestUrcliDeviceEnv(t, none)
	if _, _, err := urcliDeviceLogin(context.Background(), &urCli{}, ""); err == nil || !strings.Contains(err.Error(), "no device sign-in") {
		t.Fatalf("an issuer without the device grant: %v", err)
	}

	if _, _, err := urcliDeviceLogin(context.Background(), &urCli{}, "https://invite.example/invite#synthetic"); err == nil {
		t.Fatal("an invite login ran before Team invitations exist")
	}
	if urcliDeviceLoginEntry == nil {
		t.Fatal("ur login --device has no ur-cli")
	}
}

// A login that waits past the device code's life stops polling.
func TestDeviceGrantStopsAtItsDeadline(t *testing.T) {
	pending := make([]string, 200)
	for i := range pending {
		pending[i] = urcliDeviceAuthorizationPending
	}
	fake := newTestUrcliDeviceServer(t, pending...)
	installTestUrcliDeviceEnv(t, fake)
	previous := newUrcliDeviceEnv
	current := time.Date(2026, time.March, 4, 5, 6, 7, 0, time.UTC)
	newUrcliDeviceEnv = func(cli *urCli) (*urcliDeviceEnv, error) {
		env, err := previous(cli)
		if err != nil {
			return nil, err
		}
		env.now = func() time.Time { return current }
		env.wait = func(ctx context.Context, timeout time.Duration) error {
			current = current.Add(timeout)
			return ctx.Err()
		}
		return env, nil
	}
	t.Cleanup(func() { newUrcliDeviceEnv = previous })
	_, _, err := urcliDeviceLogin(context.Background(), &urCli{}, "")
	if err == nil || !strings.Contains(err.Error(), "in time") {
		t.Fatalf("a login past its deadline: %v", err)
	}
	// 600 s of life at 5 s a poll: the poll at the deadline is not sent
	if fake.polls() != 600/5-1 {
		t.Fatalf("%d polls", fake.polls())
	}
}
