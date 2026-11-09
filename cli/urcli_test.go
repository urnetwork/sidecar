package main

// ur-cli in ur (urcli_token.go, urcli_login.go; §7.8, D-TEAM-7): against a fake issuer and api on loopback TLS and
// a fake browser, ur login's request carries v0's command and the code the terminal shows, the code grant goes
// with a proof by the key the request named, the command goes with the token and a fresh proof, a lost answer is
// sent again and a refusal is not, and nothing ur prints holds the token, the key or the code grant.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
)

// The fake's synthetic token.
const testUrcliAccessToken = "synthetic-admin-token"

// A fake of the issuer and the api, as one origin, checking what ur-cli sends.
type testUrcliServer struct {
	t      *testing.T
	server *httptest.Server

	stateLock    sync.Mutex
	challenge    string
	jkt          string
	redirectUri  string
	code         string
	commandCount int
	proofJtis    map[string]bool
	// how many command attempts answer a lost response before one answers
	dropCommandCount int
	// the command's answer: a key, or a refusal's status
	refuseStatus int
	authKey      string
}

// A synthetic auth key in §7.8's form: a 16-byte id and a 32-byte secret, lowercase base32 with no padding.
func newTestUrcliAuthKey(t *testing.T) string {
	encoding := base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)
	id := make([]byte, 16)
	secret := make([]byte, 32)
	rand.Read(id)
	rand.Read(secret)
	return "ur-authkey-" + encoding.EncodeToString(id) + "-" + encoding.EncodeToString(secret)
}

func newTestUrcliServer(t *testing.T) *testUrcliServer {
	self := &testUrcliServer{
		t:         t,
		proofJtis: map[string]bool{},
		authKey:   newTestUrcliAuthKey(t),
	}
	self.server = httptest.NewTLSServer(http.HandlerFunc(self.serve))
	t.Cleanup(self.server.Close)
	return self
}

// A DPoP proof's parts, checked by hand: its jwk's thumbprint, its signature, htm, htu and ath.
func (self *testUrcliServer) checkProof(proof string, method string, htu string, token string) error {
	parts := strings.Split(proof, ".")
	if len(parts) != 3 {
		return errors.New("not a jws")
	}
	headerBytes, _ := base64.RawURLEncoding.DecodeString(parts[0])
	claimsBytes, _ := base64.RawURLEncoding.DecodeString(parts[1])
	signature, _ := base64.RawURLEncoding.DecodeString(parts[2])
	header := &struct {
		Typ string `json:"typ"`
		Alg string `json:"alg"`
		Jwk struct {
			Kty string `json:"kty"`
			Crv string `json:"crv"`
			X   string `json:"x"`
		} `json:"jwk"`
	}{}
	claims := &struct {
		Jti string `json:"jti"`
		Htm string `json:"htm"`
		Htu string `json:"htu"`
		Ath string `json:"ath"`
	}{}
	if json.Unmarshal(headerBytes, header) != nil || json.Unmarshal(claimsBytes, claims) != nil {
		return errors.New("the proof does not parse")
	}
	publicKey, _ := base64.RawURLEncoding.DecodeString(header.Jwk.X)
	if header.Typ != "dpop+jwt" || header.Alg != "EdDSA" || len(publicKey) != ed25519.PublicKeySize {
		return errors.New("the proof's header")
	}
	if sidecar.DpopKeyThumbprint(publicKey) != self.jkt {
		return errors.New("the proof's key is not the one the request named")
	}
	if !ed25519.Verify(publicKey, []byte(parts[0]+"."+parts[1]), signature) {
		return errors.New("the proof's signature")
	}
	ath := sha256.Sum256([]byte(token))
	if claims.Htm != method || claims.Htu != htu || claims.Ath != base64.RawURLEncoding.EncodeToString(ath[:]) {
		return errors.New("the proof's htm, htu or ath")
	}
	if self.proofJtis[claims.Jti] {
		return errors.New("a proof's jti twice")
	}
	self.proofJtis[claims.Jti] = true
	return nil
}

func (self *testUrcliServer) serve(w http.ResponseWriter, r *http.Request) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	origin := self.server.URL
	switch r.URL.Path {
	case "/.well-known/oauth-authorization-server":
		json.NewEncoder(w).Encode(map[string]string{
			"issuer":                 origin,
			"authorization_endpoint": origin + "/authorize",
			"token_endpoint":         origin + "/oauth/token",
		})
	case "/oauth/token":
		r.ParseForm()
		verifierHash := sha256.Sum256([]byte(r.PostFormValue("code_verifier")))
		if r.PostFormValue("grant_type") != "authorization_code" || r.PostFormValue("client_id") != urcliClientId ||
			r.PostFormValue("code") != self.code || r.PostFormValue("redirect_uri") != self.redirectUri ||
			r.PostFormValue("resource") != origin ||
			subtle.ConstantTimeCompare([]byte(base64.RawURLEncoding.EncodeToString(verifierHash[:])), []byte(self.challenge)) != 1 {
			self.t.Errorf("the code grant's form %v", r.PostForm)
			http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
			return
		}
		if err := self.checkProof(r.Header.Get("DPoP"), "POST", origin+"/oauth/token", self.code); err != nil {
			self.t.Errorf("the code grant's proof: %v", err)
			http.Error(w, `{"error":"invalid_dpop_proof"}`, http.StatusBadRequest)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"access_token": testUrcliAccessToken, "token_type": "DPoP", "expires_in": 3600, "scope": "auth_keys"})
	case "/network/auth-keys":
		self.commandCount += 1
		body, _ := io.ReadAll(r.Body)
		if r.Header.Get("Authorization") != "DPoP "+testUrcliAccessToken {
			self.t.Errorf("the command's authorization")
		}
		if err := self.checkProof(r.Header.Get("DPoP"), "POST", origin+"/network/auth-keys", testUrcliAccessToken); err != nil {
			self.t.Errorf("the command's proof: %v", err)
		}
		if canonical, err := sidecar.CanonicalJson(body); err != nil || string(canonical) != `{"duration_seconds":300,"max_uses":1}` {
			self.t.Errorf("the command's body %s", body)
		}
		if self.commandCount <= self.dropCommandCount {
			// the answer is lost on the way back
			hijacker := w.(http.Hijacker)
			connection, _, _ := hijacker.Hijack()
			connection.Close()
			return
		}
		if self.refuseStatus != 0 {
			http.Error(w, `{"error":"refused"}`, self.refuseStatus)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"auth_key_id": "00000000-0000-0000-0000-00000000f001", "auth_key": self.authKey})
	default:
		http.NotFound(w, r)
	}
}

// The fake browser: reads the authorization request, checks it, and follows the redirect with a code, as the
// consent page does once the person approves.
func (self *testUrcliServer) browser(terminal *bytes.Buffer, approve bool) func(authorizationUrl string) error {
	return func(authorizationUrl string) error {
		parsed, err := url.Parse(authorizationUrl)
		if err != nil {
			return err
		}
		query := parsed.Query()
		details, err := sidecar.ParseAdminCommandDetails(query.Get("authorization_details"))
		if err != nil {
			self.t.Errorf("authorization_details: %v", err)
			return nil
		}
		if !strings.Contains(terminal.String(), details.ConsentCode) {
			self.t.Errorf("the terminal does not show the page's code")
		}
		if query.Get("client_id") != urcliClientId || query.Get("response_type") != "code" || query.Get("scope") != "auth_keys" ||
			query.Get("code_challenge_method") != "S256" || query.Get("resource") != self.server.URL ||
			!strings.HasPrefix(query.Get("redirect_uri"), "http://127.0.0.1:") || details.Method != "POST" ||
			details.Path != "/network/auth-keys" {
			self.t.Errorf("the authorization request %v", query)
		}
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.challenge = query.Get("code_challenge")
			self.jkt = query.Get("dpop_jkt")
			self.redirectUri = query.Get("redirect_uri")
			self.code = "synthetic-code"
		}()
		redirect := url.Values{}
		redirect.Set("iss", self.server.URL)
		if approve {
			redirect.Set("code", "synthetic-code")
		} else {
			redirect.Set("error", "access_denied")
		}
		go func() {
			// another page's redirect, with no state of this login, changes nothing
			if response, err := http.Get(query.Get("redirect_uri") + "?code=stray&state=stray&iss=" + url.QueryEscape(self.server.URL)); err == nil {
				response.Body.Close()
			}
			redirect.Set("state", query.Get("state"))
			if response, err := http.Get(query.Get("redirect_uri") + "?" + redirect.Encode()); err == nil {
				response.Body.Close()
			}
		}()
		return nil
	}
}

// Installs an env of the fake for the test.
func installTestUrcliEnv(t *testing.T, fake *testUrcliServer, approve bool) *bytes.Buffer {
	terminal := &bytes.Buffer{}
	previous := newUrcliEnv
	newUrcliEnv = func(cli *urCli) (*urcliEnv, error) {
		settings := defaultUrcliSettings()
		settings.CallbackTimeout = time.Minute
		return &urcliEnv{
			settings:    settings,
			issuer:      fake.server.URL,
			apiOrigin:   fake.server.URL,
			httpClient:  fake.server.Client(),
			openBrowser: fake.browser(terminal, approve),
			random:      rand.Reader,
			now:         time.Now,
			out:         terminal,
		}, nil
	}
	t.Cleanup(func() { newUrcliEnv = previous })
	return terminal
}

// ur login's ur-cli gets a single-use key through a one-command admin token, sending the command again after a lost
// answer with a fresh proof, and prints neither the key nor the token.
func TestUrcliLoginGetsAKeyThroughOneAdminCommand(t *testing.T) {
	fake := newTestUrcliServer(t)
	fake.dropCommandCount = 1
	terminal := installTestUrcliEnv(t, fake, true)
	authKey, drop, err := urcliLogin(context.Background(), &urCli{}, "")
	if drop != nil {
		defer drop()
	}
	if err != nil {
		t.Fatal(err)
	}
	if authKey != fake.authKey {
		t.Fatal("ur login's key is not the api's")
	}
	if fake.commandCount != 2 {
		t.Fatalf("%d command attempts", fake.commandCount)
	}
	for _, secret := range []string{authKey, testUrcliAccessToken, "synthetic-code"} {
		if strings.Contains(terminal.String(), secret) {
			t.Fatal("the terminal shows a secret")
		}
	}
}

// A refusal of the command is not sent again, and a refused consent ends the login.
func TestUrcliLoginRefusals(t *testing.T) {
	fake := newTestUrcliServer(t)
	fake.refuseStatus = http.StatusForbidden
	installTestUrcliEnv(t, fake, true)
	_, drop, err := urcliLogin(context.Background(), &urCli{}, "")
	if drop != nil {
		drop()
	}
	var httpErr *urcliHttpError
	if !errors.As(err, &httpErr) || httpErr.Status != http.StatusForbidden || fake.commandCount != 1 {
		t.Fatalf("a refused command: %v after %d attempts", err, fake.commandCount)
	}

	denied := newTestUrcliServer(t)
	installTestUrcliEnv(t, denied, false)
	if _, _, err := urcliLogin(context.Background(), &urCli{}, ""); !errors.As(err, &httpErr) || httpErr.Code != "access_denied" {
		t.Fatalf("a denied consent: %v", err)
	}
	if denied.commandCount != 0 {
		t.Fatal("a denied consent ran the command")
	}

	if _, _, err := urcliLogin(context.Background(), &urCli{}, "https://invite.example/invite#synthetic"); err == nil {
		t.Fatal("an invite login ran before Team invitations exist")
	}
}

// ur login's command is v0's: POST /network/auth-keys, 300 s, one use, nothing else.
func TestUrcliLoginCommandIsV0s(t *testing.T) {
	command, err := urcliLoginCommand()
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := sidecar.CanonicalJson(command.Body)
	if err != nil {
		t.Fatal(err)
	}
	if command.Method != "POST" || command.Path != "/network/auth-keys" || string(canonical) != `{"duration_seconds":300,"max_uses":1}` {
		t.Fatalf("%s %s %s", command.Method, command.Path, canonical)
	}
	if urcliLoginEntry == nil {
		t.Fatal("ur login has no ur-cli")
	}
}
