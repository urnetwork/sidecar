// ur-cli in the ur process (§7.8, D-TEAM-7, §5.7): the public OAuth client that gets one admin token for one
// command, loopback PKCE (RFC 8252) with code-matched consent and a DPoP key that never leaves this process. ur login
// and, from TEAM-M6-08, ur admin call it; the daemon and MCP never do, so no agent's tool call can reach it.
//
//	discover  GET <issuer>/.well-known/oauth-authorization-server for its authorization and token endpoints, the
//	          token endpoint on the issuer's own host
//	authorize a new Ed25519 DPoP key, PKCE verifier, state and consent code; a listener on 127.0.0.1; the browser
//	          opened at the authorization endpoint with the command as RFC 9396 authorization_details, the code
//	          beside it and dpop_jkt; the terminal shows the same code, which the person matches on the page
//	callback  one GET /callback with this state and the issuer's iss
//	token     the code, verifier and redirect at the token endpoint with a proof by the DPoP key, ath over the code
//	command   the command's own bytes at the api with "Authorization: DPoP <token>" and a fresh proof, sent again
//	          after a lost response, which api answers with the stored result (admin_token_use)
//
// Nothing here prints the token, the code, the verifier or the command's answer: the person reads the URL, the
// consent code and errors, which carry statuses and codes, never a body.

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/urnetwork/sidecar"
)

// ur-cli's client_id, preregistered at the issuer.
const urcliClientId = "ur-cli"

// The scope v0's one command needs (§7.8's OAuth client scopes).
const urcliScopeAuthKeys = "auth_keys"

// Tunables of ur-cli in this process.
type urcliSettings struct {
	// How long the browser's redirect may take: 10 minutes, the consent receipt's life, as long as a person
	// needs to sign in again and compare the code.
	CallbackTimeout time.Duration
	// How long one request to the issuer or the api may take: 30 s.
	RequestTimeout time.Duration
	// How many times the command goes in all, a first send and the retries after a lost response: 3. A retry
	// is answered with the first use's stored result, so it runs nothing twice.
	CommandAttemptCount int
	// The longest answer read from the issuer or the api: 64 KiB.
	ResponseMaxByteCount int64
}

func defaultUrcliSettings() *urcliSettings {
	return &urcliSettings{
		CallbackTimeout:      10 * time.Minute,
		RequestTimeout:       30 * time.Second,
		CommandAttemptCount:  3,
		ResponseMaxByteCount: 64 * 1024,
	}
}

// Where ur-cli talks, and what it waits through. Tests replace newUrcliEnv.
type urcliEnv struct {
	settings *urcliSettings
	// the issuer, https://auth.<domain>, whose metadata names its endpoints
	issuer string
	// the api's origin, https://api.<domain>: the command's resource and its proof's htu
	apiOrigin  string
	httpClient *http.Client
	// opens the authorization page in the person's browser; ur prints the url either way
	openBrowser func(authorizationUrl string) error
	random      io.Reader
	now         func() time.Time
	// the person's terminal: stderr, never stdout, which an MCP relay owns
	out io.Writer
}

// The env this process uses: the issuer and the api from §18.9's host list.
var newUrcliEnv = func(cli *urCli) (*urcliEnv, error) {
	hostList, err := cli.hostList()
	if err != nil {
		return nil, err
	}
	env := &urcliEnv{
		settings:    defaultUrcliSettings(),
		httpClient:  &http.Client{},
		openBrowser: openUrcliBrowser,
		random:      rand.Reader,
		now:         time.Now,
		out:         cli.stderr,
	}
	for _, host := range hostList.Hosts {
		switch host.Service {
		case sidecar.SidecarHostServiceApi:
			env.apiOrigin = "https://" + host.Host
		case sidecar.SidecarHostServiceAuth:
			env.issuer = "https://" + host.Host
		}
	}
	if env.apiOrigin == "" || env.issuer == "" {
		return nil, errors.New("the host list names no api or auth host")
	}
	return env, nil
}

// Opens url in the platform's browser, best effort: ur has printed it already.
func openUrcliBrowser(authorizationUrl string) error {
	var command *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		command = exec.Command("open", authorizationUrl)
	case "windows":
		command = exec.Command("rundll32", "url.dll,FileProtocolHandler", authorizationUrl)
	default:
		command = exec.Command("xdg-open", authorizationUrl)
	}
	return command.Start()
}

// One admin token for one command, and the DPoP key that proves it, held in this process alone.
type urcliAdminGrant struct {
	command     *sidecar.AdminCommand
	accessToken string
	dpopKey     *sidecar.AdminDpopKey
	expireTime  time.Time
}

// Drops the token and erases the DPoP key, so neither outlives the command.
func (self *urcliAdminGrant) erase() {
	self.accessToken = ""
	if self.dpopKey != nil {
		self.dpopKey.Erase()
	}
}

// The issuer's metadata ur-cli reads (RFC 8414).
type urcliIssuerMetadata struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
}

// The token endpoint's answer.
type urcliTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope"`
}

// An issuer or api answer that is not a success: its status and, for an OAuth error, its code. Never its body.
type urcliHttpError struct {
	Status int
	Code   string
}

func (self *urcliHttpError) Error() string {
	if self.Code != "" {
		return fmt.Sprintf("ur-cli: %d %s", self.Status, self.Code)
	}
	return fmt.Sprintf("ur-cli: status %d", self.Status)
}

// Reads one answer within the bound: its body on 2xx, else an urcliHttpError with the OAuth error code if it has
// one.
func (self *urcliEnv) readResponse(response *http.Response) ([]byte, error) {
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, self.settings.ResponseMaxByteCount+1))
	if err != nil {
		return nil, err
	}
	if self.settings.ResponseMaxByteCount < int64(len(body)) {
		return nil, errors.New("ur-cli: an answer past its bound")
	}
	if response.StatusCode < 200 || 300 <= response.StatusCode {
		oauthError := &struct {
			Error string `json:"error"`
		}{}
		json.Unmarshal(body, oauthError)
		code := ""
		// only a code's characters, so nothing the server wrote reaches the terminal
		if len(oauthError.Error) <= 64 && strings.Trim(oauthError.Error, "abcdefghijklmnopqrstuvwxyz_") == "" {
			code = oauthError.Error
		}
		return nil, &urcliHttpError{Status: response.StatusCode, Code: code}
	}
	return body, nil
}

// The issuer's endpoints, the token endpoint on the issuer's own origin so the code goes nowhere else.
func (self *urcliEnv) discover(ctx context.Context) (*urcliIssuerMetadata, error) {
	requestCtx, cancel := context.WithTimeout(ctx, self.settings.RequestTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(requestCtx, http.MethodGet, self.issuer+"/.well-known/oauth-authorization-server", nil)
	if err != nil {
		return nil, err
	}
	response, err := self.httpClient.Do(request)
	if err != nil {
		return nil, err
	}
	body, err := self.readResponse(response)
	if err != nil {
		return nil, err
	}
	metadata := &urcliIssuerMetadata{}
	if err := json.Unmarshal(body, metadata); err != nil {
		return nil, errors.New("ur-cli: the issuer's metadata does not parse")
	}
	if metadata.Issuer != self.issuer || !strings.HasPrefix(metadata.TokenEndpoint, self.issuer+"/") {
		return nil, errors.New("ur-cli: the issuer's metadata names another issuer")
	}
	authorizationUrl, err := url.Parse(metadata.AuthorizationEndpoint)
	if err != nil || authorizationUrl.Scheme != "https" || authorizationUrl.Host == "" {
		return nil, errors.New("ur-cli: the issuer's authorization endpoint is not https")
	}
	return metadata, nil
}

// random bytes as unpadded base64url.
func (self *urcliEnv) randomText(byteCount int) (string, error) {
	draw := make([]byte, byteCount)
	if _, err := io.ReadFull(self.random, draw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(draw), nil
}

// What the browser's redirect brought back.
type urcliCallback struct {
	code string
	err  error
}

// Gets an admin token for command: the authorization with its consent code in the browser, then the code grant
// with a proof by a DPoP key made here. The caller runs the command and erases the grant.
func urcliAdminToken(ctx context.Context, env *urcliEnv, command *sidecar.AdminCommand) (*urcliAdminGrant, error) {
	metadata, err := env.discover(ctx)
	if err != nil {
		return nil, err
	}
	dpopKey, err := sidecar.NewAdminDpopKey(env.random, env.now)
	if err != nil {
		return nil, err
	}
	grant := &urcliAdminGrant{command: command, dpopKey: dpopKey}
	ok := false
	defer func() {
		if !ok {
			grant.erase()
		}
	}()
	verifier, err := env.randomText(32)
	if err != nil {
		return nil, err
	}
	challenge := sha256.Sum256([]byte(verifier))
	state, err := env.randomText(16)
	if err != nil {
		return nil, err
	}
	consentCode, err := sidecar.NewAdminConsentCode(env.random)
	if err != nil {
		return nil, err
	}
	details, err := sidecar.FormatAdminCommandDetails(command, consentCode)
	if err != nil {
		return nil, err
	}

	// one listener on loopback alone, any port (RFC 8252 §7.3), serving one callback
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	redirectUri := fmt.Sprintf("http://127.0.0.1:%d/callback", listener.Addr().(*net.TCPAddr).Port)
	callbacks := make(chan *urcliCallback, 1)
	server := &http.Server{
		ReadHeaderTimeout: env.settings.RequestTimeout,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet || r.URL.Path != "/callback" {
				http.NotFound(w, r)
				return
			}
			query := r.URL.Query()
			callback := &urcliCallback{}
			switch {
			case query.Get("state") != state:
				// another page's redirect, or none of ours: it changes nothing
				http.Error(w, "This is not the sign-in ur is waiting for.", http.StatusBadRequest)
				return
			case query.Get("iss") != metadata.Issuer:
				callback.err = errors.New("ur-cli: the redirect names another issuer")
			case query.Get("error") != "":
				callback.err = &urcliHttpError{Status: http.StatusForbidden, Code: "access_denied"}
			case query.Get("code") == "":
				callback.err = errors.New("ur-cli: the redirect carries no code")
			default:
				callback.code = query.Get("code")
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			message := "ur has what it needs. You may close this window."
			if callback.err != nil {
				message = "ur did not get what it needs. You may close this window and look at your terminal."
			}
			fmt.Fprintf(w, "<!doctype html><title>ur</title><p>%s</p>", html.EscapeString(message))
			select {
			case callbacks <- callback:
			default:
			}
		}),
	}
	go server.Serve(listener)
	defer server.Close()

	query := url.Values{}
	query.Set("client_id", urcliClientId)
	query.Set("response_type", "code")
	query.Set("redirect_uri", redirectUri)
	query.Set("scope", urcliScopeAuthKeys)
	query.Set("state", state)
	query.Set("code_challenge", base64.RawURLEncoding.EncodeToString(challenge[:]))
	query.Set("code_challenge_method", "S256")
	query.Set("resource", env.apiOrigin)
	query.Set("dpop_jkt", dpopKey.Thumbprint)
	query.Set("authorization_details", details)
	authorizationUrl := metadata.AuthorizationEndpoint + "?" + query.Encode()

	fmt.Fprintf(env.out, "Approve in your browser. If it does not open, open:\n\n  %s\n\n", authorizationUrl)
	fmt.Fprintf(env.out, "Approve only if the page shows this code:\n\n  %s\n\n", consentCode)
	if err := env.openBrowser(authorizationUrl); err != nil {
		fmt.Fprintln(env.out, "ur could not open a browser; open the address above.")
	}

	var callback *urcliCallback
	select {
	case callback = <-callbacks:
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(env.settings.CallbackTimeout):
		return nil, errors.New("ur-cli: no approval came back in time")
	}
	if callback.err != nil {
		return nil, callback.err
	}

	// the code grant, with a proof by the key the request named, its ath over the code
	proof, err := dpopKey.Sign(http.MethodPost, metadata.TokenEndpoint, callback.code)
	if err != nil {
		return nil, err
	}
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("client_id", urcliClientId)
	form.Set("code", callback.code)
	form.Set("redirect_uri", redirectUri)
	form.Set("code_verifier", verifier)
	form.Set("resource", env.apiOrigin)
	requestCtx, cancel := context.WithTimeout(ctx, env.settings.RequestTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(requestCtx, http.MethodPost, metadata.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("DPoP", proof)
	response, err := env.httpClient.Do(request)
	if err != nil {
		return nil, err
	}
	body, err := env.readResponse(response)
	if err != nil {
		return nil, err
	}
	tokenResponse := &urcliTokenResponse{}
	if err := json.Unmarshal(body, tokenResponse); err != nil || tokenResponse.AccessToken == "" {
		return nil, errors.New("ur-cli: the token answer does not parse")
	}
	if tokenResponse.TokenType != "DPoP" {
		return nil, errors.New("ur-cli: the token is not DPoP-bound")
	}
	grant.accessToken = tokenResponse.AccessToken
	grant.expireTime = env.now().Add(time.Duration(tokenResponse.ExpiresIn) * time.Second)
	ok = true
	return grant, nil
}

// Runs the grant's command at the api once, sending it again after a lost response, which api answers with the
// first use's stored result: a transport error or a 5xx. Answers the command's body.
func urcliRunCommand(ctx context.Context, env *urcliEnv, grant *urcliAdminGrant) ([]byte, error) {
	commandUrl := env.apiOrigin + grant.command.Path
	var lastErr error
	for attempt := 0; attempt < env.settings.CommandAttemptCount; attempt += 1 {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		proof, err := grant.dpopKey.Sign(grant.command.Method, commandUrl, grant.accessToken)
		if err != nil {
			return nil, err
		}
		body, err := func() ([]byte, error) {
			requestCtx, cancel := context.WithTimeout(ctx, env.settings.RequestTimeout)
			defer cancel()
			request, err := http.NewRequestWithContext(requestCtx, grant.command.Method, commandUrl, bytes.NewReader(grant.command.Body))
			if err != nil {
				return nil, err
			}
			request.Header.Set("Authorization", "DPoP "+grant.accessToken)
			request.Header.Set("DPoP", proof)
			if 0 < len(grant.command.Body) {
				request.Header.Set("Content-Type", "application/json")
			}
			response, err := env.httpClient.Do(request)
			if err != nil {
				return nil, err
			}
			return env.readResponse(response)
		}()
		if err == nil {
			return body, nil
		}
		var httpErr *urcliHttpError
		if errors.As(err, &httpErr) && httpErr.Status < 500 {
			// a definite refusal: a retry would only be refused again
			return nil, err
		}
		lastErr = err
	}
	return nil, fmt.Errorf("ur-cli: the command's answer was lost %d times: %w", env.settings.CommandAttemptCount, lastErr)
}
