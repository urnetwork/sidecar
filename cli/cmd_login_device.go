// ur login --device (§5.6, §7.8, D-TEAM-7; RFC 8628; CORE-M6-03): ur-cli's device authorization grant, for a host with
// no browser, or one whose browser cannot reach a loopback redirect. It ends as PKCE's flow does (urcli_login.go): one
// admin token for v0's one command, a single-use, user-owned auth key of at most 5 min for the daemon, and the token
// and its DPoP key dropped at once, before anything reaches the daemon (cmd_login.go).
//
//	discover   the issuer's metadata names its device_authorization_endpoint and token_endpoint, both on the issuer's
//	           own origin, so the device code goes nowhere else (RFC 8628 §4)
//	authorize  a new Ed25519 DPoP key and consent code; POST device_authorization with client_id ur-cli, scope
//	           auth_keys, the api as resource, dpop_jkt and the command as RFC 9396 authorization_details with the
//	           consent code beside it. The terminal shows the verification url, the user code, and the consent code,
//	           which the person matches on the consent page: consent stays code-matched, since an agent can drive a
//	           browser (TEAM-M6-08's trap)
//	poll       the device code at the token endpoint with a fresh proof by the DPoP key each time, its ath over the
//	           device code as the code grant's is over the code; every interval, the answer's or RFC 8628's 5 s,
//	           slow_down adding 5 s for this and every later poll (§3.5); authorization_pending polls again;
//	           access_denied, expired_token, any other refusal, or the device code's life running out ends it
//	command    as PKCE's: the one command with the token and a fresh proof, sent again only after a lost answer
//
// TEAM-M6-08 serves POST /oauth/device_authorization and the device_code grant; an issuer whose metadata names no
// device endpoint is refused here, naming it. Nothing here prints the token, the device code or the command's answer:
// the person reads the url, the user code, the consent code and errors, which carry statuses and codes, never a body.

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/urnetwork/sidecar"
)

// RFC 8628 §3.4's grant type.
const urcliDeviceCodeGrantType = "urn:ietf:params:oauth:grant-type:device_code"

// The OAuth error codes RFC 8628 §3.5 gives a poll.
const (
	urcliDeviceAuthorizationPending = "authorization_pending"
	urcliDeviceSlowDown             = "slow_down"
)

// Tunables of the device grant, beside urcliSettings' own.
type urcliDeviceSettings struct {
	// The wait between polls when the issuer's answer sets none, and the least ur waits whatever it sets: 5 s, RFC 8628
	// §3.2's default.
	PollInterval time.Duration
	// What slow_down adds to the wait, for that poll and every later one: 5 s, RFC 8628 §3.5's.
	SlowDownStep time.Duration
	// The longest a login waits for the person, whatever expires_in says: 15 min, a reading, a sign-in and a code to
	// compare on another device.
	GrantTimeout time.Duration
}

func defaultUrcliDeviceSettings() *urcliDeviceSettings {
	return &urcliDeviceSettings{
		PollInterval: 5 * time.Second,
		SlowDownStep: 5 * time.Second,
		GrantTimeout: 15 * time.Minute,
	}
}

// ur-cli's env with what the device grant adds. Tests replace newUrcliDeviceEnv.
type urcliDeviceEnv struct {
	*urcliEnv
	device *urcliDeviceSettings
	// waits timeout or until ctx ends; a test answers at once and records the wait
	wait func(ctx context.Context, timeout time.Duration) error
}

// The env this process uses: ur-cli's, from §18.9's host list.
var newUrcliDeviceEnv = func(cli *urCli) (*urcliDeviceEnv, error) {
	env, err := newUrcliEnv(cli)
	if err != nil {
		return nil, err
	}
	return &urcliDeviceEnv{
		urcliEnv: env,
		device:   defaultUrcliDeviceSettings(),
		wait: func(ctx context.Context, timeout time.Duration) error {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(timeout):
				return nil
			}
		},
	}, nil
}

// The issuer's metadata the device grant reads (RFC 8414, RFC 8628 §4).
type urcliDeviceMetadata struct {
	Issuer                      string `json:"issuer"`
	TokenEndpoint               string `json:"token_endpoint"`
	DeviceAuthorizationEndpoint string `json:"device_authorization_endpoint"`
}

// The device authorization answer (RFC 8628 §3.2).
type urcliDeviceAuthorization struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationUri         string `json:"verification_uri"`
	VerificationUriComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

// The issuer's device and token endpoints, each on the issuer's own origin, or why the device grant cannot run.
func (self *urcliDeviceEnv) discoverDevice(ctx context.Context) (*urcliDeviceMetadata, error) {
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
	metadata := &urcliDeviceMetadata{}
	if err := json.Unmarshal(body, metadata); err != nil {
		return nil, errors.New("ur-cli: the issuer's metadata does not parse")
	}
	if metadata.Issuer != self.issuer || !strings.HasPrefix(metadata.TokenEndpoint, self.issuer+"/") {
		return nil, errors.New("ur-cli: the issuer's metadata names another issuer")
	}
	if metadata.DeviceAuthorizationEndpoint == "" {
		return nil, errors.New("ur-cli: the issuer offers no device sign-in: run ur login on a host with a browser")
	}
	if !strings.HasPrefix(metadata.DeviceAuthorizationEndpoint, self.issuer+"/") {
		return nil, errors.New("ur-cli: the issuer's device endpoint is on another origin")
	}
	return metadata, nil
}

// Whether text is safe to show on the terminal: printable ASCII, so nothing the issuer wrote moves the cursor or hides
// the consent code.
func urcliDevicePrintable(text string) bool {
	if text == "" {
		return false
	}
	for i := 0; i < len(text); i += 1 {
		if c := text[i]; c < 0x21 || 0x7e < c {
			return false
		}
	}
	return true
}

// Gets an admin token for command by RFC 8628's device grant: the authorization with its consent code shown on the
// terminal, then polls with proofs by a DPoP key made here. The caller runs the command and erases the grant.
func urcliDeviceToken(ctx context.Context, env *urcliDeviceEnv, command *sidecar.AdminCommand) (*urcliAdminGrant, error) {
	metadata, err := env.discoverDevice(ctx)
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
	consentCode, err := sidecar.NewAdminConsentCode(env.random)
	if err != nil {
		return nil, err
	}
	details, err := sidecar.FormatAdminCommandDetails(command, consentCode)
	if err != nil {
		return nil, err
	}

	authorization, err := func() (*urcliDeviceAuthorization, error) {
		form := url.Values{}
		form.Set("client_id", urcliClientId)
		form.Set("scope", urcliScopeAuthKeys)
		form.Set("resource", env.apiOrigin)
		form.Set("dpop_jkt", dpopKey.Thumbprint)
		form.Set("authorization_details", details)
		requestCtx, cancel := context.WithTimeout(ctx, env.settings.RequestTimeout)
		defer cancel()
		request, err := http.NewRequestWithContext(requestCtx, http.MethodPost, metadata.DeviceAuthorizationEndpoint, strings.NewReader(form.Encode()))
		if err != nil {
			return nil, err
		}
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		response, err := env.httpClient.Do(request)
		if err != nil {
			return nil, err
		}
		body, err := env.readResponse(response)
		if err != nil {
			return nil, err
		}
		authorization := &urcliDeviceAuthorization{}
		if err := json.Unmarshal(body, authorization); err != nil || authorization.DeviceCode == "" {
			return nil, errors.New("ur-cli: the device authorization does not parse")
		}
		return authorization, nil
	}()
	if err != nil {
		return nil, err
	}
	verificationUrl, err := url.Parse(authorization.VerificationUri)
	if err != nil || verificationUrl.Scheme != "https" || verificationUrl.Host == "" ||
		!urcliDevicePrintable(authorization.VerificationUri) || !urcliDevicePrintable(authorization.UserCode) {
		return nil, errors.New("ur-cli: the device authorization names no https page or no code to show")
	}

	fmt.Fprintf(env.out, "On a device with a browser, open:\n\n  %s\n\nand enter the code:\n\n  %s\n\n", authorization.VerificationUri, authorization.UserCode)
	fmt.Fprintf(env.out, "Approve only if the page shows this code:\n\n  %s\n\n", consentCode)

	interval := env.device.PollInterval
	if answered := time.Duration(authorization.Interval) * time.Second; interval < answered {
		interval = answered
	}
	lifetime := env.device.GrantTimeout
	if answered := time.Duration(authorization.ExpiresIn) * time.Second; 0 < answered && answered < lifetime {
		lifetime = answered
	}
	deadline := env.now().Add(lifetime)
	for {
		if err := env.wait(ctx, interval); err != nil {
			return nil, err
		}
		if !env.now().Before(deadline) {
			return nil, errors.New("ur-cli: the sign-in was not approved in time")
		}
		tokenResponse, err := urcliDevicePoll(ctx, env, metadata, dpopKey, authorization.DeviceCode)
		var httpErr *urcliHttpError
		switch {
		case err == nil:
			grant.accessToken = tokenResponse.AccessToken
			grant.expireTime = env.now().Add(time.Duration(tokenResponse.ExpiresIn) * time.Second)
			ok = true
			return grant, nil
		case errors.As(err, &httpErr) && httpErr.Code == urcliDeviceAuthorizationPending:
		case errors.As(err, &httpErr) && httpErr.Code == urcliDeviceSlowDown:
			interval += env.device.SlowDownStep
		default:
			// access_denied, expired_token, or any refusal the person cannot wait out
			return nil, err
		}
	}
}

// One poll of the token endpoint with the device code (RFC 8628 §3.4), under a fresh proof whose ath is over the device
// code: the token, or the refusal with its OAuth code.
func urcliDevicePoll(ctx context.Context, env *urcliDeviceEnv, metadata *urcliDeviceMetadata, dpopKey *sidecar.AdminDpopKey,
	deviceCode string) (*urcliTokenResponse, error) {
	proof, err := dpopKey.Sign(http.MethodPost, metadata.TokenEndpoint, deviceCode)
	if err != nil {
		return nil, err
	}
	form := url.Values{}
	form.Set("grant_type", urcliDeviceCodeGrantType)
	form.Set("client_id", urcliClientId)
	form.Set("device_code", deviceCode)
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
	return tokenResponse, nil
}

// ur login --device's ur-cli: an auth key of at most 5 minutes for the daemon, minted under a token the device grant
// got, and drop, which erases the token and its DPoP key. --invite joins a Team's network, TEAM-M6-04's, and refuses
// until then, as PKCE's login does.
func urcliDeviceLogin(ctx context.Context, cli *urCli, invite string) (authKey string, drop func(), err error) {
	if invite != "" {
		return "", nil, errors.New("ur login --invite joins a Team, which is not built yet")
	}
	env, err := newUrcliDeviceEnv(cli)
	if err != nil {
		return "", nil, err
	}
	command, err := urcliLoginCommand()
	if err != nil {
		return "", nil, err
	}
	grant, err := urcliDeviceToken(ctx, env, command)
	if err != nil {
		return "", nil, err
	}
	drop = grant.erase
	body, err := urcliRunCommand(ctx, env.urcliEnv, grant)
	if err != nil {
		return "", drop, err
	}
	result := &urcliAuthKeyResult{}
	if err := json.Unmarshal(body, result); err != nil {
		return "", drop, errors.New("ur-cli: the auth key answer does not parse")
	}
	if result.Error != nil {
		// the model's refusal, which names a rule and never a key
		return "", drop, fmt.Errorf("ur-cli: the auth key was refused: %s", result.Error.Message)
	}
	if _, err := sidecar.ParseAuthKey(result.AuthKey, nil); err != nil {
		return "", drop, errors.New("ur-cli: the answer holds no auth key")
	}
	return result.AuthKey, drop, nil
}

func init() {
	urcliDeviceLoginEntry = urcliDeviceLogin
}
