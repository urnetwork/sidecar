// FCM's HTTP v1 API (§18.7, §19.4): one data message per submission at Android's high priority, with an
// OAuth 2 access token the vendor mints for itself from the project's service account: an RS256 JWT over
// the account's key, signed with the standard library alone, exchanged at the account's token_uri and
// reused until AccessTokenRefreshMargin before it lapses. The service account, endpoint and project come
// from the host (the taskworker's vault fragment, OPS-M8-01), never from code.
//
//	POST <endpoint>/v1/projects/<project_id>/messages:send   authorization: Bearer <access token>
//	FcmWakeMessage's {"message":{"token":...,"data":{"t":...,"v":"..."},"android":{"priority":"high"}}}
//
// A 200 is sent; an answer whose FcmError says UNREGISTERED is unregistered, the token no longer the
// app's; a 401 drops the cached access token and is retried; a 429 or 5xx, or no answer, is retried;
// anything else, INVALID_ARGUMENT among them, is refused. Safe for concurrent use.

package pushservice

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/urnetwork/sidecar"
)

// FCM's identifiers: the scope an access token asks for and the type of an error's FCM detail, which a test of a
// fake vendor names too, and the JWT grant and the error code of a token gone.
const (
	FcmMessagingScope     = "https://www.googleapis.com/auth/firebase.messaging"
	FcmErrorDetailType    = "type.googleapis.com/google.firebase.fcm.v1.FcmError"
	fcmJwtBearerGrantType = "urn:ietf:params:oauth:grant-type:jwt-bearer"
	fcmErrorUnregistered  = "UNREGISTERED"
)

// What an FCM vendor is held to.
type FcmVendorSettings struct {
	// The FCM API's origin, https and no path: the host's, from its vault fragment. Empty refuses.
	Endpoint string
	// The longest one submission or token exchange may take: 10 s.
	RequestTimeout time.Duration
	// How long an access token lives as its JWT asks: 1 h, Google's most.
	AccessTokenLifetime time.Duration
	// How long before an access token lapses a new one is minted: 5 min.
	AccessTokenRefreshMargin time.Duration
	// The bytes of an answer read, past which the rest is dropped: 16 KiB, an error's JSON or a token's.
	ResponseMaxByteCount int64
}

// The defaults, no endpoint among them: a host sets it.
func DefaultFcmVendorSettings() *FcmVendorSettings {
	return &FcmVendorSettings{
		RequestTimeout:           10 * time.Second,
		AccessTokenLifetime:      1 * time.Hour,
		AccessTokenRefreshMargin: 5 * time.Minute,
		ResponseMaxByteCount:     16 * 1024,
	}
}

// A service account's JSON key, as Google issues it: the fields this vendor reads.
type FcmServiceAccount struct {
	ProjectId    string `json:"project_id"`
	PrivateKeyId string `json:"private_key_id"`
	// A PEM PKCS #8 RSA private key.
	PrivateKey  string `json:"private_key"`
	ClientEmail string `json:"client_email"`
	// Where the JWT is exchanged for an access token: an https url.
	TokenUri string `json:"token_uri"`
}

// The service account in a JSON key file's bytes.
func ParseFcmServiceAccount(keyJson []byte) (*FcmServiceAccount, error) {
	account := &FcmServiceAccount{}
	if err := json.Unmarshal(keyJson, account); err != nil {
		return nil, fmt.Errorf("%w: the service account is not JSON", ErrWakeVendorSettings)
	}
	return account, nil
}

// What NewFcmVendor takes.
type FcmVendorArgs struct {
	Account *FcmServiceAccount
	// Nil takes the defaults, which name no endpoint and so refuse.
	Settings *FcmVendorSettings
	// Nil takes a transport of its own.
	Transport http.RoundTripper
	// Nil is real time.
	Clock sidecar.Clock
}

// One project's FCM submissions.
type FcmVendor struct {
	account  *FcmServiceAccount
	key      *rsa.PrivateKey
	settings *FcmVendorSettings
	sendUrl  string
	tokenUrl string
	client   *http.Client
	clock    sidecar.Clock

	stateLock sync.Mutex
	// the access token in use and when it lapses
	accessToken   string
	accessExpires time.Time
}

var _ WakeVendor = (*FcmVendor)(nil)

// A vendor on args. Refuses an endpoint or token_uri that is not https, a project or account missing, and
// a key that is not RSA.
func NewFcmVendor(args *FcmVendorArgs) (*FcmVendor, error) {
	if args == nil || args.Account == nil {
		return nil, fmt.Errorf("%w: no service account", ErrWakeVendorSettings)
	}
	settings := args.Settings
	if settings == nil {
		settings = DefaultFcmVendorSettings()
	}
	account := args.Account
	if account.ProjectId == "" || account.ClientEmail == "" || settings.RequestTimeout <= 0 || settings.AccessTokenLifetime <= 0 ||
		settings.AccessTokenRefreshMargin < 0 || settings.AccessTokenLifetime <= settings.AccessTokenRefreshMargin ||
		settings.ResponseMaxByteCount <= 0 {
		return nil, fmt.Errorf("%w: fcm needs a project, an account and positive bounds", ErrWakeVendorSettings)
	}
	endpoint, err := wakeVendorOrigin(settings.Endpoint)
	if err != nil {
		return nil, err
	}
	tokenUrl, err := url.Parse(account.TokenUri)
	if err != nil || tokenUrl.Scheme != "https" || tokenUrl.Host == "" || tokenUrl.User != nil {
		return nil, fmt.Errorf("%w: the service account's token_uri is not https", ErrWakeVendorSettings)
	}
	block, _ := pem.Decode([]byte(account.PrivateKey))
	if block == nil {
		return nil, fmt.Errorf("%w: the service account's key is not PEM", ErrWakeVendorSettings)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: the service account's key is not PKCS #8", ErrWakeVendorSettings)
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%w: the service account's key is not RSA", ErrWakeVendorSettings)
	}
	testHookSecret("pushservice.fcm_key", block.Bytes)
	transport := args.Transport
	if transport == nil {
		transport = &http.Transport{ForceAttemptHTTP2: true, TLSHandshakeTimeout: settings.RequestTimeout}
	}
	clock := args.Clock
	if clock == nil {
		clock = sidecar.RealClock{}
	}
	return &FcmVendor{
		account:  account,
		key:      key,
		settings: settings,
		sendUrl:  endpoint.JoinPath("v1", "projects", account.ProjectId, "messages:send").String(),
		tokenUrl: tokenUrl.String(),
		client:   &http.Client{Transport: transport, Timeout: settings.RequestTimeout},
		clock:    clock,
	}, nil
}

// fcm.
func (self *FcmVendor) Platform() string {
	return WakePlatformFcm
}

// The access token to send: the one in use until AccessTokenRefreshMargin before it lapses, else a new one
// from token_uri.
func (self *FcmVendor) currentAccessToken(ctx context.Context) (string, error) {
	now := self.clock.Now()
	self.stateLock.Lock()
	if self.accessToken != "" && now.Before(self.accessExpires.Add(-self.settings.AccessTokenRefreshMargin)) {
		token := self.accessToken
		self.stateLock.Unlock()
		return token, nil
	}
	self.stateLock.Unlock()
	assertion, err := self.signAssertion(now)
	if err != nil {
		return "", err
	}
	form := url.Values{"grant_type": {fcmJwtBearerGrantType}, "assertion": {assertion}}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, self.tokenUrl, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	request.Header.Set("content-type", "application/x-www-form-urlencoded")
	response, err := self.client.Do(request)
	if err != nil {
		return "", fmt.Errorf("fcm token exchange: no answer")
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(response.Body, self.settings.ResponseMaxByteCount))
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("fcm token exchange: status %d", response.StatusCode)
	}
	answer := struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}{}
	if err := json.Unmarshal(body, &answer); err != nil || answer.AccessToken == "" || answer.ExpiresIn <= 0 {
		return "", fmt.Errorf("fcm token exchange: a malformed answer")
	}
	testHookSecret("pushservice.fcm_access_token", []byte(answer.AccessToken))
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.accessToken = answer.AccessToken
	self.accessExpires = now.Add(time.Duration(answer.ExpiresIn) * time.Second)
	return answer.AccessToken, nil
}

// Drops the access token in use, so the next submission mints a new one.
func (self *FcmVendor) dropAccessToken() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.accessToken = ""
}

// The JWT the token exchange takes: RS256, iss the account, scope FCM's, aud the token_uri, living
// AccessTokenLifetime.
func (self *FcmVendor) signAssertion(now time.Time) (string, error) {
	header := map[string]string{"alg": "RS256", "typ": "JWT"}
	if self.account.PrivateKeyId != "" {
		header["kid"] = self.account.PrivateKeyId
	}
	headerJson, _ := json.Marshal(header)
	claimsJson, _ := json.Marshal(map[string]any{
		"iss":   self.account.ClientEmail,
		"scope": FcmMessagingScope,
		"aud":   self.tokenUrl,
		"iat":   now.Unix(),
		"exp":   now.Add(self.settings.AccessTokenLifetime).Unix(),
	})
	signingInput := base64.RawURLEncoding.EncodeToString(headerJson) + "." + base64.RawURLEncoding.EncodeToString(claimsJson)
	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, self.key, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	assertion := signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
	testHookSecret("pushservice.fcm_assertion", []byte(assertion))
	return assertion, nil
}

// See WakeVendor.
func (self *FcmVendor) Send(ctx context.Context, token string, payload *WakePayload) *WakeVendorResult {
	accessToken, err := self.currentAccessToken(ctx)
	if err != nil {
		return &WakeVendorResult{Outcome: WakeVendorRetry, Reason: "access_token"}
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, self.sendUrl, bytes.NewReader(FcmWakeMessage(token, payload)))
	if err != nil {
		return &WakeVendorResult{Outcome: WakeVendorRefused, Reason: "request"}
	}
	request.Header.Set("authorization", "Bearer "+accessToken)
	request.Header.Set("content-type", "application/json")
	response, err := self.client.Do(request)
	if err != nil {
		return &WakeVendorResult{Outcome: WakeVendorRetry, Reason: "transport"}
	}
	defer response.Body.Close()
	answer, _ := io.ReadAll(io.LimitReader(response.Body, self.settings.ResponseMaxByteCount))
	result := &WakeVendorResult{Outcome: wakeVendorOutcomeOf(response.StatusCode), Status: response.StatusCode}
	fcmError := struct {
		Error struct {
			Status  string `json:"status"`
			Details []struct {
				Type      string `json:"@type"`
				ErrorCode string `json:"errorCode"`
			} `json:"details"`
		} `json:"error"`
	}{}
	if result.Outcome != WakeVendorSent && json.Unmarshal(answer, &fcmError) == nil {
		if wakeVendorReasonCode(fcmError.Error.Status) {
			result.Reason = fcmError.Error.Status
		}
		for _, detail := range fcmError.Error.Details {
			if detail.Type == FcmErrorDetailType && wakeVendorReasonCode(detail.ErrorCode) {
				result.Reason = detail.ErrorCode
			}
		}
	}
	switch {
	case result.Reason == fcmErrorUnregistered:
		result.Outcome = WakeVendorUnregistered
	case response.StatusCode == http.StatusUnauthorized:
		self.dropAccessToken()
		result.Outcome = WakeVendorRetry
	}
	result.RetryAfter = wakeVendorRetryAfter(response.Header.Get("retry-after"))
	return result
}
