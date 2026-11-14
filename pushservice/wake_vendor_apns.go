// APNs (§18.7, §19.4): one background wake per submission over HTTP/2, authenticated by a provider token,
// an ES256 JWT over the team's .p8 key, signed with the standard library alone and reused for
// TokenRefreshInterval, within the 20 to 60 minutes Apple allows. The endpoint and topic come from the host
// (the taskworker's vault fragment, OPS-M8-01), never from code: production's api.push.apple.com, or the
// sandbox for a development build's aps-environment.
//
//	POST <endpoint>/3/device/<token>
//	authorization: bearer <provider token>; apns-push-type: background; apns-priority: 5; apns-topic: <topic>
//	ApnsWakeBody's {"aps":{"content-available":1},"t":...,"v":...}
//
// A 200 is sent; a 410 is unregistered, the token no longer the app's; a 403 ExpiredProviderToken drops
// the cached token and is retried; a 429 or 5xx, or no answer, is retried; anything else is refused. Safe
// for concurrent use.

package pushservice

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/urnetwork/sidecar"
)

// APNs' reasons this vendor acts on.
const (
	apnsReasonExpiredProviderToken = "ExpiredProviderToken"
)

// What an APNs vendor is held to.
type ApnsVendorSettings struct {
	// The APNs origin, https and no path: the host's, from its vault fragment. Empty refuses.
	Endpoint string
	// The app's bundle id, sent as apns-topic. Empty refuses.
	Topic string
	// The longest one submission may take: 10 s.
	RequestTimeout time.Duration
	// How long one provider token is used before a new one is signed: 40 min, within Apple's 20 to 60.
	TokenRefreshInterval time.Duration
	// The bytes of an answer read, past which the rest is dropped: 4 KiB, an APNs reason's JSON.
	ResponseMaxByteCount int64
}

// The defaults, no endpoint or topic among them: a host sets both.
func DefaultApnsVendorSettings() *ApnsVendorSettings {
	return &ApnsVendorSettings{
		RequestTimeout:       10 * time.Second,
		TokenRefreshInterval: 40 * time.Minute,
		ResponseMaxByteCount: 4 * 1024,
	}
}

// What NewApnsVendor takes.
type ApnsVendorArgs struct {
	// The Apple developer team that owns the key, the token's iss.
	TeamId string
	// The key's id, the token's kid.
	KeyId string
	// The .p8 file: a PEM PKCS #8 P-256 private key.
	PrivateKeyPem []byte
	// Nil takes the defaults, which name no endpoint or topic and so refuse.
	Settings *ApnsVendorSettings
	// Nil takes an HTTP/2 transport of its own.
	Transport http.RoundTripper
	// Nil is real time.
	Clock sidecar.Clock
}

// One app's APNs submissions.
type ApnsVendor struct {
	teamId   string
	keyId    string
	key      *ecdsa.PrivateKey
	settings *ApnsVendorSettings
	endpoint *url.URL
	client   *http.Client
	clock    sidecar.Clock

	stateLock sync.Mutex
	// the provider token in use and when it was signed
	token       string
	tokenSigned time.Time
}

var _ WakeVendor = (*ApnsVendor)(nil)

// A vendor on args. Refuses an endpoint that is not an https origin, an empty topic, team or key id, and
// a key that is not P-256.
func NewApnsVendor(args *ApnsVendorArgs) (*ApnsVendor, error) {
	if args == nil {
		return nil, fmt.Errorf("%w: no args", ErrWakeVendorSettings)
	}
	settings := args.Settings
	if settings == nil {
		settings = DefaultApnsVendorSettings()
	}
	if settings.Topic == "" || args.TeamId == "" || args.KeyId == "" || settings.RequestTimeout <= 0 ||
		settings.TokenRefreshInterval <= 0 || settings.ResponseMaxByteCount <= 0 {
		return nil, fmt.Errorf("%w: apns needs a topic, a team, a key id and positive bounds", ErrWakeVendorSettings)
	}
	endpoint, err := wakeVendorOrigin(settings.Endpoint)
	if err != nil {
		return nil, err
	}
	key, err := parseApnsKey(args.PrivateKeyPem)
	if err != nil {
		return nil, err
	}
	transport := args.Transport
	if transport == nil {
		transport = &http.Transport{ForceAttemptHTTP2: true, TLSHandshakeTimeout: settings.RequestTimeout}
	}
	clock := args.Clock
	if clock == nil {
		clock = sidecar.RealClock{}
	}
	return &ApnsVendor{
		teamId:   args.TeamId,
		keyId:    args.KeyId,
		key:      key,
		settings: settings,
		endpoint: endpoint,
		client:   &http.Client{Transport: transport, Timeout: settings.RequestTimeout},
		clock:    clock,
	}, nil
}

// An origin: https, a host, no path, query, fragment or credentials.
func wakeVendorOrigin(text string) (*url.URL, error) {
	origin, err := url.Parse(text)
	if err != nil || origin.Scheme != "https" || origin.Host == "" || origin.User != nil || (origin.Path != "" && origin.Path != "/") ||
		origin.RawQuery != "" || origin.Fragment != "" {
		return nil, fmt.Errorf("%w: a vendor's endpoint is an https origin", ErrWakeVendorSettings)
	}
	origin.Path = ""
	return origin, nil
}

// The .p8's key: PKCS #8, P-256.
func parseApnsKey(keyPem []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(keyPem)
	if block == nil {
		return nil, fmt.Errorf("%w: the apns key is not PEM", ErrWakeVendorSettings)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: the apns key is not PKCS #8", ErrWakeVendorSettings)
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, fmt.Errorf("%w: the apns key is not P-256", ErrWakeVendorSettings)
	}
	testHookSecret("pushservice.apns_key", block.Bytes)
	return key, nil
}

// apns.
func (self *ApnsVendor) Platform() string {
	return WakePlatformApns
}

// The provider token to send: the one in use while it is younger than TokenRefreshInterval, else a new one.
func (self *ApnsVendor) providerToken() (string, error) {
	now := self.clock.Now()
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.token != "" && now.Sub(self.tokenSigned) < self.settings.TokenRefreshInterval {
		return self.token, nil
	}
	token, err := signApnsProviderToken(self.key, self.keyId, self.teamId, now)
	if err != nil {
		return "", err
	}
	self.token, self.tokenSigned = token, now
	return token, nil
}

// Drops the token in use, so the next submission signs a new one.
func (self *ApnsVendor) dropProviderToken() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.token = ""
}

// An ES256 JWT: {"alg":"ES256","kid":<key id>}.{"iss":<team>,"iat":<seconds>}, its signature r || s, each
// 32 bytes big-endian.
func signApnsProviderToken(key *ecdsa.PrivateKey, keyId string, teamId string, now time.Time) (string, error) {
	header, _ := json.Marshal(map[string]string{"alg": "ES256", "kid": keyId})
	claims, _ := json.Marshal(map[string]any{"iss": teamId, "iat": now.Unix()})
	signingInput := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(claims)
	digest := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		return "", err
	}
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	token := signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
	testHookSecret("pushservice.apns_provider_token", []byte(token))
	return token, nil
}

// See WakeVendor.
func (self *ApnsVendor) Send(ctx context.Context, token string, payload *WakePayload) *WakeVendorResult {
	providerToken, err := self.providerToken()
	if err != nil {
		return &WakeVendorResult{Outcome: WakeVendorRetry, Reason: "provider token"}
	}
	// the token one path segment, whatever printable bytes it holds
	target := *self.endpoint
	target.Path = "/3/device/" + token
	target.RawPath = "/3/device/" + url.PathEscape(token)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, target.String(), bytes.NewReader(ApnsWakeBody(payload)))
	if err != nil {
		return &WakeVendorResult{Outcome: WakeVendorRefused, Reason: "request"}
	}
	request.Header.Set("authorization", "bearer "+providerToken)
	request.Header.Set("apns-push-type", "background")
	request.Header.Set("apns-priority", "5")
	request.Header.Set("apns-topic", self.settings.Topic)
	request.Header.Set("content-type", "application/json")
	response, err := self.client.Do(request)
	if err != nil {
		// no answer: the error may carry the url, so nothing of it is kept
		return &WakeVendorResult{Outcome: WakeVendorRetry, Reason: "transport"}
	}
	defer response.Body.Close()
	answer, _ := io.ReadAll(io.LimitReader(response.Body, self.settings.ResponseMaxByteCount))
	result := &WakeVendorResult{Outcome: wakeVendorOutcomeOf(response.StatusCode), Status: response.StatusCode}
	reason := struct {
		Reason string `json:"reason"`
	}{}
	if json.Unmarshal(answer, &reason) == nil && wakeVendorReasonCode(reason.Reason) {
		result.Reason = reason.Reason
	}
	switch {
	case response.StatusCode == http.StatusGone:
		result.Outcome = WakeVendorUnregistered
	case response.StatusCode == http.StatusForbidden && result.Reason == apnsReasonExpiredProviderToken:
		self.dropProviderToken()
		result.Outcome = WakeVendorRetry
	}
	result.RetryAfter = wakeVendorRetryAfter(response.Header.Get("retry-after"))
	return result
}

// Whether a vendor's reason is a code: letters, digits and _, at most 64, so nothing else of an answer is
// kept or counted.
func wakeVendorReasonCode(reason string) bool {
	if reason == "" || 64 < len(reason) {
		return false
	}
	for _, r := range reason {
		if !('a' <= r && r <= 'z' || 'A' <= r && r <= 'Z' || '0' <= r && r <= '9' || r == '_') {
			return false
		}
	}
	return true
}

// A Retry-After of whole seconds, 0 for none or another form.
func wakeVendorRetryAfter(text string) time.Duration {
	seconds, err := strconv.ParseInt(text, 10, 64)
	if err != nil || seconds <= 0 {
		return 0
	}
	return time.Duration(seconds) * time.Second
}
