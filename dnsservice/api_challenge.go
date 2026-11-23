// POST /dns/internal/acme-challenge (§12.8, D-DNS-8, R-DNS-7; DNS-M5-13): certs, the only DNS-01
// writer, having already checked the caller's §8 grant, writes the TXT values at
// _acme-challenge.<name>, or takes them out with none, and is answered the serial they took. Only the
// certs bearer reaches it, and it is a write: the dns gate's writes: false refuses it.
//
// What a challenge may be, at most two values, at most 10 writes a name an hour, an hour's life, under a
// live label or alias, or at a verified custom domain's <acme_token>.acme.<root> (QD-175; DNS-M6-02), is
// the model's (DnsChallengeWriter), since it is a rule of §12.6's one write path. This route maps the answers: a restore's 503 with Retry-After, which certs retries; a name or
// values the writer refuses, 400; the hourly cap, 429, with a Retry-After when the writer says when the
// name takes a write again (DnsChallengeRateError), until which certs holds the name's orders (QD-1204);
// a removal of nothing, the serial zero. A block whose host gives no writer answers 503 to every
// challenge, so nothing is written around the path.

package dnsservice

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// The challenge route (plan-DNS-internal-route-credential's prefix over §12.8's /dns/acme-challenge).
const DnsAcmeChallengePath = DnsInternalPathPrefix + "acme-challenge"

var (
	// A name that is no live label or alias of the root, or values no challenge may hold: 400.
	ErrDnsChallengeRefused = errors.New("dns challenge refused")
	// The name's writes this hour reached dns_challenges_per_name_hour: 429.
	ErrDnsChallengeRate = errors.New("dns challenge rate reached")
)

// The hourly cap's refusal with how long until the name takes a write again, which the route's 429
// names in its Retry-After (QD-1204). It is ErrDnsChallengeRate, and the writer's own refusal.
type DnsChallengeRateError struct {
	// How long from the refusal until a write of the name is taken: until the write whose leaving brings
	// the name's count below the cap has left the window. Zero: the writer knows no such time, as with a
	// cap of zero, and the 429 names none.
	RetryAfter time.Duration
	// What the writer refused with, nil for none.
	Err error
}

func (self *DnsChallengeRateError) Error() string {
	if self.Err == nil {
		return ErrDnsChallengeRate.Error()
	}
	return ErrDnsChallengeRate.Error() + ": " + self.Err.Error()
}

func (self *DnsChallengeRateError) Unwrap() []error {
	if self.Err == nil {
		return []error{ErrDnsChallengeRate}
	}
	return []error{ErrDnsChallengeRate, self.Err}
}

// The model's half of the route: one write through §12.6's path that takes a serial, or a removal.
// Returns ErrDnsRestoring while restoring, ErrDnsChallengeRefused or ErrDnsChallengeRate for what the
// path refuses, the latter as a *DnsChallengeRateError when the writer knows when the name takes a
// write again, and ErrDnsWriteEmpty for a removal of a challenge already gone. Safe for concurrent use.
type DnsChallengeWriter interface {
	PutChallenge(ctx context.Context, root string, name string, values []string, ttl uint32) (serial uint64, err error)
}

// The body of POST acme-challenge.
type DnsChallengeRequest struct {
	// May be left out with one root.
	Root string `json:"root,omitempty"`
	// <label>.<root> or <alias>.<root>, with or without *.: a wildcard's challenge sits at its name. Or a
	// verified custom domain's <acme_token>.acme.<root>, where the TXT sits at the name itself, the target
	// of the domain's one-time _acme-challenge CNAME (QD-175).
	Name string `json:"name"`
	// At most two. None removes the challenge.
	Values []string `json:"values,omitempty"`
}

// The answer of POST acme-challenge: the serial the write took, zero for a removal of nothing.
type DnsChallengeAnswer struct {
	Serial uint64 `json:"serial"`
}

// The challenge route.
func (self *DnsApi) challengeRoutes() []*dnsApiRoute {
	return []*dnsApiRoute{
		{method: http.MethodPost, path: DnsAcmeChallengePath, class: DnsCallerCerts, write: true, serve: self.serveChallenge},
	}
}

// The labels of the challenge counter.
const (
	dnsChallengeResultWritten   = "written"
	dnsChallengeResultRefused   = "refused"
	dnsChallengeResultRate      = "rate"
	dnsChallengeResultRestoring = "restoring"
	dnsChallengeResultFailed    = "failed"
)

func (self *DnsApi) serveChallenge(writer http.ResponseWriter, request *http.Request) {
	unavailable := func() {
		retryAfter := int(math.Ceil(self.host.GatesOrClosed().RetryAfter().Seconds()))
		writer.Header().Set("Retry-After", strconv.Itoa(max(retryAfter, 1)))
		http.Error(writer, "service unavailable", http.StatusServiceUnavailable)
	}
	if self.deps.Challenges == nil {
		self.metrics.challenges.Add(1, dnsChallengeResultFailed)
		unavailable()
		return
	}
	body, err := io.ReadAll(io.LimitReader(request.Body, int64(self.settings.Api.ChallengeRequestMaxByteCount)+1))
	if err != nil || self.settings.Api.ChallengeRequestMaxByteCount < len(body) {
		http.Error(writer, "bad request", http.StatusBadRequest)
		return
	}
	challenge := &DnsChallengeRequest{}
	if err := json.Unmarshal(body, challenge); err != nil || challenge.Name == "" {
		http.Error(writer, "bad request", http.StatusBadRequest)
		return
	}
	root, ok := self.challengeRoot(challenge.Root)
	if !ok {
		self.metrics.challenges.Add(1, dnsChallengeResultRefused)
		http.Error(writer, "bad request", http.StatusBadRequest)
		return
	}
	serial, err := self.deps.Challenges.PutChallenge(request.Context(), root, challenge.Name, challenge.Values, self.settings.Ttl.Challenge)
	switch {
	case err == nil, errors.Is(err, ErrDnsWriteEmpty):
		self.metrics.challenges.Add(1, dnsChallengeResultWritten)
	case errors.Is(err, ErrDnsRestoring):
		self.metrics.challenges.Add(1, dnsChallengeResultRestoring)
		unavailable()
		return
	case errors.Is(err, ErrDnsChallengeRefused):
		self.metrics.challenges.Add(1, dnsChallengeResultRefused)
		http.Error(writer, "challenge refused", http.StatusBadRequest)
		return
	case errors.Is(err, ErrDnsChallengeRate):
		self.metrics.challenges.Add(1, dnsChallengeResultRate)
		// whole seconds, rounded up, so certs does not ask again before the name takes a write
		var rateErr *DnsChallengeRateError
		if errors.As(err, &rateErr) && 0 < rateErr.RetryAfter {
			retryAfter := int64(math.Ceil(rateErr.RetryAfter.Seconds()))
			writer.Header().Set("Retry-After", strconv.FormatInt(max(retryAfter, 1), 10))
		}
		http.Error(writer, "too many challenges", http.StatusTooManyRequests)
		return
	default:
		self.metrics.challenges.Add(1, dnsChallengeResultFailed)
		self.log.Errorf("[dns]challenge write failed: %v", err)
		unavailable()
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	answer, _ := json.Marshal(&DnsChallengeAnswer{Serial: serial})
	writer.Write(answer)
}

// The root a challenge names, as GET requests name theirs.
func (self *DnsApi) challengeRoot(text string) (string, bool) {
	if text == "" {
		if len(self.settings.Roots) == 1 {
			return self.settings.Roots[0], true
		}
		return "", false
	}
	text = strings.ToLower(text)
	if !strings.HasSuffix(text, ".") {
		text += "."
	}
	for _, root := range self.settings.Roots {
		if root == text {
			return root, true
		}
	}
	return "", false
}
