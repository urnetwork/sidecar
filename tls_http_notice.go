//go:build !sidecar_http && !ios_extension

// §13.7's interstitial ([R:ext-edge] §2.8): on a Community network's public endpoint, a browser's first top-level
// navigation meets a one-time notice that a URnetwork user, not URnetwork, publishes the site, before the site
// itself. Never on §13.9's system publish, never under another audience, which a visitor reaches only signed in or by
// a link, and never on a request that is no navigation, so webhooks and API calls reach the service unchanged.
//
// The notice's button posts to /.well-known/ur/notice, which takes the post only when it is same-origin, so no other
// page can accept it on a visitor's behalf, and keeps the acceptance in __Host-ur-notice for NoticeLifetime. The
// tier comes from GET /sidecar/limits, cached LimitsCacheTimeout; a tier that cannot be read counts as Community,
// so the notice shows.
//
// The page names no host, path or visitor, and nothing here logs (I-13). Safe for concurrent use.

package sidecar

import (
	"context"
	"html"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// The accept path, its form field, and QuotaLimits.Tier's value for Community (§20.5).
const (
	tlsNoticePath          = "/.well-known/ur/notice"
	tlsNoticeReturnField   = "to"
	tlsNoticeTierCommunity = "free"
)

// One endpoint's notice.
type tlsHttpNotice struct {
	front  *TlsFront
	limits func(ctx context.Context) (*QuotaLimits, error)

	stateLock sync.Mutex
	// the tier last read, and when; zero before any
	tier     string
	tierTime time.Time
}

// The notice, reading the tier through limits, nil reading as Community.
func newTlsHttpNotice(front *TlsFront, limits func(ctx context.Context) (*QuotaLimits, error)) *tlsHttpNotice {
	return &tlsHttpNotice{front: front, limits: limits}
}

// Whether r meets the notice: a navigation on a public endpoint of a Community network, not the system publish,
// whose visitor has not accepted it.
func (self *tlsHttpNotice) required(r *http.Request, grant *TlsPublishGrant, view *tlsHttpSessionView) bool {
	if self.front.target.SystemPublish || grant == nil || grant.Audience != protocol.AclAudience_ACL_AUDIENCE_PUBLIC ||
		!view.navigation || view.noticeAccepted {
		return false
	}
	return self.community(r.Context())
}

// Whether the network is on Community, reading the tier when the cached one is older than LimitsCacheTimeout.
func (self *tlsHttpNotice) community(ctx context.Context) bool {
	settings := self.front.settings
	now := self.front.clock.Now()
	tier, fresh := func() (string, bool) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.tier, !self.tierTime.IsZero() && now.Before(self.tierTime.Add(settings.LimitsCacheTimeout))
	}()
	if !fresh {
		tier = ""
		if self.limits != nil {
			readCtx, cancel := context.WithCancel(ctx)
			stop := self.front.clock.AfterFunc(settings.LimitsRequestTimeout, cancel)
			limits, err := self.limits(readCtx)
			stop()
			cancel()
			if err == nil && limits != nil {
				tier = limits.Tier
			}
		}
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.tier = tier
			self.tierTime = now
		}()
	}
	// a tier that could not be read shows the notice
	return tier == "" || tier == tlsNoticeTierCommunity
}

// The notice page, its button posting back to where the visitor was going.
func (self *tlsHttpNotice) serve(w http.ResponseWriter, r *http.Request) {
	returnPath := tlsEdgeLoginReturnPath(r, self.front.settings.ReturnPathMaxByteCount)
	header := w.Header()
	header.Set("Content-Type", "text/html; charset=utf-8")
	header.Set("Cache-Control", "no-store")
	header.Set("X-Content-Type-Options", "nosniff")
	header.Set("Referrer-Policy", "no-referrer")
	header.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'")
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodHead {
		return
	}
	page := strings.ReplaceAll(tlsNoticePage, "{{to}}", html.EscapeString(returnPath))
	w.Write([]byte(page))
}

// POST /.well-known/ur/notice: same-origin alone, the acceptance kept, and 303 to where the visitor was going.
func (self *tlsHttpNotice) accept(w http.ResponseWriter, r *http.Request, view *tlsHttpSessionView) {
	if r.Method != http.MethodPost {
		tlsHttpAnswer(w, http.StatusMethodNotAllowed)
		return
	}
	if !view.sameOrigin {
		tlsHttpAnswer(w, http.StatusForbidden)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, int64(self.front.settings.ReturnPathMaxByteCount))
	if err := r.ParseForm(); err != nil {
		tlsHttpAnswer(w, http.StatusBadRequest)
		return
	}
	returnPath := r.PostForm.Get(tlsNoticeReturnField)
	if returnPath == "" || !strings.HasPrefix(returnPath, "/") || strings.HasPrefix(returnPath, "//") ||
		strings.HasPrefix(returnPath, "/\\") || tlsHttpFrontPath(returnPath) {
		returnPath = "/"
	}
	http.SetCookie(w, &http.Cookie{
		Name:     tlsNoticeCookieName,
		Value:    "1",
		Path:     "/",
		MaxAge:   int(self.front.settings.NoticeLifetime / time.Second),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	header := w.Header()
	header.Set("Cache-Control", "no-store")
	header.Set("Location", returnPath)
	w.WriteHeader(http.StatusSeeOther)
}

// The notice's page. {{to}} is the escaped return path.
const tlsNoticePage = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Before you continue</title>
<style>
body { font-family: system-ui, sans-serif; max-width: 34rem; margin: 4rem auto; padding: 0 1rem; line-height: 1.5; }
button { font: inherit; padding: 0.5rem 1rem; }
</style>
</head>
<body>
<h1>Before you continue</h1>
<p>This site is published by a URnetwork user from their own device. URnetwork does not run it, review it or see
what it sends you.</p>
<p>Do not enter passwords or payment details unless you know and trust whoever published it.</p>
<form method="post" action="/.well-known/ur/notice">
<input type="hidden" name="to" value="{{to}}">
<button type="submit">Continue to the site</button>
</form>
</body>
</html>
`
