// The refresh schedule of D-CORE-8's refresher, ported from sdk/device_token_manager.go, which this module cannot
// import (§4.6): a token refreshes at a point of its own lifetime, from iat to exp, drawn in the window between
// RefreshWindowStart and RefreshWindowEnd by a hash of its jti, so every process that loads a token takes the same
// point and clients that refreshed together spread out; never sooner than MinRefreshTimeout after the previous
// attempt; and a failed attempt retries after a uniform wait below RefreshRetryTimeout. The lifetime is the server's
// to change (7 days for strict_exp tokens, D-TEAM-14), so the schedule reads each token and hardcodes none.
//
// This file is in both legs, so it parses a token's claims by hand, base64url and encoding/json, rather than linking a
// JWT module, and reads them exactly as sdk's unverified parse does, so the two take the same point for one token
// (TestRefreshScheduleMatchesSdk). Nothing here verifies a token: /auth/refresh does that. Package-level functions are
// pure and safe for concurrent use.

package sidecar

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"math"
	"strings"
	"time"
)

// The algorithms the JWT module sdk uses registers (golang-jwt v5), whose unverified parse fails a token naming any
// other, so a draw falls back to the token's whole text alike in both.
var sidecarJwtSigningAlgs = map[string]bool{
	"none": true, "HS256": true, "HS384": true, "HS512": true, "RS256": true, "RS384": true, "RS512": true,
	"ES256": true, "ES384": true, "ES512": true, "PS256": true, "PS384": true, "PS512": true, "EdDSA": true,
}

// A token's claims as an unverified parse reads them: ok only for three dot-separated parts whose header names a
// registered algorithm and whose header and claims are JSON objects.
type sidecarJwtParse struct {
	ok        bool
	claims    map[string]any
	signature string
}

// The unverified parse of byJwt. Never fails loudly: a token that does not parse answers ok false.
func parseSidecarJwt(byJwt string) sidecarJwtParse {
	parts := strings.Split(byJwt, ".")
	if len(parts) != 3 {
		return sidecarJwtParse{}
	}
	// golang-jwt v5.3.1 decodes each segment, the signature's included, as unpadded base64url, refusing a padded
	// one, and its header and claims with json.Unmarshal, which refuses anything after the value and takes null
	// claims as none
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return sidecarJwtParse{}
	}
	header := map[string]any{}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return sidecarJwtParse{}
	}
	alg, ok := header["alg"].(string)
	if !ok || !sidecarJwtSigningAlgs[alg] {
		return sidecarJwtParse{}
	}
	claimBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return sidecarJwtParse{}
	}
	claims := map[string]any{}
	if err := json.Unmarshal(claimBytes, &claims); err != nil {
		return sidecarJwtParse{}
	}
	if _, err := base64.RawURLEncoding.DecodeString(parts[2]); err != nil {
		return sidecarJwtParse{}
	}
	return sidecarJwtParse{ok: true, claims: claims, signature: parts[2]}
}

// A string claim, or "" when it is missing or not a string.
func (self sidecarJwtParse) stringClaim(name string) string {
	value, _ := self.claims[name].(string)
	return value
}

// A NumericDate claim as golang-jwt reads it, whole seconds, or the zero time when it is missing, zero or not a
// number.
func (self sidecarJwtParse) timeClaim(name string) time.Time {
	value, ok := self.claims[name].(float64)
	if !ok || value == 0 || math.IsNaN(value) || math.IsInf(value, 0) {
		return time.Time{}
	}
	seconds, fraction := math.Modf(value)
	at := time.Unix(int64(seconds), int64(fraction*1e9))
	return at.Truncate(time.Second)
}

// Whether byJwt is a client token the schedule refreshes: one naming its client and device. Only a local scheduling
// predicate, as sdk's jwtCanRefresh is.
func sidecarJwtCanRefresh(byJwt string) bool {
	parse := parseSidecarJwt(byJwt)
	return parse.ok && parse.stringClaim("client_id") != "" && parse.stringClaim("device_id") != ""
}

// The network, client and device a token names, which neither a refresh nor POST /sidecar/bind's re-mint may change
// (QD-797).
type sidecarJwtIdentity struct {
	networkId string
	clientId  string
	deviceId  string
}

// The identity byJwt names, false when it names no network, client or device.
func sidecarJwtIdentityOf(byJwt string) (sidecarJwtIdentity, bool) {
	parse := parseSidecarJwt(byJwt)
	identity := sidecarJwtIdentity{
		networkId: parse.stringClaim("network_id"),
		clientId:  parse.stringClaim("client_id"),
		deviceId:  parse.stringClaim("device_id"),
	}
	return identity, parse.ok && identity.networkId != "" && identity.clientId != "" && identity.deviceId != ""
}

// The sidecar byJwt's sidecar_id claim names (plan-SOCK-client-auth, QD-040), which only POST /sidecar/bind's re-mint
// sets and a refresh keeps: false for a token without one, or with one that is not a nonzero id. Read unverified, as
// every claim here is.
func sidecarJwtSidecarId(byJwt string) (Id, bool) {
	parse := parseSidecarJwt(byJwt)
	if !parse.ok {
		return Id{}, false
	}
	sidecarId, err := ParseId(parse.stringClaim("sidecar_id"))
	if err != nil || sidecarId == (Id{}) {
		return Id{}, false
	}
	return sidecarId, true
}

// The token's exp, or the zero time when it has none readable.
func sidecarJwtExpiration(byJwt string) time.Time {
	parse := parseSidecarJwt(byJwt)
	if !parse.ok {
		return time.Time{}
	}
	return parse.timeClaim("exp")
}

// The token's iat, or the zero time when it has none readable.
func sidecarJwtIssuedAt(byJwt string) time.Time {
	parse := parseSidecarJwt(byJwt)
	if !parse.ok {
		return time.Time{}
	}
	return parse.timeClaim("iat")
}

// The point of a token in its window, in [0, 1): a hash of its jti, else of its signature, else of its whole text, as
// a fraction, the top 53 bits of the SHA-256 being a float64 fraction's precision.
func sidecarJwtRefreshDraw(byJwt string) float64 {
	seed := "token:" + byJwt
	if parse := parseSidecarJwt(byJwt); parse.ok {
		if id := parse.stringClaim("jti"); id != "" {
			seed = "jti:" + id
		} else if parse.signature != "" {
			seed = "signature:" + parse.signature
		}
	}
	sum := sha256.Sum256([]byte(seed))
	return float64(binary.BigEndian.Uint64(sum[:8])>>11) / float64(uint64(1)<<53)
}

// The fraction of a token's lifetime a draw selects: draw 0 is the window's start and 1 its end, a draw outside [0,
// 1] clamped, so no point falls past the window's end.
func (self *SidecarTokenRefreshSettings) refreshFraction(draw float64) float64 {
	start := max(self.RefreshWindowStart, 0)
	end := max(self.RefreshWindowEnd, start)
	if !(0 <= draw) {
		draw = 0
	} else if 1 < draw {
		draw = 1
	}
	return min(start+(end-start)*draw, end)
}

// When byJwt's scheduled refresh falls for a draw: at its point of its real lifetime, from iat, never of what remains,
// which would collapse toward the floor on every pass; a token without a sensible iat counts its lifetime from now,
// and one without a readable exp refreshes NoExpirationRefreshTimeout from now. Pure and total.
func sidecarJwtRefreshTime(byJwt string, now time.Time, draw float64, settings *SidecarTokenRefreshSettings) time.Time {
	expirationTime := sidecarJwtExpiration(byJwt)
	if expirationTime.IsZero() {
		return now.Add(settings.NoExpirationRefreshTimeout)
	}
	lifetimeStart := sidecarJwtIssuedAt(byJwt)
	if lifetimeStart.IsZero() || !lifetimeStart.Before(expirationTime) {
		lifetimeStart = now
	}
	lifetime := float64(expirationTime.Sub(lifetimeStart))
	return lifetimeStart.Add(time.Duration(settings.refreshFraction(draw) * lifetime))
}

// How long from now until refreshTime, held to MinRefreshTimeout after the previous attempt (the 5 min floor), so no
// server-set lifetime, skewed clock or malformed exp makes a hot loop. Zero when it is due.
func sidecarJwtRefreshTimeout(refreshTime time.Time, previousAttemptTime time.Time, now time.Time, settings *SidecarTokenRefreshSettings) time.Duration {
	if !previousAttemptTime.IsZero() {
		if earliest := previousAttemptTime.Add(settings.MinRefreshTimeout); refreshTime.Before(earliest) {
			refreshTime = earliest
		}
	}
	return max(refreshTime.Sub(now), 0)
}
