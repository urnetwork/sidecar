package sidecar

import (
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

// sdk/device_token_manager.go's schedule on synthetic tokens, computed by a copy of its functions over golang-jwt
// v5.3.1, sdk's parser: each token's draw, scheduled refresh and timeouts at a fixed now, with no previous attempt
// and with one a minute before. The Worker leg has no file system, so the table is embedded.
//
//go:embed testdata/token/sdk_schedule.json
var sdkScheduleJson []byte

type sdkScheduleRow struct {
	Name                string  `json:"name"`
	Token               string  `json:"token"`
	Draw                float64 `json:"draw"`
	RefreshUnixNano     int64   `json:"refresh_unix_nano"`
	TimeoutNoPrevious   int64   `json:"timeout_no_previous"`
	TimeoutAfterAttempt int64   `json:"timeout_after_attempt"`
}

// The now the table was computed at.
var sdkScheduleNow = time.Date(2026, time.March, 4, 5, 6, 7, 0, time.UTC)

// The schedule takes the same point, refresh time and timeouts as sdk's on every shared input, real tokens and the
// malformed ones whose parse falls back alike.
func TestRefreshScheduleMatchesSdk(t *testing.T) {
	rows := []sdkScheduleRow{}
	if err := json.Unmarshal(sdkScheduleJson, &rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) < 10 {
		t.Fatalf("%d rows", len(rows))
	}
	settings := DefaultSidecarSettings().TokenRefreshSettings
	for _, row := range rows {
		draw := sidecarJwtRefreshDraw(row.Token)
		if draw != row.Draw {
			t.Errorf("%s: draw %v, sdk %v", row.Name, draw, row.Draw)
		}
		refreshTime := sidecarJwtRefreshTime(row.Token, sdkScheduleNow, draw, settings)
		if refreshTime.UnixNano() != row.RefreshUnixNano {
			t.Errorf("%s: refresh %v, sdk %v", row.Name, refreshTime, time.Unix(0, row.RefreshUnixNano).UTC())
		}
		if timeout := sidecarJwtRefreshTimeout(refreshTime, time.Time{}, sdkScheduleNow, settings); int64(timeout) != row.TimeoutNoPrevious {
			t.Errorf("%s: timeout %v, sdk %v", row.Name, timeout, time.Duration(row.TimeoutNoPrevious))
		}
		if timeout := sidecarJwtRefreshTimeout(refreshTime, sdkScheduleNow.Add(-time.Minute), sdkScheduleNow, settings); int64(timeout) != row.TimeoutAfterAttempt {
			t.Errorf("%s: timeout after an attempt %v, sdk %v", row.Name, timeout, time.Duration(row.TimeoutAfterAttempt))
		}
	}
}

// A synthetic unsigned client token with the claims given.
func testClientJwt(claims string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","typ":"JWT"}`)) + "." +
		base64.RawURLEncoding.EncodeToString([]byte(claims)) + ".c3ludGhldGlj"
}

// A client token issued at iat that lives lifetime, with its own jti.
func testClientJwtAt(jti string, iat time.Time, lifetime time.Duration) string {
	return testClientJwt(fmt.Sprintf(`{"jti":%q,"iat":%d,"exp":%d,"client_id":"synthetic-client","device_id":"synthetic-device"}`,
		jti, iat.Unix(), iat.Add(lifetime).Unix()))
}

// A point is of the real lifetime, from iat, inside the 0.4 to 0.5 window, and one token's point never moves with
// the time it is read.
func TestRefreshPointIsOfTheRealLifetime(t *testing.T) {
	settings := DefaultSidecarSettings().TokenRefreshSettings
	iat := sdkScheduleNow
	byJwt := testClientJwtAt("synthetic-jti", iat, 7*24*time.Hour)
	draw := sidecarJwtRefreshDraw(byJwt)
	first := sidecarJwtRefreshTime(byJwt, iat, draw, settings)
	later := sidecarJwtRefreshTime(byJwt, iat.Add(48*time.Hour), draw, settings)
	if !first.Equal(later) {
		t.Fatalf("the point moved: %v, %v", first, later)
	}
	if first.Before(iat.Add(time.Duration(0.4*float64(7*24*time.Hour)))) || iat.Add(time.Duration(0.5*float64(7*24*time.Hour))).Before(first) {
		t.Fatalf("the point %v is outside the window", first)
	}
}

// The floor holds a refresh 5 min after the previous attempt, however early the point.
func TestRefreshFloorHoldsAfterAnAttempt(t *testing.T) {
	settings := DefaultSidecarSettings().TokenRefreshSettings
	now := sdkScheduleNow
	if timeout := sidecarJwtRefreshTimeout(now.Add(-time.Hour), now.Add(-time.Minute), now, settings); timeout != 4*time.Minute {
		t.Fatalf("timeout %v", timeout)
	}
	if timeout := sidecarJwtRefreshTimeout(now.Add(-time.Hour), time.Time{}, now, settings); timeout != 0 {
		t.Fatalf("a first attempt waits %v", timeout)
	}
}

// Only a token naming its client and device is scheduled, and the identity a refresh must keep is read from it.
func TestOnlyClientTokensRefresh(t *testing.T) {
	if !sidecarJwtCanRefresh(testClientJwtAt("j", sdkScheduleNow, time.Hour)) {
		t.Fatal("a client token is not refreshable")
	}
	for _, byJwt := range []string{"", "synthetic", testClientJwt(`{"client_id":"c"}`), testClientJwt(`{"device_id":"d"}`), testClientJwt(`{"client_id":1,"device_id":"d"}`)} {
		if sidecarJwtCanRefresh(byJwt) {
			t.Errorf("%q is refreshable", byJwt)
		}
	}
	identity, ok := sidecarJwtIdentityOf(testClientJwtAt("j", sdkScheduleNow, time.Hour))
	if !ok || identity.clientId != "synthetic-client" || identity.deviceId != "synthetic-device" {
		t.Fatalf("%+v", identity)
	}
}
