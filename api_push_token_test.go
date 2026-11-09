package sidecar

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

// A token no test or log could hold by chance.
const testPushToken = "push-token-canary-7f3a9c"

// The route's body, with the jwt as bearer, and a 200 is a set.
func TestSetPushTokenPostsTheBody(t *testing.T) {
	for _, platform := range []string{PushTokenPlatformApns, PushTokenPlatformFcm} {
		transport := answerWith(http.StatusOK, `{}`)
		api := newTestSidecarApi(t, transport)
		if err := api.SetPushToken(t.Context(), platform, testPushToken); err != nil {
			t.Fatal(err)
		}
		request, body := transport.onlyRequest(t)
		if request.Method != http.MethodPost || request.URL.String() != validSidecarSettings().ApiUrl+"/sidecar/push-token" {
			t.Fatalf("%s %s", request.Method, request.URL)
		}
		if request.Header.Get("Authorization") != "Bearer "+testByJwt || request.Header.Get("DPoP") != "" {
			t.Fatalf("headers %v", request.Header)
		}
		args := &SidecarPushTokenArgs{}
		if err := json.Unmarshal(body, args); err != nil {
			t.Fatal(err)
		}
		if args.Platform != platform || args.Token != testPushToken {
			t.Fatalf("body %s", body)
		}
	}
}

// An empty token deletes, with or without a platform.
func TestSetPushTokenEmptyDeletes(t *testing.T) {
	for _, platform := range []string{"", PushTokenPlatformApns, PushTokenPlatformFcm} {
		transport := answerWith(http.StatusOK, `{}`)
		api := newTestSidecarApi(t, transport)
		if err := api.SetPushToken(t.Context(), platform, ""); err != nil {
			t.Fatal(err)
		}
		_, body := transport.onlyRequest(t)
		if string(body) != fmt.Sprintf(`{"platform":%q,"token":""}`, platform) {
			t.Fatalf("body %s", body)
		}
	}
}

// What the route would refuse is refused here, with nothing sent.
func TestSetPushTokenRefusesBeforeSending(t *testing.T) {
	for _, c := range []struct {
		platform string
		token    string
	}{
		{platform: "", token: testPushToken},
		{platform: "gcm", token: testPushToken},
		{platform: "APNS", token: testPushToken},
		{platform: "gcm", token: ""},
		{platform: PushTokenPlatformApns, token: "two\nlines"},
		{platform: PushTokenPlatformApns, token: "a space"},
		{platform: PushTokenPlatformApns, token: "café"},
		{platform: PushTokenPlatformFcm, token: strings.Repeat("a", PushTokenMaxByteCount+1)},
	} {
		transport := answerWith(http.StatusOK, `{}`)
		api := newTestSidecarApi(t, transport)
		if err := api.SetPushToken(t.Context(), c.platform, c.token); !errors.Is(err, ErrSidecarApiArgs) {
			t.Errorf("%q %q: %v", c.platform, c.token, err)
		}
		if transport.requestCount() != 0 {
			t.Errorf("%q: sent", c.platform)
		}
	}
	if !ValidPushToken(PushTokenPlatformFcm, strings.Repeat("a", PushTokenMaxByteCount)) {
		t.Error("a token of the longest length refused")
	}
}

// A refusal names the route and its code, and neither it nor the body's printed form holds the token
// (I-7, I-13).
func TestSetPushTokenErrorsHoldNoToken(t *testing.T) {
	for _, answer := range []*scriptedApiTransport{
		answerWith(http.StatusServiceUnavailable, ""),
		answerWith(http.StatusBadRequest, `{"error":"`+testPushToken+`","code":"push_token_invalid"}`),
		answerWith(http.StatusUnauthorized, testPushToken),
	} {
		api := newTestSidecarApi(t, answer)
		err := api.SetPushToken(t.Context(), PushTokenPlatformApns, testPushToken)
		apiErr := &SidecarApiError{}
		if !errors.As(err, &apiErr) || apiErr.Route != sidecarPushTokenRoute {
			t.Fatalf("%v", err)
		}
		if strings.Contains(err.Error(), testPushToken) || strings.Contains(fmt.Sprintf("%+v %#v", err, apiErr), testPushToken) {
			t.Fatalf("an error holds the token: %v", err)
		}
	}
	args := SidecarPushTokenArgs{Platform: PushTokenPlatformApns, Token: testPushToken}
	for _, printed := range []string{fmt.Sprint(args), fmt.Sprintf("%v %+v %#v %s", args, args, args, args), fmt.Sprint(&args)} {
		if strings.Contains(printed, testPushToken) {
			t.Fatalf("printed %s", printed)
		}
	}
	// and no token, no call
	api, err := newSidecarApi(validSidecarSettings(), answerWith(http.StatusOK, `{}`), testApiClock)
	if err != nil {
		t.Fatal(err)
	}
	if err := api.SetPushToken(t.Context(), PushTokenPlatformApns, testPushToken); !errors.Is(err, ErrSidecarApiNoToken) {
		t.Fatalf("%v", err)
	}
}
