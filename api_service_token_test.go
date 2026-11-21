package sidecar

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"testing"
)

// A token a service refused goes at once (§11.20's 401 UNAUTHENTICATED, QD-927): ForgetServiceToken drops the one kept
// for its audience and scope set, in any order, so the next ask exchanges again, and leaves every other audience's and
// scope set's token kept.
func TestForgetServiceTokenExchangesAgain(t *testing.T) {
	settings := validSidecarSettings()
	settings.Clock = newTokenTestClock()
	sidecar := newSidecarBase(nil, settings)
	exchangeCount := 0
	reduceGrant := false
	transport := &scriptedApiTransport{
		answer: func(request *http.Request, body []byte) (*http.Response, error) {
			exchangeCount += 1
			token := fmt.Sprintf("synthetic-service-token-%d", exchangeCount)
			form, err := url.ParseQuery(string(body))
			if err != nil {
				return nil, err
			}
			granted := form.Get("scope")
			if reduceGrant {
				granted = "repo:b:rw"
			}
			return syntheticResponse(request, 200, fmt.Sprintf(`{"access_token":%q,"expires_in":900,"scope":%q}`, token, granted), nil), nil
		},
	}
	api, err := newSidecarApi(settings, transport, testApiClock)
	if err != nil {
		t.Fatal(err)
	}
	api.SetByJwt(testByJwt)
	installTestDpopSigner(t, api)
	sidecar.sidecarApi = api
	sidecar.applyTransition(sidecarTransition{to: SidecarStateUnenrolled})
	sidecar.applyTransition(sidecarTransition{to: SidecarStateOffline, generation: 1})
	ctx := context.Background()

	refused, err := sidecar.ServiceToken(ctx, "https://evs.example", []string{"repo:a:rw"})
	if err != nil {
		t.Fatal(err)
	}
	other, err := sidecar.ServiceToken(ctx, "https://evs.example", []string{"repo:b:rw", "repo:c:r"})
	if err != nil {
		t.Fatal(err)
	}
	gkm, err := sidecar.ServiceToken(ctx, "https://gkm.example", []string{"repo:a:rw"})
	if err != nil || exchangeCount != 3 {
		t.Fatalf("three exchanges: %d, %v", exchangeCount, err)
	}
	// forgetting a set no token is kept for, or forgetting twice, changes nothing
	sidecar.ForgetServiceToken("https://evs.example", []string{"repo:d:r"})
	sidecar.ForgetServiceToken("https://evs.example", []string{"repo:a:rw"})
	sidecar.ForgetServiceToken("https://evs.example", []string{"repo:a:rw"})
	renewed, err := sidecar.ServiceToken(ctx, "https://evs.example", []string{"repo:a:rw"})
	if err != nil || renewed == refused || exchangeCount != 4 {
		t.Fatalf("the refused token came back: %t, %d exchanges, %v", renewed == refused, exchangeCount, err)
	}
	if again, _ := sidecar.ServiceToken(ctx, "https://evs.example", []string{"repo:a:rw"}); again != renewed || exchangeCount != 4 {
		t.Errorf("the new token is not kept: %d exchanges", exchangeCount)
	}
	if kept, _ := sidecar.ServiceToken(ctx, "https://evs.example", []string{"repo:c:r", "repo:b:rw"}); kept != other || exchangeCount != 4 {
		t.Errorf("another scope set's token went: %d exchanges", exchangeCount)
	}
	if kept, _ := sidecar.ServiceToken(ctx, "https://gkm.example", []string{"repo:a:rw"}); kept != gkm || exchangeCount != 4 {
		t.Errorf("another audience's token went: %d exchanges", exchangeCount)
	}
	// the scope set's order names one key
	sidecar.ForgetServiceToken("https://evs.example", []string{"repo:c:r", "repo:b:rw"})
	if renewedOther, _ := sidecar.ServiceToken(ctx, "https://evs.example", []string{"repo:b:rw", "repo:c:r"}); renewedOther == other || exchangeCount != 5 {
		t.Errorf("a set forgotten in another order was kept: %d exchanges", exchangeCount)
	}
	// A reduced grant may serve its allowed repo now. It must not mask an
	// immediately subsequent grant of the second repo during the cache lifetime.
	reduceGrant = true
	batch := []string{"repo:b:rw", "repo:new:r"}
	partial, err := sidecar.ServiceToken(ctx, "https://gkm.example", batch)
	if err != nil {
		t.Fatal(err)
	}
	reduceGrant = false
	full, err := sidecar.ServiceToken(ctx, "https://gkm.example", batch)
	if err != nil || full == partial || exchangeCount != 7 {
		t.Fatalf("a reduced token masked the new grant: %d exchanges, %v", exchangeCount, err)
	}
}
