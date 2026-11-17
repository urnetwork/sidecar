package sidecar

import (
	"context"
	"fmt"
	"net/http"
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
	transport := &scriptedApiTransport{
		answer: func(request *http.Request, body []byte) (*http.Response, error) {
			exchangeCount += 1
			token := fmt.Sprintf("synthetic-service-token-%d", exchangeCount)
			return syntheticResponse(request, 200, `{"access_token":"`+token+`","expires_in":900,"scope":"repo:x:r"}`, nil), nil
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
}
