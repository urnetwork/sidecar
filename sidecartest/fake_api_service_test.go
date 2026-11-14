// FakeApi.ServeService: a service origin's requests reach the handler a test hands it through the api's own transport,
// api's origins stay api's, an origin no handler serves has no route, and a nil handler stops serving one.

package sidecartest

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

// The api's transport serves https://evs.<domain> through the handler ServeService gave it, and nothing else through
// it: another service's origin has no route until it is served, and none once its handler is taken back.
func TestFakeApiServesAServiceOriginThroughItsHandler(t *testing.T) {
	net := NewNet(t.Context(), nil)
	t.Cleanup(net.Close)
	api, err := net.Api()
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: api.Transport()}
	get := func(url string) (string, error) {
		t.Helper()
		response, err := client.Get(url)
		if err != nil {
			return "", err
		}
		defer response.Body.Close()
		body, err := io.ReadAll(response.Body)
		return string(body), err
	}
	if _, err := get(api.ServiceOrigin("evs") + "/evs/v1/x"); err == nil || !strings.Contains(err.Error(), "no route") {
		t.Fatalf("an origin no handler serves: %v", err)
	}
	api.ServeService("evs", http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		io.WriteString(writer, "evs saw "+request.URL.Path)
	}))
	if body, err := get(api.ServiceOrigin("evs") + "/evs/v1/x"); err != nil || body != "evs saw /evs/v1/x" {
		t.Fatalf("the served origin answered %q %v", body, err)
	}
	if _, err := get(api.ServiceOrigin("gkm") + "/gkm/groups"); err == nil {
		t.Fatal("another service's origin was served")
	}
	api.ServeService("evs", nil)
	if _, err := get(api.ServiceOrigin("evs") + "/evs/v1/x"); err == nil {
		t.Fatal("an origin was served after its handler was taken back")
	}
}
