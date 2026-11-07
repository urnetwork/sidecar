//go:build sidecar_http

// Runs under legs_test.go's Worker harness, where net/http calls the stub fetch it installs. Plain
// go_js_wasm_exec runs under node, whose process global turns fetch off in net/http, so there these
// have nothing to observe and skip.

package sidecar

import (
	"errors"
	"net/http"
	"syscall/js"
	"testing"
)

// The harness's record of every fetch, emptied here so each test reads only its own.
func workerFetchCalls(t *testing.T) js.Value {
	t.Helper()
	calls := js.Global().Get("workerFetchCalls")
	if calls.IsUndefined() {
		t.Skip("no Worker harness: net/http does not call fetch under node")
	}
	calls.Set("length", 0)
	return calls
}

// The finding itself, at the layer it happens: with no url set, a route's request leaves nothing for
// fetch, where the raw transport below hands it the token.
func TestWorkerFetchGetsNoRequestWithAnEmptyServiceUrl(t *testing.T) {
	calls := workerFetchCalls(t)
	client := &http.Client{Transport: defaultSidecarApiTransport()}

	settings := DefaultSidecarSettings()
	for _, url := range []string{
		settings.ApiUrl + "/sidecar/bind",
		settings.AuthUrl + "/oauth/token",
		settings.EvsUrl + "/evs/v1/repos",
		"//page.example/sidecar/bind",
	} {
		if _, err := client.Do(newSyntheticRequest(t, url)); !errors.Is(err, errServiceUrl) {
			t.Errorf("%q: %v", url, err)
		}
	}
	if calls.Length() != 0 {
		t.Errorf("fetch saw %d requests, the first to %s", calls.Length(), calls.Index(0).Get("url"))
	}
}

// Why the refusal has to be here: net/http alone gives fetch the relative url with the token on it, so
// a pass of the test above means the transport refused and not that fetch went unused. If a later Go
// refuses this itself, this fails, and the transport can be looked at again.
func TestWorkerFetchTakesARelativeUrlFromNetHttp(t *testing.T) {
	calls := workerFetchCalls(t)
	client := &http.Client{Transport: http.DefaultTransport}

	client.Do(newSyntheticRequest(t, "/sidecar/bind"))
	if calls.Length() != 1 {
		t.Fatalf("fetch saw %d requests", calls.Length())
	}
	call := calls.Index(0)
	if url := call.Get("url").String(); url != "/sidecar/bind" {
		t.Errorf("url %q", url)
	}
	if authorization := call.Get("authorization").String(); authorization != "Bearer synthetic-token" {
		t.Errorf("authorization %q", authorization)
	}
}

// The transport is not simply closed: a service url that is set still goes out.
func TestWorkerFetchGetsAnAbsoluteUrl(t *testing.T) {
	calls := workerFetchCalls(t)
	client := &http.Client{Transport: defaultSidecarApiTransport()}

	// the harness's fetch rejects, so this fails after fetch has seen it
	client.Do(newSyntheticRequest(t, "https://api.example/sidecar/bind"))
	if calls.Length() != 1 {
		t.Fatalf("fetch saw %d requests", calls.Length())
	}
	if url := calls.Index(0).Get("url").String(); url != "https://api.example/sidecar/bind" {
		t.Errorf("url %q", url)
	}
}
