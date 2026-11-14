//go:build !js && !ios && !android && !sdk_mobile_bind && !sidecar_http && !ios_extension

// The daemon's tls methods: their names, their params held to what each knows, an approval answered as its id, and a
// reply that carries a file's path and never its bytes.

package sidecar

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"
)

func daemonTlsMethod(t *testing.T, name string) *DaemonMethod {
	t.Helper()
	for _, method := range DaemonTlsMethods() {
		if method.Name == name {
			return method
		}
	}
	t.Fatalf("no method %s", name)
	return nil
}

func TestDaemonTlsMethodsAreNetworkMethods(t *testing.T) {
	names := []string{}
	for _, method := range DaemonTlsMethods() {
		names = append(names, method.Name)
		// each acts on one network, and none signs what only a person may: the gate asks the person
		if !method.Network || method.Confirm || method.Handler == nil {
			t.Errorf("%s: %+v", method.Name, method)
		}
	}
	if !slices.Equal(names, []string{"tls.publish", "tls.unpublish", "tls.status"}) {
		t.Errorf("methods %v", names)
	}
}

func TestDaemonTlsMethodsOnASidecarWithNoTlsComponent(t *testing.T) {
	sidecar := newTestSidecar(t)
	call := func(params string) *DaemonCall {
		return &DaemonCall{Params: json.RawMessage(params), Sidecar: sidecar}
	}
	if _, err := daemonTlsMethod(t, DaemonMethodTlsPublish).Handler(t.Context(), call(`{"host":"blog","target":"8080"}`)); !errors.Is(err, ErrTlsComponentAbsent) {
		t.Errorf("publish: %v", err)
	}
	if _, err := daemonTlsMethod(t, DaemonMethodTlsUnpublish).Handler(t.Context(), call(`{"host":"blog"}`)); !errors.Is(err, ErrTlsComponentAbsent) {
		t.Errorf("unpublish: %v", err)
	}
	reply, err := daemonTlsMethod(t, DaemonMethodTlsStatus).Handler(t.Context(), call(``))
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(reply)
	if err != nil || string(encoded) != `{"publishes":[],"certificates":[],"ct_watch_degraded":false}` {
		t.Errorf("status %s, %v", encoded, err)
	}
	// params a method does not know are refused, and the refusal names nothing they held
	for _, name := range []string{DaemonMethodTlsPublish, DaemonMethodTlsUnpublish, DaemonMethodTlsStatus} {
		_, err := daemonTlsMethod(t, name).Handler(t.Context(), call(`{"host":"blog","key":"a-secret-value"}`))
		if !errors.Is(err, errDaemonSocketParams) || strings.Contains(err.Error(), "a-secret-value") {
			t.Errorf("%s with an unknown param: %v", name, err)
		}
	}
}

func TestDaemonTlsPublishStatusCarriesAPathAndNoKey(t *testing.T) {
	expires := time.Date(2026, time.March, 5, 5, 6, 7, 0, time.UTC)
	status := newDaemonTlsPublishStatus(&TlsPublishResult{
		Name:                  "tls/5671/db",
		Url:                   "db.abcdefghij.sidecar.example:5671",
		ServerNames:           []string{"db.abcdefghij.sidecar.example"},
		GrantId:               []byte{0xab, 0xcd},
		Expires:               expires,
		Audience:              TlsPublishAudienceLink,
		AppMode:               TlsPublishAppModeRaw,
		Passthrough:           TlsPublishPassthrough,
		ClientCertificateFile: "/synthetic/link-5671-db.pem",
		Serving:               true,
	})
	encoded, err := json.Marshal(status)
	if err != nil {
		t.Fatal(err)
	}
	fields := map[string]any{}
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatal(err)
	}
	want := []string{"app_mode", "audience", "client_certificate_file", "expires_ms", "grant_id", "name", "passthrough", "server_names", "serving", "url"}
	got := []string{}
	for field := range fields {
		got = append(got, field)
	}
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Errorf("fields %v", got)
	}
	if fields["grant_id"] != "abcd" || fields["client_certificate_file"] != "/synthetic/link-5671-db.pem" || int64(fields["expires_ms"].(float64)) != expires.UnixMilli() {
		t.Errorf("status %s", encoded)
	}
	// a standing name has no expiry and no grant of its own
	standing, err := json.Marshal(newDaemonTlsPublishStatus(&TlsPublishResult{Name: "tls/443/blog"}))
	if err != nil || strings.Contains(string(standing), "expires_ms") || strings.Contains(string(standing), "grant_id") {
		t.Errorf("a standing publish %s, %v", standing, err)
	}
	if daemonTlsOrigin(&DaemonCall{Confirmed: true}) != SidecarActConfirmed || daemonTlsOrigin(&DaemonCall{}) != SidecarActUnconfirmed {
		t.Errorf("a call's origin")
	}
}
