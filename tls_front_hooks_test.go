//go:build sidecar_testhooks && !sidecar_http && !ios_extension

package sidecar

import (
	"net/http"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// The privacy harness sees every key the front makes or derives: the session root where it is made and read back,
// both cookie keys, and a TLS-ALPN-01 challenge's key; and the audience check and the target's open sit between
// their barriers on every path to the service.
func TestTlsFrontReachesTheHooks(t *testing.T) {
	recorder := recordHooks(t)
	memberId := NewId()
	fixture := newTlsFrontFixture(t, func(fixture *tlsFrontFixture) {
		fixture.policy.setGrant(protocol.AclAudience_ACL_AUDIENCE_MEMBERS, protocol.AclAppMode_ACL_APP_MODE_HTTP, nil)
		fixture.policy.members[memberId] = true
	})
	if _, err := newTlsSessionSealer(fixture.secrets, fixture.networkId); err != nil {
		t.Fatal(err)
	}
	if err := fixture.front.SetAlpnChallenge(tlsFrontTestServerName, "token.thumbprint", fixture.clock.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	request := tlsFrontTestNavigation(t, http.MethodGet, "/")
	request.AddCookie(&http.Cookie{Name: tlsSessionCookieName, Value: fixture.sealSession(t, memberId)})
	if response, _ := tlsFrontTestDo(t, fixture.httpClient(tlsAlpnHttp11), request); response.StatusCode != http.StatusOK {
		t.Fatalf("%d", response.StatusCode)
	}

	recorder.stateLock.Lock()
	defer recorder.stateLock.Unlock()
	for _, kind := range []string{"tls_front_session_root", "tls_front_session_key", "tls_front_pre_login_key", "tls_alpn_challenge_key"} {
		if !recorder.kinds[kind] {
			t.Errorf("no %s reached the hook", kind)
		}
	}
	root, err := fixture.secrets.Get(tlsFrontSessionRootRecordName)
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	for _, secret := range recorder.secrets {
		if string(secret) == string(root) {
			seen += 1
		}
	}
	if seen < 2 {
		t.Errorf("the root reached the hook %d times; made and read back is at least 2", seen)
	}
	for _, barrier := range []string{"tls.front_audience.before", "tls.front_audience.after", "tls.front_target.before", "tls.front_target.after"} {
		if !recorder.barriers[barrier] {
			t.Errorf("no %s", barrier)
		}
	}
}

// The privacy harness sees the reach receipts' visitor key where it is derived, and a members-device statement's
// check and its nonce's take sit between their barriers.
func TestTlsMembersDeviceReachesTheHooks(t *testing.T) {
	recorder := recordHooks(t)
	memberId := NewId()
	writer := newTlsReachTestWriter(t)
	fixture, issuer := newTlsEdgeLoginFixture(t, memberId, func(fixture *tlsFrontFixture) {
		fixture.policy.setGrant(protocol.AclAudience_ACL_AUDIENCE_MEMBERS_DEVICE, protocol.AclAppMode_ACL_APP_MODE_HTTP, nil)
		fixture.record = writer
	})
	device := newTlsMembersDeviceTestDevice(t, fixture.policy, memberId, true)
	client := fixture.httpClient(tlsAlpnHttp11)
	_, pending := tlsMembersDeviceTestLogin(t, fixture, issuer, client, memberId, "/")
	_, challenge := tlsMembersDeviceTestChallenge(t, client, pending)
	statement := device.statement(t, challenge.Origin, tlsMembersDeviceTestNonce(t, challenge))
	if response := tlsMembersDeviceTestPost(t, client, pending, statement, tlsFetchSiteSameOrigin); response.StatusCode != http.StatusSeeOther {
		t.Fatalf("%d", response.StatusCode)
	}

	recorder.stateLock.Lock()
	defer recorder.stateLock.Unlock()
	if !recorder.kinds["tls_front_reach_key"] {
		t.Error("no tls_front_reach_key reached the hook")
	}
	for _, barrier := range []string{"tls.front_device.before", "tls.front_device.after"} {
		if !recorder.barriers[barrier] {
			t.Errorf("no %s", barrier)
		}
	}
}

// The nonce's take is the device step's linearization point: two posts of one statement, held together inside the
// check until both have arrived, both verify, and exactly one completes the login.
func TestTlsMembersDeviceRaceCompletesOnce(t *testing.T) {
	memberId := NewId()
	fixture, issuer := newTlsEdgeLoginFixture(t, memberId, func(fixture *tlsFrontFixture) {
		fixture.policy.setGrant(protocol.AclAudience_ACL_AUDIENCE_MEMBERS_DEVICE, protocol.AclAppMode_ACL_APP_MODE_HTTP, nil)
	})
	device := newTlsMembersDeviceTestDevice(t, fixture.policy, memberId, true)
	client := fixture.httpClient(tlsAlpnHttp11)
	_, pending := tlsMembersDeviceTestLogin(t, fixture, issuer, client, memberId, "/")
	_, challenge := tlsMembersDeviceTestChallenge(t, client, pending)
	statement := device.statement(t, challenge.Origin, tlsMembersDeviceTestNonce(t, challenge))

	arrived := make(chan struct{}, 2)
	release := make(chan struct{})
	SetTestHooks(&TestHooks{Barrier: func(name string, key string) {
		if name != "tls.front_device.before" {
			return
		}
		arrived <- struct{}{}
		select {
		case <-release:
		case <-time.After(tlsFrontTestGuard):
		}
	}})
	t.Cleanup(func() { SetTestHooks(nil) })
	codes := make(chan int, 2)
	for range 2 {
		request := tlsMembersDeviceTestPostRequest(t, pending, statement)
		postClient := fixture.httpClient(tlsAlpnHttp11)
		go func() {
			response, err := postClient.Do(request)
			if err != nil {
				codes <- 0
				return
			}
			response.Body.Close()
			codes <- response.StatusCode
		}()
	}
	for range 2 {
		select {
		case <-arrived:
		case <-time.After(tlsFrontTestGuard):
			t.Fatal("the posts never met at the barrier")
		}
	}
	close(release)
	completed, refused := 0, 0
	for range 2 {
		switch <-codes {
		case http.StatusSeeOther:
			completed += 1
		case http.StatusForbidden:
			refused += 1
		}
	}
	if completed != 1 || refused != 1 {
		t.Errorf("%d completed, %d refused", completed, refused)
	}
}
