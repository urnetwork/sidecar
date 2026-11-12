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
