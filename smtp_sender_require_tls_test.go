//go:build !sidecar_http && !ios_extension

// REQUIRETLS admission and the sender's §14.5 delivery status, through an in-memory edge and MX.
package sidecar_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A pre-TLS advertisement does not survive STARTTLS. Distinguish an authenticated MX missing the
// extension from one whose TLS authentication is too weak, and deliver when both checks pass.
func TestSmtpSenderRequireTlsExtensionAndAuthentication(t *testing.T) {
	for _, c := range []struct {
		authenticated bool
		advertised    bool
		wantStatus    string
	}{
		{authenticated: true, advertised: false, wantStatus: "5.7.30"},
		{authenticated: false, advertised: true, wantStatus: "5.7.10"},
		{authenticated: true, advertised: true},
	} {
		script := sidecartest.DefaultMxScript()
		script.PreTlsKeywords = append(script.PreTlsKeywords, "REQUIRETLS")
		if c.advertised {
			script.Keywords = append(script.Keywords, "REQUIRETLS")
		}
		world := newTestSenderWorld(t, &testSenderOptions{script: script})
		if c.authenticated {
			world.tls.publishPolicy(t, "requiretls1", testTlsPolicy)
		}
		message := world.message([]string{"bob@" + testTlsDomain}, nil, "A message requiring TLS.\r\n")
		message.Flags = sidecar.SmtpFlagRequireTls
		outcome := testDomainOutcome(t, world.send(message), testTlsDomain)
		dsns := world.mailbox.Dsns()
		if c.wantStatus == "" {
			if outcome.Outcome != sidecar.SmtpOutcomeSent || len(dsns) != 0 || len(world.mx.Transactions()) != 1 {
				t.Fatalf("advertised extension and authenticated MX: %+v, DSNs %d", outcome, len(dsns))
			}
			continue
		}
		if outcome.Outcome != sidecar.SmtpOutcomeTlsRefused || len(dsns) != 1 || !bytes.Contains(dsns[0].Dsn, []byte("Status: "+c.wantStatus+"\r\n")) {
			t.Fatalf("authenticated %v, advertised %v: %+v, DSNs %s", c.authenticated, c.advertised, outcome, testDsnText(dsns))
		}
		if c.authenticated && outcome.TlsLevel != sidecar.SmtpTlsLevelMtaSts {
			t.Errorf("TLS level %d for an authenticated MX", outcome.TlsLevel)
		}
		for _, event := range world.mx.Events() {
			if strings.HasPrefix(event.Command, "MAIL ") {
				t.Fatalf("authenticated %v, advertised %v: MAIL went before refusal", c.authenticated, c.advertised)
			}
		}
	}
}
