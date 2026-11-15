//go:build !js && !sidecar_http

package fault

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	stdnet "net"
	"net/netip"
	"net/smtp"
	"net/textproto"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/sidecartest"
)

// How long a loopback exchange inside a step may take before it fails: a guard, never the proof.
const fi11TestTimeout = 8 * time.Second

// A world of one backend, echoing what reaches it, which each step reaches or leaves alone.
type fi11World struct {
	backend *sidecartest.RecordingBackend
	conn    stdnet.Conn
}

// The first step: the backend, on the run's Net, its audience check not yet passed.
func fi11Setup(world *fi11World, mustReach bool) *Step {
	return &Step{Actor: "setup", Action: func(ctx context.Context, net *Net) error {
		settings := sidecartest.DefaultRecordingBackendSettings()
		settings.Name = "the fixture's private backend"
		settings.Serve = sidecartest.RecordingBackendEcho
		settings.MustReach = mustReach
		backend, err := sidecartest.NewRecordingBackend(net, settings)
		if err != nil {
			return err
		}
		world.backend = backend
		return nil
	}}
}

// A step that sends data to the backend and reads its echo, so it arrived within the step.
func fi11Send(world *fi11World, data string) *Step {
	return &Step{Actor: "client", Action: func(ctx context.Context, net *Net) error {
		if world.conn == nil {
			conn, err := stdnet.Dial("tcp", world.backend.Addr().String())
			if err != nil {
				return err
			}
			world.conn = conn
		}
		world.conn.SetDeadline(time.Now().Add(fi11TestTimeout))
		if _, err := world.conn.Write([]byte(data)); err != nil {
			return err
		}
		echoed := make([]byte, len(data))
		_, err := io.ReadFull(world.conn, echoed)
		return err
	}}
}

// A step where the world's audience check moves.
func fi11Audience(world *fi11World, audience sidecartest.RecordingBackendAudience, reason string) *Step {
	return &Step{Actor: "world", Action: func(ctx context.Context, net *Net) error {
		world.backend.SetAudience(audience, reason)
		return nil
	}}
}

// The last step: the client hangs up.
func fi11Close(world *fi11World) *Step {
	return &Step{Actor: "client", Action: func(ctx context.Context, net *Net) error {
		if world.conn != nil {
			world.conn.Close()
		}
		return nil
	}}
}

func fi11Run(t *testing.T, steps ...*Step) *Result {
	t.Helper()
	net := sidecartest.NewNet(t.Context(), nil)
	defer net.Close()
	return Run(t.Context(), &Schedule{Id: "FI-11 fixture", Steps: steps, Check: []Invariant{FI(11)}, Tiers: []Tier{TierT2}}, net)
}

// A byte before the audience check fails FI-11 at the step it arrived in, whatever it was.
func TestFi11FailsAByteBeforeTheAudienceCheck(t *testing.T) {
	world := &fi11World{}
	result := fi11Run(t, fi11Setup(world, false), fi11Send(world, "GET / HTTP/1.1\r\n"), fi11Close(world))
	if result.Err == nil || result.FailedStep != 1 || !strings.Contains(result.Err.Error(), "bytes before its audience check") ||
		!strings.Contains(result.Err.Error(), "the fixture's private backend") {
		t.Fatalf("%s", result)
	}
	if len(result.Violations) != 1 || result.Violations[0].Invariant != "FI-11" {
		t.Fatalf("violations: %v", result.Violations)
	}
}

// After the check passes bytes may arrive; after the revocation swaps in, one byte fails FI-11.
func TestFi11FailsAByteAfterARevocationSwap(t *testing.T) {
	world := &fi11World{}
	result := fi11Run(t,
		fi11Setup(world, false),
		fi11Audience(world, sidecartest.RecordingBackendAdmitted, "the listener's audience check passed"),
		fi11Send(world, "admitted"),
		fi11Audience(world, sidecartest.RecordingBackendRevoked, "a SidecarRevoke swapped the policy"),
		fi11Send(world, "x"),
		fi11Close(world),
	)
	if result.Err == nil || result.FailedStep != 4 || !strings.Contains(result.Err.Error(), "after its flow's revocation") ||
		!strings.Contains(result.Err.Error(), "a SidecarRevoke swapped the policy") {
		t.Fatalf("%s", result)
	}
}

// A positive twin that reaches its backend admitted passes; one that reaches nothing fails at the end, since the
// check would pass on a dead path.
func TestFi11PassesATwinThatReachesTheBackend(t *testing.T) {
	world := &fi11World{}
	result := fi11Run(t,
		fi11Setup(world, true),
		fi11Audience(world, sidecartest.RecordingBackendAdmitted, "the listener's audience check passed"),
		fi11Send(world, "the twin's request"),
		fi11Close(world),
	)
	if result.Err != nil {
		t.Fatalf("%s", result)
	}
	for _, arrival := range world.backend.Arrivals() {
		if arrival.Step != 2 {
			t.Errorf("an arrival stamped %+v, sent in step 2", arrival)
		}
	}

	dead := &fi11World{}
	result = fi11Run(t, fi11Setup(dead, true), fi11Audience(dead, sidecartest.RecordingBackendAdmitted, "admitted"), fi11Close(dead))
	if result.Err == nil || result.FailedStep != -1 || !strings.Contains(result.Err.Error(), "dead path") {
		t.Fatalf("a twin reaching nothing: %s", result)
	}
}

// An MX for the proof clause, behind Go's crypto/tls, with the client's trust in it.
func fi11Mx(t *testing.T, script *sidecartest.MxScript) (*sidecartest.ScriptedMx, *tls.Config) {
	t.Helper()
	mx, err := sidecartest.NewScriptedMx("mx.recipient.example", script, nil)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(mx.Certificate())
	return mx, &tls.Config{ServerName: "mx.recipient.example", RootCAs: roots, MinVersion: tls.VersionTLS12}
}

// Sends one message to mx over STARTTLS, as an honest sender's MX dialog would, in process; the MX's answer to the
// message is the returned error.
func fi11SendMail(mx *sidecartest.ScriptedMx, config *tls.Config, message []byte) error {
	client, server := sidecartest.NewMxPipe(
		stdnet.TCPAddrFromAddrPort(netip.MustParseAddrPort("192.0.2.10:40025")),
		stdnet.TCPAddrFromAddrPort(netip.MustParseAddrPort("198.51.100.25:25")),
	)
	done := make(chan struct{})
	go func() {
		defer close(done)
		mx.ServeMx(server)
	}()
	defer func() {
		client.Close()
		<-done
	}()
	smtpClient, err := smtp.NewClient(client, "mx.recipient.example")
	if err != nil {
		return err
	}
	if err := smtpClient.Hello("sender.example"); err != nil {
		return err
	}
	if err := smtpClient.StartTLS(config); err != nil {
		return err
	}
	if err := smtpClient.Mail("sender@sender.example"); err != nil {
		return err
	}
	if err := smtpClient.Rcpt("rcpt@recipient.example"); err != nil {
		return err
	}
	writer, err := smtpClient.Data()
	if err != nil {
		return err
	}
	if _, err := writer.Write(message); err != nil {
		return err
	}
	// the MX's answer to the message; QUIT's close after it answers nothing of the message
	answer := writer.Close()
	smtpClient.Quit()
	return answer
}

// The proof clause: a proof the edge accepted for a message the scripted MX refused fails FI-11; the same proof of a
// message the MX took passes.
func TestFi11FailsAProofTheMxRefused(t *testing.T) {
	message := []byte("Subject: a fixture\r\n\r\nthe body\r\n")
	envelope := &sidecartest.MxProvedEnvelope{
		Mx: "mx.recipient.example", Sender: "<sender@sender.example>", Recipients: []string{"<rcpt@recipient.example>"},
		MessageSha256: sha256.Sum256(message), BindsTheMessage: true,
	}
	run := func(script *sidecartest.MxScript) (*Result, error) {
		mx, config := fi11Mx(t, script)
		var sendErr error
		result := fi11Run(t,
			&Step{Actor: "sender", Action: func(ctx context.Context, net *Net) error {
				ledger := sidecartest.NewMxProofLedger(net)
				ledger.AddMx("mx.recipient.example", mx)
				sendErr = fi11SendMail(mx, config, message)
				// a forging edge's verifier accepts the proof whatever the MX answered
				ledger.Proved(envelope)
				return nil
			}},
		)
		return result, sendErr
	}

	refusing := sidecartest.DefaultMxScript()
	refusing.MessageReply = "554 5.7.1 the fixture refuses this message"
	result, sendErr := run(refusing)
	var protocolErr *textproto.Error
	if !errors.As(sendErr, &protocolErr) || protocolErr.Code != 554 {
		t.Fatalf("the MX took what its script refuses: %v", sendErr)
	}
	if result.Err == nil || result.FailedStep != 0 || !strings.Contains(result.Err.Error(), "the MX's own state machine did not accept") {
		t.Fatalf("a proof of a refused message: %s", result)
	}

	result, sendErr = run(sidecartest.DefaultMxScript())
	if sendErr != nil {
		t.Fatalf("an honest send: %v", sendErr)
	}
	if result.Err != nil {
		t.Fatalf("a proof of a taken message: %s", result)
	}
}
