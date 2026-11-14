// EVS1-M6-02's tests on the stand-in (evs_world_test.go, evs_plan_test.go): a push made for an agent carries its
// agent id and its subkey's signature in the sealed provenance, which a reader verifies against the certificate's
// identity key and not_after; a certificate past its life, or a signature over another push, alarms as tampering and
// reads unattributed; an agent with no subkey signer stays agent_asserted, a push for no agent unattributed; and a
// capture of every byte the writer sent evs holds no agent id.

package sidecar

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"io"
	"net/http"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// An agent's subkey and the certificate the world signer's identity key gives it, valid until notAfter.
type evsTestAgent struct {
	agentId Id
	subkey  ed25519.PrivateKey
	cert    []byte
}

func newEvsTestAgent(t *testing.T, signer *evsTestSigner, label string, notAfter time.Time) *evsTestAgent {
	t.Helper()
	agentId := evsTestId("agent " + label)
	subkey := ed25519.NewKeyFromSeed(evsTestBytes("subkey "+label, ed25519.SeedSize))
	body, err := proto.Marshal(&protocol.AgentCert{
		SidecarId: signer.sidecarId.Bytes(), AgentId: agentId.Bytes(), PublicKey: subkey.Public().(ed25519.PublicKey),
		NotAfterMs: notAfter.UnixMilli(),
	})
	if err != nil {
		t.Fatal(err)
	}
	cert, err := proto.Marshal(&bridge.Signed{
		Body: body, SignerId: signer.sidecarId.Bytes(), Type: uint32(bridge.SignedType_SIGNED_AGENT_CERT),
		Signature: ed25519.Sign(signer.privateKey, bridge.SignedBytes(AgentCertPurpose, bridge.SignedType_SIGNED_AGENT_CERT, body)),
	})
	if err != nil {
		t.Fatal(err)
	}
	return &evsTestAgent{agentId: agentId, subkey: subkey, cert: cert}
}

// Sidecar.SignProvenance's shape over this agent alone; tamper changes the message signed.
func (self *evsTestAgent) signer(tamper bool) EvsSignProvenanceFunction {
	return func(agentId Id, purpose string, message []byte) (*AgentProvenanceSignature, error) {
		if tamper {
			message = append(bytes.Clone(message), 0xff)
		}
		keyId := sha256.Sum256(self.subkey.Public().(ed25519.PublicKey))
		return &AgentProvenanceSignature{
			AgentId: agentId, KeyId: keyId[:], Cert: self.cert,
			Signature: ed25519.Sign(self.subkey, AgentProvenanceSignedBytes(purpose, message)),
		}, nil
	}
}

// Every request body the writer's client sends, kept as it passes to the stand-in.
type evsTestCapture struct {
	handler http.Handler

	stateLock sync.Mutex
	bodies    [][]byte
}

func (self *evsTestCapture) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	body, _ := io.ReadAll(request.Body)
	self.stateLock.Lock()
	self.bodies = append(self.bodies, append([]byte(request.URL.String()), body...))
	self.stateLock.Unlock()
	request.Body = io.NopCloser(bytes.NewReader(body))
	self.handler.ServeHTTP(writer, request)
}

func (self *evsTestCapture) holds(needle []byte) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for _, body := range self.bodies {
		if bytes.Contains(body, needle) {
			return true
		}
	}
	return false
}

// A push for an agent with a subkey signer: the reader verifies the signature under the certificate, and nothing the
// writer sent evs holds the agent's id; a push for no agent reads unattributed.
func TestEvsProvenanceSubkeySignatureVerifies(t *testing.T) {
	writer := newEvsTestWriter(t)
	capture := &evsTestCapture{handler: writer.server}
	writer.test.client.http.transport = wrapSidecarApiTransport(&evsTestTransport{handler: capture})
	agent := newEvsTestAgent(t, writer.world.signer, "one", writer.test.clock.Now().Add(24*time.Hour))
	writer.test.client.args.SignProvenance = agent.signer(false)
	writer.server.know("notes.md", "plain.md")
	ctx := context.Background()
	if _, err := writer.repo.WritePaths(ctx, &EvsWritePathsArgs{AgentId: &agent.agentId, Writes: []*EvsPathWrite{
		{Path: "notes.md", Content: bytes.NewReader([]byte("an agent's notes"))},
	}}); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.write(t, "plain.md", []byte("the sidecar's own")); err != nil {
		t.Fatal(err)
	}
	reader := writer.world.reader(t, evsTestId("provenance reader"))
	reader.client.args.Gkm = writer.gkm
	reader.client.args.Transport = &evsTestTransport{handler: writer.server}
	reader.client.http.transport = wrapSidecarApiTransport(reader.client.args.Transport)
	read, err := reader.client.Repo(writer.world.repoId).Provenance(ctx, &EvsReadArgs{Path: "notes.md"})
	if err != nil || read.State != EvsProvenanceVerified || read.AgentId == nil || *read.AgentId != agent.agentId || read.Refused {
		t.Fatalf("the agent's push: %+v %v", read, err)
	}
	plain, err := reader.client.Repo(writer.world.repoId).Provenance(ctx, &EvsReadArgs{Path: "plain.md"})
	if err != nil || plain.State != EvsProvenanceUnattributed || plain.AgentId != nil {
		t.Fatalf("the sidecar's own push: %+v %v", plain, err)
	}
	if capture.holds(agent.agentId.Bytes()) || capture.holds([]byte(agent.agentId.String())) {
		t.Fatal("an agent id reached evs")
	}
	if 0 < len(reader.eventsOf(SidecarEventEvsAlarm)) {
		t.Fatal("a verified push alarmed")
	}
}

// A certificate past its life when the push was signed, or a signature over other bytes, alarms as tampering and the
// push reads unattributed; with no subkey signer, or one whose subkey AgentRevoke ended, the agent is the writer's
// word, agent_asserted.
func TestEvsProvenanceBadSignatureAlarmsAndAbsentOneIsAsserted(t *testing.T) {
	cases := []struct {
		name     string
		notAfter time.Duration
		tamper   bool
		signer   bool
		revoked  bool
		state    EvsPushProvenanceState
		refused  bool
	}{
		{name: "expired", notAfter: -time.Hour, signer: true, state: EvsProvenanceUnattributed, refused: true},
		{name: "revoked at the writer", notAfter: time.Hour, revoked: true, state: EvsProvenanceAsserted},
		{name: "another push's signature", notAfter: time.Hour, tamper: true, signer: true, state: EvsProvenanceUnattributed, refused: true},
		{name: "no subkey signer", notAfter: time.Hour, state: EvsProvenanceAsserted},
	}
	for _, c := range cases {
		writer := newEvsTestWriter(t)
		agent := newEvsTestAgent(t, writer.world.signer, c.name, writer.test.clock.Now().Add(c.notAfter))
		if c.signer {
			writer.test.client.args.SignProvenance = agent.signer(c.tamper)
		}
		if c.revoked {
			// AgentRevoke ran: the daemon signs nothing more for the agent, which the push then names alone
			writer.test.client.args.SignProvenance = func(agentId Id, purpose string, message []byte) (*AgentProvenanceSignature, error) {
				return nil, ErrAgentSubkeyRevoked
			}
		}
		writer.server.know("a.md")
		ctx := context.Background()
		if _, err := writer.repo.WritePaths(ctx, &EvsWritePathsArgs{AgentId: &agent.agentId, Writes: []*EvsPathWrite{
			{Path: "a.md", Content: bytes.NewReader([]byte("a"))},
		}}); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		reader := writer.world.reader(t, evsTestId("reader "+c.name))
		reader.client.args.Gkm = writer.gkm
		reader.client.args.Transport = &evsTestTransport{handler: writer.server}
		reader.client.http.transport = wrapSidecarApiTransport(reader.client.args.Transport)
		read, err := reader.client.Repo(writer.world.repoId).Provenance(ctx, &EvsReadArgs{Path: "a.md"})
		if err != nil || read.State != c.state || read.Refused != c.refused {
			t.Errorf("%s: %+v %v", c.name, read, err)
			continue
		}
		alarms := len(reader.eventsOf(SidecarEventEvsAlarm))
		if c.refused != (alarms == 1) {
			t.Errorf("%s: %d alarms", c.name, alarms)
		}
		if c.state == EvsProvenanceAsserted && (read.AgentId == nil || *read.AgentId != agent.agentId) {
			t.Errorf("%s: the asserted agent %v", c.name, read.AgentId)
		}
	}
}

// The message binds the push: another push id, ref or time gives other bytes, and the commits' oids in order.
func TestEvsAgentProvenanceMessageBindsThePush(t *testing.T) {
	repoId, refId, pushId := evsTestId("repo"), evsTestId("ref"), evsTestId("push")
	commits := []EvsGitOid{evsGitObjectOid(evsGitCommitKind, []byte("tree x\n")), evsGitObjectOid(evsGitCommitKind, []byte("tree y\n"))}
	message := EvsAgentProvenanceMessage(repoId, refId, pushId, 1000, commits)
	for name, other := range map[string][]byte{
		"push":    EvsAgentProvenanceMessage(repoId, refId, evsTestId("other push"), 1000, commits),
		"ref":     EvsAgentProvenanceMessage(repoId, evsTestId("other ref"), pushId, 1000, commits),
		"time":    EvsAgentProvenanceMessage(repoId, refId, pushId, 1001, commits),
		"order":   EvsAgentProvenanceMessage(repoId, refId, pushId, 1000, []EvsGitOid{commits[1], commits[0]}),
		"commits": EvsAgentProvenanceMessage(repoId, refId, pushId, 1000, commits[:1]),
	} {
		if bytes.Equal(message, other) {
			t.Errorf("another %s signs the same bytes", name)
		}
	}
	if len(message) != 16*3+8+4+2*20 {
		t.Errorf("a message of %d bytes", len(message))
	}
	if !agentProvenancePurposeKnown(AgentProvenancePurposeEvsAgent) {
		t.Error("the push purpose is no provenance purpose")
	}
	// a subkey's purpose is never one the identity key signs a statement under (D-CORE-6)
	if purpose, _ := sidecarIdentitySignedPurpose(bridge.SignedType_SIGNED_EVS_PUSH); purpose == AgentProvenancePurposeEvsAgent {
		t.Error("the agent purpose is the statement's")
	}
}
