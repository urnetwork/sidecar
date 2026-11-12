//go:build !ios_extension

// Agent-subkey provenance in a push's sealed metadata (§11.6's Records, §5.5; D-EVS-5; QD-159, QD-232; EVS1-M6-02).
// Only §5's identity key signs a push, which is what evs stores and checks; an agent is attribution, sealed:
// EvsProvenance names its agent_id and, from v1, carries the agent's subkey signature beside it, so agent ids and
// subkeys stay off every server (§11.5) and nothing evs checks changes.
//
//	sign     a push made for an agent (EvsWritePathsArgs.AgentId) names it, and where the host signs provenance
//	         (EvsClientArgs.SignProvenance, Sidecar.SignProvenance) the agent's subkey signs, under purpose evs-push,
//	         EvsAgentProvenanceMessage: repo_id || ref_id || push_id || i64be(time_ms) || u32be(n) || the push's n
//	         carried commits' oids in its order. The push id commits at most once (I-EVS-3) and the statement that
//	         names it is the identity key's, so the signature speaks for this push alone and, in git mode, for its
//	         commits. Its AgentCert, key id and signature ride beside agent_id. A host with no provenance signer, or an
//	         agent whose subkey was revoked, names the agent alone, agent_asserted
//	read     EvsCheckPushProvenance: no agent, unattributed; an agent with no certificate, agent_asserted; else
//	         VerifyAgentProvenance under the identity key that signed the statement, the statement's time_ms as the
//	         entry's time and SidecarAgentSubkeySettings' bound: verified, or refused, which the reader alarms as
//	         tampering (SidecarEvsAlarmTamper) and never attributes to the agent. A writer revoked for compromise is the
//	         caller's to judge before it asks (QD-232)
//	tainted  the run's bit rides beside them (plan-MCP-format1-tainted-files), read as it stands
//
// On every leg but the ios_extension legs. Package-level functions are safe for concurrent use.

package sidecar

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/urnetwork/sidecar/protocol"
)

// The purpose an agent subkey signs a push's provenance under, one of identity_agent.go's provenance purposes.
const AgentProvenancePurposeEvsPush = "evs-push"

// What an agent subkey signs of a push: see the file header.
func EvsAgentProvenanceMessage(repoId Id, refId Id, pushId Id, timeMs int64, commitOids []EvsGitOid) []byte {
	message := make([]byte, 0, 3*len(Id{})+8+4+len(commitOids)*len(EvsGitOid{}))
	message = append(message, repoId[:]...)
	message = append(message, refId[:]...)
	message = append(message, pushId[:]...)
	message = binary.BigEndian.AppendUint64(message, uint64(timeMs))
	message = binary.BigEndian.AppendUint32(message, uint32(len(commitOids)))
	for _, oid := range commitOids {
		message = append(message, oid[:]...)
	}
	return message
}

// The oids of the commits a push's sealed metadata carries, in its order.
func evsSealedCommitOids(commits []*protocol.EvsSealedCommit) []EvsGitOid {
	oids := make([]EvsGitOid, 0, len(commits))
	for _, commit := range commits {
		oids = append(oids, evsGitObjectOid(evsGitCommitKind, commit.GetObject()))
	}
	return oids
}

// Signs a push's provenance for agentId into provenance (see the file header): agent_id always, and the subkey's
// signature with its certificate where sign is set. A revoked subkey names the agent alone. Any other failure of sign
// is the push's: nothing is sent.
func evsSignPushProvenance(provenance *protocol.EvsProvenance, sign EvsSignProvenanceFunction, agentId Id, message []byte) error {
	provenance.AgentId = agentId.Bytes()
	if sign == nil {
		return nil
	}
	signature, err := sign(agentId, AgentProvenancePurposeEvsPush, message)
	if errors.Is(err, ErrAgentSubkeyRevoked) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("evs: the agent's provenance: %w", err)
	}
	provenance.AgentCert = signature.Cert
	provenance.AgentKeyId = signature.KeyId
	provenance.AgentSignature = signature.Signature
	return nil
}

// Signs as Sidecar.SignProvenance does: the agent's subkey over purpose and message, with its certificate.
type EvsSignProvenanceFunction func(agentId Id, purpose string, message []byte) (*AgentProvenanceSignature, error)

// How a push's provenance reads (QD-159).
type EvsPushProvenanceState int

const (
	// No agent: the push is its sidecar's own.
	EvsProvenanceUnattributed EvsPushProvenanceState = iota + 1
	// An agent with no subkey signature: the writer's word (§5.5's agent_asserted).
	EvsProvenanceAsserted
	// The certificate, the push's time and the subkey's signature all hold.
	EvsProvenanceVerified
)

// A push's provenance as a reader takes it.
type EvsPushProvenance struct {
	State EvsPushProvenanceState
	// The agent the push names, nil when unattributed, a refused signature's included.
	AgentId *Id
	// The writing run's tainted bit.
	Tainted bool
	// A subkey signature that did not hold, which the reader alarmed: the agent reads as unattributed.
	Refused bool
}

// What EvsCheckPushProvenance checks.
type EvsPushProvenanceCheck struct {
	RepoId Id
	RefId  Id
	// The push's verified statement and its opened sealed metadata.
	Statement *EvsStatement
	Metadata  *protocol.EvsSealedMetadata
	// The identity key that signed the statement, as the reader's state pins it (§6.9).
	IdentityPublicKey []byte
	// The format's bound on certificates, the reader's own (Sidecar.Settings.AgentSubkeys).
	Settings *SidecarAgentSubkeySettings
}

// A reader's check of a push's agent provenance: see the file header. An error wrapping ErrAgentProvenanceInvalid
// is a signature that does not hold, which the caller alarms on; its answer still says the tainted bit, with no agent.
func EvsCheckPushProvenance(check *EvsPushProvenanceCheck) (*EvsPushProvenance, error) {
	if check == nil || check.Statement == nil || check.Metadata == nil {
		return nil, fmt.Errorf("%w: nothing to check", ErrAgentProvenanceInvalid)
	}
	provenance := check.Metadata.GetProvenance()
	read := &EvsPushProvenance{State: EvsProvenanceUnattributed, Tainted: provenance.GetTainted()}
	if len(provenance.GetAgentId()) == 0 {
		if len(provenance.GetAgentCert()) != 0 || len(provenance.GetAgentSignature()) != 0 {
			return read, fmt.Errorf("%w: a subkey signature naming no agent", ErrAgentProvenanceInvalid)
		}
		return read, nil
	}
	agentId, err := IdFromBytes(provenance.GetAgentId())
	if err != nil {
		return read, fmt.Errorf("%w: an agent id of %d bytes", ErrAgentProvenanceInvalid, len(provenance.GetAgentId()))
	}
	if len(provenance.GetAgentCert()) == 0 {
		if len(provenance.GetAgentSignature()) != 0 || len(provenance.GetAgentKeyId()) != 0 {
			return read, fmt.Errorf("%w: a subkey signature with no certificate", ErrAgentProvenanceInvalid)
		}
		read.State, read.AgentId = EvsProvenanceAsserted, &agentId
		return read, nil
	}
	push := check.Statement.Push
	signerId, err := IdFromBytes(push.GetSignerSidecarId())
	if err != nil {
		return read, fmt.Errorf("%w: the statement's signer", ErrAgentProvenanceInvalid)
	}
	pushId, err := IdFromBytes(push.GetPushId())
	if err != nil {
		return read, fmt.Errorf("%w: the statement's push id", ErrAgentProvenanceInvalid)
	}
	settings := check.Settings
	if settings == nil {
		settings = DefaultSidecarAgentSubkeySettings()
	}
	message := EvsAgentProvenanceMessage(check.RepoId, check.RefId, pushId, push.GetTimeMs(), evsSealedCommitOids(check.Metadata.GetCommits()))
	verdict, err := VerifyAgentProvenance(&AgentProvenanceCheck{
		SidecarId: signerId, IdentityPublicKey: check.IdentityPublicKey, EntryTime: evsTime(push.GetTimeMs()),
		AgentId: agentId, Cert: provenance.GetAgentCert(), KeyId: provenance.GetAgentKeyId(),
		Signature: provenance.GetAgentSignature(), Purpose: AgentProvenancePurposeEvsPush, Message: message,
		Settings: settings,
	})
	if err != nil {
		return read, err
	}
	if verdict == AgentProvenanceVerified {
		read.State = EvsProvenanceVerified
	} else {
		read.State = EvsProvenanceAsserted
	}
	read.AgentId = &agentId
	return read, nil
}

// A push's provenance as this client reads it: EvsCheckPushProvenance under the signer's identity key at the
// statement's own pin, a refused subkey signature alarmed as tampering and read unattributed, with Refused set.
func (self *EvsClient) checkPushProvenance(repoId Id, refId Id, statement *EvsStatement, metadata *protocol.EvsSealedMetadata) (*EvsPushProvenance, error) {
	newest, err := self.verifier.config()
	if err != nil {
		return nil, err
	}
	state, err := newest.At(statement.Push.GetAuth())
	if err != nil {
		return nil, err
	}
	signerId, err := IdFromBytes(statement.Push.GetSignerSidecarId())
	if err != nil {
		return nil, fmt.Errorf("%w: its signer", ErrEvsStatementRefused)
	}
	read, err := EvsCheckPushProvenance(&EvsPushProvenanceCheck{
		RepoId: repoId, RefId: refId, Statement: statement, Metadata: metadata,
		IdentityPublicKey: state.IdentityKey(signerId), Settings: self.args.AgentSubkeys,
	})
	if errors.Is(err, ErrAgentProvenanceInvalid) {
		self.alarm(repoId, refId, SidecarEvsAlarmTamper, "", &signerId)
		read.Refused = true
		return read, nil
	}
	return read, err
}

// The provenance of the push that wrote args' path at its version, the newest when args names none: its agent and
// how that reads, and the run's tainted bit (see the file header's read row).
func (self *EvsRepo) Provenance(ctx context.Context, args *EvsReadArgs) (*EvsPushProvenance, error) {
	refId, err := self.resolveRefId(ctx, args.RefName, args.RefId)
	if err != nil {
		return nil, err
	}
	result, err := self.read(ctx, refId, []string{args.Path}, args.Version, args.Fresh)
	if err != nil {
		return nil, err
	}
	defer result.objects.close()
	verified := result.replies[0]
	switch {
	case verified.Base != nil:
		return nil, ErrEvsOverlayBase
	case verified.Absent || verified.Statement == nil:
		return nil, ErrEvsPathAbsent
	}
	commitVersion := verified.CommitVersion
	if verified.Removal != nil {
		commitVersion = verified.Removal.GetRemovalVersion()
	}
	statement := &EvsVerifiedStatement{Version: commitVersion, Statement: verified.Statement}
	payload, err := self.pushContent(ctx, result.head, statement)
	if err != nil {
		return nil, err
	}
	manifest, err := result.keys.manifest(ctx, verified.Statement.Push.GetGeneration())
	if err != nil {
		return nil, err
	}
	metadata, err := EvsOpenMetadata(manifest, payload.SealedMetadata)
	if err != nil {
		self.client.alarm(self.repoId, refId, SidecarEvsAlarmTamper, "", evsSignerOf(verified.Statement.Bytes))
		return nil, err
	}
	return self.client.checkPushProvenance(self.repoId, refId, verified.Statement, metadata)
}
