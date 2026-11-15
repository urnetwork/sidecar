//go:build !ios_extension

// RecordEntry.version 2 (RECORD-M6-04; RECORD.md section 5.3's agent key row; §5.5, D-CORE-6, QD-159): an entry an
// agent filed whose sealed plaintext is AgentSignedBody{body, agent_id, key_id, signature, agent_cert}, the agent's
// subkey signing inside the sealed body, never the header.
//
//	signed    the subkey signs "urnetwork-sidecar-v1/record-agent" || 0x00 || log_id || entry_id || body, the ids 16
//	          bytes each, so the signature holds the body to this entry of this log; the daemon signs on the agent's
//	          behalf and the key never leaves keychain.ur (I-7)
//	sealed    the AgentSignedBody, marshaled once, is what the entry's key seals and what body_commitment covers, so
//	          a version-1 reader opens it, finds the commitment holding, and shows the body generically; an Opening,
//	          a packet and an export with bodies carry these bytes, since they are what the commitment opens with
//	servers   only the identity key signs what servers store: the header's Signed. The subkey's signature, its key id
//	          and its certificate ride inside the sealed body, so no server sees an agent id, a subkey or that an
//	          entry has one (§6.9, I-4)
//	read      the certificate verifies under the identity key of the sidecar that signed the header and names that
//	          sidecar and the header's agent, the header's time falls inside its life, and the subkey's signature
//	          verifies: verified. No certificate: agent_asserted, never verified. Anything else, a body naming another
//	          agent than its header among it: invalid, never attributed, and the reader alarms bad_entry; the body
//	          still stands on the writer's own signature over its commitment
//	writer    a writer seals version 2 for a draft naming an agent once Sidecar.SignProvenance is bound, which
//	          Sidecar.Record does only with AgentSubkeys.SignRecordEntries set, off until M6's rollout; an agent
//	          whose subkey was revoked here (AgentRevoke), or that the signer fails for, seals version 1, since the
//	          capture matters more than the stronger attribution
//
// A compromised daemon's entries from its revocation's since_n on are refused at the reader's right step before any
// body opens (RECORD.md section 5.5), so nothing here reads them unattributed.
//
// Not on the ios_extension legs, which link no agent subkeys: there record_seal.go's and record_reader.go's hooks stay
// nil, every entry seals version 1 and a version-2 entry reads generically. Package-level functions are safe for
// concurrent use.

package sidecar

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// Binds the seal's and the reader's hooks for version 2, and a Sidecar's own signer for its record's writer.
func init() {
	recordAgentBodySealer = recordAgentBodySeal
	recordAgentBodyOpener = recordAgentBodyOpen
	recordSidecarAgentSigner = func(sidecar *Sidecar) RecordAgentSignFunction {
		return sidecar.SignProvenance
	}
}

// What a version-2 entry's subkey signs under AgentProvenancePurposeRecord: log_id || entry_id || body, the ids 16
// bytes each, so the three never run together.
func RecordAgentBodyMessage(logId Id, entryId Id, body []byte) []byte {
	message := make([]byte, 0, len(logId)+len(entryId)+len(body))
	message = append(message, logId[:]...)
	message = append(message, entryId[:]...)
	return append(message, body...)
}

// The AgentSignedBody of body for one entry of one log, marshaled once: what the entry seals and commits to. False
// with no error where the signer signs nothing for the agent now, a revoked subkey or ErrRecordAgentUnsigned, and the
// entry seals version 1.
func recordAgentBodySeal(sign RecordAgentSignFunction, agentId Id, logId Id, entryId Id, body []byte) ([]byte, bool, error) {
	signature, err := sign(agentId, AgentProvenancePurposeRecord, RecordAgentBodyMessage(logId, entryId, body))
	if errors.Is(err, ErrAgentSubkeyRevoked) || errors.Is(err, ErrRecordAgentUnsigned) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if signature == nil || signature.AgentId != agentId || len(signature.Signature) != ed25519.SignatureSize || len(signature.KeyId) != sha256.Size {
		// a reader would find it invalid, so it never goes out
		return nil, false, fmt.Errorf("%w: a provenance signature that is not this agent's", ErrRecordSealInvalid)
	}
	signedBody, err := proto.MarshalOptions{Deterministic: true}.Marshal(&protocol.AgentSignedBody{
		Body:      body,
		AgentId:   agentId.Bytes(),
		KeyId:     signature.KeyId,
		Signature: signature.Signature,
		AgentCert: signature.Cert,
	})
	if err != nil {
		return nil, false, fmt.Errorf("%w: agent body: %v", ErrRecordSealInvalid, err)
	}
	return signedBody, true, nil
}

// A version-2 entry's sealed plaintext, opened: the kind's body as stored and what its agent signature came to.
type RecordAgentBody struct {
	// The kind's one message, as stored inside the AgentSignedBody.
	Body []byte
	// The agent the body names, which the header's agent_id must equal.
	AgentId    []byte
	Provenance RecordAgentProvenance
}

// Opens committed, the bytes a version-2 entry's body_commitment covers, under header: the caller verified the
// header's signature and the commitment already, and identityPublicKey is the header's writer's key as the caller's
// state admits it. For a reader of an Opening, a packet or an export line that knows its entry is version 2, as the
// record's own reader does for a stream entry. ErrRecordBodyInvalid for bytes that are no AgentSignedBody; a
// signature that does not verify is no error but RecordAgentProvenanceInvalid, which the caller alarms on and never
// attributes.
func RecordAgentBodyOpen(header *StoredRecordHeader, committed []byte, identityPublicKey []byte, settings *SidecarAgentSubkeySettings) (*RecordAgentBody, error) {
	if header == nil || header.Header == nil {
		return nil, fmt.Errorf("%w: no header", ErrRecordBodyInvalid)
	}
	if settings == nil {
		settings = DefaultSidecarAgentSubkeySettings()
	}
	signedBody := &protocol.AgentSignedBody{}
	if err := proto.Unmarshal(committed, signedBody); err != nil {
		return nil, fmt.Errorf("%w: a version-2 body that is no AgentSignedBody", ErrRecordBodyInvalid)
	}
	opened := &RecordAgentBody{
		Body:       bytes.Clone(signedBody.GetBody()),
		AgentId:    bytes.Clone(signedBody.GetAgentId()),
		Provenance: RecordAgentProvenanceInvalid,
	}
	if opened.Body == nil {
		opened.Body = []byte{}
	}
	headerAgentId := header.Header.GetAgentId()
	if len(headerAgentId) != len(Id{}) || !bytes.Equal(headerAgentId, signedBody.GetAgentId()) {
		// the header, which the identity key signed, names another agent or none
		return opened, nil
	}
	logId := recordIdOf(header.Header.GetLogId())
	entryId := recordIdOf(header.Header.GetEntryId())
	provenance, err := VerifyAgentProvenance(&AgentProvenanceCheck{
		SidecarId:         recordIdOf(header.Header.GetWriterSidecarId()),
		IdentityPublicKey: identityPublicKey,
		EntryTime:         time.UnixMilli(header.Header.GetTimeMillis()),
		AgentId:           recordIdOf(headerAgentId),
		Cert:              signedBody.GetAgentCert(),
		KeyId:             signedBody.GetKeyId(),
		Signature:         signedBody.GetSignature(),
		Purpose:           AgentProvenancePurposeRecord,
		Message:           RecordAgentBodyMessage(logId, entryId, signedBody.GetBody()),
		Settings:          settings,
	})
	switch {
	case err != nil:
	case provenance == AgentProvenanceVerified:
		opened.Provenance = RecordAgentProvenanceVerified
	case provenance == AgentProvenanceAsserted:
		opened.Provenance = RecordAgentProvenanceAsserted
	}
	return opened, nil
}

// The reader's hook: RecordAgentBodyOpen over what it holds.
func recordAgentBodyOpen(args *recordAgentBodyOpenArgs) ([]byte, RecordAgentProvenance, error) {
	opened, err := RecordAgentBodyOpen(args.header, args.sealed, args.identityPublicKey, args.settings)
	if err != nil {
		return nil, "", err
	}
	return opened.Body, opened.Provenance, nil
}
