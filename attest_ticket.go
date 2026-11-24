//go:build !ios_extension && !sidecar_http

// §5.4's freshness tickets (DESIGN-COMPUTE §5.4, D-ATTEST-5, IC-9, R2-11), encoded as compute-plan-ticket-
// distribution's answer gives them (QD-1379): a ComputePolicyTicket in deterministic protobuf (attest.proto), signed
// whole as the policy is, under the same namespace by the same certified key, and served as a ComputePolicyTicketFile
// that carries those exact bytes and their armored SSHSIG, at <base>/tickets/<day>.bin. A ticket carries its batch
// (id, signed_at, expires), the policy version N a device must hold, and its window, every bound in UTC and inside the
// signature:
//
//	batch       expires at most signed_at + 14 days; no ticket of the batch is honored at or after it
//	policy      N: the device must hold version N or a later one
//	not_before  00:00 UTC of the ticket's day, or signed_at for a revocation batch's first; never before signed_at
//	not_after   not_before + 72 hours, cut to the batch's expires
//
// VerifyTicket refuses a ticket outside those bounds whatever its signature says: the bounds are settings whose
// defaults are §5.4's, and the device enforces them even where a signed ticket claims more. Strict parsing keeps a
// ticket from passing for a policy and the reverse: a ticket's bytes are protobuf that re-encodes to itself with no
// unknown field, which no JSON document is, and a policy is one JSON object, which no ticket is.
//
// A ComputePolicyTicket is immutable once verified. Safe for concurrent use.

package sidecar

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"time"

	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/urnetwork/sidecar/protocol"
)

// The ticket format this build reads and writes.
const computePolicyTicketFormat = 1

// A ticket outside its own or its batch's bounds, or not of this format: errors.Is with ErrComputePolicyRefused too.
var errComputePolicyTicketFormat = errors.New("not a freshness ticket this build takes")

// A sitting's batch (§5.4): its id, the sitting and its expiry.
type ComputePolicyTicketBatch struct {
	Id       Id
	SignedAt time.Time
	Expires  time.Time
}

// One freshness ticket, verified.
type ComputePolicyTicket struct {
	Batch ComputePolicyTicketBatch
	// N: the device must hold policy version N or a later one.
	PolicyVersion uint64
	// The window it is current in: NotBefore <= now < NotAfter, and now < Batch.Expires.
	NotBefore time.Time
	NotAfter  time.Time

	// The ticket file as verified: what a device keeps and passes on.
	file []byte
	// The certified key that signed.
	signer ComputePolicySigner
}

// The ticket file as verified, a copy: what <day>.bin holds and a device passes on.
func (self *ComputePolicyTicket) File() []byte {
	return bytes.Clone(self.file)
}

// Who signed.
func (self *ComputePolicyTicket) Signer() ComputePolicySigner {
	return self.signer
}

// Whether the ticket is current at now under settings' bounds: started, not past its window or its batch's expiry,
// and every bound within §5.4's, rechecked so a setting narrowed since it was verified narrows it too.
func (self *ComputePolicyTicket) Current(now time.Time, settings *AttestSettings) bool {
	return self.withinBounds(settings) == nil && !now.Before(self.NotBefore) && now.Before(self.NotAfter) &&
		now.Before(self.Batch.Expires)
}

// Whether self is newer than other: a later start, or the same start from a later sitting.
func (self *ComputePolicyTicket) newerThan(other *ComputePolicyTicket) bool {
	if !self.NotBefore.Equal(other.NotBefore) {
		return self.NotBefore.After(other.NotBefore)
	}
	return self.Batch.SignedAt.After(other.Batch.SignedAt)
}

// §5.4's bounds: a batch at most TicketBatchMaxLifetime from its sitting, a window at most TicketMaxWindow, starting
// no earlier than the sitting and ending no later than the batch.
func (self *ComputePolicyTicket) withinBounds(settings *AttestSettings) error {
	batch := self.Batch
	switch {
	case !batch.SignedAt.Before(batch.Expires):
		return computePolicyTicketError("its batch expires before it was signed")
	case settings.TicketBatchMaxLifetime < batch.Expires.Sub(batch.SignedAt):
		return computePolicyTicketError("its batch expires more than %s after its sitting", settings.TicketBatchMaxLifetime)
	case self.NotBefore.Before(batch.SignedAt):
		return computePolicyTicketError("it starts before its batch was signed")
	case !self.NotBefore.Before(self.NotAfter):
		return computePolicyTicketError("its window is empty")
	case settings.TicketMaxWindow < self.NotAfter.Sub(self.NotBefore):
		return computePolicyTicketError("its window passes %s", settings.TicketMaxWindow)
	case batch.Expires.Before(self.NotAfter):
		return computePolicyTicketError("its window passes its batch's expiry")
	}
	return nil
}

// A ticket refusal: what was wrong, never a value.
func computePolicyTicketError(format string, args ...any) error {
	return fmt.Errorf("%w: %w: %s", ErrComputePolicyRefused, errComputePolicyTicketFormat, fmt.Sprintf(format, args...))
}

// The ticket's bytes as signed: deterministic protobuf of this format. For the policy pipeline's ticket batches
// (ATTEST-M12-02) and sidecartest's fakes; a device only verifies.
func (self *ComputePolicyTicket) Marshal() ([]byte, error) {
	return proto.MarshalOptions{Deterministic: true}.Marshal(&protocol.ComputePolicyTicket{
		Format: computePolicyTicketFormat,
		Batch: &protocol.ComputePolicyTicketBatch{
			BatchId:    self.Batch.Id.Bytes(),
			SignedAtMs: self.Batch.SignedAt.UnixMilli(),
			ExpiresMs:  self.Batch.Expires.UnixMilli(),
		},
		PolicyVersion: self.PolicyVersion,
		NotBeforeMs:   self.NotBefore.UnixMilli(),
		NotAfterMs:    self.NotAfter.UnixMilli(),
	})
}

// The ticket file for ticket, its bytes signed by signer under namespace, as <day>.bin holds it: for the pipeline and
// sidecartest's fakes, whose software keys stand in for the holders' tokens.
func SignComputePolicyTicket(random io.Reader, signer ssh.Signer, namespace string, ticket *ComputePolicyTicket) ([]byte, error) {
	ticketBytes, err := ticket.Marshal()
	if err != nil {
		return nil, err
	}
	signature, err := ComputeSshsigSign(random, signer, namespace, ticketBytes)
	if err != nil {
		return nil, err
	}
	return proto.MarshalOptions{Deterministic: true}.Marshal(&protocol.ComputePolicyTicketFile{
		Ticket:    ticketBytes,
		Signature: signature,
	})
}

// The ticket file holds, once its signature verifies at now as a policy's does, under this build's namespace, and it
// parses strictly within §5.4's bounds; else an error wrapping ErrComputePolicyRefused. Whether it has started or is
// still current is the gate's question, not this one's.
func (self *ComputePolicyVerifier) VerifyTicket(file []byte, now time.Time) (*ComputePolicyTicket, error) {
	if self.settings.TicketMaxByteCount < len(file) {
		return nil, fmt.Errorf("%w: the ticket is %w", ErrComputePolicyRefused, errComputePolicyTooLarge)
	}
	envelope := &protocol.ComputePolicyTicketFile{}
	if err := computePolicyStrictProto(file, envelope); err != nil {
		return nil, computePolicyTicketError("the file is not a ticket file")
	}
	signer, err := self.verifySignature(envelope.GetTicket(), envelope.GetSignature(), now)
	if err != nil {
		return nil, err
	}
	encoded := &protocol.ComputePolicyTicket{}
	if err := computePolicyStrictProto(envelope.GetTicket(), encoded); err != nil {
		return nil, computePolicyTicketError("the signed bytes are not a ticket")
	}
	batch := encoded.GetBatch()
	if encoded.GetFormat() != computePolicyTicketFormat || batch == nil || len(batch.GetBatchId()) != len(Id{}) ||
		encoded.GetPolicyVersion() == 0 || batch.GetSignedAtMs() <= 0 || batch.GetExpiresMs() <= 0 ||
		encoded.GetNotBeforeMs() <= 0 || encoded.GetNotAfterMs() <= 0 {
		return nil, computePolicyTicketError("a field is missing or of another format")
	}
	batchId, err := IdFromBytes(batch.GetBatchId())
	if err != nil {
		return nil, computePolicyTicketError("its batch id is not an id")
	}
	ticket := &ComputePolicyTicket{
		Batch: ComputePolicyTicketBatch{
			Id:       batchId,
			SignedAt: time.UnixMilli(batch.GetSignedAtMs()).UTC(),
			Expires:  time.UnixMilli(batch.GetExpiresMs()).UTC(),
		},
		PolicyVersion: encoded.GetPolicyVersion(),
		NotBefore:     time.UnixMilli(encoded.GetNotBeforeMs()).UTC(),
		NotAfter:      time.UnixMilli(encoded.GetNotAfterMs()).UTC(),
		file:          bytes.Clone(file),
		signer:        *signer,
	}
	if err := ticket.withinBounds(self.settings); err != nil {
		return nil, err
	}
	return ticket, nil
}

// Decodes data into message only where it is message's deterministic encoding with no unknown field at any depth:
// one encoding per ticket, so no other bytes carry its signature, and no JSON document passes for one.
func computePolicyStrictProto(data []byte, message proto.Message) error {
	if err := (proto.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(data, message); err != nil {
		return err
	}
	if computePolicyProtoUnknown(message.ProtoReflect()) {
		return errors.New("unknown fields")
	}
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(message)
	if err != nil {
		return err
	}
	if !bytes.Equal(encoded, data) {
		return errors.New("not the deterministic encoding")
	}
	return nil
}

// Whether message or any message it holds kept unknown fields.
func computePolicyProtoUnknown(message protoreflect.Message) bool {
	if len(message.GetUnknown()) != 0 {
		return true
	}
	unknown := false
	message.Range(func(field protoreflect.FieldDescriptor, value protoreflect.Value) bool {
		if field.Message() != nil && !field.IsList() && !field.IsMap() {
			unknown = computePolicyProtoUnknown(value.Message())
		}
		return !unknown
	})
	return unknown
}

// The earlier of a and b.
func computePolicyMinTime(a time.Time, b time.Time) time.Time {
	if b.Before(a) {
		return b
	}
	return a
}
