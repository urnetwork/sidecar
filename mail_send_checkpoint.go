//go:build !ios_extension

// The device bound by an approval keeps the identity of its send before writing a copy, depositing, or queueing.
// Its sealed checkpoint holds a digest of the message and destinations, one in-flight signed deposit request,
// and outcomes in deposit order. It holds no plaintext message or addresses.

package sidecar

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"
)

const mailSendCheckpointPrefix = "send-checkpoints/"

// Active local presenters only. Hosts can reopen a MailClient on the same device state; the daemon itself holds
// its instance lock across processes. An approval binds its requester, so no other device can present this use.
var mailSendUses sync.Map

type mailSendUse struct {
	networkId Id
	sidecarId Id
	name      string
}

// The state of one reserved mail use, written atomically before each external deposit and after its acknowledgement.
type mailSendCheckpoint struct {
	SendId     Id                 `json:"send_id"`
	Time       time.Time          `json:"time"`
	Expires    time.Time          `json:"expires"`
	OpaqueId   bool               `json:"opaque_id,omitempty"`
	PlanDigest []byte             `json:"plan_digest"`
	CopyKept   bool               `json:"copy_kept,omitempty"`
	Deposits   []MailSendOutcome  `json:"deposits,omitempty"`
	Pending    *evsDepositRequest `json:"pending,omitempty"`
	Complete   bool               `json:"complete,omitempty"`
	Queued     bool               `json:"queued,omitempty"`
	EffectRef  Id                 `json:"effect_ref,omitempty"`
}

// The sealed file of one send. All actual spenders of this key have the same requester-sidecar identity.
func mailSendCheckpointName(effectKey []byte) string {
	return mailSendCheckpointPrefix + mailBinaryName(effectKey)
}

// The approval file's retention, covering every instant at which its gate can still run this use.
func mailSendCheckpointExpiry(ctx context.Context, gate MailConfigGate, now time.Time) time.Time {
	settings := defaultSidecarMcpSettings()
	if sidecar, ok := gate.(*Sidecar); ok {
		settings = sidecar.settings.Mcp
	}
	notAfter := mailSendApprovalNotAfter(ctx)
	if notAfter.IsZero() {
		notAfter = now
	}
	return notAfter.Add(max(settings.ApprovalFileRetention, settings.ApprovalCompleteTimeout))
}

// Takes the checkpoint's writer slot or returns the overlapping caller's release signal.
func (self *MailClient) trySendUse(name string) (func(), <-chan struct{}) {
	key := mailSendUse{networkId: self.networkId, sidecarId: self.sidecarId, name: name}
	released := make(chan struct{})
	other, loaded := mailSendUses.LoadOrStore(key, released)
	if loaded {
		return nil, other.(chan struct{})
	}
	return func() {
		mailSendUses.Delete(key)
		close(released)
	}, nil
}

// Waits only for another presenter of the same use.
func (self *MailClient) lockSendUse(ctx context.Context, name string) (func(), error) {
	for {
		release, other := self.trySendUse(name)
		if release != nil {
			return release, nil
		}
		testHookBarrier("mail.send.use.wait", "")
		select {
		case <-other:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// Reads an entire authenticated checkpoint. Only an absent file permits a new send under this key.
func (self *MailClient) readSendCheckpoint(name string) (*mailSendCheckpoint, error) {
	reader, err := self.store.Open(name)
	if errors.Is(err, ErrSidecarStoreAbsent) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	limit := self.sendSettings().CheckpointMaxByteCount
	data, err := io.ReadAll(io.LimitReader(reader, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	checkpoint := &mailSendCheckpoint{}
	if len(data) > limit || json.Unmarshal(data, checkpoint) != nil || checkpoint.SendId == (Id{}) ||
		checkpoint.Time.IsZero() || checkpoint.Expires.IsZero() || len(checkpoint.PlanDigest) != sha256.Size ||
		(checkpoint.Pending != nil && (len(checkpoint.Pending.Request) == 0 || checkpoint.Pending.PushId == (Id{}) || checkpoint.Pending.EntryId == (EvsToken{}))) {
		return nil, fmt.Errorf("%w: invalid mail send checkpoint", ErrSidecarStoreFailed)
	}
	return checkpoint, nil
}

// Commits the checkpoint before allowing its caller's next delivery step.
func (self *MailClient) writeSendCheckpoint(name string, checkpoint *mailSendCheckpoint) error {
	data, err := json.Marshal(checkpoint)
	if err != nil {
		return err
	}
	if self.sendSettings().CheckpointMaxByteCount < len(data) {
		return fmt.Errorf("%w: mail send checkpoint exceeds its bound", ErrSidecarStoreFailed)
	}
	writer, err := self.store.Create(name)
	if err != nil {
		return err
	}
	defer writer.Close()
	if _, err := writer.Write(data); err != nil {
		return err
	}
	testHookBarrier("mail.send.checkpoint.before", "")
	err = writer.Commit()
	testHookBarrier("mail.send.checkpoint.after", "")
	return err
}

// A digest of the exact copy, the envelope and the routing chosen at the spend. Rechecking policy cannot redirect
// an interrupted use to a new mailbox, or change its To, Cc or Bcc headers.
func mailSendPlanDigest(message []byte, mailboxId Id, plan *mailSendPlan, targets []*mailSendTarget, queue bool) []byte {
	digest := sha256.New()
	messageHash := sha256.Sum256(message)
	digest.Write(messageHash[:])
	digest.Write(mailboxId[:])
	digest.Write(binary.AppendUvarint(nil, uint64(len(targets))))
	binary.Write(digest, binary.BigEndian, queue)
	addAddresses := func(addresses []string) {
		digest.Write(binary.BigEndian.AppendUint64(nil, uint64(len(addresses))))
		for _, address := range addresses {
			digest.Write(binary.BigEndian.AppendUint64(nil, uint64(len(address))))
			io.WriteString(digest, address)
		}
	}
	addAddresses(plan.recipients)
	addAddresses(plan.outsideRecipients())
	for _, target := range targets {
		digest.Write(target.repoId[:])
		addAddresses(target.recipients)
	}
	return digest.Sum(nil)
}

// A burner's re-encoded parts keep the same opaque boundaries across presentations of one private effect key.
func mailSendBoundary(effectKey []byte, index int) string {
	mac := hmac.New(sha256.New, effectKey)
	io.WriteString(mac, "urnetwork-sidecar-v1/mail/mime-boundary")
	mac.Write(binary.BigEndian.AppendUint64(nil, uint64(index)))
	return "b" + mailBinaryName(mac.Sum(nil)[:EvsTokenByteCount])
}

// The state a restart can prove from the checkpoint. An incomplete send can be resumed by its approved caller.
func (self *mailSendCheckpoint) outcome() *SidecarOutcome {
	if !self.Complete {
		return &SidecarOutcome{State: ApprovalOutcomeUncertain}
	}
	outcome := &SidecarOutcome{State: ApprovalOutcomeDone}
	if self.EffectRef != (Id{}) {
		outcome.EffectRef = self.EffectRef.Bytes()
	}
	return outcome
}

// Drops abandoned checkpoints at the approval ledger's retention boundary. Active sends own their files.
func (self *MailClient) sweepSendCheckpoints(ctx context.Context, now time.Time) error {
	files, err := self.store.List(mailSendCheckpointPrefix)
	if err != nil {
		return err
	}
	var sweepErr error
	for _, file := range files {
		if err := ctx.Err(); err != nil {
			return errors.Join(sweepErr, err)
		}
		release, _ := self.trySendUse(file.Name)
		if release == nil {
			continue
		}
		checkpoint, err := self.readSendCheckpoint(file.Name)
		if err == nil && checkpoint != nil && now.After(checkpoint.Expires) {
			err = self.store.Remove(file.Name)
		}
		release()
		sweepErr = errors.Join(sweepErr, err)
	}
	return sweepErr
}
