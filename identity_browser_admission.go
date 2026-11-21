package sidecar

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"slices"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

const (
	BrowserAdmissionPage   = "page"
	BrowserAdmissionBurner = "burner"
)

var ErrBrowserAdmissionConfirmation = errors.New("compare the browser safety number and confirm the displayed admission on the consented device")

type BrowserAdmissionTerms struct {
	Mode       string `json:"mode"`
	MailboxId  Id     `json:"mailbox_id"`
	NotAfterMs int64  `json:"not_after_ms"`
}

type BrowserAdmissionPreview struct {
	Terms        BrowserAdmissionTerms `json:"terms"`
	SafetyNumber string                `json:"safety_number"`
	NetworkId    Id                    `json:"network_id"`
	MemberId     Id                    `json:"member_id"`
}

func (terms *BrowserAdmissionTerms) identityBytes() []byte {
	value := append([]byte(terms.Mode), terms.MailboxId.Bytes()...)
	return binary.BigEndian.AppendUint64(value, uint64(terms.NotAfterMs))
}

type browserAdmissionConfirmation struct{}

// Only a live mailbox owned by the authenticated member is available for the burner's one explicit share.
func (authority *ConfigAuthority) BrowserMailbox(memberId, mailboxId Id) *protocol.AclRepo {
	state := authority.client.State()
	if state == nil {
		return nil
	}
	repo := state.Repo(mailboxId)
	if repo == nil || repo.GetKind() != protocol.RepoKind_REPO_KIND_MAILBOX || !bytes.Equal(repo.GetOwnerMemberId(), memberId.Bytes()) ||
		repo.GetDeletion().GetDeletedAt() > repo.GetDeletion().GetRestoredAt() {
		return nil
	}
	return repo
}

type browserMailboxAuthority interface {
	BrowserMailbox(Id, Id) *protocol.AclRepo
}

// Each ephemeral identity has one mailbox grant, with the expiry the person first approved.
// The sealed approval item survives a restart between landing the admission and landing the share.
func (record *sidecarAlarmRecord) browserItem(target, member Id, key []byte) *sidecarApprovalRecord {
	for _, item := range record.Items {
		if item.Browser != nil && item.SidecarId != nil && *item.SidecarId == target && item.MemberId != nil &&
			*item.MemberId == member && bytes.Equal(item.IdentityPublicKey, key) && item.Decision != SidecarDecisionDeny {
			return item
		}
	}
	return nil
}

func (self *Sidecar) browserAdmissionRequest(ctx context.Context, target Id, terms BrowserAdmissionTerms) (*SidecarAdmissionRequest, string, error) {
	identity, authority := self.currentIdentity(), self.authority()
	if identity == nil || authority == nil || authority.Pin() == nil {
		return nil, "", ErrSidecarActNoAuthority
	}
	own, ok := self.approvalCapableAdmission(authority)
	if !ok || !self.consentedFor(authority, own.MemberId) || target == identity.SidecarId {
		return nil, "", ErrSidecarApprovalAuthority
	}
	caps := uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_READ_ONLY)
	switch terms.Mode {
	case BrowserAdmissionPage:
		if terms.MailboxId != (Id{}) || terms.NotAfterMs != 0 {
			return nil, "", ErrSidecarApiArgs
		}
	case BrowserAdmissionBurner:
		mail, ok := authority.(browserMailboxAuthority)
		if terms.NotAfterMs <= self.clock.Now().UnixMilli() || terms.MailboxId == (Id{}) || !ok || mail.BrowserMailbox(own.MemberId, terms.MailboxId) == nil {
			return nil, "", ErrSidecarApprovalAuthority
		}
		caps = 0 // The ephemeral ceiling includes its own ReaderKey and the explicitly shared mailbox.
	default:
		return nil, "", ErrSidecarApiArgs
	}
	binding, err := self.sidecarApi.browserAdmissionBinding(ctx, identity.NetworkId, target, terms.Mode)
	if err != nil {
		return nil, "", err
	}
	if terms.Mode == BrowserAdmissionBurner {
		self.alarms.stateLock.Lock()
		record, err := self.loadAlarmRecord()
		self.alarms.stateLock.Unlock()
		if err != nil {
			return nil, "", err
		}
		if previous := record.browserItem(target, own.MemberId, binding.IdentityPublicKey); previous != nil {
			retained := previous.Browser
			if retained.Mode != terms.Mode || retained.MailboxId != terms.MailboxId || retained.NotAfterMs > terms.NotAfterMs || retained.NotAfterMs <= self.clock.Now().UnixMilli() {
				return nil, "", ErrSidecarApprovalAuthority
			}
			terms = *retained
		}
	}
	anchor, err := self.Anchor()
	if err != nil {
		return nil, "", err
	}
	number, err := SafetyNumber(anchor.GenesisSha256, binding.IdentityPublicKey)
	if err != nil {
		return nil, "", err
	}
	return &SidecarAdmissionRequest{SidecarId: target, MemberId: own.MemberId, IdentityPublicKey: binding.IdentityPublicKey,
		Capabilities: caps, browser: &terms}, number, nil
}

// PreviewBrowserAdmission verifies the current binding and computes the safety number on the signer's own anchor.
func (self *Sidecar) PreviewBrowserAdmission(ctx context.Context, target Id, terms BrowserAdmissionTerms) (*BrowserAdmissionPreview, error) {
	request, number, err := self.browserAdmissionRequest(ctx, target, terms)
	if err != nil {
		return nil, err
	}
	identity := self.currentIdentity()
	if identity == nil {
		return nil, ErrSidecarNoIdentity
	}
	return &BrowserAdmissionPreview{Terms: *request.browser, SafetyNumber: number, NetworkId: identity.NetworkId, MemberId: request.MemberId}, nil
}

// ConfirmBrowserAdmission rechecks the current member and mode after the person compares both devices.
func (self *Sidecar) ConfirmBrowserAdmission(ctx context.Context, target Id, preview BrowserAdmissionPreview, check SidecarPresenceCheck) error {
	terms := preview.Terms
	request, actual, err := self.browserAdmissionRequest(ctx, target, terms)
	if err != nil {
		return err
	}
	identity := self.currentIdentity()
	if identity == nil || identity.NetworkId != preview.NetworkId || request.MemberId != preview.MemberId ||
		actual != preview.SafetyNumber || *request.browser != terms {
		return ErrBrowserAdmissionConfirmation
	}
	authority := self.authority()
	if authority == nil {
		return ErrSidecarActNoAuthority
	}
	if existing := authority.Admission(target); existing != nil {
		if existing.Row == nil || existing.Row.GetRevokedAt() != 0 || existing.MemberId != request.MemberId ||
			len(existing.TagIds) != 0 || existing.Row.GetCapabilities() != request.Capabilities || existing.Row.GetNotAfter() != terms.NotAfterMs ||
			!bytes.Equal(existing.Row.GetIdentityPublicKey(), request.IdentityPublicKey) {
			return ErrSidecarApprovalAuthority
		}
		if terms.Mode == BrowserAdmissionBurner {
			if !existing.Ephemeral {
				return ErrSidecarApprovalAuthority
			}
			return self.completeBrowserBurner(ctx, request, existing.Row, check)
		}
		if existing.Ephemeral {
			return ErrSidecarApprovalAuthority
		}
		if existing.Row.GetOwnerConfirmedAt() != 0 && authority.Consented(target, request.MemberId) {
			return nil
		}
		return self.runAdmissionAct(ctx, SidecarActConfirmed, check, request.MemberId, &target, bridge.SignedType_SIGNED_OWNER_CONFIRM, &protocol.OwnerConfirm{SidecarId: target.Bytes()}, nil)
	}
	item, err := self.OpenAdmission(request)
	if err != nil {
		return err
	}
	return self.DecideApproval(context.WithValue(ctx, browserAdmissionConfirmation{}, &terms), item, SidecarDecisionApprove, SidecarActConfirmed, check)
}

func (self *Sidecar) completeBrowserBurner(ctx context.Context, request *SidecarAdmissionRequest, row *bridge.SidecarRow, check SidecarPresenceCheck) error {
	self.alarms.stateLock.Lock()
	record, err := self.loadAlarmRecord()
	self.alarms.stateLock.Unlock()
	if err != nil {
		return err
	}
	item := record.browserItem(request.SidecarId, request.MemberId, request.IdentityPublicKey)
	identity := self.currentIdentity()
	if item == nil || *item.Browser != *request.browser || identity == nil ||
		!slices.ContainsFunc(row.GetAdmissionSigners(), func(signer []byte) bool { return bytes.Equal(signer, identity.SidecarId.Bytes()) }) {
		return ErrSidecarApprovalAuthority
	}
	authority, ok := self.authority().(browserMailboxAuthority)
	if !ok {
		return ErrSidecarApprovalAuthority
	}
	repo := authority.BrowserMailbox(request.MemberId, request.browser.MailboxId)
	if repo == nil {
		return ErrSidecarApprovalAuthority
	}
	for _, revoked := range repo.GetRevokes() {
		if bytes.Equal(revoked.GetSubject(), request.SidecarId.Bytes()) {
			return ErrSidecarApprovalAuthority
		}
	}
	for _, share := range repo.GetShares() {
		if bytes.Equal(share.GetSubject(), request.SidecarId.Bytes()) {
			if share.GetExpires() != request.browser.NotAfterMs || !bytes.Equal(share.GetSigner(), identity.SidecarId.Bytes()) {
				return ErrSidecarApprovalAuthority
			}
			return nil
		}
	}
	// Reuse the original signature while its acknowledgement is outstanding.
	pending, err := self.pendingStatements()
	if err != nil {
		return err
	}
	for _, statement := range pending {
		var signed bridge.Signed
		var share protocol.EvsShare
		if proto.Unmarshal(statement.signed, &signed) == nil && bridge.SignedType(signed.GetType()) == bridge.SignedType_SIGNED_EVS_SHARE &&
			proto.Unmarshal(signed.GetBody(), &share) == nil && bytes.Equal(share.GetRepoId(), request.browser.MailboxId.Bytes()) &&
			bytes.Equal(share.GetSubject(), request.SidecarId.Bytes()) && share.GetExpires() == request.browser.NotAfterMs {
			_, err := self.postPendingInOrder(ctx, statement)
			return err
		}
	}
	// The commit may have been interrupted while writing its second local record.
	return self.runOneStatement(ctx, SidecarActConfirmed, check, bridge.SignedType_SIGNED_EVS_SHARE, request.burnerShare())
}

func (request *SidecarAdmissionRequest) burnerShare() *protocol.EvsShare {
	return &protocol.EvsShare{RepoId: request.browser.MailboxId.Bytes(), Subject: request.SidecarId.Bytes(), Expires: request.browser.NotAfterMs}
}

func (self *Sidecar) admitBrowserBurner(ctx context.Context, request *SidecarAdmissionRequest, origin SidecarActOrigin, check SidecarPresenceCheck) error {
	act, err := self.newAct(origin)
	if err != nil {
		return err
	}
	terms := request.browser
	if err := act.Add(bridge.SignedType_SIGNED_SIDECAR_ADMIT, &protocol.SidecarAdmit{NetworkId: act.identity.NetworkId.Bytes(),
		SidecarId: request.SidecarId.Bytes(), IdentityPublicKey: request.IdentityPublicKey, IdentityAlg: configIdentityAlgEd25519,
		MemberId: request.MemberId.Bytes(), Ephemeral: true, NotAfter: terms.NotAfterMs}); err != nil {
		return err
	}
	if err := act.Add(bridge.SignedType_SIGNED_EVS_SHARE, request.burnerShare()); err != nil {
		return err
	}
	_, err = act.Run(ctx, check)
	return err
}
