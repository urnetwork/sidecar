//go:build !ios_extension

// The app and daemon open admission requests and act on the member's confirmed decision.

package sidecar

import (
	"bytes"
	"context"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// approve: the member's consented device admits its member's new device alone, the scoped case (§7.9's signers row).
// Every other admission needs counted signers, which the verified state does not yet expose.
func sidecarDecideAdmission(ctx context.Context, self *Sidecar, authority SidecarAuthority, item *sidecarApprovalRecord, decision string, origin SidecarActOrigin, check SidecarPresenceCheck) error {
	if decision != SidecarDecisionApprove {
		return nil
	}
	request, err := item.admissionRequest()
	if err != nil {
		return err
	}
	identity := self.currentIdentity()
	if identity == nil {
		return ErrSidecarNoIdentity
	}
	if !self.consentedFor(authority, request.MemberId) {
		return ErrSidecarApprovalAuthority
	}
	if request.browser != nil {
		confirmed, _ := ctx.Value(browserAdmissionConfirmation{}).(*BrowserAdmissionTerms)
		if confirmed == nil || *confirmed != *request.browser {
			return ErrBrowserAdmissionConfirmation
		}
		if confirmed.Mode == BrowserAdmissionBurner {
			return self.admitBrowserBurner(ctx, request, origin, check)
		}
	}
	// a page Worker's admission carries §7.10's stale revocations of its member's other Workers (D-TEAM-29)
	var workerId *Id
	if sidecarIsPageWorker(request.Capabilities) {
		workerId = &request.SidecarId
	}
	var confirm *protocol.OwnerConfirm
	if request.browser != nil && request.browser.Mode == BrowserAdmissionPage {
		// A pre-existing personal vault's consent list grows on OwnerConfirm.
		confirm = &protocol.OwnerConfirm{SidecarId: request.SidecarId.Bytes()}
	}
	// after an admission the signer commits the device's Add or first wrap in the config group (§5.6's reads row),
	// which GkmClient's config-group commit does once KEYS lands it: any writer leaf commits it meanwhile
	return self.runAdmissionAct(ctx, origin, check, request.MemberId, workerId, bridge.SignedType_SIGNED_SIDECAR_ADMIT, &protocol.SidecarAdmit{
		NetworkId:         identity.NetworkId.Bytes(),
		SidecarId:         request.SidecarId.Bytes(),
		IdentityPublicKey: request.IdentityPublicKey,
		IdentityAlg:       configIdentityAlgEd25519,
		MemberId:          request.MemberId.Bytes(),
		Capabilities:      request.Capabilities,
	}, confirm)
}

// Opens an admission item for a new device of this device's member, which PendingApprovals lists with its safety
// number until a person decides it. Answers its id.
func (self *Sidecar) OpenAdmission(request *SidecarAdmissionRequest) (Id, error) {
	if request == nil || len(request.IdentityPublicKey) == 0 {
		return Id{}, ErrSidecarApprovalUnknown
	}
	self.alarms.stateLock.Lock()
	defer self.alarms.stateLock.Unlock()
	record, err := self.loadAlarmRecord()
	if err != nil {
		return Id{}, err
	}
	subject := append(request.SidecarId.Bytes(), request.IdentityPublicKey...)
	if request.browser != nil {
		if previous := record.browserItem(request.SidecarId, request.MemberId, request.IdentityPublicKey); previous != nil && *previous.Browser != *request.browser {
			return Id{}, ErrSidecarApprovalAuthority
		}
		subject = append(subject, request.browser.identityBytes()...)
	}
	itemId := sidecarApprovalItemId(SidecarApprovalAdmission, subject, 0)
	sidecarId := request.SidecarId
	memberId := request.MemberId
	record.open(&sidecarApprovalRecord{
		ItemId:            itemId,
		Kind:              SidecarApprovalAdmission,
		SidecarId:         &sidecarId,
		MemberId:          &memberId,
		IdentityPublicKey: bytes.Clone(request.IdentityPublicKey),
		Capabilities:      request.Capabilities,
		Browser:           request.browser,
		RaisedAtMs:        self.clock.Now().UnixMilli(),
	})
	return itemId, self.persistAlarmRecord(record)
}
