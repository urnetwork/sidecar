//go:build !sidecar_http && !ios_extension

// SmtpSender.Check, §14.5's send capability at composition (owner decision 125, D-SMTP-20, FS-123; SMTP-M9-08):
// per recipient domain, what Send would meet, from what this device knows, sending nothing.
//
//	mode      the post-TLS mode of this device's last session with the domain's MX, kept as its pin is
//	          (SmtpPinStore.DomainMode), else the newest or/ outcome naming the domain's mode, else unknown
//	bytes     the message's encoded bytes for that mode, headers, both DKIM signatures and dot-stuffing
//	          included: BDAT's count for bdat, DATA's for data and for unknown, since only DATA has a cap
//	cap       this host's smtp_data_proof_bytes when it proves, else the largest DATA cap the member's consented
//	          prover hosts record in p/; 0 when none has recorded one
//	delay     DESIGN-DETAILS 3.2.6's units over the proving host's measure times its UnitTime, the key part, the
//	          envelope groups, the message part and the header parts; DATA adds the body's octets over its
//	          DataBytesPerSecond. A phone prices it on the p/ record of the host the rendezvous hash of the effect
//	          key picks (SmtpOutboxRunner's pick), and the wait for that host is not known, so it adds none
//	predict   too_large when the mode is data and the bytes pass the cap, unknown when the mode is unknown and
//	          they pass it or no cap is known for a mode that could be data, else ok
//
// The or/ scan reads every kept outcome record, which the 30 days or/ keeps bound (a reading: §15.7 gives no index
// by domain). Nothing here logs.
//
// Off the sidecar_http leg: a page Worker sends no mail (§18.10).

package sidecar

import (
	"bytes"
	"context"
	"time"
)

// The header block's length, its final CRLF CRLF included, as the signed message will hold it: every value written
// after the preamble has a fixed length, so the placeholders' rendering gives it.
func (self *SmtpWireMessage) headerByteCount() (uint64, error) {
	message, _, err := self.render(smtpDkimPlaceholderValues(), nil)
	if err != nil {
		return 0, err
	}
	end := bytes.Index(message, []byte("\r\n\r\n"))
	if end < 0 {
		return uint64(len(message)), nil
	}
	return uint64(end + len("\r\n\r\n")), nil
}

// DESIGN-DETAILS 3.2.6's units for a send of recipientCount recipients and a header block of headerByteCount octets
// in mode, on measure: 1 for the key part; the envelope groups, MAIL and each RCPT and in DATA mode DATA, at
// EnvelopeGroupCount commands a group; 1 for the message part; and the header parts past its head. X, the env part
// a last group's replies need when they pass the msg shape's server records, is 0: the measure records no shape's
// server capacity, so a send whose last group overflows is priced a unit short (a reading). DATA's body parts are
// priced by rate, not here. 0 when the measure lacks a field the formula needs.
func smtpSendUnits(recipientCount int, headerByteCount uint64, mode SmtpMode, measure *SmtpProverMeasure) uint64 {
	if measure == nil || measure.EnvelopeGroupCount == 0 || measure.HeadByteCount == 0 || measure.HeaderRecordByteCount == 0 {
		return 0
	}
	commandCount := uint64(1 + recipientCount)
	if mode == SmtpModeData {
		commandCount += 1
	}
	envelopeUnits := (commandCount + measure.EnvelopeGroupCount - 1) / measure.EnvelopeGroupCount
	headerUnits := uint64(0)
	if measure.HeadByteCount < headerByteCount {
		headerUnits = (headerByteCount - measure.HeadByteCount + measure.HeaderRecordByteCount - 1) / measure.HeaderRecordByteCount
	}
	return 1 + envelopeUnits + 1 + headerUnits
}

// The expected delay of a send on measure: its units times UnitTime, and in DATA mode the body's octets at
// DataBytesPerSecond. 0 when the measure cannot price it.
func smtpSendDelay(recipientCount int, headerByteCount uint64, bodyByteCount uint64, mode SmtpMode, measure *SmtpProverMeasure) time.Duration {
	units := smtpSendUnits(recipientCount, headerByteCount, mode, measure)
	if units == 0 || measure.UnitTime <= 0 {
		return 0
	}
	delay := time.Duration(units) * measure.UnitTime
	if mode == SmtpModeData && 0 < measure.DataBytesPerSecond {
		delay += time.Duration(bodyByteCount) * time.Second / time.Duration(measure.DataBytesPerSecond)
	}
	return delay
}

// The member's consented prover hosts' p/ records, by sidecar.
func (self *SmtpSender) memberProverRecords(ctx context.Context) (map[Id]*SmtpProverRecord, error) {
	records, err := self.args.Mailbox.ListProverRecords(ctx)
	if err != nil {
		return nil, err
	}
	for sidecarId := range records {
		if self.args.MemberDevice == nil || !self.args.MemberDevice(sidecarId) {
			delete(records, sidecarId)
		}
	}
	return records, nil
}

// The mode the newest kept or/ outcome names for each domain, unknown ones left out.
func (self *SmtpSender) outcomeModes(ctx context.Context) (map[string]SmtpMode, error) {
	effectKeys, err := self.args.Mailbox.ListOutcomes(ctx)
	if err != nil {
		return nil, err
	}
	modes := map[string]SmtpMode{}
	times := map[string]time.Time{}
	for _, effectKey := range effectKeys {
		outcomes, err := self.args.Mailbox.ReadOutcomes(ctx, effectKey)
		if err != nil {
			// gone since the list, or a record another version wrote that this one cannot read
			continue
		}
		for _, outcome := range outcomes {
			if outcome.Mode == SmtpModeUnknown || (!times[outcome.Domain].IsZero() && !outcome.UpdateTime.After(times[outcome.Domain])) {
				continue
			}
			modes[outcome.Domain] = outcome.Mode
			times[outcome.Domain] = outcome.UpdateTime
		}
	}
	return modes, nil
}

// What a send of message would meet at each recipient domain (see the file header). An error is ErrSmtpSendInvalid,
// ErrSmtpAssemble for a message no domain could take, or a store's or the mailbox's that cannot answer.
func (self *SmtpSender) Check(ctx context.Context, message *SmtpOutboundMessage) (*SmtpSendCheck, error) {
	plan, err := self.plan(message)
	if err != nil {
		return nil, err
	}
	if plan.wire == nil {
		return nil, plan.assembleErr
	}
	headerByteCount, err := plan.wire.headerByteCount()
	if err != nil {
		return nil, err
	}

	// the proving host's measure and cap: this one's, or for a host that only queues the member's prover hosts'
	measure := self.localMeasure()
	capByteCount := uint64(0)
	if measure != nil {
		capByteCount = measure.DataProofBytes
	} else {
		records, err := self.memberProverRecords(ctx)
		if err != nil {
			return nil, err
		}
		for _, record := range records {
			capByteCount = max(capByteCount, record.Measure.DataProofBytes)
		}
		if sidecarId, ok := smtpRendezvousHost(message.EffectKey, records); ok {
			picked := records[sidecarId].Measure
			measure = &picked
		}
	}
	modes, err := self.outcomeModes(ctx)
	if err != nil {
		return nil, err
	}

	check := &SmtpSendCheck{}
	for _, domainPlan := range plan.domains {
		mode, err := self.args.Pins.DomainMode(domainPlan.domain)
		if err != nil {
			return nil, err
		}
		if mode == SmtpModeUnknown {
			mode = modes[domainPlan.domain]
		}
		countMode := mode
		if countMode == SmtpModeUnknown {
			countMode = SmtpModeData
		}
		byteCount, err := plan.wire.ByteCount(countMode)
		if err != nil {
			return nil, err
		}
		bodyByteCount := uint64(0)
		if headerByteCount < byteCount {
			bodyByteCount = byteCount - headerByteCount
		}
		// an unknown mode is priced as BDAT, which an MX that offers CHUNKING always gets
		delayMode := mode
		if delayMode == SmtpModeUnknown {
			delayMode = SmtpModeBdat
		}
		domainCheck := &SmtpDomainCheck{
			Domain:        domainPlan.domain,
			Mode:          mode,
			ByteCount:     byteCount,
			CapByteCount:  capByteCount,
			ExpectedDelay: smtpSendDelay(len(domainPlan.recipients), headerByteCount, bodyByteCount, delayMode, measure),
			Prediction:    SmtpCheckOk,
		}
		switch {
		case mode == SmtpModeData && capByteCount < byteCount:
			domainCheck.Prediction = SmtpCheckTooLarge
			if measure == nil {
				domainCheck.Prediction = SmtpCheckUnknown
			}
		case mode == SmtpModeUnknown && capByteCount < byteCount:
			domainCheck.Prediction = SmtpCheckUnknown
		}
		check.Domains = append(check.Domains, domainCheck)
	}
	return check, nil
}
