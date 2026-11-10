//go:build !sidecar_http && !js

// §15.5's verdicts row for DMARC (RFC 7489; MAIL-M7-08): the From domain's record by mox's dmarc.Lookup, which falls
// back to the organizational domain, and the verdict computed here rather than by mox's dmarc.Verify, which makes any
// DKIM temperror its own whether or not that signature aligns, so one slow unaligned selector would turn a verified
// aligned pass into temperror. DMARC passes only on a verified aligned pass, DKIM's under adkim or SPF's under aspf;
// is temperror when the record's lookup failed, or when an aligned check was cut or failed temporarily and nothing
// aligned passed; and is otherwise fail with a record, none without one. An invalid record is none
// (plan-MAIL-small-readings#13), as several records are.

package sidecar

import (
	"context"
	"unicode/utf8"

	"github.com/mjl-/mox/dmarc"
	moxdns "github.com/mjl-/mox/dns"

	"github.com/urnetwork/sidecar/protocol"
)

// DmarcResult.alignment's bits (§15.5).
const (
	MailDmarcAlignedSpf  = 1
	MailDmarcAlignedDkim = 2
)

// What the From domain's lookup found.
type mailDmarcLookup struct {
	record *dmarc.Record
	// The lookup failed or was cut, so no record can be judged.
	temporary bool
}

// The From domain's DMARC record, where From names a domain.
func (self *MailAuthChecker) lookupDmarc(ctx context.Context, resolver *MailAuthResolver, from moxdns.Domain, fromOk bool) *mailDmarcLookup {
	if !fromOk {
		return &mailDmarcLookup{}
	}
	status, _, record, _, _, _ := self.verifiers.dmarcLookup(ctx, self.log, resolver, from)
	if status == dmarc.StatusTemperror {
		return &mailDmarcLookup{temporary: true}
	}
	return &mailDmarcLookup{record: record}
}

// The inputs of DMARC's verdict: whether a record stands or its lookup failed, and what aligned under it.
type mailDmarcInputs struct {
	recordFound     bool
	lookupTemporary bool
	dkimAlignedPass bool
	// An aligned signature that was cut or failed temporarily.
	dkimAlignedUnfinished bool
	spfAlignedPass        bool
	spfAlignedUnfinished  bool
}

// §15.5's DMARC row, and the alignment bits it rests on.
func mailDmarcVerdict(inputs *mailDmarcInputs) (protocol.DmarcVerdict, uint32) {
	alignment := uint32(0)
	if inputs.spfAlignedPass {
		alignment |= MailDmarcAlignedSpf
	}
	if inputs.dkimAlignedPass {
		alignment |= MailDmarcAlignedDkim
	}
	switch {
	case inputs.lookupTemporary:
		return protocol.DmarcVerdict_DMARC_TEMPERROR, alignment
	case !inputs.recordFound:
		return protocol.DmarcVerdict_DMARC_NONE, alignment
	case inputs.dkimAlignedPass || inputs.spfAlignedPass:
		return protocol.DmarcVerdict_DMARC_PASS, alignment
	case inputs.dkimAlignedUnfinished || inputs.spfAlignedUnfinished:
		return protocol.DmarcVerdict_DMARC_TEMPERROR, alignment
	}
	return protocol.DmarcVerdict_DMARC_FAIL, alignment
}

// DMARC's result from the record found and what was verified: each selected signature aligned under adkim, SPF's
// domain under aspf.
func (self *MailAuthChecker) judgeDmarc(ctx context.Context, found *mailDmarcLookup, selection *mailDkimSelection, spfResult *protocol.SpfResult, spfDomain moxdns.Domain, from moxdns.Domain) *protocol.DmarcResult {
	result := &protocol.DmarcResult{}
	inputs := &mailDmarcInputs{lookupTemporary: found.temporary, recordFound: found.record != nil}
	if found.record != nil {
		record := found.record
		for _, value := range []string{string(record.Policy), string(record.ADKIM), string(record.ASPF)} {
			if !utf8.ValidString(value) {
				record = nil
			}
		}
		if record != nil {
			result.P, result.Adkim, result.Aspf = string(record.Policy), string(record.ADKIM), string(record.ASPF)
		}
		for _, candidate := range selection.selected {
			if !self.aligned(ctx, candidate.sig.Domain, from, found.record.ADKIM == dmarc.AlignStrict) {
				continue
			}
			switch candidate.result.GetResult() {
			case protocol.DkimVerdict_DKIM_PASS:
				inputs.dkimAlignedPass = true
			case protocol.DkimVerdict_DKIM_TEMPERROR, protocol.DkimVerdict_DKIM_INCOMPLETE:
				inputs.dkimAlignedUnfinished = true
			}
		}
		if !spfDomain.IsZero() && self.aligned(ctx, spfDomain, from, found.record.ASPF == dmarc.AlignStrict) {
			switch spfResult.GetResult() {
			case protocol.SpfVerdict_SPF_PASS:
				inputs.spfAlignedPass = true
			case protocol.SpfVerdict_SPF_TEMPERROR, protocol.SpfVerdict_SPF_INCOMPLETE:
				inputs.spfAlignedUnfinished = true
			}
		}
	}
	result.Result, result.Alignment = mailDmarcVerdict(inputs)
	return result
}
