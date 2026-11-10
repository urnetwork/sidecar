//go:build !sidecar_http && !js

// §15.5's verdicts row for DMARC as a table: a verified aligned pass passes, whichever identifier; nothing aligned
// passing and an aligned check unfinished is temperror, and so is a failed lookup; a record with nothing aligned is
// fail, none without a record; and an unaligned check never enters it, which mox's dmarc.Verify would let a DKIM
// temperror do.

package sidecar

import (
	"testing"

	"github.com/urnetwork/sidecar/protocol"
)

func TestMailDmarcVerdictRow(t *testing.T) {
	cases := []struct {
		name      string
		inputs    mailDmarcInputs
		want      protocol.DmarcVerdict
		alignment uint32
	}{
		{name: "no record", inputs: mailDmarcInputs{}, want: protocol.DmarcVerdict_DMARC_NONE},
		{name: "no record, aligned pass", inputs: mailDmarcInputs{dkimAlignedPass: true}, want: protocol.DmarcVerdict_DMARC_NONE, alignment: MailDmarcAlignedDkim},
		{name: "lookup failed", inputs: mailDmarcInputs{lookupTemporary: true, dkimAlignedPass: true}, want: protocol.DmarcVerdict_DMARC_TEMPERROR, alignment: MailDmarcAlignedDkim},
		{name: "dkim aligned pass", inputs: mailDmarcInputs{recordFound: true, dkimAlignedPass: true}, want: protocol.DmarcVerdict_DMARC_PASS, alignment: MailDmarcAlignedDkim},
		{name: "spf aligned pass", inputs: mailDmarcInputs{recordFound: true, spfAlignedPass: true}, want: protocol.DmarcVerdict_DMARC_PASS, alignment: MailDmarcAlignedSpf},
		{name: "both", inputs: mailDmarcInputs{recordFound: true, spfAlignedPass: true, dkimAlignedPass: true}, want: protocol.DmarcVerdict_DMARC_PASS, alignment: MailDmarcAlignedSpf | MailDmarcAlignedDkim},
		{name: "a pass beside a cut", inputs: mailDmarcInputs{recordFound: true, dkimAlignedPass: true, spfAlignedUnfinished: true}, want: protocol.DmarcVerdict_DMARC_PASS, alignment: MailDmarcAlignedDkim},
		{name: "dkim cut, nothing passed", inputs: mailDmarcInputs{recordFound: true, dkimAlignedUnfinished: true}, want: protocol.DmarcVerdict_DMARC_TEMPERROR},
		{name: "spf cut, nothing passed", inputs: mailDmarcInputs{recordFound: true, spfAlignedUnfinished: true}, want: protocol.DmarcVerdict_DMARC_TEMPERROR},
		{name: "nothing aligned passed", inputs: mailDmarcInputs{recordFound: true}, want: protocol.DmarcVerdict_DMARC_FAIL},
	}
	for _, c := range cases {
		got, alignment := mailDmarcVerdict(&c.inputs)
		if got != c.want || alignment != c.alignment {
			t.Errorf("%s: %v with alignment %d", c.name, got, alignment)
		}
	}
}
