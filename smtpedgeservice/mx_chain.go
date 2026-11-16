// §14.5's dnssec_chain, which the edge collects for the MX it reached so the sidecar can authenticate it at
// TL1 (§14.4, D-SMTP-2): the MX answer's chain and the TLSA answer's, each from the validating resolver
// (SmtpMxResolver), joined into one in plan-SMTP-small-readings#2's order, the answer RRsets with their
// RRSIGs first and then every zone cut's DNSKEY and DS with theirs, each record once. The sidecar validates
// it to its own root anchors and trusts nothing else the edge says, so the edge only frames records here
// and judges none. An answer that did not validate gives no chain, and the result then carries none, so
// TL1 is not offered on that connection; a chain that would pass the frame is dropped the same way
// (sidecar.WriteSmtpPreambleResult).

package smtpedgeservice

import (
	"encoding/binary"
)

// DNS types the join sorts by (RFC 4034).
const (
	smtpDnsTypeDs     = 43
	smtpDnsTypeRrsig  = 46
	smtpDnsTypeDnskey = 48
)

// One uncompressed wire record, whole, with its type and, for an RRSIG, the type it covers.
type smtpChainRecord struct {
	octets  []byte
	rrtype  uint16
	covered uint16
}

// The records of an uncompressed wire chain, or false when it does not frame as one.
func splitSmtpChain(chain []byte, settings *SmtpEdgeSettings) ([]*smtpChainRecord, bool) {
	records := []*smtpChainRecord{}
	for offset := 0; offset < len(chain); {
		start := offset
		for {
			if len(chain) <= offset {
				return nil, false
			}
			labelLength := int(chain[offset])
			offset += 1
			if labelLength == 0 {
				break
			}
			// a chain's names are uncompressed (RFC 9102 §3)
			if settings.HostLabelMaxByteCount < labelLength || len(chain) < offset+labelLength {
				return nil, false
			}
			offset += labelLength
		}
		if len(chain) < offset+10 {
			return nil, false
		}
		rrtype := binary.BigEndian.Uint16(chain[offset:])
		rdataLength := int(binary.BigEndian.Uint16(chain[offset+8:]))
		offset += 10
		if len(chain) < offset+rdataLength {
			return nil, false
		}
		record := &smtpChainRecord{octets: chain[start : offset+rdataLength], rrtype: rrtype}
		if rrtype == smtpDnsTypeRrsig {
			if rdataLength < 2 {
				return nil, false
			}
			record.covered = binary.BigEndian.Uint16(chain[offset:])
		}
		offset += rdataLength
		records = append(records, record)
	}
	return records, true
}

// Whether a record is a zone cut's: a DNSKEY or DS, or an RRSIG over one.
func (self *smtpChainRecord) zoneMaterial() bool {
	switch self.rrtype {
	case smtpDnsTypeDnskey, smtpDnsTypeDs:
		return true
	case smtpDnsTypeRrsig:
		return self.covered == smtpDnsTypeDnskey || self.covered == smtpDnsTypeDs
	}
	return false
}

// The chains joined: every answer record, in order, then every zone record, each identical record once.
// nil when any chain does not frame, or when there is none.
func joinSmtpChains(settings *SmtpEdgeSettings, chains ...[]byte) []byte {
	var answers, zones []*smtpChainRecord
	for _, chain := range chains {
		if len(chain) == 0 {
			return nil
		}
		records, ok := splitSmtpChain(chain, settings)
		if !ok {
			return nil
		}
		for _, record := range records {
			if record.zoneMaterial() {
				zones = append(zones, record)
			} else {
				answers = append(answers, record)
			}
		}
	}
	joined := []byte{}
	seen := map[string]bool{}
	for _, record := range append(answers, zones...) {
		if seen[string(record.octets)] {
			continue
		}
		seen[string(record.octets)] = true
		joined = append(joined, record.octets...)
	}
	if len(joined) == 0 {
		return nil
	}
	return joined
}
