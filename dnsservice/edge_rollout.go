package dnsservice

import (
	"encoding/hex"

	"github.com/miekg/dns"
)

// The private block status accepts "<nonce> <root>" for a denial or "canary <root>"
// for its fresh TXT. It returns the serial and a digest of the signed public RRset.
const DnsRolloutProofHeader = "X-Ur-Dns-Rollout-Proof"

// A fresh challenge for one DNS exchange to one nameserver address on one transport.
type DnsRolloutNonce [16]byte

// The challenge is an ordinary, nonexistent child of the zone's reserved canary.
func (self DnsRolloutNonce) Owner(root string) string {
	return hex.EncodeToString(self[:]) + "." + DnsCanaryOwner(root)
}

// A fingerprint of the exact RRset and its online signature. The owner is
// case-insensitive. All record data and signature parameters are covered.
func DnsRolloutRecordProof(record dns.RR, sig *dns.RRSIG) string {
	if record == nil || sig == nil || record.Header().Rrtype != sig.TypeCovered ||
		dns.CanonicalName(record.Header().Name) != dns.CanonicalName(sig.Hdr.Name) {
		return ""
	}
	// PackRR sets Rdlength. The signature in the process cache is shared by concurrent queries.
	digest, ok := dnsRrsetDigest([]dns.RR{dns.Copy(record), dns.Copy(sig)})
	if !ok {
		return ""
	}
	return hex.EncodeToString(digest[:])
}

// Confirms the signed denial of a challenge, or the zone's signed canary TXT
// when nonce is nil. Only a signature already made by this process qualifies.
// The shared ZSK and snapshot never carry either online signature.
func (self *DnsEdge) CachedRolloutProof(root string, nonce *DnsRolloutNonce) (string, uint32) {
	rootServing := self.servings[root]
	if rootServing == nil {
		return "", 0
	}
	serving := rootServing.Load()
	if serving == nil {
		return "", 0
	}
	soa := serving.view.denialSoa()
	var record dns.RR
	if nonce != nil {
		nsec, ok := dnsCompactNsec(nonce.Owner(root), soa.Hdr.Ttl, []uint16{dns.TypeRRSIG, dns.TypeNSEC, dns.TypeNXNAME})
		if !ok {
			return "", 0
		}
		record = nsec
	} else {
		// Read the current view without DO. A private status read never signs anything.
		query := new(dns.Msg)
		query.SetQuestion(DnsCanaryOwner(root), dns.TypeTXT)
		reply := Answer(&DnsQuery{Message: query, Tcp: true}, serving.view, self.healthy.Load())
		if reply == nil || len(reply.Answer) != 1 || reply.Answer[0].Header().Rrtype != dns.TypeTXT {
			return "", 0
		}
		record = reply.Answer[0]
	}
	digest, ok := dnsRrsetDigest([]dns.RR{record})
	if !ok {
		return "", 0
	}
	key := dnsSignatureKey{zskId: serving.keys.zskId, owner: record.Header().Name, rrType: record.Header().Rrtype, digest: digest}
	now := self.clock.Now()
	if sig := self.signer.cache.get(key, now, 0); sig != nil && verifyDnsSignedSection([]dns.RR{record, sig}, serving.keys, nil, now) == nil {
		return DnsRolloutRecordProof(record, sig), soa.Serial
	}
	return "", 0
}
