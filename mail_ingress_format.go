//go:build !ios_extension

// MailIngress's bounds (§15.5, plan-MAIL-format-bytes#7; MAIL-M7-19): what the router builds within and what a
// receiver holds it to, the one object both sides' settings carry (QD-702), so its defaults stay here. They are the
// format's values, and changing one is a format change that no deployment makes on one side alone. mxedge's router
// reads it as MxEdgeSettings.Ingress, and a receiver's IngressMaxByteCount (MailSessionSettings) takes its default
// from MaxByteCount.
//
// The builder (mxedgeservice/ingress.go) holds ip_listings to ListingMaxCount entries of at most
// ListingMaxByteCount bytes, then, while the message still passes MaxByteCount, drops ptr_name first and
// ip_listings from the end next. version, sender_ip, sender_port, sni, ehlo_name and receive_time_millis are never
// dropped.

package sidecar

// The version a MailIngress the router builds holds: this format's, which a receiver refuses any other than
// (ParseMailIngress), 0 included.
const MailIngressVersion = mailFormatVersion

// What one MailIngress holds at most.
type MailIngressFormatSettings struct {
	// The whole message's bytes: §15.5's 1,024, which StreamOpen.metadata's own 1,024 B bound also allows.
	MaxByteCount int
	// The most listing categories ip_listings carries: 16 (plan-MAIL-format-bytes#7).
	ListingMaxCount int
	// The most bytes one listing category holds: 12, room for a feed's category names, such as "exploit".
	ListingMaxByteCount int
	// The most bytes of ehlo_name: RFC 5321 §4.5.3.1.2's longest domain, 255, which §15.5 names.
	EhloNameMaxByteCount int
	// The most bytes of sni and ptr_name: RFC 1035's longest name in its dotted text form, 253.
	HostNameMaxByteCount int
}

// The format's values, the only source of their defaults. A fresh value each call, sharing nothing mutable.
func DefaultMailIngressFormatSettings() *MailIngressFormatSettings {
	return &MailIngressFormatSettings{
		MaxByteCount:         1024,
		ListingMaxCount:      16,
		ListingMaxByteCount:  12,
		EhloNameMaxByteCount: 255,
		HostNameMaxByteCount: 253,
	}
}

// Whether every bound is positive.
func (self *MailIngressFormatSettings) Valid() bool {
	return self != nil && 0 < self.MaxByteCount && 0 < self.ListingMaxCount && 0 < self.ListingMaxByteCount &&
		0 < self.EhloNameMaxByteCount && 0 < self.HostNameMaxByteCount
}
