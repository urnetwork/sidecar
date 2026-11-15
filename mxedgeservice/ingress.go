// MailIngress (§15.5, §2.8 mx-1, plan-MAIL-format-bytes#7; MAIL-M7-19): what the router tells a receiver
// of the session it splices, in StreamOpen.metadata on a Required stream, within the format's bound
// (sidecar.MailIngressFormatSettings, 1,024 B).
//
//	version              this format's (sidecar.MailIngressVersion)
//	sender_ip, _port     the sender the lb's PROXY header named, unmapped: 4 or 16 bytes
//	sni                  the ClientHello's, as NormalizeSni gave it
//	ehlo_name            the pre-TLS EHLO or HELO argument, which the dialog held to printable ASCII
//	                     within 255 B
//	ptr_name             the router's forward-confirmed PTR, or "" (ptr.go)
//	ip_listings          the local feed mirror's categories (MAIL-M7-20), at most ListingMaxCount of at
//	                     most ListingMaxByteCount bytes each; longer ones are left out, never cut
//	receive_time_millis  when the router accepted the connection
//
// Past the bound, ptr_name goes first and then ip_listings from the end. version, sender_ip,
// sender_port, sni, ehlo_name and receive_time_millis are never dropped: a message that cannot fit them
// is refused, which the field bounds above make impossible.
//
// The router holds what it built in memory for the stream's open alone, and nothing here logs a field
// (I-13). Safe for concurrent use.

package mxedgeservice

import (
	"errors"
	"net/netip"
	"time"
	"unicode/utf8"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// A MailIngress that could not be built within its bound, or of a field the format refuses.
var errMxIngressRefused = errors.New("MailIngress cannot be built within its bound")

// What one session's MailIngress holds.
type mxIngressFields struct {
	sender      netip.AddrPort
	sni         string
	ehloName    string
	ptrName     string
	listings    []string
	receiveTime time.Time
}

// The bytes of fields' MailIngress within format's bound, as the file header says.
func buildMailIngress(format *sidecar.MailIngressFormatSettings, fields *mxIngressFields) ([]byte, error) {
	sender := fields.sender.Addr().Unmap().WithZone("")
	if !sender.IsValid() {
		return nil, errMxIngressRefused
	}
	if fields.sni == "" || format.HostNameMaxByteCount < len(fields.sni) || !utf8.ValidString(fields.sni) ||
		format.EhloNameMaxByteCount < len(fields.ehloName) || !utf8.ValidString(fields.ehloName) {
		return nil, errMxIngressRefused
	}
	ingress := &protocol.MailIngress{
		Version:           sidecar.MailIngressVersion,
		SenderIp:          sender.AsSlice(),
		SenderPort:        uint32(fields.sender.Port()),
		Sni:               fields.sni,
		EhloName:          fields.ehloName,
		ReceiveTimeMillis: uint64(fields.receiveTime.UnixMilli()),
	}
	if fields.ptrName != "" && len(fields.ptrName) <= format.HostNameMaxByteCount && utf8.ValidString(fields.ptrName) {
		ingress.PtrName = fields.ptrName
	}
	for _, listing := range fields.listings {
		if format.ListingMaxCount <= len(ingress.IpListings) {
			break
		}
		if listing == "" || format.ListingMaxByteCount < len(listing) || !utf8.ValidString(listing) {
			continue
		}
		ingress.IpListings = append(ingress.IpListings, listing)
	}
	marshal := proto.MarshalOptions{Deterministic: true}
	for {
		data, err := marshal.Marshal(ingress)
		if err != nil {
			return nil, errMxIngressRefused
		}
		if len(data) <= format.MaxByteCount {
			return data, nil
		}
		switch {
		case ingress.PtrName != "":
			ingress.PtrName = ""
		case 0 < len(ingress.IpListings):
			ingress.IpListings = ingress.IpListings[:len(ingress.IpListings)-1]
		default:
			return nil, errMxIngressRefused
		}
	}
}
