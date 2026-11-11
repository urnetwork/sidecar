//go:build !sidecar_http && !ios_extension

// §9.5's and §9.6's field sizes and defaults: what a registration, a Find and a ticket hold at most, and what a
// registration's zero fields take (QD-702). They are the protocol's values, and changing one is a protocol
// change that no deployment makes on one side alone, so each side's settings carry this one object and its
// defaults stay here. The sockets engine reads it as socketsservice.SocketsSettings.Format.
//
// The registrar's, the listener's and the dialer's checks of the same values (socket_registrar.go,
// socket_listen.go, socket_ticket.go and socket_dial.go) still hold them as constants, and read this object
// once those files move to settings. A page's 1,024 entries is socket_api.go's SocketRegistrationPageMaxEntryCount
// until that file moves too.

package sidecar

// What a registration, a Find and a ticket hold at most, and what a registration's zero fields take.
type SocketFormatSettings struct {
	// The most bytes a registration's claim holds: 1,024, room for a §6 Signed over a SocketRegistrationClaim of
	// at most a name, a listen id, a protocol and an app_mode (§9.5).
	ClaimMaxByteCount int
	// The most bytes a registration's protocol holds: 32.
	ProtocolMaxByteCount int
	// The most ALPN ids one registration lists: 16.
	AlpnMaxCount int
	// The most bytes one ALPN id holds: 255, RFC 7301's.
	AlpnMaxByteCount int
	// The most bytes a registration's app_mode holds: 8, room past "http" and "raw".
	AppModeMaxByteCount int
	// The most a registration's weight may be: 1,000 (§9.5's 1-1000).
	MaxWeight int
	// What a registration's weight of 0 takes: 100 (§9.5).
	DefaultWeight int
	// What a registration's max_streams of 0 takes: 256 (§9.5).
	DefaultMaxStreams int
	// The most bytes a signed ticket holds: 512, what StreamOpen.ticket carries (§9.6).
	TicketMaxByteCount int
	// The most failed tickets one Find reports: 2, the primary and backup of the dialer's last Find (§9.6).
	FailedTicketMaxCount int
	// The most bytes a Find's affinity key holds: 64, room for tlsedge's keyed hash of a visitor's /24 or /48
	// (§9.7).
	AffinityKeyMaxByteCount int
}

// §9.5's, §9.6's and §9.7's values, the only source of their defaults. A fresh value each call, sharing nothing
// mutable with any other.
func DefaultSocketFormatSettings() *SocketFormatSettings {
	return &SocketFormatSettings{
		ClaimMaxByteCount:       1024,
		ProtocolMaxByteCount:    32,
		AlpnMaxCount:            16,
		AlpnMaxByteCount:        255,
		AppModeMaxByteCount:     8,
		MaxWeight:               1000,
		DefaultWeight:           100,
		DefaultMaxStreams:       256,
		TicketMaxByteCount:      512,
		FailedTicketMaxCount:    2,
		AffinityKeyMaxByteCount: 64,
	}
}
