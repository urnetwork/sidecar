// What ur tun's names share on every platform (§12.9, §17.10; BRIDGE-M4-18, BRIDGE-M6-06): the bridge's pass-through
// to this host's own resolvers for the names its zone does not hold, a published app.<net>.<root> among them, and the
// resolver file Linux and macOS both keep. Each platform's bridge_dns file says which resolvers are this host's and
// points the zones at <block>.0.53 its own way.
//
// The pass-through's queries ride connect's dialer, so while the default route rides the tun under exits they carry
// connect's egress binding, its mark on Linux and its interface on macOS and Windows, and keep the host's own route, as
// the daemon's transport does.

package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"net"
	"net/netip"
	"os"
	"strings"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar/device"
)

// The system's resolver file, on Linux and macOS.
const urResolvConfPath = "/etc/resolv.conf"

// The bridge's pass-through (device.BridgeResolverUpstream) over servers, this host's resolvers outside the tun, read
// again at each query: the query to each in turn until one answers, over UDP, and over TCP when the answer is truncated.
func urResolverUpstream(servers func() []netip.Addr) device.BridgeResolverUpstream {
	// connect's egress machinery: its binding on each socket it makes while one is set, nothing otherwise. A dial of an
	// address needs none of a strategy's settings, its TLS roots among them, so a zero ConnectSettings makes it, and the
	// query's context bounds it
	dialer := (&connect.ConnectSettings{}).NetDialer()
	return func(ctx context.Context, query []byte) ([]byte, error) {
		resolvers := servers()
		if len(resolvers) == 0 {
			return nil, errors.New("no resolver of this host's is outside the tun")
		}
		var lastErr error
		for _, server := range resolvers {
			answer, err := urDnsExchange(ctx, dialer, server, query)
			if err == nil {
				return answer, nil
			}
			lastErr = err
			if ctx.Err() != nil {
				break
			}
		}
		return nil, lastErr
	}
}

// zone as a resolver file or a rule names it: lowercase, with no trailing dot, each label one to ZoneLabelMaxByteCount
// letters, digits or hyphens with no hyphen at either end, the whole at most ZoneNameMaxByteCount (RFC 1035 2.3.1,
// RFC 1123 2.1). False for anything else, which a platform must not write: a name with a slash would name a path.
func urTunZoneName(zone string, settings *urTunSettings) (string, bool) {
	name := strings.ToLower(strings.TrimSuffix(zone, "."))
	if name == "" || settings.ZoneNameMaxByteCount < len(name) {
		return "", false
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" || settings.ZoneLabelMaxByteCount < len(label) || label[0] == '-' || label[len(label)-1] == '-' {
			return "", false
		}
		for _, c := range []byte(label) {
			if !('a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '-') {
				return "", false
			}
		}
	}
	return name, true
}

// The nameservers path lists, in its order; none for a file that is absent or unreadable.
func urReadResolvConf(path string) []netip.Addr {
	file, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer file.Close()
	return urParseResolvConf(file)
}

// The nameserver lines' addresses, a zone kept for a link-local one.
func urParseResolvConf(file io.Reader) []netip.Addr {
	nameservers := []netip.Addr{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 || fields[0] != "nameserver" {
			continue
		}
		if address, err := netip.ParseAddr(fields[1]); err == nil {
			nameservers = append(nameservers, address)
		}
	}
	return nameservers
}

// One DNS exchange with server on port 53 (RFC 1035 4.2) through dialer: over UDP, again over TCP for an answer whose TC
// bit is set. The answer must carry the query's id and the response bit.
func urDnsExchange(ctx context.Context, dialer *net.Dialer, server netip.Addr, query []byte) ([]byte, error) {
	const dnsHeaderByteCount = 12
	if len(query) < dnsHeaderByteCount {
		return nil, errors.New("not a query")
	}
	address := net.JoinHostPort(server.String(), "53")
	check := func(answer []byte) error {
		if len(answer) < dnsHeaderByteCount || answer[0] != query[0] || answer[1] != query[1] || answer[2]&0x80 == 0 {
			return errors.New("not an answer to the query")
		}
		return nil
	}
	deadline, hasDeadline := ctx.Deadline()
	udp, err := dialer.DialContext(ctx, "udp", address)
	if err != nil {
		return nil, err
	}
	answer, err := func() ([]byte, error) {
		defer udp.Close()
		if hasDeadline {
			udp.SetDeadline(deadline)
		}
		if _, err := udp.Write(query); err != nil {
			return nil, err
		}
		// a DNS message's length is a uint16 (RFC 1035 4.2.2)
		buffer := make([]byte, math.MaxUint16)
		for {
			n, err := udp.Read(buffer)
			if err != nil {
				return nil, err
			}
			if check(buffer[:n]) == nil {
				return buffer[:n], nil
			}
		}
	}()
	if err != nil {
		return nil, err
	}
	// TC: the whole answer comes over TCP
	if answer[2]&0x02 == 0 {
		return answer, nil
	}
	if math.MaxUint16 < len(query) {
		return nil, errors.New("a query too long for TCP's length")
	}
	stream, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}
	defer stream.Close()
	if hasDeadline {
		stream.SetDeadline(deadline)
	}
	framed := binary.BigEndian.AppendUint16(nil, uint16(len(query)))
	if _, err := stream.Write(append(framed, query...)); err != nil {
		return nil, err
	}
	var lengthBytes [2]byte
	if _, err := io.ReadFull(stream, lengthBytes[:]); err != nil {
		return nil, err
	}
	answer = make([]byte, binary.BigEndian.Uint16(lengthBytes[:]))
	if _, err := io.ReadFull(stream, answer); err != nil {
		return nil, err
	}
	if err := check(answer); err != nil {
		return nil, err
	}
	return answer, nil
}
