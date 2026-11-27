// Who holds the gateway's port when the daemon cannot (DESIGN-COMPUTE §8.4: "`ur status` names the port's holder where
// the OS shows it"): each OS's file looks, within GatewaySettings.HolderLookupTimeout, and names a process by its pid,
// its name and its uid as far as the OS shows them to this user, "" where it shows nothing. Linux's /proc/net/tcp and
// tcp6 name every listening socket's uid and inode, and /proc/<pid>/fd names the process of an inode this user may read
// (gateway_holder_linux.go); macOS's lsof names this user's own processes (gateway_holder_darwin.go); another system
// names none. What is read here is the device's own and goes only to `ur status`.

package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
)

// /proc/net/tcp's columns and the state of a listening socket: format values.
const (
	procNetTcpLocalColumn = 1
	procNetTcpStateColumn = 3
	procNetTcpUidColumn   = 7
	procNetTcpInodeColumn = 9
	procNetTcpListenState = "0A"
)

// A listening socket /proc/net/tcp or tcp6 names.
type procNetTcpListener struct {
	uid   int
	inode string
}

// The listening socket of table, /proc/net/tcp's or tcp6's text, bound to address, a loopback address and port, with
// its owner's uid and its inode; false where none is.
func procNetTcpListenerOf(table io.Reader, address string) (*procNetTcpListener, bool) {
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return nil, false
	}
	ip := net.ParseIP(host)
	port, err := strconv.Atoi(portText)
	if ip == nil || err != nil {
		return nil, false
	}
	want := procNetTcpAddress(ip, port)
	scanner := bufio.NewScanner(table)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) <= procNetTcpInodeColumn || !strings.EqualFold(fields[procNetTcpLocalColumn], want) ||
			fields[procNetTcpStateColumn] != procNetTcpListenState {
			continue
		}
		uid, err := strconv.Atoi(fields[procNetTcpUidColumn])
		if err != nil {
			continue
		}
		return &procNetTcpListener{uid: uid, inode: fields[procNetTcpInodeColumn]}, true
	}
	return nil, false
}

// An address as /proc/net/tcp writes it: the address's 32-bit words each in host order on a little-endian machine, as
// hex, then the port as hex.
func procNetTcpAddress(ip net.IP, port int) string {
	raw := ip.To4()
	if raw == nil {
		raw = ip.To16()
	}
	words := make([]byte, len(raw))
	for i := 0; i+4 <= len(raw); i += 4 {
		words[i], words[i+1], words[i+2], words[i+3] = raw[i+3], raw[i+2], raw[i+1], raw[i]
	}
	return strings.ToUpper(hex.EncodeToString(words)) + fmt.Sprintf(":%04X", port)
}

// What `ur status` says of a holder: its pid and name where known, and its uid.
func urGatewayHolderText(pid int, name string, uid int) string {
	switch {
	case 0 < pid && name != "":
		return fmt.Sprintf("pid %d (%s), uid %d", pid, name, uid)
	case 0 < pid:
		return fmt.Sprintf("pid %d, uid %d", pid, uid)
	}
	return fmt.Sprintf("a process of uid %d", uid)
}
