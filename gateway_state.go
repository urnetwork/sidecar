//go:build !js && !ios && !android && !sdk_mobile_bind && !sidecar_http && !ios_extension

// The instance's gateway state (DESIGN-COMPUTE §8.4, GW-M12-01): <state>/gateway/gateway.json, the reading of §8.4's
// "the port chosen at install and kept in the daemon's settings", since no persistent daemon settings file exists.
//
//	port   the port the listener binds on 127.0.0.1 and [::1], drawn once, at the first grant's install, from
//	       GatewaySettings' range among the ports both loopback addresses had free (ChooseGatewayPort), and kept for
//	       the instance, so every harness's settings name the one port
//	hold   whether any grant stands on any network the daemon hosts: the daemon binds the port while it is set, its
//	       busy rule keeps it up while it is set, and its unit holds the port across restarts while it is set
//	       (§8.4's "held while any grant exists"). It sits here, outside every network's sealed store, so a daemon
//	       whose keychain is still locked holds the port from its start: no other user's process may take the port
//	       while a harness may call, whatever the daemon can read
//
// Nothing here is secret: a port and a flag. The file is 0600 under a 0700 directory, written whole through a
// temporary file renamed over it, so a kill leaves the old file or the new one.
//
// Package-level functions are safe for concurrent use; two writers race only in which whole file stands.

package sidecar

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
)

// The state file's format version.
const gatewayStateVersion = 1

// The state's directory under <state>, and its file's name.
const (
	gatewayStateDirectoryName = "gateway"
	gatewayStateFileName      = "gateway.json"
)

// The loopback addresses the listener binds, and the only ones (R-GW-4).
const (
	gatewayLoopbackIpv4 = "127.0.0.1"
	gatewayLoopbackIpv6 = "::1"
)

// A state file that does not read as one.
var ErrGatewayState = errors.New("gateway state unreadable")

// The instance's gateway state: see the file header.
type GatewayState struct {
	Version int `json:"version"`
	// 0 before any install chose one.
	Port int  `json:"port"`
	Hold bool `json:"hold"`
}

// Where the state file lives under <state>.
func GatewayStatePath(stateDirectory string) string {
	return filepath.Join(stateDirectory, gatewayStateDirectoryName, gatewayStateFileName)
}

// Whether the state can be served: a version this build reads, and a port a TCP listener binds, or none.
func (self *GatewayState) validate() error {
	if self.Version != gatewayStateVersion {
		return fmt.Errorf("%w: version %d", ErrGatewayState, self.Version)
	}
	if self.Port < 0 || 65535 < self.Port {
		return fmt.Errorf("%w: a port out of range", ErrGatewayState)
	}
	if self.Hold && self.Port == 0 {
		return fmt.Errorf("%w: a hold with no port", ErrGatewayState)
	}
	return nil
}

// Whether the listener binds now: a port, and a grant standing.
func (self *GatewayState) Holds() bool {
	return self != nil && self.Hold && 0 < self.Port
}

// The state under stateDirectory, read up to byteCount bytes: an empty state, version set, where none was written; an
// error wrapping ErrGatewayState where the file does not read as one.
func ReadGatewayState(stateDirectory string, byteCount int64) (*GatewayState, error) {
	file, err := os.Open(GatewayStatePath(stateDirectory))
	if errors.Is(err, os.ErrNotExist) {
		return &GatewayState{Version: gatewayStateVersion}, nil
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()
	content, err := io.ReadAll(io.LimitReader(file, byteCount+1))
	if err != nil {
		return nil, err
	}
	if byteCount < int64(len(content)) {
		return nil, fmt.Errorf("%w: past %d bytes", ErrGatewayState, byteCount)
	}
	state := &GatewayState{}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(state); err != nil {
		return nil, fmt.Errorf("%w: it does not decode", ErrGatewayState)
	}
	if err := state.validate(); err != nil {
		return nil, err
	}
	return state, nil
}

// Writes state under stateDirectory, 0600 in a 0700 directory, by a temporary file synced and renamed over it.
func WriteGatewayState(stateDirectory string, state *GatewayState) error {
	if err := state.validate(); err != nil {
		return err
	}
	encoded, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	path := GatewayStatePath(stateDirectory)
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, "."+gatewayStateFileName+".*")
	if err != nil {
		return err
	}
	written := false
	defer func() {
		if !written {
			temporary.Close()
			os.Remove(temporary.Name())
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return err
	}
	if _, err := temporary.Write(append(encoded, '\n')); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporary.Name(), path); err != nil {
		return err
	}
	written = true
	if runtime.GOOS == "windows" {
		// no directory opens to sync there, and NTFS journals the rename itself
		return nil
	}
	parent, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer parent.Close()
	return parent.Sync()
}

// The listener's addresses at port, IPv4's first: 127.0.0.1:<port> and [::1]:<port>, and never another.
func GatewayLoopbackAddresses(port int) []string {
	return []string{
		net.JoinHostPort(gatewayLoopbackIpv4, strconv.Itoa(port)),
		net.JoinHostPort(gatewayLoopbackIpv6, strconv.Itoa(port)),
	}
}

// A port both loopback addresses have free now, drawn at random from settings' range: each candidate is bound on
// 127.0.0.1 and then on [::1], and taken only when both bind, or when [::1] is unavailable on a host with no IPv6,
// which the listener then serves without. listen is net.Listen unless a test stands one in; random is crypto/rand's
// reader when nil. Both listeners close before this returns, so the daemon binds the port next.
func ChooseGatewayPort(settings *GatewaySettings, listen func(network string, address string) (net.Listener, error), random io.Reader) (int, error) {
	if listen == nil {
		listen = net.Listen
	}
	if random == nil {
		random = rand.Reader
	}
	span := settings.PortLast - settings.PortFirst + 1
	if settings.PortFirst < 1 || 65535 < settings.PortLast || span < 1 {
		return 0, fmt.Errorf("%w: no gateway port range", errInvalidSettings)
	}
	for attempt := 0; attempt < settings.PortChoiceAttemptCount; attempt += 1 {
		drawn := [8]byte{}
		if _, err := io.ReadFull(random, drawn[:]); err != nil {
			return 0, err
		}
		port := settings.PortFirst + int(binary.BigEndian.Uint64(drawn[:])%uint64(span))
		addresses := GatewayLoopbackAddresses(port)
		ipv4, err := listen("tcp4", addresses[0])
		if err != nil {
			continue
		}
		ipv6, err := listen("tcp6", addresses[1])
		free := err == nil || !gatewayAddressInUse(err)
		if ipv6 != nil {
			ipv6.Close()
		}
		ipv4.Close()
		if free {
			return port, nil
		}
	}
	return 0, fmt.Errorf("no port of %d to %d was free on both loopback addresses after %d tries", settings.PortFirst,
		settings.PortLast, settings.PortChoiceAttemptCount)
}
