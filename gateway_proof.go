//go:build !js && !ios && !android && !sdk_mobile_bind && !sidecar_http && !ios_extension

// Is the listener the daemon? (DESIGN-COMPUTE §8.4, D-GW-3, GW-M12-01.) Harnesses do not authenticate the gateway, so
// a token goes only to a port the daemon is shown to hold:
//
//	key     `ur gateway token` and `ur gateway run` ask the daemon over its control socket, whose peer check admits its
//	        own uid alone (DESIGN §5.8), for a fresh key (the daemon's gateway.key): ListenerProofKeyByteCount random
//	        bytes under a random id, held in the daemon's memory alone for ListenerProofKeyLife, never written, at most
//	        ListenerProofKeyCount at once, the oldest ending first
//	ask     the command sends GET /v1/ur/listener?key_id=<id>&nonce=<nonce> to each loopback address of the port it
//	        checks, with a fresh nonce each time
//	answer  the listener answers {"mac": ...}: HMAC-SHA256 under the key over a label, the key's id, the nonce and the
//	        address the request arrived on, as the listener's own socket reads it
//	check   the command takes the answer only where it is that MAC over the address it dialed, compared in constant
//	        time; anything else, an error, a timeout or no answer, refuses, and the command prints nothing and exits
//	        non-zero, so a process that took the port gets no token and the harness's call fails closed
//
// The address in the MAC is what stops a relay: a process that took 127.0.0.1:<port> while the daemon holds [::1]:<port>
// could pass the ask on to the daemon's other address, but the daemon's answer then names that address, which the
// command did not dial. Only the daemon can make the MAC, since only it and the command hold the key, and the command
// holds it only for its one ask.
//
// Safe for concurrent use.

package sidecar

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"sync"
	"time"
)

// The proof's route, its query's names, and the MAC's label: format values.
const (
	GatewayListenerPath       = "/v1/ur/listener"
	gatewayListenerKeyIdParam = "key_id"
	gatewayListenerNonceParam = "nonce"
	gatewayListenerProofLabel = "ur-gateway-listener-proof-v1"
)

var (
	// The listener did not prove it is the daemon: wrapped with how it failed, never with a key or a MAC.
	ErrGatewayListenerUnproven = errors.New("the gateway's port is not proven to be the daemon's")
	// The daemon holds no key of that id: it ended, or it was never given.
	errGatewayListenerKeyUnknown = errors.New("no such listener key")
)

// What the daemon gives a command for its asks (gateway.key's reply). The key is secret for its minute: the command
// holds it in memory alone and prints none of it.
type GatewayListenerKey struct {
	KeyId string `json:"key_id"`
	// The key's bytes in base64url.
	Key string `json:"key"`
	// The instance's port.
	Port int `json:"port"`
	// The port's loopback addresses the daemon serves now.
	Addresses []string `json:"addresses"`
	// The port's loopback addresses another process holds, which the daemon cannot serve.
	HeldElsewhere []string `json:"held_elsewhere,omitempty"`
}

// The listener's answer.
type gatewayListenerAnswer struct {
	Mac string `json:"mac"`
}

// One key the daemon gave.
type gatewayListenerProofKey struct {
	key      []byte
	issuedAt time.Time
}

// The daemon's side of the proof: see the file header.
type GatewayListenerProof struct {
	settings *GatewaySettings
	clock    Clock
	random   io.Reader

	stateLock sync.Mutex
	keyIdKeys map[string]*gatewayListenerProofKey
	// the ids in the order given, oldest first
	keyIds []string
}

// The proof over settings, its keys drawn from random, crypto/rand's reader when nil.
func NewGatewayListenerProof(settings *GatewaySettings, clock Clock, random io.Reader) *GatewayListenerProof {
	if random == nil {
		random = rand.Reader
	}
	return &GatewayListenerProof{
		settings:  settings,
		clock:     clockOrReal(clock),
		random:    random,
		keyIdKeys: map[string]*gatewayListenerProofKey{},
	}
}

// A fresh key for one command's asks, held until ListenerProofKeyLife passes.
func (self *GatewayListenerProof) NewKey() (string, []byte, error) {
	if self.settings.ListenerProofKeyByteCount <= 0 || self.settings.ListenerProofKeyCount <= 0 {
		return "", nil, fmt.Errorf("%w: the listener proof gives no keys", errInvalidSettings)
	}
	key := make([]byte, self.settings.ListenerProofKeyByteCount)
	if _, err := io.ReadFull(self.random, key); err != nil {
		return "", nil, err
	}
	testHookSecret("gateway_listener_key", key)
	keyIdBytes := make([]byte, max(1, self.settings.ListenerProofKeyIdByteCount))
	if _, err := io.ReadFull(self.random, keyIdBytes); err != nil {
		return "", nil, err
	}
	keyId := base64.RawURLEncoding.EncodeToString(keyIdBytes)
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.sweepWithLock()
	for self.settings.ListenerProofKeyCount <= len(self.keyIds) {
		delete(self.keyIdKeys, self.keyIds[0])
		self.keyIds = self.keyIds[1:]
	}
	self.keyIdKeys[keyId] = &gatewayListenerProofKey{key: key, issuedAt: self.clock.Now()}
	self.keyIds = append(self.keyIds, keyId)
	return keyId, slices.Clone(key), nil
}

// Drops every key past its life.
func (self *GatewayListenerProof) sweepWithLock() {
	now := self.clock.Now()
	kept := self.keyIds[:0]
	for _, keyId := range self.keyIds {
		key := self.keyIdKeys[keyId]
		if key != nil && now.Before(key.issuedAt.Add(self.settings.ListenerProofKeyLife)) {
			kept = append(kept, keyId)
			continue
		}
		delete(self.keyIdKeys, keyId)
	}
	self.keyIds = kept
}

// The MAC of keyId's key over nonce and the address the ask arrived on.
func (self *GatewayListenerProof) mac(keyId string, nonce []byte, address string) ([]byte, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.sweepWithLock()
	key, ok := self.keyIdKeys[keyId]
	if !ok {
		return nil, errGatewayListenerKeyUnknown
	}
	return GatewayListenerMac(key.key, keyId, nonce, address), nil
}

// The ask's answer, behind the listener's guard: the MAC over the address the request's own socket arrived on.
func (self *GatewayListenerProof) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		writeGatewayGuardError(writer, http.StatusMethodNotAllowed, "method_not_allowed", "the listener proof is a GET")
		return
	}
	query := request.URL.Query()
	keyId := query.Get(gatewayListenerKeyIdParam)
	nonce, err := base64.RawURLEncoding.DecodeString(query.Get(gatewayListenerNonceParam))
	if keyId == "" || err != nil || len(nonce) != self.settings.ListenerProofNonceByteCount {
		writeGatewayGuardError(writer, http.StatusBadRequest, "invalid_request", "the proof takes a key id and a nonce")
		return
	}
	localAddr, _ := request.Context().Value(http.LocalAddrContextKey).(net.Addr)
	address, ok := gatewayCanonicalAddress(localAddr)
	if !ok {
		writeGatewayGuardError(writer, http.StatusBadRequest, "invalid_request", "the proof answers on a loopback address alone")
		return
	}
	mac, err := self.mac(keyId, nonce, address)
	if err != nil {
		writeGatewayGuardError(writer, http.StatusNotFound, "unknown_key", "no such key: ask the daemon again")
		return
	}
	encoded, _ := json.Marshal(&gatewayListenerAnswer{Mac: base64.RawURLEncoding.EncodeToString(mac)})
	writer.Header().Set("Content-Type", gatewayGuardContentType)
	writer.Header().Set("Cache-Control", "no-store")
	writer.Write(encoded)
}

// A socket's address in GatewayLoopbackAddresses' form, host and port, for any TCP address; false for another kind.
func gatewayCanonicalAddress(addr net.Addr) (string, bool) {
	tcpAddr, ok := addr.(*net.TCPAddr)
	if !ok || tcpAddr.IP == nil {
		return "", false
	}
	host := tcpAddr.IP.String()
	if ipv4 := tcpAddr.IP.To4(); ipv4 != nil {
		host = ipv4.String()
	}
	return net.JoinHostPort(host, strconv.Itoa(tcpAddr.Port)), true
}

// HMAC-SHA256 under key over the proof's label and, each with its length, the key's id, the nonce and the address.
func GatewayListenerMac(key []byte, keyId string, nonce []byte, address string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(gatewayListenerProofLabel))
	for _, part := range [][]byte{[]byte(keyId), nonce, []byte(address)} {
		length := [4]byte{}
		binary.BigEndian.PutUint32(length[:], uint32(len(part)))
		mac.Write(length[:])
		mac.Write(part)
	}
	return mac.Sum(nil)
}

// The command's side: one ask of the listener at address, one of the port's loopback addresses, answering nil only
// where the answer is key's MAC over a fresh nonce and the address the command dialed. Anything else wraps
// ErrGatewayListenerUnproven. random is crypto/rand's reader when nil.
func ProveGatewayListener(ctx context.Context, settings *GatewaySettings, key *GatewayListenerKey, address string, random io.Reader) error {
	if random == nil {
		random = rand.Reader
	}
	keyBytes, err := base64.RawURLEncoding.DecodeString(key.Key)
	if err != nil || len(keyBytes) == 0 || key.KeyId == "" {
		return fmt.Errorf("%w: the daemon gave no key", ErrGatewayListenerUnproven)
	}
	defer clear(keyBytes)
	if !slices.Contains(GatewayLoopbackAddresses(key.Port), address) {
		return fmt.Errorf("%w: %s is not one of the port's loopback addresses", ErrGatewayListenerUnproven, address)
	}
	nonce := make([]byte, settings.ListenerProofNonceByteCount)
	if _, err := io.ReadFull(random, nonce); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, settings.ListenerProofTimeout)
	defer cancel()
	dialer := &net.Dialer{}
	transport := &http.Transport{
		// never a proxy: the ask is to the address itself
		Proxy: nil,
		DialContext: func(ctx context.Context, network string, dialed string) (net.Conn, error) {
			// the address the MAC must name, whatever the URL resolves to
			return dialer.DialContext(ctx, "tcp", address)
		},
		DisableKeepAlives: true,
	}
	defer transport.CloseIdleConnections()
	query := url.Values{}
	query.Set(gatewayListenerKeyIdParam, key.KeyId)
	query.Set(gatewayListenerNonceParam, base64.RawURLEncoding.EncodeToString(nonce))
	target := &url.URL{Scheme: "http", Host: address, Path: GatewayListenerPath, RawQuery: query.Encode()}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return err
	}
	response, err := transport.RoundTrip(request)
	if err != nil {
		return fmt.Errorf("%w: %s did not answer: %w", ErrGatewayListenerUnproven, address, err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, settings.ListenerProofAnswerByteCount+1))
	if err != nil || settings.ListenerProofAnswerByteCount < int64(len(body)) {
		return fmt.Errorf("%w: %s's answer did not read", ErrGatewayListenerUnproven, address)
	}
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: %s answered %d", ErrGatewayListenerUnproven, address, response.StatusCode)
	}
	answer := &gatewayListenerAnswer{}
	if err := json.Unmarshal(body, answer); err != nil {
		return fmt.Errorf("%w: %s's answer is no proof", ErrGatewayListenerUnproven, address)
	}
	mac, err := base64.RawURLEncoding.DecodeString(answer.Mac)
	if err != nil || !hmac.Equal(mac, GatewayListenerMac(keyBytes, key.KeyId, nonce, address)) {
		return fmt.Errorf("%w: %s's answer is not the daemon's", ErrGatewayListenerUnproven, address)
	}
	return nil
}

// Every address of key the command proves before it takes a token: 127.0.0.1:<port> always, since every harness
// setting ur writes names it, and [::1]:<port> where the daemon serves it, so a harness that resolves localhost to it
// reaches the daemon too. Refused, wrapping ErrGatewayListenerUnproven, where another process holds either address,
// or the daemon does not serve 127.0.0.1:<port>.
func GatewayListenerAddressesToProve(key *GatewayListenerKey) ([]string, error) {
	addresses := GatewayLoopbackAddresses(key.Port)
	if key.Port <= 0 || 65535 < key.Port {
		return nil, fmt.Errorf("%w: the daemon names no port", ErrGatewayListenerUnproven)
	}
	if 0 < len(key.HeldElsewhere) {
		return nil, fmt.Errorf("%w: another process holds %v", ErrGatewayListenerUnproven, key.HeldElsewhere)
	}
	if !slices.Contains(key.Addresses, addresses[0]) {
		return nil, fmt.Errorf("%w: the daemon does not serve %s", ErrGatewayListenerUnproven, addresses[0])
	}
	proven := []string{addresses[0]}
	if slices.Contains(key.Addresses, addresses[1]) {
		proven = append(proven, addresses[1])
	}
	return proven, nil
}
