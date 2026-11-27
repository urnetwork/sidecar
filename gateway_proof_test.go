//go:build !js && !ios && !android && !sdk_mobile_bind && !sidecar_http && !ios_extension && !windows

package sidecar

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// DESIGN-COMPUTE §8.4's "Is the listener the daemon?" (GW-M12-01): a command takes a token only once the port answers
// the nonce's MAC under the key the daemon gave it over its control socket, over the address the command dialed; a
// process that took the port, or relays the ask to the daemon's other address, proves nothing; and the key is fresh per
// ask, bounded, and never written.

// A gateway serving port's state from directory, closed at the test's end.
func startTestGatewayServer(t *testing.T, directory string, port int, clock Clock) *GatewayServer {
	t.Helper()
	writeTestGatewayState(t, directory, port, true)
	server := NewGatewayServer(&GatewayServerArgs{StateDirectory: directory, Clock: clock})
	t.Cleanup(server.Close)
	if status := server.Start(); !status.Serving {
		t.Fatalf("not serving: %+v", status)
	}
	return server
}

// The daemon's own listener proves itself on each address it serves.
func TestListenerProofAnswersOnTheDaemonsPort(t *testing.T) {
	port := testGatewayPort(t)
	server := startTestGatewayServer(t, t.TempDir(), port, nil)
	key, err := server.ListenerKey()
	if err != nil {
		t.Fatal(err)
	}
	addresses, err := GatewayListenerAddressesToProve(key)
	if err != nil {
		t.Fatal(err)
	}
	if addresses[0] != net.JoinHostPort("127.0.0.1", strconv.Itoa(port)) {
		t.Fatalf("proves %v first", addresses)
	}
	for _, address := range addresses {
		if err := ProveGatewayListener(context.Background(), DefaultGatewaySettings(), key, address, nil); err != nil {
			t.Errorf("%s: %v", address, err)
		}
	}
}

// Another process on the port, answering garbage or a MAC under a key of its own, proves nothing, and a daemon that
// finds its port taken says so, so the command refuses before it asks.
func TestListenerProofRefusesForeignHolder(t *testing.T) {
	port := testGatewayPort(t)
	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	foreignListener, err := net.Listen("tcp4", address)
	if err != nil {
		t.Fatal(err)
	}
	foreignKey := []byte("a key of the foreign process's own")
	answers := []func(request *http.Request) []byte{
		func(request *http.Request) []byte { return []byte("{}") },
		func(request *http.Request) []byte { return []byte(`{"mac":"AAAA"}`) },
		func(request *http.Request) []byte {
			nonce, _ := base64.RawURLEncoding.DecodeString(request.URL.Query().Get("nonce"))
			mac := GatewayListenerMac(foreignKey, request.URL.Query().Get("key_id"), nonce, address)
			encoded, _ := json.Marshal(map[string]string{"mac": base64.RawURLEncoding.EncodeToString(mac)})
			return encoded
		},
	}
	answer := answers[0]
	foreign := &http.Server{Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Write(answer(request))
	})}
	served := make(chan struct{})
	go func() {
		defer close(served)
		foreign.Serve(foreignListener)
	}()
	t.Cleanup(func() {
		foreign.Close()
		<-served
	})

	directory := t.TempDir()
	writeTestGatewayState(t, directory, port, true)
	server := NewGatewayServer(&GatewayServerArgs{StateDirectory: directory, Holder: func(address string) string { return "pid 77 (synthetic)" }})
	t.Cleanup(server.Close)
	status := server.Start()
	if !status.Addresses[0].InUse || status.Addresses[0].Holder != "pid 77 (synthetic)" || status.Addresses[0].Serving {
		t.Fatalf("the daemon's view of a taken port: %+v", status.Addresses[0])
	}
	key, err := server.ListenerKey()
	if err == nil {
		if _, err := GatewayListenerAddressesToProve(key); !errors.Is(err, ErrGatewayListenerUnproven) {
			t.Fatalf("a key on a port another holds is proved: %v", err)
		}
	} else if !errors.Is(err, ErrGatewayNotServing) {
		t.Fatal(err)
	}

	// and the command's own check, had the daemon named the port as its own
	proof := NewGatewayListenerProof(DefaultGatewaySettings(), nil, nil)
	keyId, keyBytes, err := proof.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	claimed := &GatewayListenerKey{KeyId: keyId, Key: base64.RawURLEncoding.EncodeToString(keyBytes), Port: port, Addresses: []string{address}}
	for i := range answers {
		answer = answers[i]
		if err := ProveGatewayListener(context.Background(), DefaultGatewaySettings(), claimed, address, nil); !errors.Is(err, ErrGatewayListenerUnproven) {
			t.Errorf("answer %d proved the foreign process: %v", i, err)
		}
	}
}

// A process that took 127.0.0.1:<port> while the daemon holds [::1]:<port>, relaying the ask there, gets the daemon's
// MAC over [::1]:<port>, which the command, having dialed 127.0.0.1:<port>, refuses.
func TestListenerProofRefusesARelay(t *testing.T) {
	port := testGatewayPort(t)
	ipv4 := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	ipv6 := net.JoinHostPort("::1", strconv.Itoa(port))
	relayListener, err := net.Listen("tcp4", ipv4)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	writeTestGatewayState(t, directory, port, true)
	server := NewGatewayServer(&GatewayServerArgs{StateDirectory: directory})
	t.Cleanup(server.Close)
	status := server.Start()
	if !status.Addresses[1].Serving {
		relayListener.Close()
		t.Skipf("this host serves no IPv6 loopback: %s", status.Addresses[1].Reason)
	}
	relay := &http.Server{Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		forwarded, _ := http.NewRequest(http.MethodGet, "http://"+ipv6+request.URL.RequestURI(), nil)
		response, err := (&http.Transport{}).RoundTrip(forwarded)
		if err != nil {
			writer.WriteHeader(http.StatusBadGateway)
			return
		}
		defer response.Body.Close()
		writer.WriteHeader(response.StatusCode)
		io.Copy(writer, response.Body)
	})}
	served := make(chan struct{})
	go func() {
		defer close(served)
		relay.Serve(relayListener)
	}()
	t.Cleanup(func() {
		relay.Close()
		<-served
	})
	key, err := server.ListenerKey()
	if err != nil {
		t.Fatal(err)
	}
	// were the daemon to call the port its own, the command's check alone stops the relay
	key.Addresses, key.HeldElsewhere = []string{ipv4, ipv6}, nil
	if err := ProveGatewayListener(context.Background(), DefaultGatewaySettings(), key, ipv4, nil); !errors.Is(err, ErrGatewayListenerUnproven) {
		t.Fatalf("the relay proved: %v", err)
	}
	if err := ProveGatewayListener(context.Background(), DefaultGatewaySettings(), key, ipv6, nil); err != nil {
		t.Fatalf("the daemon's own address: %v", err)
	}
}

// The MAC names the address the ask arrived on: the same key, id and nonce over another address is another MAC, and
// the listener answers with the address its socket reads.
func TestListenerMacBindsTheAddress(t *testing.T) {
	proof := NewGatewayListenerProof(DefaultGatewaySettings(), nil, nil)
	keyId, key, err := proof.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	nonce := bytes.Repeat([]byte{7}, DefaultGatewaySettings().ListenerProofNonceByteCount)
	if bytes.Equal(GatewayListenerMac(key, keyId, nonce, "127.0.0.1:31238"), GatewayListenerMac(key, keyId, nonce, "[::1]:31238")) {
		t.Fatal("the MAC does not name the address")
	}
	for _, local := range []*net.TCPAddr{{IP: net.ParseIP("127.0.0.1"), Port: 31238}, {IP: net.IPv6loopback, Port: 31238}} {
		request := httptest.NewRequest(http.MethodGet, "http://placeholder.invalid/v1/ur/listener?key_id="+keyId+"&nonce="+
			base64.RawURLEncoding.EncodeToString(nonce), nil)
		request = request.WithContext(context.WithValue(request.Context(), http.LocalAddrContextKey, net.Addr(local)))
		recorder := httptest.NewRecorder()
		proof.ServeHTTP(recorder, request)
		answer := &gatewayListenerAnswer{}
		if err := json.Unmarshal(recorder.Body.Bytes(), answer); err != nil {
			t.Fatal(err)
		}
		address, _ := gatewayCanonicalAddress(local)
		mac, _ := base64.RawURLEncoding.DecodeString(answer.Mac)
		if !bytes.Equal(mac, GatewayListenerMac(key, keyId, nonce, address)) {
			t.Errorf("%s: the answer is not the MAC over its own address", address)
		}
	}
}

// Each ask gets a fresh key; a key past its life, one pushed out by ListenerProofKeyCount newer ones, or one never
// given answers nothing; and no key reaches the state directory.
func TestListenerKeyFreshBoundedAndNeverWritten(t *testing.T) {
	clock := newRecordTestClock()
	settings := DefaultGatewaySettings()
	settings.ListenerProofKeyCount = 3
	proof := NewGatewayListenerProof(settings, clock, nil)
	nonce := bytes.Repeat([]byte{9}, settings.ListenerProofNonceByteCount)
	ask := func(keyId string) int {
		request := httptest.NewRequest(http.MethodGet, "http://placeholder.invalid/v1/ur/listener?key_id="+keyId+"&nonce="+
			base64.RawURLEncoding.EncodeToString(nonce), nil)
		request = request.WithContext(context.WithValue(request.Context(), http.LocalAddrContextKey,
			net.Addr(&net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 31239})))
		recorder := httptest.NewRecorder()
		proof.ServeHTTP(recorder, request)
		return recorder.Code
	}
	firstId, firstKey, err := proof.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	secondId, secondKey, err := proof.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	if firstId == secondId || bytes.Equal(firstKey, secondKey) || len(firstKey) != settings.ListenerProofKeyByteCount {
		t.Fatal("two asks got one key")
	}
	if ask(firstId) != http.StatusOK || ask("never-given") != http.StatusNotFound {
		t.Fatal("a given key, or one never given")
	}
	clock.advance(settings.ListenerProofKeyLife)
	if ask(firstId) != http.StatusNotFound || ask(secondId) != http.StatusNotFound {
		t.Fatal("a key past its life answers")
	}
	ids := []string{}
	for i := 0; i < settings.ListenerProofKeyCount+1; i += 1 {
		keyId, _, err := proof.NewKey()
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, keyId)
	}
	if ask(ids[0]) != http.StatusNotFound || ask(ids[len(ids)-1]) != http.StatusOK {
		t.Fatal("the oldest key past the count still answers, or the newest does not")
	}

	directory := t.TempDir()
	port := testGatewayPort(t)
	server := startTestGatewayServer(t, directory, port, nil)
	key, err := server.ListenerKey()
	if err != nil {
		t.Fatal(err)
	}
	keyBytes, _ := base64.RawURLEncoding.DecodeString(key.Key)
	filepath.WalkDir(directory, func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		content, _ := os.ReadFile(path)
		if bytes.Contains(content, keyBytes) || bytes.Contains(content, []byte(key.Key)) {
			t.Errorf("%s holds the proof key", path)
		}
		return nil
	})
}
