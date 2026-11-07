package localstack

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

// What a scripted node saw and how it answers: one in-process node speaking RESP, so a redirect or a
// lost socket happens on demand.
type scriptedNode struct {
	listener net.Listener
	address  string
	// The reply's raw bytes. An empty reply closes the socket, as a node dying mid-call does.
	answer func(socket *scriptedSocket, args []string) string

	stateLock sync.Mutex
	commands  []string
}

// One accepted connection.
type scriptedSocket struct {
	conn net.Conn
	// Commands on this socket so far, for what ASK demands of its order.
	commands []string
}

func (self *scriptedSocket) push(frame string) error {
	_, err := self.conn.Write([]byte(frame))
	return err
}

func newScriptedNode(t *testing.T, answer func(socket *scriptedSocket, args []string) string) *scriptedNode {
	listener := listenOnStackPort(t)
	self := &scriptedNode{listener: listener, address: listener.Addr().String(), answer: answer}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go self.serve(conn)
		}
	}()
	return self
}

func (self *scriptedNode) serve(conn net.Conn) {
	defer conn.Close()
	socket := &scriptedSocket{conn: conn}
	reader := bufio.NewReader(conn)
	for {
		value, err := readRedisValue(reader)
		if err != nil {
			return
		}
		args := make([]string, 0, len(value.values))
		for _, arg := range value.values {
			args = append(args, string(arg.text))
		}
		command := strings.Join(args, " ")
		socket.commands = append(socket.commands, command)
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.commands = append(self.commands, command)
		}()
		reply := self.answer(socket, args)
		if reply == "" {
			return
		}
		if err := socket.push(reply); err != nil {
			return
		}
	}
}

// How many commands began with prefix.
func (self *scriptedNode) count(prefix string) int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	count := 0
	for _, command := range self.commands {
		if strings.HasPrefix(command, prefix) {
			count += 1
		}
	}
	return count
}

// CLUSTER SLOTS giving every slot to address.
func allSlotsReply(address string) string {
	host, port, _ := net.SplitHostPort(address)
	return fmt.Sprintf("*1\r\n*3\r\n:0\r\n:16383\r\n*2\r\n$%d\r\n%s\r\n:%s\r\n", len(host), host, port)
}

func bulkReply(text string) string {
	return fmt.Sprintf("$%d\r\n%s\r\n", len(text), text)
}

func newRedisOn(t *testing.T, address string, change func(settings *RedisSettings)) *Redis {
	settings := DefaultRedisSettings()
	settings.SeedAddresses = []string{address}
	settings.ResubscribeTimeout = 1 * time.Millisecond
	if change != nil {
		change(settings)
	}
	redis, err := NewRedis(t.Context(), settings)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(redis.Close)
	return redis
}

func TestASeedOffTheStackIsRefused(t *testing.T) {
	settings := DefaultRedisSettings()
	settings.SeedAddresses = []string{"127.0.0.1:6379"}
	if _, err := NewRedis(t.Context(), settings); err == nil {
		t.Error("a production tunnel's port was taken")
	}
}

func TestAClusterWithNoSlotsFailsAtTheStart(t *testing.T) {
	node := newScriptedNode(t, func(socket *scriptedSocket, args []string) string {
		return "*0\r\n"
	})
	settings := DefaultRedisSettings()
	settings.SeedAddresses = []string{node.address}
	if _, err := NewRedis(t.Context(), settings); err == nil || !strings.Contains(err.Error(), "no slots") {
		t.Errorf("err %v", err)
	}
}

// Slots moved: the call lands on the new master, and later calls go straight there.
func TestMovedIsFollowedAndTheSlotsReread(t *testing.T) {
	target := newScriptedNode(t, func(socket *scriptedSocket, args []string) string {
		return bulkReply("value")
	})
	moved := false
	var stateLock sync.Mutex
	origin := newScriptedNode(t, nil)
	origin.answer = func(socket *scriptedSocket, args []string) string {
		stateLock.Lock()
		defer stateLock.Unlock()
		if args[0] == "CLUSTER" {
			if moved {
				return allSlotsReply(target.address)
			}
			return allSlotsReply(origin.address)
		}
		moved = true
		return fmt.Sprintf("-MOVED 1 %s\r\n", target.address)
	}
	redis := newRedisOn(t, origin.address, nil)
	for range 2 {
		value, found, err := redis.Get(t.Context(), "{a}k")
		if err != nil || !found || string(value) != "value" {
			t.Fatalf("value %q, %v, %v", value, found, err)
		}
	}
	if origin.count("GET") != 1 || target.count("GET") != 2 {
		t.Errorf("origin took %d, target %d", origin.count("GET"), target.count("GET"))
	}
}

// A node takes an ASK's command only straight after ASKING on the same socket.
func TestAskSendsAskingOnTheSameSocket(t *testing.T) {
	target := newScriptedNode(t, func(socket *scriptedSocket, args []string) string {
		if args[0] == "ASKING" {
			return "+OK\r\n"
		}
		if 2 <= len(socket.commands) && socket.commands[len(socket.commands)-2] == "ASKING" {
			return bulkReply("value")
		}
		return "-ERR no asking\r\n"
	})
	origin := newScriptedNode(t, nil)
	origin.answer = func(socket *scriptedSocket, args []string) string {
		if args[0] == "CLUSTER" {
			return allSlotsReply(origin.address)
		}
		return fmt.Sprintf("-ASK 1 %s\r\n", target.address)
	}
	redis := newRedisOn(t, origin.address, nil)
	value, found, err := redis.Get(t.Context(), "{a}k")
	if err != nil || !found || string(value) != "value" {
		t.Fatalf("value %q, %v, %v", value, found, err)
	}
	// ASK is for one command, so the slot stays where it was
	if address, _ := redis.addressOf("{a}k"); address != origin.address {
		t.Errorf("address %s", address)
	}
}

func TestARedirectOffTheStackIsRefused(t *testing.T) {
	for _, reply := range []string{"-MOVED 1 203.0.113.7:56401\r\n", "-ASK 1 127.0.0.1:6379\r\n"} {
		origin := newScriptedNode(t, nil)
		origin.answer = func(socket *scriptedSocket, args []string) string {
			if args[0] == "CLUSTER" {
				return allSlotsReply(origin.address)
			}
			return reply
		}
		redis := newRedisOn(t, origin.address, nil)
		if _, _, err := redis.Get(t.Context(), "{a}k"); err == nil {
			t.Errorf("%q was followed", reply)
		}
	}
}

func TestRedirectsStopAtTheLimit(t *testing.T) {
	origin := newScriptedNode(t, nil)
	origin.answer = func(socket *scriptedSocket, args []string) string {
		if args[0] == "CLUSTER" {
			return allSlotsReply(origin.address)
		}
		return fmt.Sprintf("-MOVED 1 %s\r\n", origin.address)
	}
	redis := newRedisOn(t, origin.address, func(settings *RedisSettings) { settings.RedirectLimit = 2 })
	if _, _, err := redis.Get(t.Context(), "{a}k"); err == nil || !strings.Contains(err.Error(), "redirects") {
		t.Errorf("err %v", err)
	}
	if origin.count("GET") != 3 {
		t.Errorf("tried %d times", origin.count("GET"))
	}
}

// host_redis.go: the host runs a script by SHA-1, falling back to its source.
func TestAScriptANodeLacksIsSentInFull(t *testing.T) {
	origin := newScriptedNode(t, nil)
	origin.answer = func(socket *scriptedSocket, args []string) string {
		switch args[0] {
		case "CLUSTER":
			return allSlotsReply(origin.address)
		case "EVALSHA":
			return "-NOSCRIPT No matching script. Please use EVAL.\r\n"
		}
		return ":7\r\n"
	}
	redis := newRedisOn(t, origin.address, nil)
	script := &sidecar.RedisScript{Name: "seven", Source: "return 7"}
	reply, err := redis.RunScript(t.Context(), script, []string{"{a}k"}, []string{"arg"})
	if err != nil || reply.Integer != 7 {
		t.Fatalf("reply %+v, %v", reply, err)
	}
	if origin.count("EVAL return 7 1 {a}k arg") != 1 {
		t.Errorf("no eval of the source")
	}
}

// Redis did not answer, so nobody knows what the write did: it is never sent twice.
func TestALostSocketIsTheCallersToJudge(t *testing.T) {
	origin := newScriptedNode(t, nil)
	origin.answer = func(socket *scriptedSocket, args []string) string {
		if args[0] == "CLUSTER" {
			return allSlotsReply(origin.address)
		}
		return ""
	}
	redis := newRedisOn(t, origin.address, nil)
	if err := redis.Set(t.Context(), "{a}k", []byte("v"), 0); err == nil {
		t.Fatal("a dead socket answered")
	}
	if origin.count("SET") != 1 {
		t.Errorf("sent %d times", origin.count("SET"))
	}
}

func TestACancelledCallEndsAndItsSocketIsNotReused(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	defer close(release)
	origin := newScriptedNode(t, nil)
	origin.answer = func(socket *scriptedSocket, args []string) string {
		if args[0] == "CLUSTER" {
			return allSlotsReply(origin.address)
		}
		close(entered)
		<-release
		return ""
	}
	redis := newRedisOn(t, origin.address, nil)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		_, _, err := redis.Get(ctx, "{a}k")
		done <- err
	}()
	<-entered
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Errorf("err %v", err)
	}
	// its reply may still arrive, so the socket must not go back for another call to read
	if count := func() int {
		redis.stateLock.Lock()
		defer redis.stateLock.Unlock()
		return len(redis.idleConnections[origin.address])
	}(); count != 0 {
		t.Errorf("idle sockets %d", count)
	}
}

func TestErrorsReadTheSameAsTheFakes(t *testing.T) {
	for _, c := range []struct {
		text string
		want error
	}{
		{text: "CROSSSLOT Keys in request don't hash to the same slot", want: sidecartest.ErrRedisCrossSlot},
		{text: "WRONGTYPE Operation against a key holding the wrong kind of value", want: sidecartest.ErrRedisWrongType},
		{text: "NOGROUP No such key 'k' or consumer group 'g'", want: sidecartest.ErrRedisNoGroup},
	} {
		if err := redisFailureError(c.text); !errors.Is(err, c.want) {
			t.Errorf("%s: %v", c.text, err)
		}
	}
}

func TestAPositiveTtlNeverRoundsToZero(t *testing.T) {
	for _, c := range []struct {
		ttl  time.Duration
		want int64
	}{
		{ttl: 1 * time.Nanosecond, want: 1},
		{ttl: 999 * time.Microsecond, want: 1},
		{ttl: 1 * time.Millisecond, want: 1},
		{ttl: 1001 * time.Microsecond, want: 2},
		{ttl: 1 * time.Minute, want: 60000},
	} {
		if got := redisMilliseconds(c.ttl); got != c.want {
			t.Errorf("%v: %d", c.ttl, got)
		}
	}
}

// A node answering a subscription: its acknowledgement, and pmessages pushed on demand.
func subscribingAnswer(origin **scriptedNode, sockets chan<- *scriptedSocket) func(socket *scriptedSocket, args []string) string {
	return func(socket *scriptedSocket, args []string) string {
		switch args[0] {
		case "CLUSTER":
			return allSlotsReply((*origin).address)
		case "PSUBSCRIBE":
			sockets <- socket
			return fmt.Sprintf("*3\r\n%s%s:1\r\n", bulkReply("psubscribe"), bulkReply(args[1]))
		}
		return "-ERR unexpected\r\n"
	}
}

func pmessage(keyPattern string, key string) string {
	return fmt.Sprintf(
		"*4\r\n%s%s%s%s",
		bulkReply("pmessage"),
		bulkReply(redisKeyspaceChannelPrefix+keyPattern),
		bulkReply(redisKeyspaceChannelPrefix+key),
		bulkReply("set"),
	)
}

func TestAnEventReachesOnlyItsPatternsCallbacks(t *testing.T) {
	sockets := make(chan *scriptedSocket, 8)
	var origin *scriptedNode
	origin = newScriptedNode(t, subscribingAnswer(&origin, sockets))
	redis := newRedisOn(t, origin.address, nil)
	first := make(chan sidecar.RedisKeyEvent, 4)
	second := make(chan sidecar.RedisKeyEvent, 4)
	if _, err := redis.AddKeyEventCallback("{a_*}n", func(event sidecar.RedisKeyEvent) { first <- event }); err != nil {
		t.Fatal(err)
	}
	socket := <-sockets
	if _, err := redis.AddKeyEventCallback("{b_*}n", func(event sidecar.RedisKeyEvent) { second <- event }); err != nil {
		t.Fatal(err)
	}
	<-sockets
	if err := socket.push(pmessage("{b_*}n", "{b_1}n")); err != nil {
		t.Fatal(err)
	}
	if event := <-second; event.Key != "{b_1}n" || event.Resync {
		t.Errorf("event %+v", event)
	}
	if err := socket.push(pmessage("{a_*}n", "{a_1}n")); err != nil {
		t.Fatal(err)
	}
	if event := <-first; event.Key != "{a_1}n" {
		t.Errorf("event %+v", event)
	}
	if 0 < len(first) || 0 < len(second) {
		t.Errorf("heard %d and %d more", len(first), len(second))
	}
}

// A lost socket comes back with every pattern, and only then does Resync go out, so a callback's
// reread misses nothing published in the gap.
func TestResyncFollowsAWonBackSubscription(t *testing.T) {
	sockets := make(chan *scriptedSocket, 8)
	var origin *scriptedNode
	origin = newScriptedNode(t, subscribingAnswer(&origin, sockets))
	redis := newRedisOn(t, origin.address, nil)
	events := make(chan sidecar.RedisKeyEvent, 4)
	if _, err := redis.AddKeyEventCallback("{a_*}n", func(event sidecar.RedisKeyEvent) { events <- event }); err != nil {
		t.Fatal(err)
	}
	first := <-sockets
	if 0 < len(events) {
		t.Fatal("a first subscription is no resync")
	}
	first.conn.Close()
	// the pattern is back on a new socket
	for socket := range sockets {
		if socket != first {
			break
		}
	}
	if event := <-events; !event.Resync || event.Key != "" {
		t.Errorf("event %+v", event)
	}
}

func TestARemovedCallbackHearsNoMore(t *testing.T) {
	sockets := make(chan *scriptedSocket, 8)
	var origin *scriptedNode
	origin = newScriptedNode(t, subscribingAnswer(&origin, sockets))
	redis := newRedisOn(t, origin.address, nil)
	removed := make(chan sidecar.RedisKeyEvent, 4)
	kept := make(chan sidecar.RedisKeyEvent, 4)
	remove, err := redis.AddKeyEventCallback("{a_*}n", func(event sidecar.RedisKeyEvent) { removed <- event })
	if err != nil {
		t.Fatal(err)
	}
	socket := <-sockets
	if _, err := redis.AddKeyEventCallback("{a_*}n", func(event sidecar.RedisKeyEvent) { kept <- event }); err != nil {
		t.Fatal(err)
	}
	<-sockets
	remove()
	if err := socket.push(pmessage("{a_*}n", "{a_1}n")); err != nil {
		t.Fatal(err)
	}
	<-kept
	if 0 < len(removed) {
		t.Error("a removed callback heard an event")
	}
}
