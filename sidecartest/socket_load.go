// §22.8's sockets load harness (SOCK-M5-17; R-SOCK-6, D-SOCK-5, D-SOCK-10): simulated listeners and dialers against one
// sockets engine, so a T5 host can drive §9.8's numbers, 100,000 listeners and about 6,700 registration calls a second,
// and read what §22.8 asks of them: Find's p99 server-side, and each listener's share of in-flight streams against its
// share of weight (within ±25%, proposed). The evidence run is a T5 host's on server's Redis store; CI runs it scaled
// down on FakeSocketStore (socket_load_test.go).
//
// The engine runs in process on its own handler, on a FakeHost with §19.11's sockets gate open, a FakeSocketGate that
// gives every simulated listener listen and every dialer dial, and the store the caller gives. Time is the harness's
// FakeClock, stepped a Tick at a time: each step ends the streams due to end, sends each listener's heartbeat when due
// and its eager report when its in-flight count moved by §9.5's max(8, 25% of max_streams) at most every 2 s, sends the
// step's Finds, the dialers in turn over the groups in turn, opens a stream on each primary ticket's listener for
// StreamDuration, and once past Warmup samples every listener's in-flight count each SampleInterval. Find's time is
// measured on the real clock around the engine's handler alone, which is the server side of a Find. A ticket that
// names a listener the harness does not hold, or that does not verify, counts as failed.
//
// One run at a time. The harness never sleeps: simulated seconds pass as fast as the engine serves.

package sidecartest

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"slices"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/socketsservice"
)

// One run's shape. DefaultSocketLoadSettings is §22.8's T5 run; a CI run scales it down.
type SocketLoadSettings struct {
	// How many listeners, spread evenly over GroupCount names of one network.
	ListenerCount int
	GroupCount    int
	// The weights a group's listeners register with, in turn.
	Weights []int
	// Each listener's max_streams.
	MaxStreams int
	// How many dialers, each a client of its own, and how many Finds a simulated second they send in all.
	DialerCount    int
	FindsPerSecond int
	// How long a stream a ticket opens lives.
	StreamDuration time.Duration
	// §9.5's heartbeat, eager report interval and the in-flight move that sends one early.
	HeartbeatInterval   time.Duration
	EagerReportInterval time.Duration
	EagerReportMinMove  int
	EagerReportPercent  int
	// One step of simulated time.
	Tick time.Duration
	// Simulated time before sampling starts, and in all.
	Warmup   time.Duration
	Duration time.Duration
	// How often the in-flight counts are sampled.
	SampleInterval time.Duration
	// Seeds the harness's own draws: heartbeat phases and the order of Finds.
	Seed uint64
}

// §22.8's run: 100,000 listeners heartbeating every 15 s, about 6,700 registration calls a second.
func DefaultSocketLoadSettings() *SocketLoadSettings {
	return &SocketLoadSettings{
		ListenerCount:       100000,
		GroupCount:          1000,
		Weights:             []int{100, 200, 300},
		MaxStreams:          256,
		DialerCount:         2000,
		FindsPerSecond:      20000,
		StreamDuration:      10 * time.Second,
		HeartbeatInterval:   15 * time.Second,
		EagerReportInterval: 2 * time.Second,
		EagerReportMinMove:  8,
		EagerReportPercent:  25,
		Tick:                100 * time.Millisecond,
		Warmup:              30 * time.Second,
		Duration:            120 * time.Second,
		SampleInterval:      time.Second,
		Seed:                1,
	}
}

// What a run came to.
type SocketLoadReport struct {
	FindCount int
	// Finds whose ticket opened a stream, and the rest by their refusal's code; a call that failed outright, or whose
	// tickets opened nothing, is "failed".
	FindOkCount  int
	FindRefusals map[string]int
	// Tickets whose listener was at max_streams, so the dialer went to the backup (§9.7's Fairness).
	ListenerBusyCount     int
	FindP50               time.Duration
	FindP99               time.Duration
	RegistrationCallCount int
	// Registration calls per simulated second.
	RegistrationCallsPerSecond float64
	// The largest |observed share / weight share - 1| over every listener of every group, from the sampled in-flight
	// counts: §22.8's ±25% asks this be at most 0.25.
	ShareMaxDeviation float64
}

// One simulated listener.
type socketLoadListener struct {
	clientId     connect.Id
	sidecarId    connect.Id
	token        string
	registration *sidecar.SocketRegistration
	weight       int
	group        int
	inflight     int
	reported     int
	reportTime   time.Time
	nextBeat     time.Time
	setVersion   uint64
	// the sum of sampled in-flight counts
	sampledSum int64
}

// One stream a ticket opened, ending at end.
type socketLoadStream struct {
	listener *socketLoadListener
	end      time.Time
}

// A FakeSocketGate's view of a ticket key the harness signs with.
type socketLoadTicketKeys struct {
	privateKey ed25519.PrivateKey
}

func (self *socketLoadTicketKeys) SigningKey() (string, ed25519.PrivateKey, bool) {
	return "load", self.privateKey, true
}

func (self *socketLoadTicketKeys) VerifyKeys() []*sidecar.SocketTicketKey {
	return []*sidecar.SocketTicketKey{{KeyId: "load", PublicKey: self.privateKey.Public().(ed25519.PublicKey), ExpireTimeMillis: 1 << 62}}
}

// Runs one load against an engine on store, whose clock must be clock: FakeSocketStore on clock, or server's store on
// it. engineSettings nil is the engine's defaults.
func RunSocketLoad(ctx context.Context, clock *FakeClock, store socketsservice.SocketStore, engineSettings *socketsservice.SocketsSettings, settings *SocketLoadSettings) (*SocketLoadReport, error) {
	if settings == nil {
		settings = DefaultSocketLoadSettings()
	}
	if settings.ListenerCount < settings.GroupCount || settings.GroupCount <= 0 || settings.DialerCount <= 0 || len(settings.Weights) == 0 ||
		settings.Tick <= 0 || settings.Duration <= settings.Warmup || settings.SampleInterval <= 0 {
		return nil, errors.New("socket load: a run's shape is refused")
	}
	if engineSettings == nil {
		engineSettings = socketsservice.DefaultSocketsSettings()
	}
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	random := rand.New(rand.NewPCG(settings.Seed, settings.Seed^0x9e3779b97f4a7c15))

	host := NewFakeHost(runCtx, clock, nil, nil, nil)
	networkId := connect.NewId()
	if err := host.Gates.Set("sidecar:\n  sockets: {enabled: true, percent: 100}\n"); err != nil {
		return nil, err
	}
	serviceHost := host.ServiceHost()
	authenticator := NewFakeAuthenticator(clock, NewFaultQueue())
	serviceHost.Authenticator = authenticator
	gate := NewFakeSocketGate(clock, nil)
	_, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, err
	}
	ticketKeys := &socketLoadTicketKeys{privateKey: privateKey}
	engine, err := socketsservice.NewSocketsService(runCtx, serviceHost, store, gate, engineSettings)
	if err != nil {
		return nil, err
	}
	defer engine.Close()
	engine.SetTicketKeys(ticketKeys)
	handler := engine.Handler()

	issue := func(clientId connect.Id, sidecarId *connect.Id) string {
		return authenticator.Issue(&sidecar.Principal{
			NetworkId: networkId,
			ClientId:  clientId,
			SidecarId: sidecarId,
			Audience:  socketsservice.SocketsAudience,
			IssuedAt:  clock.Now(),
			ExpiresAt: clock.Now().Add(settings.Duration + 24*time.Hour),
		})
	}
	nameKeys := make([][]byte, settings.GroupCount)
	for group := range nameKeys {
		nameKeys[group] = binaryNameKey(group)
	}
	listeners := make([]*socketLoadListener, 0, settings.ListenerCount)
	listenerByClientId := map[connect.Id]*socketLoadListener{}
	for index := range settings.ListenerCount {
		group := index % settings.GroupCount
		_, identityKey, err := ed25519.GenerateKey(nil)
		if err != nil {
			return nil, err
		}
		listener := &socketLoadListener{
			clientId:  connect.NewId(),
			sidecarId: connect.NewId(),
			weight:    settings.Weights[(index/settings.GroupCount)%len(settings.Weights)],
			group:     group,
			nextBeat:  clock.Now().Add(time.Duration(random.Int64N(int64(settings.HeartbeatInterval)))),
		}
		listener.token = issue(listener.clientId, &listener.sidecarId)
		listenId := connect.NewId()
		body, err := proto.MarshalOptions{Deterministic: true}.Marshal(&protocol.SocketRegistrationClaim{
			NetworkId: networkId.Bytes(),
			NameToken: nameKeys[group],
			ListenId:  listenId.Bytes(),
			Protocol:  "tcp",
		})
		if err != nil {
			return nil, err
		}
		claim, err := proto.MarshalOptions{Deterministic: true}.Marshal(&bridge.Signed{
			Body:      body,
			Signature: ed25519.Sign(identityKey, bridge.SignedBytes(sidecar.SocketRegistrationPurpose, bridge.SignedType_SIGNED_SOCKET_REGISTRATION, body)),
			Type:      uint32(bridge.SignedType_SIGNED_SOCKET_REGISTRATION),
		})
		if err != nil {
			return nil, err
		}
		listener.registration = &sidecar.SocketRegistration{
			NameToken:  nameKeys[group],
			SealedName: make([]byte, 152),
			ListenId:   &listenId,
			Protocol:   "tcp",
			Weight:     listener.weight,
			MaxStreams: settings.MaxStreams,
			Serving:    true,
			Claim:      claim,
		}
		gate.AllowListenPrefix(networkId, listener.sidecarId, nil, FakeSocketGrant{GrantId: []byte("load listen")})
		gate.SetIdentityKey(networkId, listener.sidecarId, identityKey.Public().(ed25519.PublicKey))
		listeners = append(listeners, listener)
		listenerByClientId[listener.clientId] = listener
	}
	type socketLoadDialer struct {
		clientId connect.Id
		token    string
	}
	dialers := make([]*socketLoadDialer, settings.DialerCount)
	for index := range dialers {
		clientId := connect.NewId()
		sidecarId := connect.NewId()
		dialers[index] = &socketLoadDialer{clientId: clientId, token: issue(clientId, &sidecarId)}
		for _, nameKey := range nameKeys {
			gate.AllowDial(networkId, clientId, nameKey, FakeSocketGrant{GrantId: []byte("load dial")})
		}
	}
	gate.Load(networkId)

	report := &SocketLoadReport{FindRefusals: map[string]int{}}
	serve := func(method string, path string, token string, body any, answer any) (time.Duration, error) {
		bodyBytes, err := json.Marshal(body)
		if err != nil {
			return 0, err
		}
		request := httptest.NewRequestWithContext(runCtx, method, "http://sockets.load.example"+path, bytes.NewReader(bodyBytes))
		request.Header.Set("Authorization", "Bearer "+token)
		recorder := httptest.NewRecorder()
		start := time.Now()
		handler.ServeHTTP(recorder, request)
		elapsed := time.Since(start)
		if recorder.Code != http.StatusOK {
			return elapsed, fmt.Errorf("socket load: %s answered %d", path, recorder.Code)
		}
		return elapsed, json.Unmarshal(recorder.Body.Bytes(), answer)
	}
	beat := func(listener *socketLoadListener, now time.Time) error {
		listener.setVersion += 1
		listener.registration.Inflight = listener.inflight
		result := &sidecar.SocketRegistrationsResult{}
		if _, err := serve(http.MethodPost, "/socket/registrations", listener.token, &sidecar.SocketRegistrationsArgs{
			SetVersion:    listener.setVersion,
			Registrations: []*sidecar.SocketRegistration{listener.registration},
		}, result); err != nil {
			return err
		}
		report.RegistrationCallCount += 1
		if result.Error != nil {
			return fmt.Errorf("socket load: a heartbeat refused %s", result.Error.Code)
		}
		listener.reported = listener.inflight
		listener.reportTime = now
		return nil
	}
	start := clock.Now()
	for _, listener := range listeners {
		if err := beat(listener, start); err != nil {
			return nil, err
		}
	}
	streams := []*socketLoadStream{}
	findTimes := []time.Duration{}
	findsPerTick := float64(settings.FindsPerSecond) * settings.Tick.Seconds()
	findDebt := 0.0
	nextDialer := 0
	nextGroup := 0
	nextSample := start.Add(settings.Warmup)
	sampleCount := 0
	verifyKeys := ticketKeys.VerifyKeys()
	for now := clock.Now(); now.Sub(start) < settings.Duration; now = clock.Now() {
		if err := runCtx.Err(); err != nil {
			return nil, err
		}
		// streams due end
		kept := streams[:0]
		for _, stream := range streams {
			if now.Before(stream.end) {
				kept = append(kept, stream)
				continue
			}
			stream.listener.inflight -= 1
		}
		streams = kept
		// heartbeats, and eager reports at most every EagerReportInterval
		for _, listener := range listeners {
			move := max(settings.EagerReportMinMove, settings.MaxStreams*settings.EagerReportPercent/100)
			moved := move <= listener.inflight-listener.reported || move <= listener.reported-listener.inflight
			eager := moved && settings.EagerReportInterval <= now.Sub(listener.reportTime)
			if !now.Before(listener.nextBeat) || eager {
				if !now.Before(listener.nextBeat) {
					listener.nextBeat = listener.nextBeat.Add(settings.HeartbeatInterval)
				}
				if err := beat(listener, now); err != nil {
					return nil, err
				}
			}
		}
		// the step's Finds
		findDebt += findsPerTick
		for ; 1 <= findDebt; findDebt -= 1 {
			dialer := dialers[nextDialer]
			nextDialer = (nextDialer + 1) % len(dialers)
			group := nextGroup
			nextGroup = (nextGroup + 1) % settings.GroupCount
			result := &sidecar.SocketFindResult{}
			elapsed, err := serve(http.MethodPost, "/socket/find", dialer.token, &sidecar.SocketFindArgs{NameToken: nameKeys[group], NetworkId: &networkId}, result)
			report.FindCount += 1
			findTimes = append(findTimes, elapsed)
			switch {
			case err != nil:
				report.FindRefusals["failed"] += 1
				continue
			case result.Error != nil:
				report.FindRefusals[string(result.Error.Code)] += 1
				continue
			}
			// the primary, else the backup when the primary's listener is full, as its admission answers busy
			opened := false
			for _, findTicket := range []*sidecar.SocketFindTicket{result.Primary, result.Backup} {
				if findTicket == nil {
					continue
				}
				ticket, err := sidecar.VerifySocketTicket(findTicket.Ticket, verifyKeys, uint64(now.UnixMilli()))
				if err != nil {
					break
				}
				listenerClientId, err := sidecar.IdFromBytes(ticket.GetListenerClientId())
				listener := listenerByClientId[connect.Id(listenerClientId)]
				if err != nil || listener == nil {
					break
				}
				if settings.MaxStreams <= listener.inflight {
					report.ListenerBusyCount += 1
					continue
				}
				listener.inflight += 1
				streams = append(streams, &socketLoadStream{listener: listener, end: now.Add(settings.StreamDuration)})
				opened = true
				break
			}
			if opened {
				report.FindOkCount += 1
			} else {
				report.FindRefusals["failed"] += 1
			}
		}
		// a sample past the warmup
		if !now.Before(nextSample) {
			nextSample = nextSample.Add(settings.SampleInterval)
			sampleCount += 1
			for _, listener := range listeners {
				listener.sampledSum += int64(listener.inflight)
			}
		}
		clock.Advance(settings.Tick)
	}
	report.RegistrationCallsPerSecond = float64(report.RegistrationCallCount) / settings.Duration.Seconds()
	if 0 < len(findTimes) {
		slices.Sort(findTimes)
		report.FindP50 = findTimes[len(findTimes)/2]
		report.FindP99 = findTimes[min(len(findTimes)-1, len(findTimes)*99/100)]
	}
	if 0 < sampleCount {
		groupSampled := make([]int64, settings.GroupCount)
		groupWeight := make([]int64, settings.GroupCount)
		for _, listener := range listeners {
			groupSampled[listener.group] += listener.sampledSum
			groupWeight[listener.group] += int64(listener.weight)
		}
		for _, listener := range listeners {
			if groupSampled[listener.group] == 0 {
				continue
			}
			observed := float64(listener.sampledSum) / float64(groupSampled[listener.group])
			expected := float64(listener.weight) / float64(groupWeight[listener.group])
			deviation := observed/expected - 1
			if deviation < 0 {
				deviation = -deviation
			}
			report.ShareMaxDeviation = max(report.ShareMaxDeviation, deviation)
		}
	}
	return report, nil
}

// A group's name key: a one-segment token path, 16 bytes.
func binaryNameKey(group int) []byte {
	nameKey := make([]byte, 16)
	copy(nameKey, fmt.Sprintf("load group %d", group))
	return nameKey
}
