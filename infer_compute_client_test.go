//go:build !ios_extension && !sidecar_http

package sidecar

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// Credentials a test scripts: each token in turn after a forget, and proofs that name what they sign.
type testComputeCredentials struct {
	stateLock sync.Mutex
	tokens    []string
	forgotten int
	tokenErr  error
}

func (self *testComputeCredentials) token(ctx context.Context) (string, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.tokenErr != nil {
		return "", self.tokenErr
	}
	return self.tokens[min(self.forgotten, len(self.tokens)-1)], nil
}

func (self *testComputeCredentials) forget() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.forgotten += 1
}

func (self *testComputeCredentials) proof(method string, url string, accessToken string) (string, error) {
	return "proof " + method + " " + url + " " + dpopAth(accessToken), nil
}

// One request a test broker saw.
type testComputeRequest struct {
	method        string
	path          string
	authorization string
	dpop          string
	contentType   string
	body          []byte
}

// A broker over TLS that answers each request by script, recording what it saw.
type testComputeBroker struct {
	server *httptest.Server

	stateLock sync.Mutex
	requests  []*testComputeRequest
	answer    func(index int, request *testComputeRequest, writer http.ResponseWriter)
}

func newTestComputeBroker(t *testing.T, answer func(index int, request *testComputeRequest, writer http.ResponseWriter)) *testComputeBroker {
	broker := &testComputeBroker{answer: answer}
	broker.server = httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, _ := io.ReadAll(request.Body)
		seen := &testComputeRequest{
			method:        request.Method,
			path:          request.URL.Path,
			authorization: request.Header.Get("Authorization"),
			dpop:          request.Header.Get(computeServiceDpopHeader),
			contentType:   request.Header.Get("Content-Type"),
			body:          body,
		}
		broker.stateLock.Lock()
		index := len(broker.requests)
		broker.requests = append(broker.requests, seen)
		broker.stateLock.Unlock()
		broker.answer(index, seen, writer)
	}))
	t.Cleanup(broker.server.Close)
	return broker
}

// What the broker saw.
func (self *testComputeBroker) seen() []*testComputeRequest {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return append([]*testComputeRequest{}, self.requests...)
}

// A client of broker with credentials, on clock.
func newTestComputeServiceClient(t *testing.T, broker *testComputeBroker, credentials *testComputeCredentials, settings *InferSettings, clock Clock) *ComputeServiceClient {
	t.Helper()
	if settings == nil {
		settings = DefaultInferSettings()
	}
	client, err := newComputeServiceClient(&computeServiceClientArgs{
		BaseUrl:     broker.server.URL,
		Credentials: credentials,
		Settings:    settings,
		HttpClient:  broker.server.Client(),
		Clock:       clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

// Writes message as the broker's protobuf answer, its clock at brokerTime.
func testComputeAnswer(writer http.ResponseWriter, message proto.Message, brokerTime time.Time) {
	body, _ := proto.MarshalOptions{Deterministic: true}.Marshal(message)
	writer.Header().Set("Content-Type", computeServiceProtobufContentType)
	writer.Header().Set(ComputeServiceTimeHeader, strconv.FormatInt(brokerTime.UnixMilli(), 10))
	writer.WriteHeader(http.StatusOK)
	writer.Write(body)
}

// Writes the broker's refusal.
func testComputeRefuse(writer http.ResponseWriter, status int, body string) {
	writer.Header().Set("Content-Type", computeServiceJsonContentType)
	writer.WriteHeader(status)
	writer.Write([]byte(body))
}

// Each request carries the compute token as its bearer and the ClientKey's proof of its method, url and token, over
// https alone, and the client keeps the broker's clock from the answer.
func TestComputeClientCarriesDpopAndReadsClock(t *testing.T) {
	clock := newTestEnvelopeClock()
	brokerTime := clock.Now().Add(3*time.Second + 250*time.Millisecond)
	broker := newTestComputeBroker(t, func(index int, request *testComputeRequest, writer http.ResponseWriter) {
		testComputeAnswer(writer, &protocol.InferCatalogAnswer{Version: 7}, brokerTime)
	})
	credentials := &testComputeCredentials{tokens: []string{"compute-token-1"}}
	client := newTestComputeServiceClient(t, broker, credentials, nil, clock)
	if _, known := client.BrokerNow(); known {
		t.Error("a broker clock before any answer")
	}
	answer := &protocol.InferCatalogAnswer{}
	if err := client.Get(context.Background(), "/v1/catalog", answer, 0); err != nil {
		t.Fatal(err)
	}
	if answer.GetVersion() != 7 {
		t.Errorf("answered %v", answer)
	}
	seen := broker.seen()
	if len(seen) != 1 {
		t.Fatalf("%d requests", len(seen))
	}
	url := broker.server.URL + "/v1/catalog"
	if seen[0].authorization != "Bearer compute-token-1" || seen[0].dpop != "proof GET "+url+" "+dpopAth("compute-token-1") {
		t.Errorf("the request's credentials: %q, %q", seen[0].authorization, seen[0].dpop)
	}
	brokerNow, known := client.BrokerNow()
	if !known || !brokerNow.Equal(brokerTime) {
		t.Errorf("the broker's clock reads %v (%t), the broker's %v", brokerNow, known, brokerTime)
	}
	clock.Advance(time.Minute)
	if brokerNow, _ := client.BrokerNow(); !brokerNow.Equal(brokerTime.Add(time.Minute)) {
		t.Errorf("a minute on, the broker's clock reads %v", brokerNow)
	}

	// a POST's body is protobuf, and http is refused before anything is sent
	if err := client.Post(context.Background(), "/v1/infer/dispute", &protocol.InferCatalogAnswer{Version: 1}, nil, 0); err != nil {
		t.Fatal(err)
	}
	if seen := broker.seen(); seen[1].method != http.MethodPost || seen[1].contentType != computeServiceProtobufContentType || len(seen[1].body) == 0 {
		t.Errorf("the POST: %+v", seen[1])
	}
	for _, base := range []string{"http://compute.example", "https://user@compute.example", "https://compute.example/v1", "compute.example"} {
		if _, err := newComputeServiceClient(&computeServiceClientArgs{BaseUrl: base, Credentials: credentials, Settings: DefaultInferSettings()}); err == nil {
			t.Errorf("%s was taken", base)
		}
	}
	unconfigured, err := newComputeServiceClient(&computeServiceClientArgs{Credentials: credentials, Settings: DefaultInferSettings()})
	if err != nil {
		t.Fatal(err)
	}
	if err := unconfigured.Get(context.Background(), "/v1/catalog", answer, 0); !errors.Is(err, ErrComputeServiceUnconfigured) {
		t.Errorf("with no url: %v", err)
	}
	if err := client.Get(context.Background(), "/elsewhere", answer, 0); !errors.Is(err, ErrComputeServiceRequest) {
		t.Errorf("a path off compute/v1: %v", err)
	}
}

// A 401 drops the token and asks once more under a new one; a 503 is asked again within the retries; any other
// refusal goes back at once with the broker's code, which errors.Is matches; and an answer past its bound is refused.
func TestComputeClientRenewsTokenRetriesAndBounds(t *testing.T) {
	clock := newTestEnvelopeClock()
	settings := DefaultInferSettings()
	// no wait between tries, so the fake clock never has to move
	settings.ComputeServiceRetryInterval = 0
	settings.ComputeServiceRetryAfterMaxDuration = 0
	broker := newTestComputeBroker(t, func(index int, request *testComputeRequest, writer http.ResponseWriter) {
		switch {
		case request.path == "/v1/renew" && request.authorization == "Bearer old":
			testComputeRefuse(writer, http.StatusUnauthorized, `{"code":"unauthenticated"}`)
		case request.path == "/v1/renew":
			testComputeAnswer(writer, &protocol.InferCatalogAnswer{Version: 2}, clock.Now())
		case request.path == "/v1/busy" && index < 4:
			testComputeRefuse(writer, http.StatusServiceUnavailable, `{"code":"unavailable","retry_after_ms":1000}`)
		case request.path == "/v1/busy":
			testComputeAnswer(writer, &protocol.InferCatalogAnswer{Version: 3}, clock.Now())
		case request.path == "/v1/stale":
			testComputeRefuse(writer, http.StatusConflict, `{"code":"catalog_stale"}`)
		case request.path == "/v1/odd":
			testComputeRefuse(writer, http.StatusConflict, `{"code":"Not A Code <script>"}`)
		default:
			testComputeAnswer(writer, &protocol.InferCatalogAnswer{Version: 4, Models: []*protocol.InferCatalogModel{{Provider: strings.Repeat("x", 4096)}}}, clock.Now())
		}
	})
	credentials := &testComputeCredentials{tokens: []string{"old", "new"}}
	client := newTestComputeServiceClient(t, broker, credentials, settings, clock)
	answer := &protocol.InferCatalogAnswer{}
	if err := client.Get(context.Background(), "/v1/renew", answer, 0); err != nil || answer.GetVersion() != 2 || credentials.forgotten != 1 {
		t.Errorf("after a 401: %v, %v, forgotten %d", answer, err, credentials.forgotten)
	}
	if err := client.Get(context.Background(), "/v1/busy", answer, 0); err != nil || answer.GetVersion() != 3 {
		t.Errorf("after two 503s: %v, %v", answer, err)
	}
	err := client.Get(context.Background(), "/v1/stale", answer, 0)
	var refusal *ComputeServiceError
	if !errors.As(err, &refusal) || refusal.Code != "catalog_stale" || refusal.Status != http.StatusConflict ||
		!errors.Is(err, &ComputeServiceError{Code: "catalog_stale"}) || errors.Is(err, &ComputeServiceError{Code: "capacity"}) {
		t.Errorf("a refusal: %v", err)
	}
	if err := client.Get(context.Background(), "/v1/odd", answer, 0); !errors.As(err, &refusal) || refusal.Code != "status_409" ||
		strings.Contains(err.Error(), "script") {
		t.Errorf("a refusal whose code is no word: %v", err)
	}
	if err := client.Get(context.Background(), "/v1/large", answer, 1024); !errors.Is(err, ErrComputeServiceAnswer) {
		t.Errorf("an answer past its bound: %v", err)
	}
	settings.ComputeServiceRequestMaxByteCount = 8
	if err := client.Post(context.Background(), "/v1/large", &protocol.InferCatalogAnswer{Version: 1, PublishedMs: 1 << 40}, nil, 0); !errors.Is(err, ErrComputeServiceRequest) {
		t.Errorf("a request past its bound: %v", err)
	}
	credentials.tokenErr = ErrSidecarServiceTokenLocked
	before := len(broker.seen())
	if err := client.Get(context.Background(), "/v1/renew", answer, 0); !errors.Is(err, ErrSidecarServiceTokenLocked) || len(broker.seen()) != before {
		t.Errorf("with no token: %v, %d requests sent", err, len(broker.seen())-before)
	}
}
