// The lb's 502 and 504 (QD-758; §11.8's retry id row, §22.8's lb drain row): a 502 or 504 whose body is not an evs
// refusal is no answer from evs at all, so a segment upload and a push send the same bytes again after
// ReadRetryWait until evs answers, and an evs refusal a 502 or 504 carries keeps its meaning. Against the stand-in
// evs of the write tests (evs_plan_test.go), behind a stand-in lb that answers in its place.

package sidecar

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// nginx's own pages for a 502 and a 504, as the lb answers when the block a request reached died or went silent.
const (
	evsTestLbBadGatewayPage     = "<html>\r\n<head><title>502 Bad Gateway</title></head>\r\n<body>\r\n<center><h1>502 Bad Gateway</h1></center>\r\n<hr><center>nginx</center>\r\n</body>\r\n</html>\r\n"
	evsTestLbGatewayTimeoutPage = "<html>\r\n<head><title>504 Gateway Time-out</title></head>\r\n<body>\r\n<center><h1>504 Gateway Time-out</h1></center>\r\n<hr><center>nginx</center>\r\n</body>\r\n</html>\r\n"
)

// What the stand-in lb answers one request in evs's place.
type evsTestLbAnswer struct {
	status int
	body   []byte
	// The request goes on to evs first and its answer is dropped: the lb's 502 after the block it reached committed.
	passFirst bool
}

// One request as it reached the lb.
type evsTestLbRequest struct {
	target string
	body   []byte
}

// A stand-in lb in front of a test evs: it answers each route's next requests from its queue, and passes the rest on.
// Routes are "segment" for a segment PUT, "push" for a push's POST and "other".
type evsTestLb struct {
	evs http.Handler

	stateLock sync.Mutex
	answers   map[string][]*evsTestLbAnswer
	requests  map[string][]*evsTestLbRequest
}

func newEvsTestLb(evs http.Handler) *evsTestLb {
	return &evsTestLb{evs: evs, answers: map[string][]*evsTestLbAnswer{}, requests: map[string][]*evsTestLbRequest{}}
}

// The route a request names.
func evsTestLbRoute(request *http.Request) string {
	switch {
	case request.Method == http.MethodPut && strings.Contains(request.URL.Path, "/segments/"):
		return "segment"
	case request.Method == http.MethodPost && strings.HasSuffix(request.URL.Path, "/push"):
		return "push"
	}
	return "other"
}

// Answers route's next requests with answers, in order, before passing any on.
func (self *evsTestLb) answer(route string, answers ...*evsTestLbAnswer) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.answers[route] = append(self.answers[route], answers...)
}

// The requests of route that reached the lb, in order.
func (self *evsTestLb) requestsOf(route string) []*evsTestLbRequest {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return append([]*evsTestLbRequest{}, self.requests[route]...)
}

func (self *evsTestLb) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	route := evsTestLbRoute(request)
	body, err := io.ReadAll(request.Body)
	if err != nil {
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	var answer *evsTestLbAnswer
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.requests[route] = append(self.requests[route], &evsTestLbRequest{target: request.URL.RequestURI(), body: body})
		if answers := self.answers[route]; 0 < len(answers) {
			answer = answers[0]
			self.answers[route] = answers[1:]
		}
	}()
	request.Body = io.NopCloser(bytes.NewReader(body))
	if answer == nil {
		self.evs.ServeHTTP(writer, request)
		return
	}
	if answer.passFirst {
		self.evs.ServeHTTP(httptest.NewRecorder(), request)
	}
	writer.WriteHeader(answer.status)
	writer.Write(answer.body)
}

// A test writer whose client reaches its evs through lb.
func newEvsTestWriterBehind(t *testing.T) (*evsTestWriter, *evsTestLb) {
	t.Helper()
	writer := newEvsTestWriter(t)
	lb := newEvsTestLb(writer.server)
	writer.test.client.args.Transport = &evsTestTransport{handler: lb}
	writer.test.client.http.transport = wrapSidecarApiTransport(writer.test.client.args.Transport)
	return writer, lb
}

// Whether every request holds the first's target and bytes.
func evsTestLbSameBytes(requests []*evsTestLbRequest) bool {
	for _, request := range requests[1:] {
		if request.target != requests[0].target || !bytes.Equal(request.body, requests[0].body) {
			return false
		}
	}
	return true
}

// A 502 or 504 whose body is no evs refusal, nginx's page, nothing, text, or a reply naming no code of §11.8's table,
// is no answer from evs: its outcome unknown, no code, nothing of its body read, and so never a refusal of nothing,
// which a read alone would retry here. A read takes it as it took one before, sent once.
func TestEvsTransportReadsALbBadGatewayAsNoAnswer(t *testing.T) {
	noCode, err := proto.Marshal(&protocol.EvsRefusalReply{PushId: evsTestId("push").Bytes(), Recorded: true, RetryAfterMs: 5000})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		status int
		body   []byte
	}{
		{name: "nginx 502", status: http.StatusBadGateway, body: []byte(evsTestLbBadGatewayPage)},
		{name: "nginx 504", status: http.StatusGatewayTimeout, body: []byte(evsTestLbGatewayTimeoutPage)},
		{name: "empty 502", status: http.StatusBadGateway},
		{name: "text 504", status: http.StatusGatewayTimeout, body: []byte("upstream timed out")},
		{name: "no code 502", status: http.StatusBadGateway, body: noCode},
	}
	for _, c := range cases {
		count := 0
		test := newEvsTestClient(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			count += 1
			writer.WriteHeader(c.status)
			writer.Write(c.body)
		}), newEvsTestStore(t))
		call := &evsCall{route: "GET /evs/v1/repos/{repo_id}/refs", method: http.MethodGet,
			path: "/evs/v1/repos/" + evsUrlId(evsTestId("repo")) + "/refs", repoId: evsTestId("repo"), role: evsScopeRead, retry: true}
		err := test.client.http.callMessage(context.Background(), call, nil)
		evsError, ok := EvsErrorOf(err)
		if !ok || evsError.Status != c.status || !evsError.OutcomeUnknown || evsError.RefusesNothing() {
			t.Errorf("%s: %#v", c.name, err)
			continue
		}
		if evsError.Code != protocol.EvsRefusalCode_EVS_REFUSAL_CODE_UNSPECIFIED || evsError.PushId != nil || evsError.Recorded || evsError.RetryAfter != 0 {
			t.Errorf("%s: the lb's body was read: %#v", c.name, evsError)
		}
		if count != 1 || len(test.clock.waited()) != 0 {
			t.Errorf("%s: a read sent %d times, waiting %v", c.name, count, test.clock.waited())
		}
		if strings.Contains(err.Error(), evsTestServiceToken) {
			t.Errorf("%s: the error repeats the token", c.name)
		}
	}
}

// An evs refusal a 502 or 504 carries keeps its meaning: a final one is not retried, and one of unknown outcome is
// unknown by its own word.
func TestEvsTransportKeepsAnEvsRefusalInALbBadGateway(t *testing.T) {
	pushId := evsTestId("push")
	final, err := proto.Marshal(&protocol.EvsRefusalReply{Code: protocol.EvsRefusalCode_EVS_REFUSAL_SCOPE})
	if err != nil {
		t.Fatal(err)
	}
	unknown, err := proto.Marshal(&protocol.EvsRefusalReply{
		PushId: pushId.Bytes(), Code: protocol.EvsRefusalCode_EVS_REFUSAL_UNAVAILABLE, Outcome: protocol.EvsPushOutcome_EVS_PUSH_OUTCOME_UNKNOWN,
	})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name    string
		status  int
		body    []byte
		unknown bool
		sent    int
	}{
		{name: "final 502", status: http.StatusBadGateway, body: final, unknown: false, sent: 1},
		{name: "unknown 504", status: http.StatusGatewayTimeout, body: unknown, unknown: true, sent: 2},
	}
	for _, c := range cases {
		count := 0
		test := newEvsTestClient(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			count += 1
			if 1 < count {
				writer.WriteHeader(http.StatusOK)
				return
			}
			writer.WriteHeader(c.status)
			writer.Write(c.body)
		}), newEvsTestStore(t))
		call := &evsCall{route: "POST /evs/v1/repos/{repo_id}/push", method: http.MethodPost,
			path: "/evs/v1/repos/" + evsUrlId(evsTestId("repo")) + "/push", repoId: evsTestId("repo"), role: evsScopeWrite,
			body: &protocol.EvsPushRequest{Statement: []byte("statement")}}
		var first error
		err := test.client.retryRefusingNothing(context.Background(), func() error {
			err := test.client.http.callMessage(context.Background(), call, nil)
			if first == nil {
				first = err
			}
			return err
		})
		evsError, ok := EvsErrorOf(first)
		if !ok || evsError.Status != c.status || evsError.OutcomeUnknown != c.unknown {
			t.Errorf("%s: %#v", c.name, first)
		}
		if c.unknown && (evsError == nil || evsError.PushId == nil || *evsError.PushId != pushId) {
			t.Errorf("%s: the refusal's push id was not read: %#v", c.name, first)
		}
		if count != c.sent || (c.unknown && err != nil) || (!c.unknown && err == nil) {
			t.Errorf("%s: sent %d times, ending %v", c.name, count, err)
		}
	}
}

// A segment PUT the lb answers 502, then 504, goes again with its same segment id, push id and bytes after
// ReadRetryWait each time, and lands once: the write commits under its one push id, and reads back.
func TestEvsUploadRetriesALbBadGatewayWithTheSameBytes(t *testing.T) {
	writer, lb := newEvsTestWriterBehind(t)
	lb.answer("segment",
		&evsTestLbAnswer{status: http.StatusBadGateway, body: []byte(evsTestLbBadGatewayPage)},
		&evsTestLbAnswer{status: http.StatusGatewayTimeout, body: []byte(evsTestLbGatewayTimeoutPage)},
	)
	content := evsTestContent("lb drain", 64*1024)
	result, err := writer.write(t, "big.txt", content)
	if err != nil {
		t.Fatal(err)
	}
	uploads := lb.requestsOf("segment")
	if len(uploads) != 3 || !evsTestLbSameBytes(uploads) {
		t.Fatalf("%d segment PUTs, each the first's target and bytes: %t", len(uploads), 0 < len(uploads) && evsTestLbSameBytes(uploads))
	}
	if len(writer.server.uploads) != 1 || !strings.Contains(uploads[0].target, writer.server.uploads[0]) {
		t.Errorf("the segment landed %d times", len(writer.server.uploads))
	}
	pushIds := writer.server.postedPushIds(t)
	if len(pushIds) != 1 || result.PushId != pushIds[0] || !strings.Contains(uploads[0].target, "push="+evsUrlId(pushIds[0])) {
		t.Errorf("push ids %v, the write's %s", pushIds, result.PushId)
	}
	if len(writer.world.commits) != 1 {
		t.Errorf("%d commits", len(writer.world.commits))
	}
	retryWait := writer.test.client.settings.ReadRetryWait
	if waits := writer.test.clock.waited(); len(waits) != 2 || waits[0] != retryWait || waits[1] != retryWait {
		t.Errorf("waits %v, not ReadRetryWait twice", waits)
	}
	if read, _, err := writer.read(t, "big.txt"); err != nil || !bytes.Equal(read, content) {
		t.Errorf("read back: %v", err)
	}
}

// A push the lb answers 502 after the block it reached committed it, then 504, goes again with its same statement,
// and the retry answers the original version: one commit (FS-1's client side, the lost answer the lb's).
func TestEvsPushRetriesALbBadGatewayWithTheSameStatement(t *testing.T) {
	writer, lb := newEvsTestWriterBehind(t)
	lb.answer("push",
		&evsTestLbAnswer{status: http.StatusBadGateway, body: []byte(evsTestLbBadGatewayPage), passFirst: true},
		&evsTestLbAnswer{status: http.StatusGatewayTimeout, body: []byte(evsTestLbGatewayTimeoutPage)},
	)
	result, err := writer.write(t, "a.txt", []byte("content a"))
	if err != nil {
		t.Fatal(err)
	}
	posts := lb.requestsOf("push")
	if len(posts) != 3 || !evsTestLbSameBytes(posts) {
		t.Fatalf("%d posts, each the first's bytes: %t", len(posts), 0 < len(posts) && evsTestLbSameBytes(posts))
	}
	if result.Version != 1 || len(writer.world.commits) != 1 {
		t.Errorf("version %d after %d commits", result.Version, len(writer.world.commits))
	}
	if pushIds := writer.server.postedPushIds(t); len(pushIds) != 2 || pushIds[0] != pushIds[1] || result.PushId != pushIds[0] {
		t.Errorf("evs took push ids %v, the write's %s", pushIds, result.PushId)
	}
	retryWait := writer.test.client.settings.ReadRetryWait
	if waits := writer.test.clock.waited(); len(waits) < 2 || waits[len(waits)-2] != retryWait || waits[len(waits)-1] != retryWait {
		t.Errorf("waits %v", waits)
	}
}

// An evs refusal a 502 carries ends the push as evs's answer, sent once: nothing of it is the lb's.
func TestEvsPushReturnsAnEvsRefusalInALbBadGateway(t *testing.T) {
	writer, lb := newEvsTestWriterBehind(t)
	refusal, err := proto.Marshal(&protocol.EvsRefusalReply{Code: protocol.EvsRefusalCode_EVS_REFUSAL_SCOPE})
	if err != nil {
		t.Fatal(err)
	}
	lb.answer("push", &evsTestLbAnswer{status: http.StatusBadGateway, body: refusal})
	_, err = writer.write(t, "a.txt", []byte("content a"))
	evsError, ok := EvsErrorOf(err)
	if !ok || evsError.Status != http.StatusBadGateway || evsError.OutcomeUnknown {
		t.Fatalf("the write ended %#v", err)
	}
	if posts := lb.requestsOf("push"); len(posts) != 1 || len(writer.world.commits) != 0 {
		t.Errorf("%d posts, %d commits", len(posts), len(writer.world.commits))
	}
}
