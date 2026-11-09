// §6.8's sync routes on T2's api (PROTO-M1-11): GET /sidecar/sync/poll and GET /sidecar/sync/versions,
// as server's handlers answer them (server/api/handlers/sidecar_sync_handlers.go), from the Net's hint
// state (push_net.go). A poll holds on pushservice's own LongPoll, its holds on the Net's clock; a
// versions page is pushservice.VersionsPage of {scp_<C>}ver, core taken from it or else from the api's
// clock in µs, as server's controller fills it. Each answers a binary PollResponse,
// application/octet-stream, never 204, its cursor taken from the query as base64url with no padding.
//
// The bearer names the client, as a sidecar's strict_exp token does, and one this api does not know is
// 401. An api with no hint state, one NewFakeApi made outside a Net, answers 503 with Retry-After, as
// server does while its push gate is closed. T3 runs the same requests on server's routes (Q-TEST-1).

package sidecartest

import (
	"encoding/base64"
	"errors"
	"net/http"
	"strconv"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/pushservice"
)

// What a refused poll is asked to wait, in whole seconds: the long-poll's busy answer, as server asks.
func fakeApiSyncRetryAfter() string {
	return strconv.Itoa(int(pushservice.DefaultLongPollSettings().BusyRetryAfter / time.Second))
}

// The sync routes' state: where the hint state comes from. Set once, when Net.AddApi makes the api, and
// read only after.
type fakeApiSyncState struct {
	// the Net's hint state, nil outside a Net
	push func() (*netPush, error)
}

// The routes, on the api's mux.
func (self *FakeApi) addSyncRoutes() {
	self.mux.HandleFunc("GET /sidecar/sync/poll", self.counted("GET /sidecar/sync/poll", self.handleSyncPoll))
	self.mux.HandleFunc("GET /sidecar/sync/versions", self.counted("GET /sidecar/sync/versions", self.handleSyncVersions))
}

// The hint state, or false having answered the request 503, as a closed push gate does.
func (self *FakeApi) syncPush(writer http.ResponseWriter) (*netPush, bool) {
	if self.sync.push == nil {
		writer.Header().Set("Retry-After", fakeApiSyncRetryAfter())
		fakeApiRefuse(writer, http.StatusServiceUnavailable, "", "Sidecar push is off.", nil)
		return nil, false
	}
	plane, err := self.sync.push()
	if err != nil {
		writer.Header().Set("Retry-After", fakeApiSyncRetryAfter())
		fakeApiRefuse(writer, http.StatusServiceUnavailable, "", "Sidecar push is off.", nil)
		return nil, false
	}
	return plane, true
}

// The client the bearer names and the cursor the query carries, or false having answered 401 or 400.
func (self *FakeApi) syncClientAndCursor(writer http.ResponseWriter, request *http.Request) (connect.Id, []byte, bool) {
	client := self.client(request)
	if client == nil {
		fakeApiRefuse(writer, http.StatusUnauthorized, "", "Not authorized.", nil)
		return connect.Id{}, nil, false
	}
	cursor := []byte(nil)
	if encoded := request.URL.Query().Get("cursor"); encoded != "" {
		decoded, err := base64.RawURLEncoding.DecodeString(encoded)
		if err != nil {
			fakeApiRefuse(writer, http.StatusBadRequest, "", "Invalid cursor.", nil)
			return connect.Id{}, nil, false
		}
		cursor = decoded
	}
	return connect.Id(client.clientId), cursor, true
}

// Writes response as a sync route's 200 body.
func fakeApiWritePollResponse(writer http.ResponseWriter, response *protocol.PollResponse) {
	body, err := proto.Marshal(response)
	if err != nil {
		fakeApiRefuse(writer, http.StatusInternalServerError, "", "Unexpected error.", nil)
		return
	}
	writer.Header().Set("Content-Type", "application/octet-stream")
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(http.StatusOK)
	writer.Write(body)
}

// GET /sidecar/sync/poll?cursor=: one poll, held on the Net's clock until a hint or HoldTimeout. Past the
// long-poll's bound on held polls, 503 with Retry-After.
func (self *FakeApi) handleSyncPoll(writer http.ResponseWriter, request *http.Request) {
	plane, ok := self.syncPush(writer)
	if !ok {
		return
	}
	clientId, cursor, ok := self.syncClientAndCursor(writer, request)
	if !ok {
		return
	}
	response, err := plane.longPoll.Poll(request.Context(), clientId, cursor)
	switch {
	case errors.Is(err, pushservice.ErrLongPollBusy), errors.Is(err, pushservice.ErrLongPollClosed):
		writer.Header().Set("Retry-After", fakeApiSyncRetryAfter())
		fakeApiRefuse(writer, http.StatusServiceUnavailable, "", "Too many held polls.", nil)
		return
	case err != nil:
		fakeApiRefuse(writer, http.StatusInternalServerError, "", "Unexpected error.", nil)
		return
	}
	fakeApiWritePollResponse(writer, response)
}

// GET /sidecar/sync/versions?cursor=: one page of the client's versions, reset set and no hints.
func (self *FakeApi) handleSyncVersions(writer http.ResponseWriter, request *http.Request) {
	plane, ok := self.syncPush(writer)
	if !ok {
		return
	}
	clientId, cursor, ok := self.syncClientAndCursor(writer, request)
	if !ok {
		return
	}
	fieldValues, err := plane.redis.HashGetAll(request.Context(), pushservice.HintVersionsKey(clientId))
	if err != nil {
		fakeApiRefuse(writer, http.StatusInternalServerError, "", "Unexpected error.", nil)
		return
	}
	topicVersions := pushservice.ParseHintVersions(fieldValues)
	if _, ok := topicVersions[sidecar.PushTopicCore]; !ok {
		// api's clock in µs, core's version when ver holds none (plan-CORE-core-hint-body #3)
		topicVersions[sidecar.PushTopicCore] = uint64(self.clock.Now().UnixMicro())
	}
	response, err := pushservice.VersionsPage(topicVersions, cursor)
	if errors.Is(err, pushservice.ErrVersionsCursor) {
		fakeApiRefuse(writer, http.StatusBadRequest, "", "Invalid cursor.", nil)
		return
	}
	if err != nil {
		fakeApiRefuse(writer, http.StatusInternalServerError, "", "Unexpected error.", nil)
		return
	}
	fakeApiWritePollResponse(writer, response)
}
