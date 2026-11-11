// GET /socket/list and GET /socket/keys at T2 (SOCK-M5-05): a network's own names, edge names in the clear and
// blinded ones as token paths with their seals, in pages that each take a token of the caller's bucket; and
// the ticket keys for anyone.

package socketsservice_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/socketsservice"
)

// A network's names page by cursor, each page at most ListPageCount, edge names in the clear and blinded ones as
// their token paths and seals; another network's client sees none of them.
func TestSocketListPagesTheNetworksOwnNames(t *testing.T) {
	world := newTestSocketWorld(t)
	process := world.newProcess(func(settings *socketsservice.SocketsSettings) {
		settings.ListPageCount = 2
	})
	if err := process.service.RegisterNamespace(sidecar.SocketNamespaceTls, &testSocketRecordingHooks{}); err != nil {
		t.Fatal(err)
	}
	listener := testSocketEnrolledListener(world, process)
	blinded := []*sidecar.SocketRegistration{
		listener.blindedRegistration(t, testSocketTokenPath(t, 1)),
		listener.blindedRegistration(t, testSocketTokenPath(t, 2)),
	}
	edge := listener.edgeRegistration(t, "tls/443/blog", "tls", "http")
	process.registerOk(listener, 1, blinded[0], blinded[1], edge)

	listed := []*sidecar.SocketListName{}
	cursor := ""
	for page := 0; ; page += 1 {
		code, result := process.list(listener.token, cursor)
		if code != http.StatusOK || result.Error != nil || 2 < len(result.Names) {
			t.Fatalf("page %d answered %d, %+v", page, code, result)
		}
		listed = append(listed, result.Names...)
		if result.NextCursor == "" {
			break
		}
		cursor = result.NextCursor
	}
	if len(listed) != 3 {
		t.Fatalf("%d names listed", len(listed))
	}
	for _, name := range listed {
		switch {
		case name.Name != "":
			if name.Name != "tls/443/blog" || len(name.NameToken) != 0 || len(name.SealedName) != 0 {
				t.Errorf("an edge name listed as %+v", name)
			}
		default:
			found := false
			for _, registration := range blinded {
				if bytes.Equal(registration.NameToken, name.NameToken) && bytes.Equal(registration.SealedName, name.SealedName) {
					found = true
				}
			}
			if !found {
				t.Errorf("a blinded name listed as %+v", name)
			}
		}
	}

	stranger := world.newSidecar(testSocketId())
	code, result := process.list(stranger.token, "")
	if code != http.StatusOK || result.Error != nil || len(result.Names) != 0 {
		t.Fatalf("another network's client answered %d, %+v", code, result)
	}
	if code, result := process.list(listener.token, "not-a-cursor"); code != http.StatusOK || result.Error == nil || result.Error.Code != sidecar.SocketErrorCodeInvalid {
		t.Fatalf("a cursor no page gave answered %d, %+v", code, result)
	}
	if code, _ := process.list("", ""); code != http.StatusUnauthorized {
		t.Fatalf("no token answered %d", code)
	}
}

// Each page of a listing is one token of the caller's bucket (SOCK.md reading 10).
func TestSocketListChargesTheBucket(t *testing.T) {
	world := newTestSocketWorld(t)
	process := world.newProcess(nil)
	listener := testSocketEnrolledListener(world, process)
	for index := range 500 {
		if code, result := process.list(listener.token, ""); code != http.StatusOK || result.Error != nil {
			t.Fatalf("page %d answered %d, %+v", index, code, result)
		}
	}
	code, result := process.list(listener.token, "")
	if code != http.StatusOK || result.Error == nil || result.Error.Code != sidecar.SocketErrorCodeUnavailable || result.Error.RetryAfterMs == 0 {
		t.Fatalf("a page past the burst answered %d, %+v", code, result)
	}
}

// GET /socket/keys answers anyone, with every key a ticket verifies under, and none from an engine with no keys.
func TestSocketKeysArePublic(t *testing.T) {
	world := newTestSocketWorld(t)
	process := world.newProcess(nil)
	recorder := process.call(http.MethodGet, "/socket/keys", "", nil)
	if recorder.Code != http.StatusOK {
		t.Fatalf("answered %d", recorder.Code)
	}
	result := &sidecar.SocketKeysResult{}
	if err := json.Unmarshal(recorder.Body.Bytes(), result); err != nil {
		t.Fatal(err)
	}
	if len(result.Keys) != 1 || result.Keys[0].KeyId != "k1" || !bytes.Equal(result.Keys[0].PublicKey, world.ticketKeys.VerifyKeys()[0].PublicKey) {
		t.Fatalf("keys %+v", result.Keys)
	}
	process.service.SetTicketKeys(nil)
	recorder = process.call(http.MethodGet, "/socket/keys", "", nil)
	if err := json.Unmarshal(recorder.Body.Bytes(), result); err != nil || recorder.Code != http.StatusOK || len(result.Keys) != 0 {
		t.Fatalf("an engine with no keys answered %d, %+v, %v", recorder.Code, result, err)
	}
}
