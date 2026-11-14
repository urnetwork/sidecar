//go:build !sidecar_http && !ios_extension

// The api's clock beside another service's (§7.4, QD-757), on the legs that call the sockets service.

package sidecar

import (
	"context"
	"net/http"
	"testing"
	"time"
)

// The sockets service's answer gives its own clock, which the registrar keeps from server_time (§9.6), never api's:
// a Date 5 min off api's on an answer from the sockets origin leaves the api's reading where it stood.
func TestApiClockIsNotReadFromAnotherServicesAnswer(t *testing.T) {
	world := newTestApiClockWorld(t, 10*time.Minute)
	ctx := context.Background()
	if err := world.api.RemoveClient(ctx, NewId()); err != nil {
		t.Fatal(err)
	}
	kept := world.api.currentApiClockOffset()
	if kept != -10*time.Minute {
		t.Fatalf("offset %s", kept)
	}
	world.override = func(request *http.Request, requestIndex int) *http.Response {
		if request.URL.Host != "sockets.example" {
			return nil
		}
		return syntheticResponse(request, 200, `{"names":[]}`, world.date(http.Header{}, world.apiNow.Add(5*time.Minute)))
	}
	if _, err := world.api.SocketList(ctx, ""); err != nil {
		t.Fatal(err)
	}
	if offset := world.api.currentApiClockOffset(); offset != kept {
		t.Errorf("another service's answer moved the offset to %s", offset)
	}
}
