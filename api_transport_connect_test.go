//go:build !sidecar_http

package sidecar

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/urnetwork/connect"
)

// Answers one HTTP request on conn with body, after handing the request it read to served.
func serveOneApiRequest(conn net.Conn, body string, served chan<- *http.Request) {
	defer conn.Close()
	request, err := http.ReadRequest(bufio.NewReader(conn))
	if err != nil {
		return
	}
	// net.Pipe is unbuffered, so the client's body has to be read before it can read an answer
	io.ReadAll(request.Body)
	served <- request
	fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
}

// The connect leg's api dial goes through the client strategy's ConnectSettings().DialContext, and
// never net/http's defaults: the dial the strategy was built with sees the api's address, here
// served in process, and an environment proxy is not taken.
func TestConnectTransportDialsThroughConnectSettings(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://proxy.example:3128")
	t.Setenv("HTTPS_PROXY", "http://proxy.example:3128")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	dialLock := sync.Mutex{}
	dials := []string{}
	served := make(chan *http.Request, 1)
	presented := testBindClientJwt(NewId(), NewId())
	reply := testBindReply(1, presented, NewId())
	strategySettings := connect.DefaultClientStrategySettings()
	strategySettings.ConnectSettings.DialContextSettings = &connect.DialContextSettings{
		DialContext: func(ctx context.Context, network string, addr string) (net.Conn, error) {
			func() {
				dialLock.Lock()
				defer dialLock.Unlock()
				dials = append(dials, addr)
			}()
			if !strings.HasPrefix(network, "tcp") {
				return nil, fmt.Errorf("network %s", network)
			}
			clientConn, serverConn := net.Pipe()
			go serveOneApiRequest(serverConn, reply, served)
			return clientConn, nil
		},
	}
	strategy := connect.NewClientStrategy(ctx, strategySettings)

	settings := validSidecarSettings()
	settings.ApiUrl = "http://api.example"
	api, err := newSidecarApi(settings, newSidecarApiTransport(ctx, strategy), testApiClock)
	if err != nil {
		t.Fatal(err)
	}
	api.SetByJwt(presented)

	bound, err := api.Bind(ctx, []byte("synthetic-binding"))
	if err != nil {
		t.Fatal(err)
	}
	if bound.Generation != 1 {
		t.Errorf("generation %d", bound.Generation)
	}
	request := <-served
	if request.URL.Path != "/sidecar/bind" || request.Header.Get("Authorization") != "Bearer "+presented {
		t.Errorf("served %s %q", request.URL.Path, request.Header.Get("Authorization"))
	}
	dialLock.Lock()
	defer dialLock.Unlock()
	if !slices.Equal(dials, []string{"api.example:80"}) {
		t.Errorf("dials %q", dials)
	}
}

// Until the core installs a strategy's transport, a connect leg sends nothing rather than fall back
// to net/http's default transport.
func TestConnectLegRefusesWithoutAStrategy(t *testing.T) {
	api, err := newSidecarApi(validSidecarSettings(), nil, testApiClock)
	if err != nil {
		t.Fatal(err)
	}
	api.SetByJwt(testByJwt)
	if _, err := api.Bind(context.Background(), []byte("synthetic-binding")); !errors.Is(err, errSidecarApiNoTransport) {
		t.Errorf("err %v", err)
	}
	if _, err := api.Enroll(context.Background(), testEnrollArgs()); !errors.Is(err, errSidecarApiNoTransport) {
		t.Errorf("err %v", err)
	}
}
