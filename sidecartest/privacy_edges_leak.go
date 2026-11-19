//go:build sidecar_leaktest

// The leaks of CC4's M5 classes (privacy_edges.go; §22.7's self-test; TEST-M5-01): each puts a value through the path
// a real bug would take into its class, an edge's own store write, the report intake's row, a dialer's Find over its
// transport, a querier's bytes to a dns edge, and a query handed to the upstream resolver. None goes through
// PrivacyCapture.Add. This file links only under sidecar_leaktest, which check/ fails on any release leg.

package sidecartest

import (
	"bytes"
	"io"
	stdnet "net"
	"net/http"
	"slices"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/smtpedgeservice"
	"github.com/urnetwork/sidecar/tlsedgeservice"
)

// tlsedge's bug: the hello's server name, or what followed it, where the record's published host belongs.
var _ = RegisterLeak(&Leak{Class: PrivacyClassEdgeRecord, Binary: true, Put: func(t testing.TB, net *Net, value []byte) {
	store := NewFakeTlsEdgeStore(nil)
	net.Capture().AddTlsEdgeRecords("tlsedge1", store)
	record := &tlsedgeservice.TlsConnectionRecord{ConnectionId: sidecar.NewId(), NetworkId: sidecar.NewId(), Host: string(value)}
	if err := store.InsertConnectionRecords(t.Context(), []*tlsedgeservice.TlsConnectionRecord{record}); err != nil {
		t.Fatal(err)
	}
}})

// The intake's bug: a reported message's text where the complaint's reporter belongs.
var _ = RegisterLeak(&Leak{Class: PrivacyClassReportParse, Binary: true, Put: func(t testing.TB, net *Net, value []byte) {
	store := NewFakeSmtpEdgeStore(net.Clock(), nil)
	net.Capture().AddReportParse("mxedge1", store, nil)
	complaint := &smtpedgeservice.SmtpComplaint{ComplaintId: sidecar.NewId(), NetworkId: sidecar.NewId(), Reporter: string(value)}
	if err := store.InsertComplaint(t.Context(), complaint); err != nil {
		t.Fatal(err)
	}
}})

// A sockets service that answers every Find with no ticket.
type leakFindTransport struct{}

func (self *leakFindTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.Body != nil {
		io.Copy(io.Discard, request.Body)
		request.Body.Close()
	}
	return &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(bytes.NewReader([]byte(`{}`))), Request: request}, nil
}

// A dialer's bug: a name in the clear where a Find carries its token path.
var _ = RegisterLeak(&Leak{Class: PrivacyClassFind, Binary: true, Embeds: true, Put: func(t testing.TB, net *Net, value []byte) {
	client := &http.Client{Transport: net.Capture().Finds("tlsedge1").Transport(&leakFindTransport{})}
	body := slices.Concat([]byte(`{"network_id":"00000000-0000-0000-0000-000000000000","name":"`), value, []byte(`"}`))
	request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "http://sockets.example/socket/find", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
}})

// A device's bug: a private name's query sent to a dns edge, which answers it on the device alone.
var _ = RegisterLeak(&Leak{Class: PrivacyClassDnsEdgeQuery, Binary: true, Put: func(t testing.TB, net *Net, value []byte) {
	querier, edge := stdnet.Pipe()
	read := make(chan struct{})
	go func() {
		defer close(read)
		io.Copy(io.Discard, edge)
		edge.Close()
	}()
	conn := net.Capture().DnsEdgeQueries("dns").WrapConn("ns1", querier)
	if _, err := conn.Write(value); err != nil {
		t.Fatal(err)
	}
	conn.Close()
	<-read
}})

// A device's bug: a private name passed on to the resolver outside URnetwork.
var _ = RegisterLeak(&Leak{Class: PrivacyClassUpstreamResolver, Binary: true, Put: func(t testing.TB, net *Net, value []byte) {
	// the query is captured as it arrived, whether or not it is a dns message
	NewFakeUpstreamResolver(net, "the host's resolver").Resolve(t.Context(), value)
}})
