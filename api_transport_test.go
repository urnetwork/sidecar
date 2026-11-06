package sidecar

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"testing"
)

// Records what reaches it, as the page Worker's fetch would see it. Answers 204.
type recordingTransport struct {
	requests []*http.Request
}

func (self *recordingTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	self.requests = append(self.requests, request)
	return &http.Response{StatusCode: http.StatusNoContent, Body: http.NoBody, Request: request}, nil
}

// Tells a refused request's body was closed, which http.RoundTripper asks of every error.
type closeRecordingBody struct {
	io.Reader
	closed bool
}

func (self *closeRecordingBody) Close() error {
	self.closed = true
	return nil
}

func newSyntheticRequest(t *testing.T, url string) *http.Request {
	t.Helper()
	request, err := http.NewRequest("POST", url, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer synthetic-token")
	return request
}

// The url a route builds when its service url is empty, and its neighbors: each would reach fetch as it
// stands, and each is refused before the transport below sees it.
func TestTransportRefusesARequestWithNoAbsoluteUrl(t *testing.T) {
	transport := &recordingTransport{}
	client := &http.Client{Transport: &absoluteUrlTransport{transport: transport}}

	for _, url := range []string{
		"",
		"/sidecar/bind",
		"sidecar/bind",
		"//page.example/sidecar/bind",
		"ftp://api.example/sidecar/bind",
		"file:///sidecar/bind",
		"https:///sidecar/bind",
		"https://user:pass@api.example/sidecar/bind",
	} {
		_, err := client.Do(newSyntheticRequest(t, url))
		if !errors.Is(err, errServiceUrl) {
			t.Errorf("%q: %v", url, err)
		}
	}
	if len(transport.requests) != 0 {
		t.Errorf("%d requests reached the transport", len(transport.requests))
	}
}

func TestTransportPassesAnAbsoluteUrl(t *testing.T) {
	transport := &recordingTransport{}
	client := &http.Client{Transport: &absoluteUrlTransport{transport: transport}}

	for _, url := range []string{"https://api.example/sidecar/bind?a=1", "http://127.0.0.1:50080/sidecar/bind"} {
		response, err := client.Do(newSyntheticRequest(t, url))
		if err != nil {
			t.Fatalf("%q: %v", url, err)
		}
		response.Body.Close()
	}
	if len(transport.requests) != 2 {
		t.Errorf("%d requests reached the transport", len(transport.requests))
	}
}

func TestTransportClosesARefusedBody(t *testing.T) {
	body := &closeRecordingBody{Reader: bytes.NewReader([]byte("synthetic"))}
	request := newSyntheticRequest(t, "/sidecar/bind")
	request.Body = body

	transport := &absoluteUrlTransport{transport: &recordingTransport{}}
	if _, err := transport.RoundTrip(request); !errors.Is(err, errServiceUrl) {
		t.Fatal(err)
	}
	if !body.closed {
		t.Error("a refused request's body stayed open")
	}
}

func TestTransportRefusesARequestWithNoUrl(t *testing.T) {
	transport := &absoluteUrlTransport{transport: &recordingTransport{}}
	if _, err := transport.RoundTrip(&http.Request{}); !errors.Is(err, errServiceUrl) {
		t.Errorf("err %v", err)
	}
}
