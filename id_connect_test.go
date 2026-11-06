//go:build !sidecar_http

package sidecar

import (
	"encoding/json"
	"testing"

	"github.com/urnetwork/connect"
)

// Stops compiling if the two layouts drift, since this conversion is the whole boundary.
var (
	_ = connect.Id(Id{})
	_ = Id(connect.Id{})
)

func TestIdReadsAsConnectIdDoes(t *testing.T) {
	for i := 0; i < 1000; i += 1 {
		connectId := connect.NewId()
		id := Id(connectId)

		if id.String() != connectId.String() {
			t.Fatalf("string %q, connect %q", id, connectId)
		}
		rootJson, err := json.Marshal(id)
		if err != nil {
			t.Fatal(err)
		}
		connectJson, err := json.Marshal(connectId)
		if err != nil {
			t.Fatal(err)
		}
		if string(rootJson) != string(connectJson) {
			t.Fatalf("json %s, connect %s", rootJson, connectJson)
		}
		if string(id.Bytes()) != string(connectId.Bytes()) {
			t.Fatalf("bytes %x, connect %x", id.Bytes(), connectId.Bytes())
		}
	}
}

func TestIdSortsAsConnectIdDoes(t *testing.T) {
	previous := connect.NewId()
	for i := 0; i < 1000; i += 1 {
		next := connect.NewId()
		if Id(previous).Cmp(Id(next)) != previous.Cmp(next) {
			t.Fatalf("Cmp of %v and %v disagrees", previous, next)
		}
		if Id(next).Cmp(Id(previous)) != next.Cmp(previous) {
			t.Fatalf("Cmp of %v and %v disagrees", next, previous)
		}
		previous = next
	}
}

func TestConnectParsesRootIds(t *testing.T) {
	id := NewId()

	parsed, err := connect.ParseId(id.String())
	if err != nil {
		t.Fatal(err)
	}
	if Id(parsed) != id {
		t.Errorf("connect parsed %v, want %v", parsed, id)
	}

	src, err := json.Marshal(id)
	if err != nil {
		t.Fatal(err)
	}
	var decoded connect.Id
	if err := json.Unmarshal(src, &decoded); err != nil {
		t.Fatal(err)
	}
	if Id(decoded) != id {
		t.Errorf("connect decoded %v, want %v", decoded, id)
	}
}

func TestRootParsesConnectIds(t *testing.T) {
	connectId := connect.NewId()

	parsed, err := ParseId(connectId.String())
	if err != nil {
		t.Fatal(err)
	}
	if connect.Id(parsed) != connectId {
		t.Errorf("parsed %v, want %v", parsed, connectId)
	}

	src, err := json.Marshal(connectId)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Id
	if err := json.Unmarshal(src, &decoded); err != nil {
		t.Fatal(err)
	}
	if connect.Id(decoded) != connectId {
		t.Errorf("decoded %v, want %v", decoded, connectId)
	}
}
