// ParseMlsHeader reads a member's commit with no key and refuses everything the subset refuses. mls_framing_test.go
// reads both framings through it, on messages the framing seals.

package sidecar

import (
	"bytes"
	"errors"
	"testing"
)

// A PrivateMessage of contentType, framed with the root's own encoder.
func mlsTestPrivateMessage(t *testing.T, contentType uint8, authenticatedData []byte) []byte {
	t.Helper()
	encoder := &mlsEncoder{}
	encoder.writeUint16(mlsProtocolVersion10)
	encoder.writeUint16(mlsWireFormatPrivateMessage)
	encoder.writeVector(gkmTestId("group").Bytes())
	encoder.writeUint64(41)
	encoder.writeUint8(contentType)
	encoder.writeVector(authenticatedData)
	encoder.writeVector(bytes.Repeat([]byte{0xee}, 20))
	encoder.writeVector(bytes.Repeat([]byte{0xcc}, 300))
	encoded, err := encoder.finish()
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func TestParseMlsHeaderReadsAMembersCommit(t *testing.T) {
	authenticatedData := []byte("a GkmCommitHeader")
	header, err := ParseMlsHeader(mlsTestPrivateMessage(t, mlsContentTypeCommit, authenticatedData))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(header.GroupId, gkmTestId("group").Bytes()) || header.Epoch != 41 || header.ContentType != 3 ||
		!bytes.Equal(header.AuthenticatedData, authenticatedData) {
		t.Errorf("header %+v", header)
	}
}

func TestParseMlsHeaderRefusesWhatTheSubsetRefuses(t *testing.T) {
	commit := mlsTestPrivateMessage(t, mlsContentTypeCommit, []byte("header"))
	withWireFormat := func(wireFormat uint16) []byte {
		changed := bytes.Clone(commit)
		changed[2], changed[3] = byte(wireFormat>>8), byte(wireFormat)
		return changed
	}
	refusals := map[string][]byte{
		"application data":                            mlsTestPrivateMessage(t, 1, nil),
		"a standalone proposal":                       mlsTestPrivateMessage(t, 2, nil),
		"content type 0":                              mlsTestPrivateMessage(t, 0, nil),
		"a PrivateMessage's bytes as a PublicMessage": withWireFormat(mlsWireFormatPublicMessage),
		"a Welcome":                                   withWireFormat(3),
		"a GroupInfo":                                 withWireFormat(4),
		"a KeyPackage":                                withWireFormat(5),
		"wire format 0":                               withWireFormat(0),
		"version 2":                                   append([]byte{0, 2}, commit[2:]...),
		"a byte past the message":                     append(bytes.Clone(commit), 0),
		"a message cut short":                         commit[:len(commit)-1],
		"nothing":                                     {},
		"a three-byte header only":                    commit[:3],
	}
	for name, message := range refusals {
		if _, err := ParseMlsHeader(message); err == nil {
			t.Errorf("%s was read", name)
		} else if !errors.Is(err, errMlsRefused) && !errors.Is(err, errMlsMalformed) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// KEK_e is the exporter's "UR evs 1.0 kek" output for the repo, 32 bytes.
func TestMlsKekIsTheEpochsExport(t *testing.T) {
	exporter := mlsTestExporter{secret: gkmTestBytes("exporter secret", 32)}
	repoId := gkmTestId("repo")
	kek, err := MlsKek(exporter, repoId)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := exporter.Exporter("UR evs 1.0 kek", repoId.Bytes(), 32)
	if !bytes.Equal(kek, want) {
		t.Error("another export")
	}
	if _, err := MlsKek(mlsTestExporter{short: true}, repoId); err == nil {
		t.Error("a short KEK passed")
	}
}

// An exporter over the suite's own MLS-Exporter, or one that answers short.
type mlsTestExporter struct {
	secret []byte
	short  bool
}

// MLS-Exporter under the production suite.
func (self mlsTestExporter) Exporter(label string, context []byte, length int) ([]byte, error) {
	if self.short {
		return make([]byte, length-1), nil
	}
	return mlsSuite.exporter("test", self.secret, label, context, length)
}
