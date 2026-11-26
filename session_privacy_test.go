//go:build !sidecar_http && !js

// DESIGN-COMPUTE §24.11 and §24.16's privacy row (CTXH-M11-01): DESIGN §22.7's metadata guard finds no new server field
// in the session wire. Every message §24.5 adds travels sealed, inside a record entry or a vault file, so none is a
// root a server parses, none is reachable from one, and record.proto stays a sealed file. External, since sidecartest
// imports the root, and off the sidecar_http leg, whose root lacks what sidecartest links.

package sidecar_test

import (
	"os"
	"strings"
	"testing"

	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"gopkg.in/yaml.v3"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The messages the session wire adds, and the fields it adds to messages the record had.
var testSessionWireMessages = []protoreflect.FullName{
	"urnetwork.sidecar.SessionEntryBody",
	"urnetwork.sidecar.SessionPart",
	"urnetwork.sidecar.SessionBlobBody",
	"urnetwork.sidecar.CallContext",
	"urnetwork.sidecar.SeqRange",
	"urnetwork.sidecar.ApprovalNotice",
}

// The guard passes the tree, no root fields.yml names reaches a session message, none of them is a root itself, and
// record.proto is a sealed file, so the session wire adds nothing a server sees beyond what DESIGN §2.8's evs rows
// already show for any entry.
func TestSessionPrivacyNoNewServerField(t *testing.T) {
	guard, err := sidecartest.LoadSchemaGuard()
	if err != nil {
		t.Fatal(err)
	}
	findings, err := guard.Check()
	if err != nil {
		t.Fatal(err)
	}
	for _, finding := range findings {
		for _, name := range testSessionWireMessages {
			if strings.Contains(finding, string(name.Name())) || strings.Contains(finding, "body_apart") || strings.Contains(finding, "bodies_dropped") {
				t.Errorf("the guard names the session wire: %s", finding)
			}
		}
	}

	content, err := os.ReadFile("testdata/metadata/fields.yml")
	if err != nil {
		t.Fatal(err)
	}
	fieldMap := struct {
		Roots       map[string]string `yaml:"roots"`
		SealedFiles map[string]string `yaml:"sealed_files"`
		Fields      map[string]string `yaml:"fields"`
	}{}
	if err := yaml.Unmarshal(content, &fieldMap); err != nil {
		t.Fatal(err)
	}
	if _, ok := fieldMap.SealedFiles["protocol/record.proto"]; !ok {
		t.Error("record.proto is no sealed file in fields.yml")
	}
	sessionNames := map[protoreflect.FullName]bool{}
	for _, name := range testSessionWireMessages {
		sessionNames[name] = true
		if _, root := fieldMap.Roots[string(name.Name())]; root {
			t.Errorf("%s is a root a server parses", name.Name())
		}
	}
	for key := range fieldMap.Fields {
		message, field, _ := strings.Cut(key, ".")
		if sessionNames["urnetwork.sidecar."+protoreflect.FullName(message)] || field == "body_apart" || field == "bodies_dropped" {
			t.Errorf("fields.yml maps %s to a row", key)
		}
	}
	// what every root of record.proto reaches, a server's view, holds no session message
	for root := range fieldMap.Roots {
		descriptor, err := protoregistry.GlobalFiles.FindDescriptorByName("urnetwork.sidecar." + protoreflect.FullName(root))
		if err != nil {
			continue
		}
		message, ok := descriptor.(protoreflect.MessageDescriptor)
		if !ok {
			continue
		}
		seen := map[protoreflect.FullName]bool{}
		var walk func(message protoreflect.MessageDescriptor)
		walk = func(message protoreflect.MessageDescriptor) {
			if seen[message.FullName()] {
				return
			}
			seen[message.FullName()] = true
			if sessionNames[message.FullName()] {
				t.Errorf("the root %s reaches %s", root, message.FullName())
			}
			fields := message.Fields()
			for i := 0; i < fields.Len(); i += 1 {
				if fields.Get(i).Message() != nil {
					walk(fields.Get(i).Message())
				}
			}
		}
		walk(message)
	}
	// the record's own entry carries body_apart sealed in its writer's stream, never as a root
	if _, root := fieldMap.Roots[string((&protocol.RecordEntry{}).ProtoReflect().Descriptor().Name())]; root {
		t.Error("RecordEntry is a root")
	}
}
