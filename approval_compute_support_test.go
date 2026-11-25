package sidecar

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"slices"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// A kind-27 message as the client builds it: the body, field 80, and the run's state.
func testSupportSendActionArgs() *SupportSendActionArgs {
	return &SupportSendActionArgs{
		Body: []byte(`{"v":1,"product":"urnetwork","text":"the build fails"}`),
		Support: &protocol.SupportFields{
			Product: SupportProductUrnetwork, Entry: "100171", Kind: supportKindBug, Text: "the build fails",
			ClientRef: bytes.Repeat([]byte{0x27}, 16),
			Bundle: &protocol.BundleManifest{
				Events: 3, First: 1764000000, Last: 1764000600, Bytes: 512, Sha256: bytes.Repeat([]byte{0x01}, 32),
				Codes: []*protocol.BundleCodeCount{{Component: "daemon", Code: "started", Count: 1}},
			},
		},
		TaintReasons: []string{"web_tool"},
	}
}

// Kind 27 is on the gate's list after 26, a compute kind, its row version 5's alone.
func TestSupportSendIsKind27OnTheGateAtVersion5(t *testing.T) {
	if sidecarGateKinds[len(sidecarGateKinds)-1] != SidecarActionSupportSend || !sidecarGateKindKnown(SidecarActionSupportSend) ||
		!approvalComputeKind(SidecarActionSupportSend) {
		t.Fatal("kind 27 is not the gate's last, or not a compute kind")
	}
	row, ok := CanonicalActionFields(SidecarActionSupportSend)
	if !ok || !slices.Equal(row.Versions, []uint32{canonicalActionVersionCompute}) || len(row.Server) != 0 {
		t.Fatalf("kind 27's row: %+v", row)
	}
	if value := protocol.SidecarActionKind_value["SIDECAR_ACTION_KIND_SUPPORT_SEND"]; value != int32(SidecarActionSupportSend) {
		t.Fatalf("record.proto's value %d", value)
	}
}

// A tainted run's plain message is basis taint and no rule, which the classifier may decide; field 3 hashes the body.
func TestSupportSendActionOfATaintedRun(t *testing.T) {
	args := testSupportSendActionArgs()
	stored, err := NewSupportSendAction(args)
	if err != nil {
		t.Fatal(err)
	}
	action := stored.Action
	sum := sha256.Sum256(args.Body)
	if action.GetVersion() != canonicalActionVersionCompute || action.GetAuto().GetBasis() != approvalComputeAutoBasisTaint ||
		len(action.GetAuto().GetRules()) != 0 || !bytes.Equal(action.GetBodySha256(), sum[:]) || !supportSendActionBinds(action, args.Body) {
		t.Fatalf("the action reads %v", action)
	}
	if _, err := ParseStoredCanonicalAction(stored.Bytes); err != nil {
		t.Fatalf("the stored action does not parse: %v", err)
	}
	if supportSendActionBinds(action, append(bytes.Clone(args.Body), ' ')) {
		t.Fatal("field 3 binds a body that differs")
	}
}

// The private mark and a file make the message outward in any run: basis always, with the rule that says why.
func TestSupportSendActionOfAMarkedRunAndAFile(t *testing.T) {
	marked := testSupportSendActionArgs()
	marked.TaintReasons = nil
	marked.Private = true
	stored, err := NewSupportSendAction(marked)
	if err != nil {
		t.Fatal(err)
	}
	if auto := stored.Action.GetAuto(); auto.GetBasis() != approvalComputeAutoBasisAlways || !slices.Equal(auto.GetRules(), []uint32{approvalComputeAutoRulePrivateData}) {
		t.Fatalf("a marked run's field 70: %v", auto)
	}
	withFile := testSupportSendActionArgs()
	withFile.Private = true
	withFile.Support.Files = []*protocol.FileFields{{Name: "build.log", Type: supportFileTypeText, Size: 12, Sha256: bytes.Repeat([]byte{0x02}, 32)}}
	stored, err = NewSupportSendAction(withFile)
	if err != nil {
		t.Fatal(err)
	}
	if auto := stored.Action.GetAuto(); !slices.Equal(auto.GetRules(), []uint32{approvalComputeAutoRulePrivateData, approvalComputeAutoRuleAttachment}) {
		t.Fatalf("a marked run's file's field 70: %v", auto)
	}
	// a clean run's plain message is W, and files no action
	clean := testSupportSendActionArgs()
	clean.TaintReasons = nil
	if _, err := NewSupportSendAction(clean); !errors.Is(err, ErrCanonicalActionInvalid) {
		t.Fatalf("a clean run's plain message: %v", err)
	}
}

// Field 80's rules, each refusing the action a builder that broke it would store.
func TestSupportSendActionRefusesABrokenField80(t *testing.T) {
	cases := []struct {
		name   string
		change func(action *protocol.CanonicalAction)
	}{
		{name: "another product", change: func(action *protocol.CanonicalAction) { action.Support.Product = "recurd" }},
		{name: "an entry not FB's", change: func(action *protocol.CanonicalAction) { action.Support.Entry = "R-204" }},
		{name: "a kind FB does not name", change: func(action *protocol.CanonicalAction) { action.Support.Kind = 7 }},
		{name: "no text", change: func(action *protocol.CanonicalAction) { action.Support.Text = "" }},
		{name: "text past its bound", change: func(action *protocol.CanonicalAction) { action.Support.Text = strings.Repeat("a", 16*1024+1) }},
		{name: "a short client_ref", change: func(action *protocol.CanonicalAction) { action.Support.ClientRef = []byte{1} }},
		{name: "a bundle with no hash", change: func(action *protocol.CanonicalAction) { action.Support.Bundle.Sha256 = nil }},
		{name: "four files", change: func(action *protocol.CanonicalAction) {
			for range 4 {
				action.Support.Files = append(action.Support.Files, &protocol.FileFields{Name: "a", Type: 1, Sha256: bytes.Repeat([]byte{3}, 32)})
			}
			action.Auto = &protocol.AutoFields{Basis: approvalComputeAutoBasisAlways, Rules: []uint32{approvalComputeAutoRuleAttachment}}
		}},
		{name: "a file of no type", change: func(action *protocol.CanonicalAction) {
			action.Support.Files = []*protocol.FileFields{{Name: "a", Type: 9, Sha256: bytes.Repeat([]byte{3}, 32)}}
			action.Auto = &protocol.AutoFields{Basis: approvalComputeAutoBasisAlways, Rules: []uint32{approvalComputeAutoRuleAttachment}}
		}},
		{name: "a file without its rule", change: func(action *protocol.CanonicalAction) {
			action.Support.Files = []*protocol.FileFields{{Name: "a", Type: 1, Sha256: bytes.Repeat([]byte{3}, 32)}}
		}},
		{name: "the attachment rule without a file", change: func(action *protocol.CanonicalAction) {
			action.Auto = &protocol.AutoFields{Basis: approvalComputeAutoBasisAlways, Rules: []uint32{approvalComputeAutoRuleAttachment}}
		}},
		{name: "a rule under basis taint", change: func(action *protocol.CanonicalAction) {
			action.Auto = &protocol.AutoFields{Basis: approvalComputeAutoBasisTaint, Rules: []uint32{approvalComputeAutoRulePrivateData}}
		}},
		{name: "rule 11 on kind 27", change: func(action *protocol.CanonicalAction) { action.Auto.Rules = []uint32{11} }},
		{name: "version 1", change: func(action *protocol.CanonicalAction) { action.Version = 1 }},
		{name: "field 49", change: func(action *protocol.CanonicalAction) { action.TookTainted = true }},
	}
	stored, err := NewSupportSendAction(testSupportSendActionArgs())
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cases {
		action := proto.Clone(stored.Action).(*protocol.CanonicalAction)
		c.change(action)
		changed, err := proto.MarshalOptions{Deterministic: true}.Marshal(action)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ParseStoredCanonicalAction(changed); !errors.Is(err, ErrCanonicalActionInvalid) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	// private_data and attachment ride kind 27 alone
	if approvalComputeAutoRuleAllowed(SidecarActionServiceWrite, approvalComputeAutoRulePrivateData) ||
		!approvalComputeAutoRuleAllowed(SidecarActionSupportSend, approvalComputeAutoRuleAttachment) ||
		approvalComputeAutoRuleAllowed(SidecarActionSupportSend, 11) {
		t.Fatal("field 70's rules by kind")
	}
}
