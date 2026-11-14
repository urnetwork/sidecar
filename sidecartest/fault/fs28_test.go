//go:build !js && !ios && !android && !sdk_mobile_bind

package fault

// FS-28 (§22.8; §16.6's harness_ok, D-MCP-9, D-MCP-14, D-MCP-19, I-8, I-9, FI-7, owner decisions 47, 75 and 142;
// MCP-M3-25) on T2, on fs27_test.go's hook world: a same-uid process, a shell child of the harness, submits a
// PermissionRequest for an outward tool's call, and the call then reaches the gate. The member has the requesting CLI
// alone and no presence key, and the document's evidenceDefault lists harness.
//
// The refusal: the run read untrusted data first. The forged event yields no harness decision: the call's request is
// filed tainted and waits for a person, nothing runs. Its twin read a local file: the same forged event yields a
// decision the daemon signs, channel harness, citing the hook_event entry the ingest sealed for the event, source
// hook, and the call runs once. That is the disclosed residual, and the forger being a shell child and no harness is
// why no binding to the harness binary is possible: the daemon reads the same hello either way.
//
// Both then go on the same way. A requests rule of its own naming harness lets a forged event count in the tainted
// run as in the untainted one. An event reporting bypassPermissions, dontAsk or auto is no evidence in either: each
// such call waits. With a presence key registered for the member harness_ok is false, the call waits, and the
// decision the key signs on the daemon's own request, as its presence prompt does, spends as channel presence. FI-7
// after every step.
//
// A KeyRegister and an OwnerConfirm are acts, no gate action: no request carries one, so no harness decision can
// approve one, and a hook's origin signs neither (the root's TestHarnessCannotRegisterKey, and
// sidecartest's TestSecondCliApprovalAccepted for a decision). The prompt itself, over a platform authenticator, is the
// root's TestPromptYieldsChannelPresence.

import (
	"bytes"
	"context"
	"fmt"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

var Fs28 = Register("FS-28", "", []Tier{TierT2}, Twin(Fs28ForgedEventInTaintedRun, Fs28ForgedEventInUntaintedRun))

// See the file header.
func Fs28ForgedEventInTaintedRun(net *Net) *Schedule {
	schedule := fs28(true)
	schedule.Refuses = "a harness decision on a forged PermissionRequest in a tainted run whose rule does not name harness, on an event in a mode that skips the prompt, and for a member who holds a presence key"
	return schedule
}

// See the file header.
func Fs28ForgedEventInUntaintedRun(net *Net) *Schedule {
	return fs28(false)
}

// FS-28's session and the recipients of its calls.
const (
	fs28Session   = "s1"
	fs28Default   = "default@recipient.example"
	fs28RuleNamed = "rule@recipient.example"
	fs28Presence  = "presence@recipient.example"
)

// The modes that skip the person's prompt, each voiding harness evidence.
var fs28SkippingModes = []string{"bypassPermissions", "dontAsk", "auto"}

func fs28ModeRecipient(mode string) string {
	return mode + "@recipient.example"
}

// The channels a rule's evidence list names in FS-28: every one.
func fs28Evidence(world *sidecartest.ApprovalWorld, ruleNamesHarness bool) {
	world.SetEvidence(ruleNamesHarness,
		protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE,
		protocol.ApprovalChannel_APPROVAL_CHANNEL_PRESENCE,
		protocol.ApprovalChannel_APPROVAL_CHANNEL_HARNESS,
	)
}

// The approval whose request is for the newest call to recipient.
func (self *fsHookWorld) approvalOf(recipient string) (sidecar.Id, error) {
	answer, err := self.answer(recipient)
	if err != nil {
		return sidecar.Id{}, err
	}
	log := self.approvalWorld().Log()
	for _, approvalId := range log.ApprovalIds() {
		if request := log.Request(approvalId); request != nil && bytes.Equal(request.Action.Bytes, answer.action.Canonical) {
			return approvalId, nil
		}
	}
	return sidecar.Id{}, fmt.Errorf("no request filed for %s", recipient)
}

// The call for recipient ran on one harness decision, which cites a hook_event entry the ingest sealed, source hook.
func (self *fsHookWorld) wantHarnessDecision(recipient string, effectCount int) error {
	if err := self.wantDone(recipient, effectCount); err != nil {
		return err
	}
	approvalId, err := self.approvalOf(recipient)
	if err != nil {
		return err
	}
	decisions, err := self.approvalWorld().Decisions(approvalId)
	if err != nil {
		return err
	}
	if len(decisions) != 1 || decisions[0].Decision.GetChannel() != uint32(protocol.ApprovalChannel_APPROVAL_CHANNEL_HARNESS) {
		return fmt.Errorf("the call for %s holds %d decisions, not one of channel harness", recipient, len(decisions))
	}
	if !bytes.Equal(decisions[0].Signed.GetSignerId(), self.approvalWorld().Laptop.SidecarId.Bytes()) {
		return fmt.Errorf("the harness decision for %s is not the requesting daemon's", recipient)
	}
	draft := self.writer.draftOf(decisions[0].Decision.GetEvidenceSha256())
	if draft == nil || draft.Kind != sidecar.RecordKindHookEvent || draft.Source != sidecar.RecordSourceHook {
		return fmt.Errorf("the harness decision for %s cites no hook_event entry of source hook: %+v", recipient, draft)
	}
	return nil
}

// The call for recipient waits with no decision kept for it.
func (self *fsHookWorld) wantNoDecision(recipient string, tainted bool, effectCount int) (sidecar.Id, error) {
	approvalId, err := self.wantPending(recipient, tainted, effectCount)
	if err != nil {
		return sidecar.Id{}, err
	}
	channels, err := self.channels(approvalId)
	if err != nil {
		return sidecar.Id{}, err
	}
	if len(channels) != 0 {
		return sidecar.Id{}, fmt.Errorf("the call for %s holds decisions of channels %v", recipient, channels)
	}
	return approvalId, nil
}

// A shell child of the harness submits a PermissionRequest for the fixture tool's call to recipient, reporting mode.
func fs28Forge(hooks **fsHookWorld, recipient string, mode string) *Step {
	return fsHookStep("forger", hooks, func(ctx context.Context, hooks *fsHookWorld) error {
		harness := hooks.harness("harness")
		return harness.HookFrom(harness.ShellChild("forger"), fsHookPermissionRequest(harness, fs28Session, recipient, mode))
	})
}

// tainted is the refusal: the run reads the web before the forged event. Else its twin.
func fs28(tainted bool) *Schedule {
	var hooks *fsHookWorld
	key := sidecartest.NewFixturePresenceKey("fs28", bridge.KeyAlg_KEY_ALG_WEBAUTHN_ES256)
	// the effects so far, which each judge moves on
	effects := 0
	steps := []*Step{
		{Actor: "setup", Action: func(ctx context.Context, net *Net) error {
			world, err := newFsHookWorld(net, false)
			if err != nil {
				return err
			}
			hooks = world
			// the CLI alone, no presence key, harness by the document's default alone
			hooks.approvalWorld().SetMemberDevices(nil, nil)
			fs28Evidence(hooks.approvalWorld(), false)
			if err := hooks.startHarness("harness", sidecartest.FakeHarnessClaudeCode).SessionStart(fs28Session, "startup"); err != nil {
				return err
			}
			return hooks.startRelay("relay", "harness")
		}},
		fsHookStep("harness", &hooks, func(ctx context.Context, hooks *fsHookWorld) error {
			if tainted {
				return hooks.harness("harness").ToolCall(fs28Session, false, "WebFetch", map[string]any{"url": "https://docs.example/page"})
			}
			return hooks.harness("harness").ToolCall(fs28Session, false, "Read", map[string]any{"file_path": fsHookCwd + "/a.go"})
		}),

		// the forged event, under evidenceDefault
		fs28Forge(&hooks, fs28Default, "default"),
		fsHookCall(&hooks, "relay", fs28Default),
		fsHookStep("judge", &hooks, func(ctx context.Context, hooks *fsHookWorld) error {
			if tainted {
				if _, err := hooks.wantNoDecision(fs28Default, true, effects); err != nil {
					return fmt.Errorf("a forged event in a tainted run, harness by evidenceDefault alone: %w", err)
				}
				return nil
			}
			effects += 1
			if err := hooks.wantHarnessDecision(fs28Default, effects); err != nil {
				return fmt.Errorf("a forged event in an untainted run: %w", err)
			}
			return nil
		}),

		// a requests rule of its own names harness: the forged event counts in either run
		fsHookStep("authority", &hooks, func(ctx context.Context, hooks *fsHookWorld) error {
			fs28Evidence(hooks.approvalWorld(), true)
			return nil
		}),
		fs28Forge(&hooks, fs28RuleNamed, "default"),
		fsHookCall(&hooks, "relay", fs28RuleNamed),
		fsHookStep("judge", &hooks, func(ctx context.Context, hooks *fsHookWorld) error {
			effects += 1
			if err := hooks.wantHarnessDecision(fs28RuleNamed, effects); err != nil {
				return fmt.Errorf("a forged event under a rule that names harness: %w", err)
			}
			return nil
		}),
	}

	// each mode that skips the prompt voids the event
	for _, mode := range fs28SkippingModes {
		recipient := fs28ModeRecipient(mode)
		steps = append(steps,
			fs28Forge(&hooks, recipient, mode),
			fsHookCall(&hooks, "relay", recipient),
			fsHookStep("judge", &hooks, func(ctx context.Context, hooks *fsHookWorld) error {
				if _, err := hooks.wantNoDecision(recipient, tainted, effects); err != nil {
					return fmt.Errorf("an event in mode %s: %w", mode, err)
				}
				return nil
			}),
		)
	}

	steps = append(steps,
		// a presence key registered for the member: no harness decision, and the key's own decision spends
		fsHookStep("authority", &hooks, func(ctx context.Context, hooks *fsHookWorld) error {
			world := hooks.approvalWorld()
			world.SetPresenceKeys(key.KeyRow(world.Member.Bytes(), world.Laptop.SidecarId.Bytes(), 3))
			return nil
		}),
		fs28Forge(&hooks, fs28Presence, "default"),
		fsHookCall(&hooks, "relay", fs28Presence),
		fsHookStep("judge", &hooks, func(ctx context.Context, hooks *fsHookWorld) error {
			approvalId, err := hooks.wantNoDecision(fs28Presence, tainted, effects)
			if err != nil {
				return fmt.Errorf("a forged event for a member who holds a presence key: %w", err)
			}
			hooks.keep(fs28Presence, approvalId)
			return nil
		}),
		fsHookStep("presence", &hooks, func(ctx context.Context, hooks *fsHookWorld) error {
			world := hooks.approvalWorld()
			notAfter := hooks.net.Clock().Now().Add(sidecar.DefaultSidecarSettings().Mcp.ApprovalRequestTimeout)
			decision, err := world.SignPresenceDecision(hooks.kept(fs28Presence), notAfter, key)
			if err != nil {
				return err
			}
			return world.Deliver(ctx, hooks.kept(fs28Presence), decision)
		}),
		fsHookCall(&hooks, "relay", fs28Presence),
		fsHookStep("judge", &hooks, func(ctx context.Context, hooks *fsHookWorld) error {
			effects += 1
			if err := hooks.wantDone(fs28Presence, effects); err != nil {
				return fmt.Errorf("the presence decision: %w", err)
			}
			channels, err := hooks.channels(hooks.kept(fs28Presence))
			if err != nil {
				return err
			}
			if len(channels) != 1 || channels[0] != protocol.ApprovalChannel_APPROVAL_CHANNEL_PRESENCE {
				return fmt.Errorf("the presence prompt's decision reads channels %v", channels)
			}
			return nil
		}),
		fsHookReconcile(&hooks),
	)
	return &Schedule{
		Steps: steps,
		Check: []Invariant{FI(7)},
		Tiers: []Tier{TierT2},
	}
}

func TestFs28(t *testing.T) {
	RunRow(t, "FS-28", "", nil)
}
