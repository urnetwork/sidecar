// ur devices and ur devices revoke (§5.6's revocation, D-CORE-20, D-CORE-13, CORE-M3-04; FS-98, FS-124's CLI cases):
//
//	ur devices                         this member's devices, this one first (5.4's Devices)
//	ur devices revoke <name|sidecar_id> [--compromise [--since=<time|position>]] [--keep-key=<key_id>]...
//	                                   revokes another of the member's devices as lost, or with --compromise as
//	                                   compromise from the entry --since names: a log position, or an RFC 3339 loss
//	                                   time whose first entry at or after it the device proposes
//
// revoke prints the plan on the terminal, what the cascade parks and voids, what stands, and each key the device
// registered, and signs only once the person answers yes on /dev/tty, never from stdin, argv or MCP: the daemon's
// devices.revoke is a Confirm method (the root's daemon_devices.go). Under Presence the daemon then runs its presence
// prompt, and a refused or failed check signs nothing (REVOKE_CANCELLED). The keys a plan lists are revoked with the
// device unless --keep-key names them, and only under Presence: a device with no presence key revokes none. At
// k > 1 the call signs the proposal and the device's Suspend and prints the proposal's id, which another admin's
// device approves with `ur approve <proposal_id>`.
//
// A compromise revocation with no --since asks the loss time on the terminal, since nothing else says where P starts.

package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/docopt/docopt-go"

	"github.com/urnetwork/sidecar"
)

func init() {
	registerUrCommand(&urCommand{
		name: "devices",
		usage: strings.Join([]string{
			"  ur devices [--network=<name>]",
			"  ur devices revoke <device> [--compromise] [--since=<since>] [--keep-key=<key_id>]... [--network=<name>]",
		}, "\n"),
		summary: "list this member's devices, or revoke another of them as lost or compromised, confirmed on the terminal",
		run:     runUrDevices,
	})
	urDaemonMethodExtensions = append(urDaemonMethodExtensions, urDevicesMethods)
}

// What the devices methods act on: a target on a daemon that hosts Sidecars, whose presence prompt the signing ones
// run.
type urDevicesTarget interface {
	devicesDaemon() *sidecar.Daemon
}

func (self *urDaemonNetwork) devicesDaemon() *sidecar.Daemon {
	return self.daemon
}

// The root's devices methods over target's daemon, each finding its network's Sidecar per call, with the two-call
// methods a remote-mode app's decisions and presence key take (CORE-M8-03).
func urDevicesMethods(target urDaemonTarget) []*sidecar.DaemonMethod {
	devices, ok := target.(urDevicesTarget)
	if !ok || devices.devicesDaemon() == nil {
		return nil
	}
	return append(sidecar.DaemonDevicesMethods(devices.devicesDaemon()), sidecar.DaemonApprovalsMethods(devices.devicesDaemon())...)
}

// What §5.6's codes mean, for the line ur prints beside each.
var urDeviceRefusalTexts = map[string]string{
	sidecar.DeviceRevokeCodeSelf:       "that is this device: sign it out with ur logout instead",
	sidecar.DeviceRevokeCodeNotOwn:     "no device of this member has that name or id: another member's device, an agent's or an unknown one is an admin's to revoke",
	sidecar.DeviceRevokeCodeNotCapable: "this device may not revoke: only a consented device of the member that is not read-only, a burner or suspended does",
	sidecar.DeviceRevokeCodeCancelled:  "the presence check failed or was refused, so nothing was signed",
	sidecar.DeviceRevokeCodeSince:      "--since is later than the entry the loss time gives, past the newest entry, or a time still to come",
	sidecar.DeviceRevokeCodeParksSelf:  "from there the revocation would park this device too",
	sidecar.DeviceRevokeCodeStale:      "the plan changed since it was shown: run the command again and read the new one",
	sidecar.DeviceRevokeCodeRefused:    "the network refused the statement",
}

// A refusal as ur's error.
func urDeviceRefusalError(refusal *sidecar.DaemonDeviceRefusal) error {
	text := urDeviceRefusalTexts[refusal.Code]
	if refusal.Code == sidecar.DeviceRevokeCodeParksSelf && refusal.Position != 0 {
		text = fmt.Sprintf("%s: entry %d put it among what the device signed for. Give a later --since, or revoke from another device", text, refusal.Position)
	}
	if text == "" {
		return errors.New(refusal.Code)
	}
	return fmt.Errorf("%s: %s", refusal.Code, text)
}

// Runs the part of ur devices its first word names.
func runUrDevices(ctx context.Context, cli *urCli, options docopt.Opts) error {
	if urOptionBool(options, "revoke") {
		return runUrDevicesRevoke(ctx, cli, options)
	}
	network, _ := options.String("--network")
	reply := &sidecar.DaemonDevicesListReply{}
	if err := cli.callDaemon(ctx, sidecar.DaemonMethodDevicesList, &sidecar.DaemonDevicesListParams{Network: network}, false, reply); err != nil {
		return err
	}
	for _, device := range reply.Devices {
		notes := []string{device.State}
		if device.This {
			notes = append(notes, "this device")
		}
		if device.ReadOnly {
			notes = append(notes, "read-only")
		}
		if device.Ephemeral {
			notes = append(notes, "burner")
		}
		if device.AdmittedAtMs != 0 {
			notes = append(notes, "admitted "+time.UnixMilli(device.AdmittedAtMs).UTC().Format(time.RFC3339))
		}
		if device.LastChangeMs != 0 {
			notes = append(notes, "last change "+time.UnixMilli(device.LastChangeMs).UTC().Format(time.RFC3339))
		}
		cli.printf("%s  %s  %s\n", device.SidecarId, urDeviceName(device.Name), strings.Join(notes, ", "))
	}
	return nil
}

// A config device name as a line shows it, a dash for a device that carries none.
func urDeviceName(name string) string {
	if name == "" {
		return "-"
	}
	return name
}

// --since as devices.preview takes it: a log position, or an RFC 3339 loss time.
func urParseSince(since string) (sinceN uint64, lostAtMs int64, err error) {
	if position, err := strconv.ParseUint(since, 10, 64); err == nil && position != 0 {
		return position, 0, nil
	}
	if at, err := time.Parse(time.RFC3339, since); err == nil {
		return 0, at.UnixMilli(), nil
	}
	return 0, 0, fmt.Errorf("--since takes a log position or an RFC 3339 time: %q", since)
}

// One row of a plan as the terminal shows it.
func urDeviceRevokeItemLine(item *sidecar.DaemonDeviceRevokeItem) string {
	effect := map[string]string{
		sidecar.DeviceRevokeEffectPark:   "parks ",
		sidecar.DeviceRevokeEffectVoid:   "voids ",
		sidecar.DeviceRevokeEffectStands: "stands",
		sidecar.DeviceRevokeEffectReseal: "reseal",
		sidecar.DeviceRevokeEffectKey:    "key   ",
	}[item.Effect]
	if effect == "" {
		effect = item.Effect
	}
	line := fmt.Sprintf("  %s  %s %s", effect, item.Kind, item.Id)
	if item.Name != "" {
		line += " (" + item.Name + ")"
	}
	if item.Position != 0 {
		line += fmt.Sprintf(", entry %d", item.Position)
	}
	return line
}

// ur devices revoke: the plan on the terminal, the person's yes, then the confirmed call.
func runUrDevicesRevoke(ctx context.Context, cli *urCli, options docopt.Opts) error {
	device, _ := options.String("<device>")
	network, _ := options.String("--network")
	since, _ := options.String("--since")
	compromise := urOptionBool(options, "--compromise")
	keepKeyIds, _ := options["--keep-key"].([]string)
	for _, keepKeyId := range keepKeyIds {
		if decoded, err := hex.DecodeString(keepKeyId); err != nil || len(decoded) == 0 {
			return fmt.Errorf("%q is not a key id", keepKeyId)
		}
	}
	params := &sidecar.DaemonDevicesPreviewParams{Network: network, Device: device, Reason: sidecar.DeviceRevokeLost}
	switch {
	case since != "" && !compromise:
		return errors.New("--since goes with --compromise")
	case compromise:
		params.Reason = sidecar.DeviceRevokeCompromise
		if since == "" {
			// nothing else says where what the device signed stops being trusted
			tty, err := cli.openTty()
			if err != nil {
				return fmt.Errorf("%w: %w", errUrNoTty, err)
			}
			fmt.Fprint(tty, "When was the device lost or taken? An RFC 3339 time, or a log position: ")
			answer, err := tty.readLine()
			tty.Close()
			if err != nil {
				return err
			}
			since = strings.TrimSpace(answer)
		}
		sinceN, lostAtMs, err := urParseSince(since)
		if err != nil {
			return err
		}
		params.SinceN, params.LostAtMs = sinceN, lostAtMs
	}
	preview := &sidecar.DaemonDevicesPreviewReply{}
	if err := cli.callDaemon(ctx, sidecar.DaemonMethodDevicesPreview, params, false, preview); err != nil {
		return err
	}
	if preview.Refusal != nil {
		return urDeviceRefusalError(preview.Refusal)
	}
	plan := preview.Plan
	if plan == nil {
		return errors.New("the daemon answered no plan")
	}
	// the keys the plan lists go with the device unless kept, and only under Presence
	planKeyIds := []string{}
	for _, item := range plan.Items {
		if item.Effect == sidecar.DeviceRevokeEffectKey {
			planKeyIds = append(planKeyIds, item.Id)
		}
	}
	for _, keepKeyId := range keepKeyIds {
		if !slices.Contains(planKeyIds, strings.ToLower(keepKeyId)) {
			return fmt.Errorf("--keep-key %s names no key the device registered", keepKeyId)
		}
	}
	revokeKeyIds := []string{}
	if plan.Presence {
		for _, planKeyId := range planKeyIds {
			if !slices.ContainsFunc(keepKeyIds, func(keepKeyId string) bool { return strings.EqualFold(keepKeyId, planKeyId) }) {
				revokeKeyIds = append(revokeKeyIds, planKeyId)
			}
		}
	}

	tty, err := cli.openTty()
	if err != nil {
		return fmt.Errorf("%w: %w", errUrNoTty, err)
	}
	fmt.Fprintf(tty, "Revoke device %s %s as %s", urDeviceName(plan.Name), plan.SidecarId, plan.Reason)
	if plan.SinceN != 0 {
		fmt.Fprintf(tty, ", from entry %d", plan.SinceN)
		if plan.SinceTimeMs != 0 {
			fmt.Fprintf(tty, " (%s)", time.UnixMilli(plan.SinceTimeMs).UTC().Format(time.RFC3339))
		}
	}
	fmt.Fprintln(tty)
	for _, item := range plan.Items {
		line := urDeviceRevokeItemLine(item)
		if item.Effect == sidecar.DeviceRevokeEffectKey {
			if slices.Contains(revokeKeyIds, item.Id) {
				line += ": revoked with the device"
			} else {
				line += ": kept"
			}
		}
		fmt.Fprintln(tty, line)
	}
	if 0 < len(planKeyIds) && !plan.Presence {
		fmt.Fprintln(tty, "  no key is revoked: this device holds no presence key to revoke one under")
	}
	if 1 < plan.Signatures {
		fmt.Fprintf(tty, "  it takes %d admins: this signs the proposal and suspends the device at once, and another admin's device approves it\n", plan.Signatures)
	}
	if plan.Presence {
		fmt.Fprintln(tty, "  the authenticator then asks for biometry, a passcode or a touch")
	}
	tty.Close()
	confirmed, err := confirmOnTty(cli, "Revoke it?")
	if err != nil {
		return err
	}
	if !confirmed {
		cli.printf("nothing changed\n")
		return nil
	}
	reply := &sidecar.DaemonDevicesRevokeReply{}
	if err := cli.callDaemon(ctx, sidecar.DaemonMethodDevicesRevoke,
		&sidecar.DaemonDevicesRevokeParams{Network: network, PlanId: plan.PlanId, RevokeKeyIds: revokeKeyIds}, true, reply); err != nil {
		return err
	}
	for _, item := range reply.Joined {
		cli.printf("joined since the plan was shown:%s\n", urDeviceRevokeItemLine(item))
	}
	for _, keyId := range reply.RevokedKeyIds {
		cli.printf("key %s revoked\n", keyId)
	}
	switch {
	case reply.Refusal != nil:
		return urDeviceRefusalError(reply.Refusal)
	case reply.ProposalId != "":
		cli.printf("authority_pending: device %s is suspended, and revoked once another admin's device runs\n  ur approve %s\n", plan.SidecarId, reply.ProposalId)
	case reply.Pending:
		cli.printf("signed: the network's answer was lost, so the same statements are sent again until they land\n")
	default:
		cli.printf("device %s revoked at entry %d\n", plan.SidecarId, reply.Position)
	}
	return nil
}
