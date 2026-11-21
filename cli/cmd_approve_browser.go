package main

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/docopt/docopt-go"
	"github.com/urnetwork/sidecar"
)

const (
	urMethodBrowserPreview = "approvals.browser_preview"
	urMethodBrowserConfirm = "approvals.browser_confirm"
)

type urBrowserAdmission struct {
	Network string     `json:"network,omitempty"`
	Target  sidecar.Id `json:"sidecar_id"`
	sidecar.BrowserAdmissionPreview
}

func init() { urDaemonMethodExtensions = append(urDaemonMethodExtensions, urBrowserApprovalMethods) }

func urBrowserApprovalMethods(target urDaemonTarget) []*sidecar.DaemonMethod {
	network, ok := target.(*urDaemonNetwork)
	if !ok {
		return nil
	}
	return []*sidecar.DaemonMethod{{Name: urMethodBrowserPreview, Network: true,
		Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
			var args urBrowserAdmission
			if err := decodeUrParams(call, &args); err != nil {
				return nil, err
			}
			return call.Sidecar.PreviewBrowserAdmission(ctx, args.Target, args.Terms)
		}}, {Name: urMethodBrowserConfirm, Network: true, Confirm: true,
		Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
			var args urBrowserAdmission
			if err := decodeUrParams(call, &args); err != nil {
				return nil, err
			}
			return nil, call.Sidecar.ConfirmBrowserAdmission(ctx, args.Target, args.BrowserAdmissionPreview, network.presenceCheck(call.Sidecar))
		}}}
}

func runUrApproveBrowser(ctx context.Context, cli *urCli, options docopt.Opts) error {
	target, err := sidecar.ParseId(urOptionString(options, "<sidecar_id>"))
	if err != nil || target == (sidecar.Id{}) {
		return errors.New("supply the sidecar ID shown by the browser")
	}
	args := &urBrowserAdmission{Network: urOptionString(options, "--network"), Target: target}
	args.Terms.Mode = sidecar.BrowserAdmissionPage
	if urOptionBool(options, "burner") {
		mailbox, err := sidecar.ParseId(urOptionString(options, "<mailbox_repo_id>"))
		if err != nil || mailbox == (sidecar.Id{}) {
			return errors.New("supply your mailbox repo ID")
		}
		duration, err := time.ParseDuration(urOptionString(options, "--for"))
		if err != nil || duration <= 0 {
			return errors.New("supply a positive duration for the burner")
		}
		args.Terms = sidecar.BrowserAdmissionTerms{Mode: sidecar.BrowserAdmissionBurner, MailboxId: mailbox, NotAfterMs: time.Now().Add(duration).UnixMilli()}
	}
	preview := &sidecar.BrowserAdmissionPreview{}
	if err := cli.callDaemon(ctx, urMethodBrowserPreview, args, false, preview); err != nil {
		return err
	}
	if preview.SafetyNumber == "" || preview.NetworkId == (sidecar.Id{}) || preview.MemberId == (sidecar.Id{}) ||
		preview.Terms.Mode != args.Terms.Mode || preview.Terms.MailboxId != args.Terms.MailboxId ||
		preview.Terms.NotAfterMs > args.Terms.NotAfterMs {
		return sidecar.ErrBrowserAdmissionConfirmation
	}
	args.BrowserAdmissionPreview = *preview
	tty, err := cli.openTty()
	if err != nil {
		return fmt.Errorf("%w: %w", errUrNoTty, err)
	}
	fmt.Fprintf(tty, "Member %s in network %s.\n", args.MemberId, args.NetworkId)
	if args.Terms.Mode == sidecar.BrowserAdmissionBurner {
		fmt.Fprintf(tty, "Grant ephemeral device %s read access to mailbox %s until %s.\n", target, args.Terms.MailboxId, time.UnixMilli(args.Terms.NotAfterMs).Format(time.RFC3339))
	} else {
		fmt.Fprintf(tty, "Admit browser device %s as read-only for your member account.\n", target)
	}
	fmt.Fprintf(tty, "Compare every digit with the safety number on the browser.\n%s\n", sidecar.FormatSafetyNumber(preview.SafetyNumber))
	tty.Close()
	confirmed, err := confirmOnTty(cli, "Do the numbers match, and do you approve the access shown?")
	if err != nil {
		return err
	}
	if !confirmed {
		cli.printf("nothing changed\n")
		return nil
	}
	if err := cli.callDaemon(ctx, urMethodBrowserConfirm, args, true, nil); err != nil {
		return err
	}
	cli.printf("Browser device %s approved.\n", target)
	return nil
}
