package main

// ur admin directory's show (admin_directory_cmd.go) and the ServiceSettings record holding its settings (QD-1207): the
// show prints the settings and, under them, the record where its signer no longer stands, with that signer, its member,
// why and who files another, or that this device could not say; nothing where the signer stands or the settings are
// not known here. directory_cmd_test.go runs the command's signing paths. Synthetic values only.

import (
	"bytes"
	"context"
	"testing"

	"github.com/urnetwork/sidecar"
)

// A ur over a stand-in daemon whose admin.directory.show answers show, and what it printed on stdout and stderr.
func testUrAdminDirectoryShowCli(t *testing.T, show *urAdminDirectoryReply) (*urCli, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	daemon := startTestUrDaemon(t, shortTestDirectory(t), func(daemon *sidecar.Daemon) {
		err := daemon.RegisterMethod(&sidecar.DaemonMethod{Name: urMethodAdminDirectoryShow, Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
			return show, nil
		}})
		if err != nil {
			t.Fatal(err)
		}
	})
	return newTestUrCli(daemon.socketPath)
}

// The show prints the settings, then the carried record's line naming its signer, the signer's member, why the signer
// no longer stands and who files another; a record whose signer stands adds nothing.
func TestUrAdminDirectoryShowListsTheCarriedRecord(t *testing.T) {
	settings, _ := testUrAdminCarried()
	cli, stdout, stderr := testUrAdminDirectoryShowCli(t, &urAdminDirectoryReply{Runs: "prompt", Workers: "off", Carried: settings})
	if code := cli.main(context.Background(), []string{"ur", "admin", "directory"}); code != urExitOk {
		t.Fatalf("exit %d, stderr:\n%s", code, stderr.String())
	}
	want := "directory settings: runs prompt, workers off\n" +
		"the ServiceSettings record holding these settings stands under a signer who no longer stands until another is filed: " +
		"service_settings: signed by " + settings.SignerId.String() + " of member " + settings.MemberId.String() +
		", revoked at position 42, its member no longer the network's; an Owner or Admin files another: ur admin settings with any option\n"
	if text := stdout.String(); text != want {
		t.Errorf("the show printed\n%s\nwant\n%s", text, want)
	}

	standing, stdout, _ := testUrAdminDirectoryShowCli(t, &urAdminDirectoryReply{Runs: "auto", Workers: "on"})
	if code := standing.main(context.Background(), []string{"ur", "admin", "directory"}); code != urExitOk || stdout.String() != "directory settings: runs auto, workers on\n" {
		t.Errorf("a standing signer's record: exit %d, printed\n%s", code, stdout.String())
	}
}

// A show whose record could not be read says so under the settings; one whose settings are not known here says that
// alone, since such a device holds no record.
func TestUrAdminDirectoryShowSaysWhenItCannotListTheCarriedRecord(t *testing.T) {
	cli, stdout, _ := testUrAdminDirectoryShowCli(t, &urAdminDirectoryReply{Runs: "auto", Workers: "on", CarriedUnknown: true})
	if code := cli.main(context.Background(), []string{"ur", "admin", "directory"}); code != urExitOk {
		t.Fatalf("exit %d", code)
	}
	want := "directory settings: runs auto, workers on\n" +
		"whether the ServiceSettings record holding these settings stands under a standing signer is not known here, " +
		"since this device could not read the config head's records now\n"
	if text := stdout.String(); text != want {
		t.Errorf("the show printed\n%s\nwant\n%s", text, want)
	}

	unknown, stdout, _ := testUrAdminDirectoryShowCli(t, &urAdminDirectoryReply{Unknown: true})
	if code := unknown.main(context.Background(), []string{"ur", "admin", "directory"}); code != urExitOk ||
		stdout.String() != "directory settings: not known here, since this device opens no config head\n" {
		t.Errorf("settings not known: exit %d, printed\n%s", code, stdout.String())
	}
}
