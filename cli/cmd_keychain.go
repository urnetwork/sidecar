// The keychain's commands (§5.9's Pass, R-CORE-7, plan-CORE-cli-ui-missing #2): ur unlock opens U with the pass, ur
// lock drops U and every R_n from memory as auto-lock does, ur keychain pass rewraps U under a new pass, and ur
// keychain rotate rotates U and every R_n. Every pass is read from /dev/tty with echo off, never argv, the environment
// or stdin, and approves nothing.

package main

import (
	"context"
	"errors"

	"github.com/docopt/docopt-go"
)

func init() {
	registerUrCommand(&urCommand{
		name:    "unlock",
		usage:   "  ur unlock",
		summary: "open the keychain with its pass, read from the terminal",
		run:     runUrUnlock,
	})
	registerUrCommand(&urCommand{
		name:    "lock",
		usage:   "  ur lock",
		summary: "drop every key from the daemon's memory now",
		run:     runUrLock,
	})
	registerUrCommand(&urCommand{
		name:    "keychain",
		usage:   "  ur keychain pass\n  ur keychain rotate",
		summary: "change the keychain's pass, or rotate its keys",
		run:     runUrKeychain,
	})
}

func runUrUnlock(ctx context.Context, cli *urCli, options docopt.Opts) error {
	pass, err := readPassFromTty(cli, "pass: ")
	if err != nil {
		return err
	}
	defer clear(pass)
	return cli.callDaemon(ctx, urMethodUnlock, &urPassParams{Pass: pass}, false, nil)
}

func runUrLock(ctx context.Context, cli *urCli, options docopt.Opts) error {
	return cli.callDaemon(ctx, urMethodLock, nil, false, nil)
}

func runUrKeychain(ctx context.Context, cli *urCli, options docopt.Opts) error {
	if rotate, _ := options.Bool("rotate"); rotate {
		pass, err := readPassFromTty(cli, "pass: ")
		if err != nil {
			return err
		}
		defer clear(pass)
		return cli.callDaemon(ctx, urMethodKeychainRotate, &urPassParams{Pass: pass}, false, nil)
	}
	oldPass, err := readPassFromTty(cli, "current pass: ")
	if err != nil {
		return err
	}
	defer clear(oldPass)
	newPass, err := readPassFromTty(cli, "new pass: ")
	if err != nil {
		return err
	}
	defer clear(newPass)
	again, err := readPassFromTty(cli, "new pass again: ")
	if err != nil {
		return err
	}
	defer clear(again)
	if string(again) != string(newPass) {
		return errors.New("the new passes differ")
	}
	return cli.callDaemon(ctx, urMethodKeychainPass, &urPassChangeParams{OldPass: oldPass, NewPass: newPass}, false, nil)
}
