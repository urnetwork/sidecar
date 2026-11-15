// ur admin scim-token (TEAM-M6-07; QD-828, §7.6): the team's SCIM bearer, which its IdP presents at
// /scim/v2/<network_id>/, run by a one-command admin token as cmd_admin.go's Team parts are:
//
//	ur admin scim-token issue    POST /network/scim-token {}: a new bearer, printed once with the SCIM base URL to
//	                             give the IdP; it replaces any earlier bearer, which stops working at once
//	ur admin scim-token remove   POST /network/scim-token {remove: true}: SCIM off, every SCIM request answering 401
//
// The part registers itself (C-21). Its words are explicit, with no default, since an issue retires the IdP's bearer.
// The bearer is shown once, for the IdP alone; a replay's answer carries none, since the server keeps only its
// SHA-256, and the part says to issue another.

package main

import (
	"context"
	"errors"

	"github.com/docopt/docopt-go"
)

var _ = registerUrAdminPart(&urAdminPart{
	word: "scim-token",
	usage: []string{
		"  ur admin scim-token issue [--device]",
		"  ur admin scim-token remove [--device]",
	},
	run: runUrAdminScimToken,
})

// ur admin scim-token issue|remove.
func runUrAdminScimToken(ctx context.Context, cli *urCli, options docopt.Opts) error {
	remove := urOptionBool(options, "remove")
	body := map[string]any{}
	switch {
	case remove:
		body["remove"] = true
	case urOptionBool(options, "issue"):
	default:
		return errors.New("ur admin scim-token takes issue or remove")
	}
	command, err := urAdminCommand("POST", "/network/scim-token", body)
	if err != nil {
		return err
	}
	result := &struct {
		ScimBearer string `json:"scim_bearer"`
		ScimUrl    string `json:"scim_url"`
		ScimOn     bool   `json:"scim_on"`
		Removed    bool   `json:"removed"`
	}{}
	if err := urAdminRun(ctx, cli, options, command, result); err != nil {
		return err
	}
	if remove {
		if result.Removed {
			cli.printf("SCIM is off: the team's bearer was removed, and every SCIM request answers 401\n")
		} else {
			cli.printf("SCIM was off already: the team held no bearer\n")
		}
		return nil
	}
	if !result.ScimOn {
		return errors.New("the answer to POST /network/scim-token says SCIM is off")
	}
	cli.printf("a new SCIM bearer for the team's IdP, at the SCIM base URL %s; any earlier bearer stopped working\n", result.ScimUrl)
	if result.ScimBearer == "" {
		// the first answer was lost, and the server keeps no bearer to answer a retry with
		cli.printf("its bearer was in an answer that was lost: run ur admin scim-token issue again\n")
		return nil
	}
	cli.printf("its bearer, shown once, for the IdP alone: %s\n", result.ScimBearer)
	return nil
}
