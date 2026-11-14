// ur login's half of ur-cli (§5.6, §7.8): v0's one admin command, a single-use, user-owned auth key of at most 5
// minutes for this device's daemon, minted with a one-command admin token in this process. ur login (cmd_login.go)
// drops the token and its DPoP key at once and hands the key to the daemon over the control socket; nothing here
// prints the key.

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/urnetwork/sidecar"
)

// The auth key v0's command creates: 300 seconds, one use, no tags, so the key is the user's own (§7.8).
const (
	urcliLoginKeyDurationSeconds = 300
	urcliLoginKeyMaxUses         = 1
)

// The command ur login runs: POST /network/auth-keys for its single-use key.
func urcliLoginCommand() (*sidecar.AdminCommand, error) {
	body, err := json.Marshal(map[string]int64{
		"duration_seconds": urcliLoginKeyDurationSeconds,
		"max_uses":         urcliLoginKeyMaxUses,
	})
	if err != nil {
		return nil, err
	}
	return &sidecar.AdminCommand{Method: "POST", Path: "/network/auth-keys", Body: body}, nil
}

// The api's answer to POST /network/auth-keys, as model.CreateAuthKeyResult writes it.
type urcliAuthKeyResult struct {
	AuthKeyId string `json:"auth_key_id"`
	AuthKey   string `json:"auth_key"`
	Error     *struct {
		Message string `json:"message"`
	} `json:"error"`
}

// ur login's ur-cli: an auth key of at most 5 minutes for the daemon, and drop, which erases the admin token and
// its DPoP key. --invite joins a Team's network, which is TEAM-M6-04's, and refuses until then.
func urcliLogin(ctx context.Context, cli *urCli, invite string) (authKey string, drop func(), err error) {
	if invite != "" {
		return "", nil, errors.New("ur login --invite joins a Team, which is not built yet")
	}
	env, err := newUrcliEnv(cli)
	if err != nil {
		return "", nil, err
	}
	command, err := urcliLoginCommand()
	if err != nil {
		return "", nil, err
	}
	grant, err := urcliAdminToken(ctx, env, command)
	if err != nil {
		return "", nil, err
	}
	drop = grant.erase
	body, err := urcliRunCommand(ctx, env, grant)
	if err != nil {
		return "", drop, err
	}
	result := &urcliAuthKeyResult{}
	if err := json.Unmarshal(body, result); err != nil {
		return "", drop, errors.New("ur-cli: the auth key answer does not parse")
	}
	if result.Error != nil {
		// the model's refusal, which names a rule and never a key
		return "", drop, fmt.Errorf("ur-cli: the auth key was refused: %s", result.Error.Message)
	}
	if _, err := sidecar.ParseAuthKey(result.AuthKey, nil); err != nil {
		return "", drop, errors.New("ur-cli: the answer holds no auth key")
	}
	return result.AuthKey, drop, nil
}

func init() {
	urcliLoginEntry = urcliLogin
}
