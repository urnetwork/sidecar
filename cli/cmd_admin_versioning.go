// ur admin versioning (TEAM-M10-01; §7.9's VersioningRules, §11.7; owner decisions 164, 167): shows the network's
// VersioningRules from the verified config head, or, with --rules, replaces them with the JSON given, signed by this
// device, an Owner's, Admin's or Network admin's, confirmed on /dev/tty, and saved into the config head through this
// device's config writer, never through MCP. The record sets the versioning an honest writer gives each path it
// creates from then on; existing paths keep theirs.
//
// --rules is JSON, rules in order, each selector optional, as in
//
//	{"rules": [{"kinds": ["general"], "path_glob": "build/**", "size_above_bytes": 1048576, "versioning": "off"}]}

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/docopt/docopt-go"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// The control methods ur admin versioning calls.
const (
	urMethodAdminVersioning     = "admin.versioning.get"
	urMethodAdminVersioningSave = "admin.versioning.save"
)

func init() {
	urDaemonMethodExtensions = append(urDaemonMethodExtensions, urAdminVersioningMethods)
}

// What the versioning methods act on.
type urAdminVersioningTarget interface {
	versioningRules() (*protocol.VersioningRules, bool, error)
	saveVersioningRules(ctx context.Context, rules *protocol.VersioningRules) error
}

func (self *urDaemonNetwork) versioningRules() (*protocol.VersioningRules, bool, error) {
	running, err := self.onlySidecar()
	if err != nil {
		return nil, false, err
	}
	return running.VersioningRules()
}

// A confirmed control call.
func (self *urDaemonNetwork) saveVersioningRules(ctx context.Context, rules *protocol.VersioningRules) error {
	running, err := self.onlySidecar()
	if err != nil {
		return err
	}
	return running.SaveVersioningRules(ctx, rules, sidecar.SidecarActConfirmed)
}

// One rule as --rules writes it.
type urVersioningRuleJson struct {
	Kinds          []string `json:"kinds,omitempty"`
	RepoIds        []string `json:"repo_ids,omitempty"`
	PathGlob       string   `json:"path_glob,omitempty"`
	SizeAboveBytes uint64   `json:"size_above_bytes,omitempty"`
	Versioning     string   `json:"versioning"`
}

type urVersioningRulesJson struct {
	Rules []*urVersioningRuleJson `json:"rules"`
}

// The record --rules writes, checked as every reader checks it.
func urParseVersioningRules(text string) (*protocol.VersioningRules, error) {
	parsed := &urVersioningRulesJson{}
	if err := json.Unmarshal([]byte(text), parsed); err != nil {
		return nil, fmt.Errorf("the rules do not parse: %w", err)
	}
	rules := &protocol.VersioningRules{}
	for i, rule := range parsed.Rules {
		if rule == nil {
			return nil, fmt.Errorf("rule %d is empty", i)
		}
		next := &protocol.VersioningRule{PathGlob: rule.PathGlob, SizeAboveBytes: rule.SizeAboveBytes}
		switch rule.Versioning {
		case "on":
			next.Versioning = protocol.VersioningMode_VERSIONING_MODE_ON
		case "off":
			next.Versioning = protocol.VersioningMode_VERSIONING_MODE_OFF
		default:
			return nil, fmt.Errorf("rule %d's versioning is on or off: %q", i, rule.Versioning)
		}
		for _, kind := range rule.Kinds {
			value, ok := protocol.RepoKind_value["REPO_KIND_"+strings.ToUpper(kind)]
			if !ok {
				return nil, fmt.Errorf("rule %d names no repo kind %q", i, kind)
			}
			next.Kinds = append(next.Kinds, uint32(value))
		}
		for _, repoIdText := range rule.RepoIds {
			repoId, err := sidecar.ParseId(repoIdText)
			if err != nil {
				return nil, fmt.Errorf("rule %d names no repo id %q", i, repoIdText)
			}
			next.RepoIds = append(next.RepoIds, repoId.Bytes())
		}
		rules.Rules = append(rules.Rules, next)
	}
	if err := sidecar.CheckVersioningRules(rules); err != nil {
		return nil, err
	}
	return rules, nil
}

// A record as --rules would write it.
func urFormatVersioningRules(rules *protocol.VersioningRules) string {
	formatted := &urVersioningRulesJson{Rules: []*urVersioningRuleJson{}}
	for _, rule := range rules.GetRules() {
		next := &urVersioningRuleJson{PathGlob: rule.GetPathGlob(), SizeAboveBytes: rule.GetSizeAboveBytes(), Versioning: "on"}
		if rule.GetVersioning() == protocol.VersioningMode_VERSIONING_MODE_OFF {
			next.Versioning = "off"
		}
		for _, kind := range rule.GetKinds() {
			next.Kinds = append(next.Kinds, strings.ToLower(strings.TrimPrefix(protocol.RepoKind(kind).String(), "REPO_KIND_")))
		}
		for _, repoId := range rule.GetRepoIds() {
			if id, err := sidecar.IdFromBytes(repoId); err == nil {
				next.RepoIds = append(next.RepoIds, id.String())
			}
		}
		formatted.Rules = append(formatted.Rules, next)
	}
	text, _ := json.Marshal(formatted)
	return string(text)
}

// The rules as the methods carry them: --rules' JSON.
type urVersioningReply struct {
	Rules string `json:"rules,omitempty"`
	// No record: the platform rule holds, versionless above 64 MiB.
	Platform bool `json:"platform,omitempty"`
}

type urVersioningParams struct {
	Rules string `json:"rules"`
}

// The versioning methods over target, when it hosts a Sidecar.
func urAdminVersioningMethods(target urDaemonTarget) []*sidecar.DaemonMethod {
	versioning, ok := target.(urAdminVersioningTarget)
	if !ok {
		return nil
	}
	return []*sidecar.DaemonMethod{
		{
			Name: urMethodAdminVersioning,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				rules, known, err := versioning.versioningRules()
				if err != nil {
					return nil, err
				}
				if !known {
					return nil, errors.New("this device opens no config head, so it cannot read the network's rules")
				}
				if rules == nil {
					return &urVersioningReply{Platform: true}, nil
				}
				return &urVersioningReply{Rules: urFormatVersioningRules(rules)}, nil
			},
		},
		{
			Name:    urMethodAdminVersioningSave,
			Confirm: true,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				params := &urVersioningParams{}
				if err := decodeUrParams(call, params); err != nil {
					return nil, err
				}
				rules, err := urParseVersioningRules(params.Rules)
				if err != nil {
					return nil, err
				}
				return nil, versioning.saveVersioningRules(ctx, rules)
			},
		},
	}
}

// ur admin versioning: the rules, or a new record confirmed on the terminal.
func runUrAdminVersioning(ctx context.Context, cli *urCli, options docopt.Opts) error {
	text, _ := options.String("--rules")
	if text == "" {
		reply := &urVersioningReply{}
		if err := cli.callDaemon(ctx, urMethodAdminVersioning, nil, false, reply); err != nil {
			return err
		}
		if reply.Platform {
			cli.printf("no VersioningRules: the platform rule holds, versionless above 64 MiB\n")
			return nil
		}
		cli.printf("%s\n", reply.Rules)
		return nil
	}
	rules, err := urParseVersioningRules(text)
	if err != nil {
		return err
	}
	confirmed, err := confirmOnTty(cli, fmt.Sprintf("replace the network's VersioningRules with %d rule(s), for paths created from now on?", len(rules.GetRules())))
	if err != nil {
		return err
	}
	if !confirmed {
		cli.printf("nothing changed\n")
		return nil
	}
	if err := cli.callDaemon(ctx, urMethodAdminVersioningSave, &urVersioningParams{Rules: text}, true, nil); err != nil {
		return err
	}
	cli.printf("the network's VersioningRules are saved\n")
	return nil
}
