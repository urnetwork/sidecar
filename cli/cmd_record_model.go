// ur record model (RECORD.md section 12; RECORD-M6-08).
//
//	ur record model set --port=<port> [--engine=<engine>] [--engine-version=<version>] [--quantization=<quantization>] [--weights=<path>]...
//	ur record model show [--port=<port>]
//
// A model host's statement of what it serves on a local port. set is a person's: the command shows what it will
// declare on the terminal and declares only on a yes there, the daemon refuses a caller with a harness process among
// its ancestors, and no MCP tool reaches it. Each field of the manifest says how it is known: declared, typed here;
// reported, read from the engine's own listing; measured, the daemon's hash of the files --weights names, which shows
// the bytes on disk at hashing and not what the engine loaded. Nothing is ever shown as attested. Weight paths stay
// on this host.

package main

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strconv"

	"github.com/docopt/docopt-go"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// The control methods ur record model calls.
const (
	urMethodRecordModelSet  = "record.model.set"
	urMethodRecordModelShow = "record.model.show"
)

func init() {
	registerUrRecordPart(&urRecordPart{
		word: "model",
		usage: []string{
			"  ur record model set --port=<port> [--engine=<engine>] [--engine-version=<version>] [--quantization=<quantization>] [--weights=<path>]...",
			"  ur record model show [--port=<port>]",
		},
		run: runUrRecordModel,
	})
	urDaemonMethodExtensions = append(urDaemonMethodExtensions, urRecordModelMethods)
}

// What a declaration states, as the methods take it. Weights are absolute paths on the daemon's host.
type urRecordModelParams struct {
	Port          uint32   `json:"port"`
	Engine        string   `json:"engine,omitempty"`
	EngineVersion string   `json:"engine_version,omitempty"`
	Quantization  string   `json:"quantization,omitempty"`
	Weights       []string `json:"weights,omitempty"`
}

// One field of a manifest as shown.
type urRecordModelField struct {
	Name     string `json:"name"`
	Value    string `json:"value"`
	Evidence string `json:"evidence"`
}

// One port's manifest as shown.
type urRecordModelItem struct {
	Port         uint32                `json:"port"`
	Fields       []*urRecordModelField `json:"fields"`
	WeightsBytes uint64                `json:"weights_bytes,omitempty"`
	// the model entry later receipts name; nil before any, and while one waits in the spool
	EntryId *sidecar.Id `json:"entry_id,omitempty"`
	LogId   *sidecar.Id `json:"log_id,omitempty"`
	// the engine asked for a credential, so nothing is read from it
	Credential bool `json:"credential,omitempty"`
	Written    bool `json:"written,omitempty"`
}

// The manifests asked for.
type urRecordModelReply struct {
	Items []*urRecordModelItem `json:"items"`
}

// What the model methods act on: a daemon target that runs a Sidecar's record. pid is the caller's, as the daemon
// read it.
type urRecordModelTarget interface {
	recordModelSet(ctx context.Context, params *urRecordModelParams, pid int, confirmed bool) (*urRecordModelReply, error)
	recordModelShow(ctx context.Context, port uint32) (*urRecordModelReply, error)
}

// How a field's evidence reads. Attested is reserved, and a value claiming it is shown as what it is: unverified.
func urRecordModelEvidence(evidence uint32) string {
	switch evidence {
	case sidecar.RecordModelEvidenceDeclared:
		return "declared"
	case sidecar.RecordModelEvidenceReported:
		return "reported"
	case sidecar.RecordModelEvidenceMeasured:
		return "measured"
	}
	return "unverified"
}

// A status as the reply carries it.
func urRecordModelItemOf(status *sidecar.RecordModelStatus) *urRecordModelItem {
	item := &urRecordModelItem{Port: status.Port, Fields: []*urRecordModelField{}, Credential: status.Credential, Written: status.Written}
	add := func(name string, field *protocol.ModelField) {
		if field != nil {
			item.Fields = append(item.Fields, &urRecordModelField{Name: name, Value: field.GetValue(), Evidence: urRecordModelEvidence(field.GetEvidence())})
		}
	}
	add("served_name", status.Manifest.GetServedName())
	add("engine", status.Manifest.GetEngine())
	add("engine_version", status.Manifest.GetEngineVersion())
	add("quantization", status.Manifest.GetQuantization())
	add("weights_digest", status.Manifest.GetWeightsDigest())
	item.WeightsBytes = status.Manifest.GetWeightsBytes()
	if status.Ref != nil {
		entryId, logId := status.Ref.EntryId, status.Ref.LogId
		item.EntryId, item.LogId = &entryId, &logId
	}
	return item
}

// The hosted record's manifests.
func (self *urDaemonNetwork) recordModels() (*sidecar.Sidecar, *sidecar.RecordModels, error) {
	running, err := self.onlySidecar()
	if err != nil {
		return nil, nil, err
	}
	record, err := running.Record()
	if err != nil {
		return nil, nil, err
	}
	return running, record.Models(), nil
}

func (self *urDaemonNetwork) recordModelSet(ctx context.Context, params *urRecordModelParams, pid int, confirmed bool) (*urRecordModelReply, error) {
	running, models, err := self.recordModels()
	if err != nil {
		return nil, err
	}
	status, err := models.Declare(ctx, &sidecar.RecordModelDeclareArgs{
		Port:            params.Port,
		Fields:          sidecar.RecordModelFields{Engine: params.Engine, EngineVersion: params.EngineVersion, Quantization: params.Quantization},
		WeightPaths:     params.Weights,
		HarnessAncestor: running.HarnessAncestor(ctx, pid),
		Confirmed:       confirmed,
	})
	if err != nil {
		return nil, err
	}
	return &urRecordModelReply{Items: []*urRecordModelItem{urRecordModelItemOf(status)}}, nil
}

func (self *urDaemonNetwork) recordModelShow(ctx context.Context, port uint32) (*urRecordModelReply, error) {
	_, models, err := self.recordModels()
	if err != nil {
		return nil, err
	}
	reply := &urRecordModelReply{Items: []*urRecordModelItem{}}
	if port != 0 {
		status, held, err := models.Show(port)
		if err != nil {
			return nil, err
		}
		if held {
			reply.Items = append(reply.Items, urRecordModelItemOf(status))
		}
		return reply, nil
	}
	statuses, err := models.List()
	if err != nil {
		return nil, err
	}
	for _, status := range statuses {
		reply.Items = append(reply.Items, urRecordModelItemOf(status))
	}
	return reply, nil
}

// The model methods over target, when it runs a Sidecar's record.
func urRecordModelMethods(target urDaemonTarget) []*sidecar.DaemonMethod {
	models, ok := target.(urRecordModelTarget)
	if !ok {
		return nil
	}
	return []*sidecar.DaemonMethod{
		{
			Name:    urMethodRecordModelSet,
			Confirm: true,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				params := &urRecordModelParams{}
				if err := decodeUrParams(call, params); err != nil || params.Port == 0 {
					return nil, errors.New("a model declaration takes its port")
				}
				return models.recordModelSet(ctx, params, urCallPid(call), call.Confirmed)
			},
		},
		{
			Name: urMethodRecordModelShow,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				params := &urRecordModelParams{}
				if err := decodeUrParams(call, params); err != nil {
					return nil, errors.New("a model listing takes a port or none")
				}
				return models.recordModelShow(ctx, params.Port)
			},
		},
	}
}

// --port's value: a TCP port, 0 for none given.
func parseUrRecordModelPort(text string) (uint32, error) {
	if text == "" {
		return 0, nil
	}
	port, err := strconv.ParseUint(text, 10, 16)
	if err != nil || port == 0 {
		return 0, fmt.Errorf("--port is a port from 1 to 65535, not %q", text)
	}
	return uint32(port), nil
}

// The manifests as a person reads them: each field with how it is known.
func printUrRecordModels(cli *urCli, reply *urRecordModelReply) {
	if len(reply.Items) == 0 {
		cli.printf("no model manifest\n")
		return
	}
	for _, item := range reply.Items {
		cli.printf("port %d\n", item.Port)
		for _, field := range item.Fields {
			cli.printf("  %-15s %s  (%s)\n", field.Name, field.Value, field.Evidence)
		}
		if item.WeightsBytes != 0 {
			cli.printf("  %-15s %d\n", "weights_bytes", item.WeightsBytes)
		}
		if item.Credential {
			cli.printf("  the port asks for a credential, so nothing is read from its engine\n")
		}
		switch {
		case item.EntryId != nil:
			cli.printf("  model entry %s in log %s; reach receipts written from now name it\n", item.EntryId, item.LogId)
		default:
			cli.printf("  its model entry waits to be written\n")
		}
	}
	cli.printf("a run is joined to a manifest by inference: %s\n", sidecar.RecordModelJoinLabel)
}

// Runs set or show.
func runUrRecordModel(ctx context.Context, cli *urCli, options docopt.Opts) error {
	port, err := parseUrRecordModelPort(urOptionString(options, "--port"))
	if err != nil {
		return err
	}
	if !urOptionBool(options, "set") {
		reply := &urRecordModelReply{}
		if err := cli.callDaemon(ctx, urMethodRecordModelShow, &urRecordModelParams{Port: port}, false, reply); err != nil {
			return err
		}
		printUrRecordModels(cli, reply)
		return nil
	}
	params := &urRecordModelParams{
		Port:          port,
		Engine:        urOptionString(options, "--engine"),
		EngineVersion: urOptionString(options, "--engine-version"),
		Quantization:  urOptionString(options, "--quantization"),
	}
	for _, path := range urOptionStrings(options, "--weights") {
		// the daemon hashes them, and its working directory is not this one
		absolute, err := filepath.Abs(path)
		if err != nil {
			return err
		}
		params.Weights = append(params.Weights, absolute)
	}
	tty, err := cli.openTty()
	if err != nil {
		return fmt.Errorf("%w: %w", errUrNoTty, err)
	}
	fmt.Fprintf(tty, "port %d: engine %q, engine version %q, quantization %q, as your statement; %d weight paths to hash\n",
		params.Port, params.Engine, params.EngineVersion, params.Quantization, len(params.Weights))
	tty.Close()
	confirmed, err := confirmOnTty(cli, fmt.Sprintf("Declare what port %d serves in the record?", params.Port))
	if err != nil {
		return err
	}
	if !confirmed {
		cli.printf("nothing was declared\n")
		return nil
	}
	reply := &urRecordModelReply{}
	if err := cli.callDaemon(ctx, urMethodRecordModelSet, params, true, reply); err != nil {
		return err
	}
	printUrRecordModels(cli, reply)
	return nil
}
