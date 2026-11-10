// ur record log (RECORD.md section 10.2, RECORD-M6-05): the verifiable log of a team record.
//
//	ur record log on --log=<log> [--interval=<duration>] [--witness=<name,url,vkey>]...
//	ur record log off --log=<log>
//	ur record log checkpoint [--log=<log>]
//	ur record log status [--log=<log>]
//
// on and off are a log admin's, confirmed on /dev/tty, and their daemon methods are Confirm ones, so nothing but a
// confirmed control call reaches them (D-CORE-13). on names this device as the log's checkpointer, with a log key the
// daemon draws and keeps; status prints that key as the verifier key a recipient or a witness's operator pins, each
// witness with what it last answered, and each finding the monitor raised. --log takes "team", the default, or a
// log's id.

package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/docopt/docopt-go"

	"github.com/urnetwork/sidecar"
)

// The control methods ur record log calls.
const (
	urMethodRecordLogOn         = "record.log.on"
	urMethodRecordLogOff        = "record.log.off"
	urMethodRecordLogCheckpoint = "record.log.checkpoint"
	urMethodRecordLogStatus     = "record.log.status"
)

func init() {
	registerUrRecordPart(&urRecordPart{
		word: "log",
		usage: []string{
			"  ur record log on --log=<log> [--interval=<duration>] [--witness=<witness>]...",
			"  ur record log off --log=<log>",
			"  ur record log checkpoint [--log=<log>]",
			"  ur record log status [--log=<log>]",
		},
		run: runUrRecordLog,
	})
	urDaemonMethodExtensions = append(urDaemonMethodExtensions, urRecordLogMethods)
}

// record.log.on's params.
type urRecordLogOnParams struct {
	Log             string                `json:"log"`
	IntervalSeconds int64                 `json:"interval_seconds,omitempty"`
	Witnesses       []*urRecordLogWitness `json:"witnesses,omitempty"`
}

// One --witness: its cosigner name, its https submission prefix and its verifier key.
type urRecordLogWitness struct {
	Name string `json:"name"`
	Url  string `json:"url"`
	Vkey string `json:"vkey"`
}

// The params of off, checkpoint and status.
type urRecordLogParams struct {
	Log string `json:"log"`
}

// record.log.checkpoint's reply.
type urRecordLogCheckpointReply struct {
	// 0 when no batch was due.
	Batch    uint64   `json:"batch"`
	Size     uint64   `json:"size,omitempty"`
	Cosigned []string `json:"cosigned,omitempty"`
}

// One witness in record.log.status's reply.
type urRecordLogWitnessStatus struct {
	Name          string `json:"name"`
	Url           string `json:"url"`
	Size          uint64 `json:"size,omitempty"`
	MissCount     int    `json:"miss_count,omitempty"`
	Refusal       string `json:"refusal,omitempty"`
	CosignedBatch uint64 `json:"cosigned_batch,omitempty"`
}

// record.log.status's reply: ids, sizes and public keys, never the log key.
type urRecordLogStatusReply struct {
	LogId             sidecar.Id                  `json:"log_id"`
	On                bool                        `json:"on"`
	Origin            string                      `json:"origin"`
	Checkpointer      *sidecar.Id                 `json:"checkpointer,omitempty"`
	LogKey            string                      `json:"log_key,omitempty"`
	IntervalSeconds   uint32                      `json:"interval_seconds,omitempty"`
	ThisDevice        bool                        `json:"this_device"`
	Witnesses         []*urRecordLogWitnessStatus `json:"witnesses,omitempty"`
	Batch             uint64                      `json:"batch"`
	Size              uint64                      `json:"size"`
	Root              string                      `json:"root,omitempty"`
	WaitingLeafCount  int                         `json:"waiting_leaf_count"`
	UnbackedLeafCount uint64                      `json:"unbacked_leaf_count,omitempty"`
	Stopped           string                      `json:"stopped,omitempty"`
	Findings          []string                    `json:"findings,omitempty"`
}

// What the log methods act on: a daemon target that runs a Sidecar's record.
type urRecordLogTarget interface {
	recordLogOn(ctx context.Context, params *urRecordLogOnParams, confirmed bool) error
	recordLogOff(ctx context.Context, log string, confirmed bool) error
	recordLogCheckpoint(ctx context.Context, log string) (*urRecordLogCheckpointReply, error)
	recordLogStatus(ctx context.Context, log string) (*urRecordLogStatusReply, error)
}

// The only hosted network's record, and the log name names there.
func (self *urDaemonNetwork) recordLog(name string) (*sidecar.SidecarRecord, sidecar.Id, error) {
	running, err := self.onlySidecar()
	if err != nil {
		return nil, sidecar.Id{}, err
	}
	record, err := running.Record()
	if err != nil {
		return nil, sidecar.Id{}, err
	}
	if name == "" {
		name = sidecar.RecordLogNameTeam
	}
	logId, err := record.ResolveLog(name)
	return record, logId, err
}

func (self *urDaemonNetwork) recordLogOn(ctx context.Context, params *urRecordLogOnParams, confirmed bool) error {
	record, logId, err := self.recordLog(params.Log)
	if err != nil {
		return err
	}
	args := &sidecar.RecordLogOnArgs{LogId: logId, Interval: time.Duration(params.IntervalSeconds) * time.Second, Confirmed: confirmed}
	for _, witness := range params.Witnesses {
		args.Witnesses = append(args.Witnesses, &sidecar.RecordLogWitnessArgs{Name: witness.Name, Url: witness.Url, Vkey: witness.Vkey})
	}
	return record.Log().On(ctx, args)
}

func (self *urDaemonNetwork) recordLogOff(ctx context.Context, log string, confirmed bool) error {
	record, logId, err := self.recordLog(log)
	if err != nil {
		return err
	}
	return record.Log().Off(ctx, logId, confirmed)
}

func (self *urDaemonNetwork) recordLogCheckpoint(ctx context.Context, log string) (*urRecordLogCheckpointReply, error) {
	record, logId, err := self.recordLog(log)
	if err != nil {
		return nil, err
	}
	result, err := record.Log().Checkpoint(ctx, logId, true)
	if err != nil {
		return nil, err
	}
	if result == nil {
		return &urRecordLogCheckpointReply{}, nil
	}
	return &urRecordLogCheckpointReply{Batch: result.Batch, Size: result.Size, Cosigned: result.CosignedNames}, nil
}

func (self *urDaemonNetwork) recordLogStatus(ctx context.Context, log string) (*urRecordLogStatusReply, error) {
	record, logId, err := self.recordLog(log)
	if err != nil {
		return nil, err
	}
	// the monitor runs at this sync, so the status is of what evs holds now
	if err := record.Reader().Sync(ctx, logId); err != nil {
		return nil, err
	}
	status, err := record.Log().Status(logId)
	if err != nil {
		return nil, err
	}
	reply := &urRecordLogStatusReply{
		LogId: status.LogId, On: status.On, Origin: status.Origin, Checkpointer: status.CheckpointerSidecarId, LogKey: status.LogKey,
		IntervalSeconds: status.IntervalSeconds, ThisDevice: status.ThisDevice, Batch: status.Batch, Size: status.Size,
		Root: hex.EncodeToString(status.Root), WaitingLeafCount: status.WaitingLeafCount, UnbackedLeafCount: status.UnbackedLeafCount,
		Stopped: status.Stopped, Findings: status.Findings,
	}
	for _, witness := range status.Witnesses {
		reply.Witnesses = append(reply.Witnesses, &urRecordLogWitnessStatus{
			Name: witness.Name, Url: witness.Url, Size: witness.Size, MissCount: witness.MissCount, Refusal: witness.Refusal, CosignedBatch: witness.CosignedBatch,
		})
	}
	return reply, nil
}

// The log methods over target, when it runs a Sidecar's record.
func urRecordLogMethods(target urDaemonTarget) []*sidecar.DaemonMethod {
	logs, ok := target.(urRecordLogTarget)
	if !ok {
		return nil
	}
	return []*sidecar.DaemonMethod{
		{
			Name:    urMethodRecordLogOn,
			Confirm: true,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				params := &urRecordLogOnParams{}
				if err := decodeUrParams(call, params); err != nil || params.Log == "" {
					return nil, errors.New("turning a log on takes the log")
				}
				return nil, logs.recordLogOn(ctx, params, call.Confirmed)
			},
		},
		{
			Name:    urMethodRecordLogOff,
			Confirm: true,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				params := &urRecordLogParams{}
				if err := decodeUrParams(call, params); err != nil || params.Log == "" {
					return nil, errors.New("turning a log off takes the log")
				}
				return nil, logs.recordLogOff(ctx, params.Log, call.Confirmed)
			},
		},
		{
			Name: urMethodRecordLogCheckpoint,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				params := &urRecordLogParams{}
				if err := decodeUrParams(call, params); err != nil {
					return nil, errors.New("a checkpoint takes at most the log")
				}
				return logs.recordLogCheckpoint(ctx, params.Log)
			},
		},
		{
			Name: urMethodRecordLogStatus,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				params := &urRecordLogParams{}
				if err := decodeUrParams(call, params); err != nil {
					return nil, errors.New("a status takes at most the log")
				}
				return logs.recordLogStatus(ctx, params.Log)
			},
		},
	}
}

// One --witness as typed: name,url,vkey, split at its first two commas: a name holds none, and a url that holds one
// is not taken.
func parseUrRecordLogWitness(text string) (*urRecordLogWitness, error) {
	parts := strings.SplitN(text, ",", 3)
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return nil, fmt.Errorf("--witness takes name,url,vkey, not %q", text)
	}
	return &urRecordLogWitness{Name: parts[0], Url: parts[1], Vkey: parts[2]}, nil
}

// Runs the part of ur record log its second word names.
func runUrRecordLog(ctx context.Context, cli *urCli, options docopt.Opts) error {
	log := urOptionString(options, "--log")
	switch {
	case urOptionBool(options, "on"):
		params := &urRecordLogOnParams{Log: log}
		if text := urOptionString(options, "--interval"); text != "" {
			interval, err := time.ParseDuration(text)
			if err != nil || interval <= 0 || interval%time.Second != 0 {
				return fmt.Errorf("--interval takes a duration of whole seconds, such as 1h, not %q", text)
			}
			params.IntervalSeconds = int64(interval / time.Second)
		}
		for _, text := range urOptionStrings(options, "--witness") {
			witness, err := parseUrRecordLogWitness(text)
			if err != nil {
				return err
			}
			params.Witnesses = append(params.Witnesses, witness)
		}
		question := fmt.Sprintf("Turn on the verifiable log of %s, with this device as its checkpointer", log)
		if 0 < len(params.Witnesses) {
			names := []string{}
			for _, witness := range params.Witnesses {
				names = append(names, witness.Name+" at "+witness.Url)
			}
			question += ", sending each checkpoint's origin, size and root to " + strings.Join(names, " and ")
		}
		confirmed, err := confirmOnTty(cli, question+"?")
		if err != nil {
			return err
		}
		if !confirmed {
			cli.printf("nothing changed\n")
			return nil
		}
		if err := cli.callDaemon(ctx, urMethodRecordLogOn, params, true, nil); err != nil {
			return err
		}
		cli.printf("the verifiable log of %s is on\n", log)
		return nil
	case urOptionBool(options, "off"):
		confirmed, err := confirmOnTty(cli, fmt.Sprintf("Turn off the verifiable log of %s from its next batch?", log))
		if err != nil {
			return err
		}
		if !confirmed {
			cli.printf("nothing changed\n")
			return nil
		}
		if err := cli.callDaemon(ctx, urMethodRecordLogOff, &urRecordLogParams{Log: log}, true, nil); err != nil {
			return err
		}
		cli.printf("the verifiable log of %s is off\n", log)
		return nil
	case urOptionBool(options, "checkpoint"):
		reply := &urRecordLogCheckpointReply{}
		if err := cli.callDaemon(ctx, urMethodRecordLogCheckpoint, &urRecordLogParams{Log: log}, false, reply); err != nil {
			return err
		}
		if reply.Batch == 0 {
			cli.printf("nothing waits for a checkpoint\n")
			return nil
		}
		cli.printf("batch %d filed at size %d", reply.Batch, reply.Size)
		if 0 < len(reply.Cosigned) {
			cli.printf(", cosigned by %s", strings.Join(reply.Cosigned, ", "))
		}
		cli.printf("\n")
		return nil
	case urOptionBool(options, "status"):
		reply := &urRecordLogStatusReply{}
		if err := cli.callDaemon(ctx, urMethodRecordLogStatus, &urRecordLogParams{Log: log}, false, reply); err != nil {
			return err
		}
		printUrRecordLogStatus(cli, reply)
		return nil
	}
	return errors.New("ur record log takes on, off, checkpoint or status")
}

// The status, a line a fact.
func printUrRecordLogStatus(cli *urCli, reply *urRecordLogStatusReply) {
	state := "off"
	if reply.On {
		state = "on"
	}
	cli.printf("log %s: %s\n", reply.LogId, state)
	cli.printf("origin: %s\n", reply.Origin)
	if reply.Checkpointer != nil {
		where := ""
		if reply.ThisDevice {
			where = " (this device)"
		}
		cli.printf("checkpointer: %s%s, every %s\n", reply.Checkpointer, where, time.Duration(reply.IntervalSeconds)*time.Second)
		cli.printf("log key: %s\n", reply.LogKey)
	}
	cli.printf("batch %d, size %d", reply.Batch, reply.Size)
	if reply.Root != "" {
		cli.printf(", root %s", reply.Root)
	}
	cli.printf("; %d leaves wait\n", reply.WaitingLeafCount)
	if len(reply.Witnesses) == 0 && reply.On {
		cli.printf("no witness: each checkpoint is the team's own statement\n")
	}
	for _, witness := range reply.Witnesses {
		cli.printf("witness %s at %s: cosigned through batch %d", witness.Name, witness.Url, witness.CosignedBatch)
		if witness.Refusal != "" {
			cli.printf("; left out of the last %d notes: %s", witness.MissCount, witness.Refusal)
		}
		cli.printf("\n")
	}
	if 0 < reply.UnbackedLeafCount {
		cli.printf("%d leaves have no entry this device holds: expired or lost\n", reply.UnbackedLeafCount)
	}
	if reply.Stopped != "" {
		cli.printf("the checkpointer stopped: %s\n", reply.Stopped)
	}
	for _, finding := range reply.Findings {
		cli.printf("finding: %s\n", finding)
	}
}
