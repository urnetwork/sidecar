//go:build linux

// FIDO2 security keys on Linux as ur daemon's presence provider (MCP-M3-09): each /dev/hidraw<n> whose report
// descriptor declares FIDO's usage page, 0xF1D0, opened read-write, with no cgo. A report goes out as a zero report id
// and its 64 bytes, and comes in as its 64 bytes. presence_fido.go speaks CTAP2 over them. A host whose hidraw nodes
// the daemon's user cannot open, as most need a udev rule for, finds no key, and every prompt refuses.

package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/urnetwork/sidecar"
)

// Where Linux lists hidraw nodes and their descriptors.
const (
	urHidrawClassDirectory  = "/sys/class/hidraw"
	urHidrawDeviceDirectory = "/dev"
)

// The FIDO provider over this host's hidraw keys, its credentials under <state>/presence.
func urPlatformPresenceProvider(stateDirectory string, ingest *sidecar.SidecarIngestSettings, log sidecar.Logger) sidecar.PresenceProvider {
	settings := defaultUrFidoSettings()
	return newUrFidoProvider(filepath.Join(stateDirectory, "presence"), func() ([]urFidoDevice, error) {
		return urHidrawDevices(settings)
	}, settings, log)
}

// Every hidraw node whose descriptor is FIDO's, opened.
func urHidrawDevices(settings *urFidoSettings) ([]urFidoDevice, error) {
	entries, err := os.ReadDir(urHidrawClassDirectory)
	if err != nil {
		return nil, err
	}
	devices := []urFidoDevice{}
	for _, entry := range entries {
		descriptor, err := os.ReadFile(filepath.Join(urHidrawClassDirectory, entry.Name(), "device", "report_descriptor"))
		if err != nil || !urFidoReportDescriptor(descriptor) {
			continue
		}
		file, err := os.OpenFile(filepath.Join(urHidrawDeviceDirectory, entry.Name()), os.O_RDWR, 0)
		if err != nil {
			continue
		}
		devices = append(devices, &urHidrawDevice{file: file, settings: settings})
	}
	return devices, nil
}

// One open hidraw node.
type urHidrawDevice struct {
	file     *os.File
	settings *urFidoSettings
}

// The report, behind its zero report id.
func (self *urHidrawDevice) Write(report []byte) error {
	_, err := self.file.Write(append([]byte{0}, report...))
	return err
}

// One report, its read bounded by ctx's deadline where the node can be polled.
func (self *urHidrawDevice) Read(ctx context.Context) ([]byte, error) {
	if deadline, ok := ctx.Deadline(); ok {
		// a node the poller cannot take reads blocking, ended by ctx's close below
		_ = self.file.SetReadDeadline(deadline)
	}
	stop := context.AfterFunc(ctx, func() {
		_ = self.file.SetReadDeadline(time.Now())
	})
	defer stop()
	report := make([]byte, self.settings.ReportByteCount)
	n, err := self.file.Read(report)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if errors.Is(err, os.ErrDeadlineExceeded) {
			return nil, context.DeadlineExceeded
		}
		return nil, err
	}
	return report[:n], nil
}

func (self *urHidrawDevice) Close() error {
	return self.file.Close()
}
