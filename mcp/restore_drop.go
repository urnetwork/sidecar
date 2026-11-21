//go:build !js && !ios && !android && !sdk_mobile_bind

// An executed drop on this device's restore points (§16.7, §5.9's dropped row; D-CORE-19, D-MCP-8, FI-8;
// MCP-M10-01). The root cannot import mcp/, so RestorePoints hands each network's Sidecar a holder
// (Sidecar.AddDropHolder), which Sidecar.ApplyExecutedDrop calls as it does for every decrypted copy kept outside evs:
//
//	base   every run's point of the network on disk, open in this process or not, loses each sealed base copy whose
//	       bytes a listed version alone holds (SidecarExecutedDrop.DroppedContent): a copy whose bytes a live version
//	       shares stays, and so does one the drop's Live cannot answer for, so a doubt keeps the copy (FI-27)
//	holds  each open point's held copies the same
//	reads  the manifest keeps the copy's name, so a plan and an apply read the copy absent and name the path dropped,
//	       never not-exact (restore_plan.go, restore_apply.go): run_restore reports it dropped and restores nothing of
//	       it, so a path whose needed version is dropped is never partly restored
//
// A second call for a drop applied finds nothing more to remove. Nothing of a path is logged (I-13).

package mcp

import (
	"context"
	"crypto/sha256"
	"errors"
	"strings"

	"github.com/urnetwork/sidecar"
)

// What a network's drop holder is registered with and reads: *sidecar.Sidecar's holders, its local store, where its
// runs' points are, and its identity, which names the network its open points are under.
type McpRestoreDropHost interface {
	AddDropHolder(holder sidecar.SidecarDropHolder) (func(), error)
	LocalStore() sidecar.SidecarStore
	Identity() *sidecar.SidecarIdentity
}

// Registers the points' drop holder with host, a daemon's network as its Sidecar starts. The answer removes it.
func (self *RestorePoints) AddDropHolder(host McpRestoreDropHost) (func(), error) {
	return host.AddDropHolder(&restoreDropHolder{points: self, host: host})
}

// One network's holder of the points' copies.
type restoreDropHolder struct {
	points *RestorePoints
	host   McpRestoreDropHost
}

// See sidecar.SidecarDropHolder, and the file header.
func (self *restoreDropHolder) ApplyExecutedDrop(ctx context.Context, drop *sidecar.SidecarExecutedDrop) error {
	if drop == nil {
		return nil
	}
	restoreStore, err := self.host.LocalStore().Directory(restoreDirectoryName, restoreClass)
	if err != nil {
		return err
	}
	entries, err := restoreStore.List("")
	if err != nil {
		return err
	}
	errs := []error{}
	for _, entry := range entries {
		// a run's point is its directory holding a manifest
		runText, name, ok := strings.Cut(entry.Name, "/")
		if !ok || name != restoreManifestName {
			continue
		}
		if _, err := sidecar.ParseId(runText); err != nil {
			continue
		}
		runStore, err := restoreStore.Directory(runText, "")
		if err != nil {
			errs = append(errs, err)
			continue
		}
		errs = append(errs, self.dropBaseCopies(ctx, runStore, drop))
	}
	if identity := self.host.Identity(); identity != nil {
		for _, point := range self.points.openPoints(identity.NetworkId) {
			errs = append(errs, point.dropHeldCopies(ctx, drop))
		}
	}
	return errors.Join(errs...)
}

// Removes each base copy of one run's point that only the drop's listed versions hold.
func (self *restoreDropHolder) dropBaseCopies(ctx context.Context, runStore sidecar.SidecarStore, drop *sidecar.SidecarExecutedDrop) error {
	manifest := &restoreManifest{}
	found, err := readRestoreJson(runStore, restoreManifestName, manifest, self.points.settings.RestoreManifestByteCount)
	if err != nil || !found {
		return err
	}
	errs := []error{}
	for _, file := range manifest.Files {
		if file == nil || file.Copy == "" || file.State == nil || len(file.State.Sha256) != sha256.Size {
			continue
		}
		dropped, err := drop.DroppedContent(ctx, [sha256.Size]byte(file.State.Sha256))
		if err != nil {
			// what the drop cannot answer for stays
			errs = append(errs, err)
			continue
		}
		if dropped {
			errs = append(errs, runStore.Remove(file.Copy))
		}
	}
	return errors.Join(errs...)
}

// The points this process holds open of networkId.
func (self *RestorePoints) openPoints(networkId sidecar.Id) []*RestorePoint {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	points := []*RestorePoint{}
	for key, point := range self.points {
		if key.networkId == networkId {
			points = append(points, point)
		}
	}
	return points
}

// Removes each held copy of the point that only the drop's listed versions hold.
func (self *RestorePoint) dropHeldCopies(ctx context.Context, drop *sidecar.SidecarExecutedDrop) error {
	type heldCopy struct {
		name   string
		sha256 []byte
	}
	held := func() []heldCopy {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		copies := []heldCopy{}
		for _, hold := range self.holds {
			for _, file := range hold.files {
				if file.copyName != "" && file.state != nil && len(file.state.Sha256) == sha256.Size {
					copies = append(copies, heldCopy{name: file.copyName, sha256: file.state.Sha256})
				}
			}
		}
		return copies
	}()
	errs := []error{}
	for _, candidate := range held {
		dropped, err := drop.DroppedContent(ctx, [sha256.Size]byte(candidate.sha256))
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if dropped {
			errs = append(errs, self.store.Remove(candidate.name))
		}
	}
	return errors.Join(errs...)
}
