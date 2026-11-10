//go:build !sidecar_http

// The team directory's SidecarComponent (§5.4, RECORD-M6-13): runs a DirectoryClient's sync loop on each client
// generation and stops with it. Its sealed directory is §5.9's directory/, under file class search, which
// Sidecar.DirectoryClient opens under the same name.
//
// Nothing adds this component yet: the daemon's composition does, beside the record's, as each lands. The sidecar_http
// leg runs no component (§18.10): the console's page Worker builds its read_only client with NewDirectoryClient.

package sidecar

import (
	"sync"
)

// Whether this leg's directory client refuses every write: no, a daemon's writes.
const directoryLegReadOnly = false

// The directory's component. Close comes after its last generation is detached (SidecarComponent), so no Attach races
// it.
type directoryComponent struct {
	client *DirectoryClient
	// each attached generation's loop, waited for at Close
	runs sync.WaitGroup
}

// A component running client's sync loop.
func NewDirectoryComponent(client *DirectoryClient) SidecarComponent {
	return &directoryComponent{client: client}
}

// The directory's own name, its keychain namespace and directory.
func (self *directoryComponent) Name() string {
	return directoryComponentName
}

// Starts the generation's sync loop, which ends with env.Ctx.
func (self *directoryComponent) Attach(env *SidecarEnv) error {
	self.runs.Add(1)
	go func() {
		defer self.runs.Done()
		self.client.Run(env.Ctx)
	}()
	return nil
}

// Waits for the last generation's loop, whose context has ended by now.
func (self *directoryComponent) Close() {
	self.runs.Wait()
}
