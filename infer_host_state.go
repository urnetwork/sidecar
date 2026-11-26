//go:build !ios_extension && !sidecar_http && !js

// Where the local half keeps its files on a leg with a disk (INFER-M11-06): the instance's state directory, the OS
// backend's; infer_host_state_js.go answers the page leg, which has none.

package sidecar

// The instance's state directory on its disk, where the local half keeps its files: ErrInferNoModelDirectory where
// its store is not the OS backend, as a test's memory store is not.
func (self *Sidecar) inferStateDirectory() (string, error) {
	if self.instance == nil {
		return "", ErrInferNoModelDirectory
	}
	backend, ok := self.instance.backend.(*osStoreBackend)
	if !ok {
		return "", ErrInferNoModelDirectory
	}
	return backend.directory, nil
}
