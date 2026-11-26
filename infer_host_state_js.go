//go:build js && !ios_extension && !sidecar_http

// Where the local half keeps its files on the js leg (INFER-M11-06): nowhere, since a page keeps no files on a disk,
// so it pulls and loads no local model; infer_host_state.go answers every leg with a disk.

package sidecar

// See infer_host_state.go: the js leg has no disk.
func (self *Sidecar) inferStateDirectory() (string, error) {
	return "", ErrInferNoModelDirectory
}
