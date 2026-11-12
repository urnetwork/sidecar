//go:build !ios_extension

// What a removal lists of the versionless files below it (§11.7's removal row; FS-67; EVS2-M10-15): a push removing a
// directory, and a ref's DELETE, list each versionless file below as a file removal of its own, so the commit names
// every version it replaces and the purge deletes their content a minute later; a versionless file the push leaves
// unlisted goes only at its marker's collection, which the fold alarms (EVS2-M10-07). EvsPlanRemove walks the tree the
// caller gives, a head-mode client's verified listings where it holds no tree, breadth first, and lists each file
// whose newest version is versionless, a path the same push writes again excepted, which keeps its own content.
//
// On every leg but ios_extension. Package-level functions are safe for concurrent use.

package sidecar

import (
	"context"
	"errors"
	"fmt"

	"github.com/urnetwork/sidecar/protocol"
)

// One child of a directory as a removal's walk reads it.
type EvsPlanRemoveChild struct {
	// Its path, raw names joined by /.
	Path      string
	Directory bool
	// A file's newest version's versioning.
	Versioning uint32
}

// The tree a removal walks: a directory's children at the head the plan reads.
type EvsPlanRemoveTree interface {
	Children(ctx context.Context, directory string) ([]*EvsPlanRemoveChild, error)
}

// A walk past §11.6's depth: no tree a ref holds goes so deep.
var ErrEvsPlanRemoveDepth = errors.New("evs: a removal's walk past the token path's depth")

// The file removals a removal of directory lists (see the file header): each versionless file below it, but the paths
// in written, which the push writes again. directory "" is the ref's root, a DELETE's.
func EvsPlanRemove(ctx context.Context, tree EvsPlanRemoveTree, directory string, written map[string]bool) ([]*EvsPathWrite, error) {
	removals := []*EvsPathWrite{}
	level := []string{directory}
	for depth := 0; 0 < len(level); depth += 1 {
		if EvsTokenPathMaxLength < depth {
			return nil, fmt.Errorf("%w: %d levels", ErrEvsPlanRemoveDepth, depth)
		}
		next := []string{}
		for _, parent := range level {
			children, err := tree.Children(ctx, parent)
			if err != nil {
				return nil, err
			}
			for _, child := range children {
				switch {
				case child.Directory:
					next = append(next, child.Path)
				case child.Versioning != uint32(protocol.EvsVersioning_EVS_VERSIONING_KEPT) && !written[child.Path]:
					removals = append(removals, &EvsPathWrite{Path: child.Path, Remove: true})
				}
			}
		}
		level = next
	}
	return removals, nil
}
