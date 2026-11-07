// Tree math against the mlswg's tree-math vectors, RFC 9420's worked tables, and the semantic
// definitions Appendix C gives.

package sidecar

import (
	"slices"
	"testing"
)

func TestMlsTreeMathVectors(t *testing.T) {
	var vectors []struct {
		NLeaves uint32    `json:"n_leaves"`
		NNodes  uint32    `json:"n_nodes"`
		Root    uint32    `json:"root"`
		Left    []*uint32 `json:"left"`
		Right   []*uint32 `json:"right"`
		Parent  []*uint32 `json:"parent"`
		Sibling []*uint32 `json:"sibling"`
	}
	mlsLoadVectors(t, "tree-math", &vectors)
	if len(vectors) == 0 {
		t.Fatal("no vectors")
	}
	check := func(name string, node int, got mlsNodeIndex, ok bool, want *uint32) {
		t.Helper()
		if want == nil {
			if ok {
				t.Errorf("%s of %d: %d, want none", name, node, got)
			}
			return
		}
		if !ok || uint32(got) != *want {
			t.Errorf("%s of %d: %d, %v, want %d", name, node, got, ok, *want)
		}
	}
	for _, vector := range vectors {
		if !mlsTreeLeafCountValid(vector.NLeaves) {
			t.Errorf("leaf count %d is not valid", vector.NLeaves)
		}
		if width := mlsTreeWidth(vector.NLeaves); width != vector.NNodes {
			t.Errorf("%d leaves: width %d, want %d", vector.NLeaves, width, vector.NNodes)
		}
		if root := mlsTreeRoot(vector.NLeaves); uint32(root) != vector.Root {
			t.Errorf("%d leaves: root %d, want %d", vector.NLeaves, root, vector.Root)
		}
		for index := range vector.Parent {
			node := mlsNodeIndex(index)
			left, ok := node.left()
			check("left", index, left, ok, vector.Left[index])
			right, ok := node.right()
			check("right", index, right, ok, vector.Right[index])
			parent, ok := node.parent(vector.NLeaves)
			check("parent", index, parent, ok, vector.Parent[index])
			sibling, ok := node.sibling(vector.NLeaves)
			check("sibling", index, sibling, ok, vector.Sibling[index])
		}
	}
}

func TestMlsTreeLeafCountValid(t *testing.T) {
	cases := []struct {
		leafCount uint32
		valid     bool
	}{
		{leafCount: 0},
		{leafCount: 1, valid: true},
		{leafCount: 2, valid: true},
		{leafCount: 3},
		{leafCount: 1000},
		{leafCount: 1024, valid: true},
		{leafCount: mlsTreeLeafCountMaximum, valid: true},
		{leafCount: mlsTreeLeafCountMaximum + 1},
		{leafCount: 0xffffffff},
	}
	for _, c := range cases {
		if valid := mlsTreeLeafCountValid(c.leafCount); valid != c.valid {
			t.Errorf("%d: %v", c.leafCount, valid)
		}
	}
}

// Figure 11's tree, read as indices: leaves A, B, E, F and G are leaves 0, 1, 4, 5 and 6; parents
// T, V, U, X, Y, Z and W are nodes 1, 5, 3, 9, 11, 13 and 7.
func TestMlsDirectPathsAndCopathsOfFigure11(t *testing.T) {
	cases := []struct {
		leaf       mlsLeafIndex
		directPath []mlsNodeIndex
		copath     []mlsNodeIndex
	}{
		{leaf: 0, directPath: []mlsNodeIndex{1, 3, 7}, copath: []mlsNodeIndex{2, 5, 11}},
		{leaf: 1, directPath: []mlsNodeIndex{1, 3, 7}, copath: []mlsNodeIndex{0, 5, 11}},
		{leaf: 4, directPath: []mlsNodeIndex{9, 11, 7}, copath: []mlsNodeIndex{10, 13, 3}},
		{leaf: 5, directPath: []mlsNodeIndex{9, 11, 7}, copath: []mlsNodeIndex{8, 13, 3}},
		{leaf: 6, directPath: []mlsNodeIndex{13, 11, 7}, copath: []mlsNodeIndex{14, 9, 3}},
	}
	for _, c := range cases {
		if path := c.leaf.node().directPath(8); !slices.Equal(path, c.directPath) {
			t.Errorf("leaf %d: direct path %v, want %v", c.leaf, path, c.directPath)
		}
		if copath := c.leaf.node().copath(8); !slices.Equal(copath, c.copath) {
			t.Errorf("leaf %d: copath %v, want %v", c.leaf, copath, c.copath)
		}
	}
}

func TestMlsPathsOfTheRootAreEmpty(t *testing.T) {
	for _, leafCount := range []uint32{1, 2, 8} {
		root := mlsTreeRoot(leafCount)
		if path := root.directPath(leafCount); len(path) != 0 {
			t.Errorf("%d leaves: direct path %v", leafCount, path)
		}
		if copath := root.copath(leafCount); len(copath) != 0 {
			t.Errorf("%d leaves: copath %v", leafCount, copath)
		}
	}
}

// Node indices can come off the wire: none may loop forever or walk a path that is not there.
func TestMlsNodesOutsideTheTreeHaveNoPaths(t *testing.T) {
	const leafCount = 8
	for _, node := range []mlsNodeIndex{15, 16, 17, 1023, 0xfffffffe, 0xffffffff} {
		if parent, ok := node.parent(leafCount); ok {
			t.Errorf("node %d: parent %d", node, parent)
		}
		if sibling, ok := node.sibling(leafCount); ok {
			t.Errorf("node %d: sibling %d", node, sibling)
		}
		if path := node.directPath(leafCount); len(path) != 0 {
			t.Errorf("node %d: direct path %v", node, path)
		}
		if copath := node.copath(leafCount); len(copath) != 0 {
			t.Errorf("node %d: copath %v", node, copath)
		}
	}
}

// The largest tree must not overflow 32 bits anywhere.
func TestMlsLargestTree(t *testing.T) {
	leafCount := mlsTreeLeafCountMaximum
	if width := mlsTreeWidth(leafCount); width != 0xffffffff {
		t.Fatalf("width %#x", width)
	}
	root := mlsTreeRoot(leafCount)
	if root != 0x7fffffff {
		t.Fatalf("root %#x", root)
	}
	lastLeaf := mlsLeafIndex(leafCount - 1)
	path := lastLeaf.node().directPath(leafCount)
	if len(path) != 31 || path[len(path)-1] != root {
		t.Fatalf("path %v", path)
	}
	if copath := lastLeaf.node().copath(leafCount); len(copath) != 31 {
		t.Fatalf("copath %v", copath)
	}
	if ancestor := mlsCommonAncestor(mlsLeafIndex(0).node(), lastLeaf.node()); ancestor != root {
		t.Fatalf("ancestor %#x", ancestor)
	}
	if !root.subtreeContains(lastLeaf.node()) || !root.subtreeContains(0) {
		t.Fatal("the root does not contain its leaves")
	}
}

func TestMlsCommonAncestorMatchesTheSemanticDefinition(t *testing.T) {
	// common_ancestor_semantic: the lowest node on both paths, each node on its own path
	semantic := func(first mlsNodeIndex, second mlsNodeIndex, leafCount uint32) mlsNodeIndex {
		firstPath := append([]mlsNodeIndex{first}, first.directPath(leafCount)...)
		secondPath := append([]mlsNodeIndex{second}, second.directPath(leafCount)...)
		var lowest mlsNodeIndex
		found := false
		for _, node := range firstPath {
			if slices.Contains(secondPath, node) && (!found || node.level() < lowest.level()) {
				lowest = node
				found = true
			}
		}
		if !found {
			t.Fatalf("nodes %d and %d share no ancestor", first, second)
		}
		return lowest
	}
	for _, leafCount := range []uint32{1, 2, 4, 8, 16, 32} {
		width := mlsTreeWidth(leafCount)
		for first := mlsNodeIndex(0); uint32(first) < width; first++ {
			for second := mlsNodeIndex(0); uint32(second) < width; second++ {
				want := semantic(first, second, leafCount)
				if got := mlsCommonAncestor(first, second); got != want {
					t.Errorf("%d leaves: ancestor of %d and %d is %d, want %d", leafCount, first, second, got, want)
				}
			}
		}
	}
}

func TestMlsSubtreeContainsMatchesTheDirectPath(t *testing.T) {
	for _, leafCount := range []uint32{1, 2, 8, 32} {
		width := mlsTreeWidth(leafCount)
		for ancestor := mlsNodeIndex(0); uint32(ancestor) < width; ancestor++ {
			for node := mlsNodeIndex(0); uint32(node) < width; node++ {
				want := ancestor == node || slices.Contains(node.directPath(leafCount), ancestor)
				if got := ancestor.subtreeContains(node); got != want {
					t.Errorf("%d leaves: %d contains %d: %v, want %v", leafCount, ancestor, node, got, want)
				}
			}
		}
	}
}

func TestMlsLeafAndNodeConversions(t *testing.T) {
	for leaf := mlsLeafIndex(0); leaf < 64; leaf++ {
		node := leaf.node()
		if !node.isLeaf() || node.leaf() != leaf || node.level() != 0 {
			t.Errorf("leaf %d: node %d", leaf, node)
		}
		if parent, _ := node.parent(64); parent.isLeaf() {
			t.Errorf("leaf %d: its parent %d is a leaf", leaf, parent)
		}
	}
	levels := map[mlsNodeIndex]int{0: 0, 1: 1, 2: 0, 3: 2, 5: 1, 7: 3, 15: 4}
	for node, level := range levels {
		if got := node.level(); got != level {
			t.Errorf("node %d: level %d, want %d", node, got, level)
		}
	}
}
