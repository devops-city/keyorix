package core

import (
	"math"
	"math/rand"
)

// Isolation Forest (Liu, Ting & Zhou, 2008) — an unsupervised outlier detector.
// The intuition: anomalies are "few and different", so a random binary partition of
// the feature space isolates them in fewer splits than normal points. We build an
// ensemble of randomly-grown trees on a subsample of the *normal* distribution (the
// learned baseline), then score new points by their average path length: a short
// path (isolated quickly) means anomalous.
//
// This is a pure-Go, dependency-free implementation operating on []float64 feature
// vectors. It is deliberately small — the secret-access feature space is low-
// dimensional (see anomaly_ml.go) — and fully deterministic given a seeded RNG so
// scores are reproducible and testable. Like the rest of the anomaly subsystem it
// only ever sees access *metadata*, never secret values.

// eulerGamma is the Euler–Mascheroni constant, used in the harmonic-number
// approximation H(i) ≈ ln(i) + γ within the path-length normalisation c(n).
const eulerGamma = 0.5772156649

// iTreeNode is a node of a single isolation tree. Internal nodes carry a random
// split (a feature index and threshold); external (leaf) nodes carry the size of the
// subsample that reached them, so an unbuilt subtree's expected depth can be folded
// into the path length via c(size).
type iTreeNode struct {
	left, right *iTreeNode
	splitFeat   int
	splitVal    float64
	size        int // population at a leaf; 0 for internal nodes
	external    bool
}

// isolationForest is a trained ensemble. psi is the subsample size actually used to
// grow each tree; it is the normaliser for the anomaly score.
type isolationForest struct {
	trees []*iTreeNode
	psi   int
}

// avgPathLength is c(n): the average path length of an unsuccessful search in a binary
// search tree of n nodes. It normalises observed path lengths so the score is
// comparable across forests grown on different subsample sizes.
func avgPathLength(n int) float64 {
	switch {
	case n <= 1:
		return 0
	case n == 2:
		return 1
	default:
		h := math.Log(float64(n-1)) + eulerGamma
		return 2*h - 2*float64(n-1)/float64(n)
	}
}

// newIsolationForest grows numTrees isolation trees, each on an independent random
// subsample of at most sampleSize rows drawn from data. Returns nil when there is too
// little data to learn from (fewer than 2 rows) — callers treat a nil forest as "no
// ML signal" and fall back to the statistical rules.
func newIsolationForest(data [][]float64, numTrees, sampleSize int, rng *rand.Rand) *isolationForest {
	if len(data) < 2 || numTrees < 1 {
		return nil
	}
	psi := max(min(sampleSize, len(data)), 2)
	// Height limit per the paper: anomalies are isolated well above this, so growing
	// deeper only refines the (already long) paths of normal points.
	heightLimit := int(math.Ceil(math.Log2(float64(psi))))

	f := &isolationForest{psi: psi, trees: make([]*iTreeNode, 0, numTrees)}
	for range numTrees {
		sub := subsample(data, psi, rng)
		f.trees = append(f.trees, buildITree(sub, 0, heightLimit, rng))
	}
	return f
}

// subsample draws k rows from data without replacement via a partial Fisher–Yates
// shuffle over an index permutation, so each tree sees a different slice of the
// baseline. Rows are shared by reference (read-only during training).
func subsample(data [][]float64, k int, rng *rand.Rand) [][]float64 {
	n := len(data)
	idx := make([]int, n)
	for i := range idx {
		idx[i] = i
	}
	if k > n {
		k = n
	}
	for i := 0; i < k; i++ {
		j := i + rng.Intn(n-i) // NOSONAR -- PRNG intentional for isolation forest ML algorithm
		idx[i], idx[j] = idx[j], idx[i]
	}
	out := make([][]float64, k)
	for i := 0; i < k; i++ {
		out[i] = data[idx[i]]
	}
	return out
}

// buildITree grows one isolation tree by recursively splitting on a random feature at
// a random threshold within that feature's observed range. Recursion stops at the
// height limit, at a single (or empty) sample, or when the chosen feature is constant
// across the node (no separating split exists).
func buildITree(samples [][]float64, depth, heightLimit int, rng *rand.Rand) *iTreeNode {
	if depth >= heightLimit || len(samples) <= 1 {
		return &iTreeNode{external: true, size: len(samples)}
	}
	// Choose the split feature among those that actually vary in this node. Picking a
	// constant feature would yield a degenerate (one-sided) split and waste depth, so a
	// node is only a leaf when *every* feature is constant (the points are identical).
	feat, minV, maxV, ok := pickSplitFeature(samples, rng)
	if !ok {
		return &iTreeNode{external: true, size: len(samples)}
	}
	split := minV + rng.Float64()*(maxV-minV) // NOSONAR -- PRNG intentional for isolation forest ML algorithm

	left := make([][]float64, 0, len(samples))
	right := make([][]float64, 0, len(samples))
	for _, s := range samples {
		if s[feat] < split {
			left = append(left, s)
		} else {
			right = append(right, s)
		}
	}
	return &iTreeNode{
		splitFeat: feat,
		splitVal:  split,
		left:      buildITree(left, depth+1, heightLimit, rng),
		right:     buildITree(right, depth+1, heightLimit, rng),
	}
}

// pickSplitFeature returns a uniformly random feature among those with a non-zero
// range across samples, plus that feature's min and max. ok is false when no feature
// varies (all sampled points are identical), so the node must become a leaf.
func pickSplitFeature(samples [][]float64, rng *rand.Rand) (feat int, minV, maxV float64, ok bool) {
	nFeat := len(samples[0])
	type rng2 struct{ lo, hi float64 }
	ranges := make([]rng2, nFeat)
	for f := range nFeat {
		ranges[f] = rng2{samples[0][f], samples[0][f]}
	}
	for _, s := range samples {
		for f := range nFeat {
			if s[f] < ranges[f].lo {
				ranges[f].lo = s[f]
			}
			if s[f] > ranges[f].hi {
				ranges[f].hi = s[f]
			}
		}
	}
	varying := make([]int, 0, nFeat)
	for f := range nFeat {
		if ranges[f].hi > ranges[f].lo {
			varying = append(varying, f)
		}
	}
	if len(varying) == 0 {
		return 0, 0, 0, false
	}
	feat = varying[rng.Intn(len(varying))] // NOSONAR -- PRNG intentional for isolation forest ML algorithm
	return feat, ranges[feat].lo, ranges[feat].hi, true
}

// pathLength returns the depth at which x is isolated in one tree, folding in the
// expected remaining depth c(size) when x lands in a leaf that still holds >1 sample
// (i.e. an unbuilt subtree truncated by the height limit).
func pathLength(x []float64, node *iTreeNode, depth int) float64 {
	if node.external {
		return float64(depth) + avgPathLength(node.size)
	}
	if x[node.splitFeat] < node.splitVal {
		return pathLength(x, node.left, depth+1)
	}
	return pathLength(x, node.right, depth+1)
}

// score returns the isolation-forest anomaly score s(x) = 2^(-E[h(x)] / c(psi)),
// in [0,1): values approaching 1 are strongly anomalous (consistently short paths),
// values around 0.5 are indistinguishable from normal. Returns 0.5 for a forest that
// failed to grow (defensive — newIsolationForest returns nil rather than such a one).
func (f *isolationForest) score(x []float64) float64 {
	if f == nil || len(f.trees) == 0 {
		return 0.5
	}
	var total float64
	for _, t := range f.trees {
		total += pathLength(x, t, 0)
	}
	avg := total / float64(len(f.trees))
	norm := avgPathLength(f.psi)
	if norm == 0 {
		return 0.5
	}
	return math.Pow(2, -avg/norm)
}
