package vote

import (
	"crypto/sha256"
	"math/big"

	"github.com/zzGHzz/zkVote/common"
	"github.com/zzGHzz/zkVote/zk"
)

// BinaryVote structure
type BinaryVote struct {
	gkX, gkY *big.Int                   // authority's public key
	ballots  map[[32]byte]*BinaryBallot // binary ballots
}

// BinaryTallyProof structure
type BinaryTallyProof struct {
	hX, hY *big.Int // h = prod_i g^a_i
	YX, YY *big.Int // Y = prod_i y_i
	V      *big.Int // V = sum_i v_i
	proof  *zk.ECFSProof
}

// NewBinaryVote news a yes-or-no vote
func NewBinaryVote(maxVoter uint, gkX, gkY *big.Int) (*BinaryVote, error) {
	if !isOnCurve(gkX, gkY) {
		return nil, ErrInvalidPubKey
	}

	vote := new(BinaryVote)
	vote.gkX = new(big.Int).Set(gkX)
	vote.gkY = new(big.Int).Set(gkY)
	vote.ballots = make(map[[32]byte]*BinaryBallot)

	return vote, nil
}

// Cast casts a ballot
func (v *BinaryVote) Cast(b *BinaryBallot) error {
	data := sha256.Sum256(common.ConcatBytesTight(b.xX.Bytes(), b.xY.Bytes()))

	if err := b.Verify(); err != nil {
		return ErrInvalidBallot
	}

	v.ballots[data] = b

	return nil
}

// Tally tallies results
//
// 1. Compute voting result
// 2. Generate zkp for tally results
func (v *BinaryVote) Tally(k *big.Int)
