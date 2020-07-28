package vote

import (
	"crypto/sha256"
	"errors"
	"math/big"

	"github.com/zzGHzz/zkVote/common"
	"github.com/zzGHzz/zkVote/zk"
)

// BinaryTally structure
type BinaryTally struct {
	hX, hY *big.Int // h = prod_i g^a_i where i ==> the i'th voter
	YX, YY *big.Int // Y = prod_i y_i where y_i = g^{k*a_i}g^v_i
	I      uint     // number of ballots
}

// BinaryTallyRes structure
type BinaryTallyRes struct {
	v      uint          // Number of yes votes
	hX, hY *big.Int      // h = prod_i g^a_i
	XX, XY *big.Int      // X = h^k
	YX, YY *big.Int      // Y = X * g^v
	proof  *zk.ECFSProof // zkp proves the correctness of h^k
}

// NewBinaryTally creates a binary tally
func NewBinaryTally(hX, hY, YX, YY *big.Int, I uint) (*BinaryTally, error) {
	if !isOnCurve(hX, hY) {
		return nil, errors.New("h not on curve")
	}

	if !isOnCurve(YX, YY) {
		return nil, errors.New("Y not on curve")
	}

	return &BinaryTally{
		new(big.Int).Set(hX), new(big.Int).Set(hY),
		new(big.Int).Set(YX), new(big.Int).Set(YY),
		I,
	}, nil
}

// Tally computes result and zk proof
func (t *BinaryTally) Tally(k *big.Int) (*BinaryTallyRes, error) {
	if !isInRange(k) {
		return nil, ErrInvalidPrivKey
	}

	// X = h^k where h = prod_i g^a_i
	XX, XY := curve.ScalarMult(t.hX, t.hY, k.Bytes())

	// Get inv(X)
	XY = XY.Sub(curve.Params().P, XY)

	// g^v = Y/X
	gvX, gvY := curve.Add(XX, XY, t.YX, t.YY)

	// power break v
	tmpX, tmpY := big.NewInt(0), big.NewInt(0)
	v := uint(0)
	for {
		v = v + 1
		tmpX, tmpY = curve.Add(tmpX, tmpY, curve.Params().Gx, curve.Params().Gy)
		if tmpX.Cmp(gvX) == 0 && tmpY.Cmp(gvY) == 0 {
			break
		}
		if v > t.I {
			return nil, errors.New("Tally failed")
		}
	}

	// Generate zkp for proving the correctness of h^k
	prover, err := zk.NewECFSProver(k, t.hX, t.hY)
	if err != nil {
		return nil, err
	}
	gkX, gkY := curve.ScalarBaseMult(k.Bytes())
	data := sha256.Sum256(common.ConcatBytesTight(gkX.Bytes(), gkY.Bytes()))
	proof, err := prover.Prove(data[:])
	if err != nil {
		return nil, err
	}

	return &BinaryTallyRes{
		v,
		new(big.Int).Set(t.hX), new(big.Int).Set(t.hY),
		XX, XY,
		new(big.Int).Set(t.YX), new(big.Int).Set(t.YY),
		proof,
	}, nil
}

// Verify verifies tally result
func (r *BinaryTallyRes) Verify(gkX, gkY *big.Int) error {
	if !isOnCurve(gkX, gkY) {
		return errors.New("g^k not on curve")
	}

	if !isOnCurve(r.hX, r.hY) {
		return errors.New("h not on curve")
	}

	if !isOnCurve(r.XX, r.XY) {
		return errors.New("X not on curve")
	}

	if !isOnCurve(r.YX, r.YY) {
		return errors.New("Y not on curve")
	}

	// Check the correctness of v
	X, Y := curve.ScalarBaseMult(big.NewInt(int64(r.v)).Bytes())
	X, Y = curve.Add(X, Y, r.XX, r.XY)
	if X.Cmp(r.YX) != 0 || Y.Cmp(r.YY) != 0 {
		return errors.New("Y != X * g^v")
	}

	// Verify zkp
	data := sha256.Sum256(common.ConcatBytesTight(gkX.Bytes(), gkY.Bytes())) // hash of g^k
	res, err := r.proof.Verify(data[:])
	if err != nil {
		return err
	}
	if !res {
		return errors.New("Invalid zkp")
	}

	return nil
}
