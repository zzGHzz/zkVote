// Prove the knowledge of secrete x where y = g^x

package zk

import (
	"crypto/sha256"
	"fmt"
	"math/big"

	"github.com/zzGHzz/zkVote/common"
)

// ECFSProver - prover structure
type ECFSProver struct {
	x      *big.Int
	yX, yY *big.Int
}

// ECFSProof - proof structure
type ECFSProof struct {
	yX, yY    *big.Int
	tX, tY, r *big.Int
}

// NewECFSProver news a prover
func NewECFSProver(x *big.Int) (*ECFSProver, error) {
	// check the range of x
	if !isInRange(x) {
		return nil, ErrOutOfRange
	}

	// y = g^k
	yX, yY := curve.ScalarBaseMult(x.Bytes())

	return &ECFSProver{new(big.Int).Set(x), yX, yY}, nil
}

// Prove generates ECFSProof
func (p *ECFSProver) Prove(data []byte) (*ECFSProof, error) {
	// v <--r-- Z_q^*
	v, err := ecrand()
	if err != nil {
		return nil, err
	}

	// t = g^v
	tX, tY := curve.ScalarBaseMult(v.Bytes())

	// c = H(data, g, y, t)
	c := sha256.Sum256(common.ConcatBytesTight(
		data[:],
		Gx.Bytes(), Gy.Bytes(),
		p.yX.Bytes(), p.yY.Bytes(),
		tX.Bytes(), tY.Bytes(),
	))
	fmt.Printf("%x\n", c)

	// r = v - c*x
	r := new(big.Int).SetBytes(c[:])
	r = r.Mul(r, p.x)
	r = r.Sub(v, r)
	r = r.Mod(r, N)

	return &ECFSProof{
		new(big.Int).Set(p.yX), new(big.Int).Set(p.yY),
		tX, tY, r,
	}, nil
}

// Verify verifies ECFSProof
func (p *ECFSProof) Verify(data []byte) (bool, error) {
	// y must be on curve
	if !isOnCurve(p.yX, p.yY) {
		return false, ErrNotOnCurve
	}

	// t must be on curve
	if !isOnCurve(p.tX, p.tY) {
		return false, ErrNotOnCurve
	}

	// r must be in range
	if !isInRange(p.r) {
		return false, ErrOutOfRange
	}

	// c = hash(data, g, y, t)
	c := sha256.Sum256(common.ConcatBytesTight(
		data[:],
		Gx.Bytes(), Gy.Bytes(),
		p.yX.Bytes(), p.yY.Bytes(),
		p.tX.Bytes(), p.tY.Bytes(),
	))
	fmt.Printf("%x\n", c)

	// check t = (g^r)(y^c)
	X1, Y1 := curve.ScalarBaseMult(p.r.Bytes())
	X2, Y2 := curve.ScalarMult(p.yX, p.yY, new(big.Int).SetBytes(c[:]).Bytes())
	X1, Y1 = curve.Add(X1, Y1, X2, Y2)
	if X1.Cmp(p.tX) != 0 || Y1.Cmp(p.tY) != 0 {
		return false, nil
	}
	return true, nil
}
