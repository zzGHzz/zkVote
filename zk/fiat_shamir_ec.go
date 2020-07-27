// Prove the knowledge of secrete x where y = g^x

package zk

import (
	"crypto/elliptic"
	"crypto/sha256"
	"fmt"
	"math/big"

	"github.com/zzGHzz/zkVote/common"
)

// ECFSProver - prover structure
type ECFSProver struct {
	curve  elliptic.Curve
	x      *big.Int
	yX, yY *big.Int
}

// ECFSProof - proof structure
type ECFSProof struct {
	curve     elliptic.Curve
	yX, yY    *big.Int
	tX, tY, r *big.Int
}

// NewECFSProver news a prover
func NewECFSProver(curve elliptic.Curve, x *big.Int) (*ECFSProver, error) {
	// check the range of k
	if x.Cmp(big.NewInt(0)) <= 0 || x.Cmp(curve.Params().N) >= 0 {
		return nil, errOutOfRange
	}

	// y = g^k
	yX, yY := curve.ScalarBaseMult(x.Bytes())

	return &ECFSProver{curve, new(big.Int).Set(x), yX, yY}, nil
}

// Prove generates ECFSProof
func (p *ECFSProver) Prove(data []byte) (*ECFSProof, error) {
	// v <--r-- Z_q^*
	v, err := ecrand(p.curve)
	if err != nil {
		return nil, err
	}

	// t = g^v
	tX, tY := p.curve.ScalarBaseMult(v.Bytes())

	// c = H(data, g, y, t)
	c := sha256.Sum256(common.ConcatBytesTight(
		data[:],
		p.curve.Params().Gx.Bytes(), p.curve.Params().Gy.Bytes(),
		p.yX.Bytes(), p.yY.Bytes(),
		tX.Bytes(), tY.Bytes(),
	))
	fmt.Printf("%x\n", c)

	// r = v - c*x
	r := new(big.Int).SetBytes(c[:])
	r = r.Mul(r, p.x)
	// r = r.Mod(r, p.curve.Params().N)
	r = r.Sub(v, r)
	r = r.Mod(r, p.curve.Params().N)

	return &ECFSProof{
		p.curve,
		new(big.Int).Set(p.yX), new(big.Int).Set(p.yY),
		tX, tY, r}, nil
}

// Verify verifies ECFSProof
func (p *ECFSProof) Verify(data []byte) (bool, error) {
	// y must be on curve
	if !p.curve.IsOnCurve(p.yX, p.yY) {
		return false, errNotOnCurve
	}

	// t must be on curve
	if !p.curve.IsOnCurve(p.tX, p.tY) {
		return false, errNotOnCurve
	}

	// r must be in range
	if p.r.Cmp(big.NewInt(0)) <= 0 || p.r.Cmp(p.curve.Params().N) >= 0 {
		return false, errOutOfRange
	}

	// c = hash(data, g, y, t)
	c := sha256.Sum256(common.ConcatBytesTight(
		data[:],
		p.curve.Params().Gx.Bytes(), p.curve.Params().Gy.Bytes(),
		p.yX.Bytes(), p.yY.Bytes(),
		p.tX.Bytes(), p.tY.Bytes(),
	))
	fmt.Printf("%x\n", c)

	// check t = (g^r)(y^c)
	X1, Y1 := p.curve.ScalarBaseMult(p.r.Bytes())
	X2, Y2 := p.curve.ScalarMult(p.yX, p.yY, new(big.Int).SetBytes(c[:]).Bytes())
	X1, Y1 = p.curve.Add(X1, Y1, X2, Y2)
	if X1.Cmp(p.tX) != 0 || Y1.Cmp(p.tY) != 0 {
		return false, nil
	}
	return true, nil
}
