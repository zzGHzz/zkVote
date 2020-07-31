package vote

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"

	"github.com/zzGHzz/zkVote/zk"
)

// BinaryBallot - ballot structure
type BinaryBallot struct {
	hX, hY *big.Int // h = g^a
	yX, yY *big.Int // y = g^{a*k} * g^v
	zkp    *zk.BinaryProof
}

// NewBinaryBallot generates a binary ballot
func NewBinaryBallot(value bool, a, gkX, gkY *big.Int, data []byte) (*BinaryBallot, error) {
	var (
		yX, yY *big.Int

		prover *zk.BinaryProver
		proof  *zk.BinaryProof
		err    error
	)

	if !isOnCurve(gkX, gkY) {
		return nil, errors.New("Invalid g^k")
	}

	if !isInRange(a) {
		return nil, errors.New("Invalid a")
	}

	// y = g^{k*a}
	yX, yY = curve.ScalarMult(gkX, gkY, a.Bytes())

	if value {
		// y = y * g^v
		yX, yY = curve.Add(yX, yY, curve.Params().Gx, curve.Params().Gy)
	}

	// Set global ECC var for zk package
	zk.SetEllipticCurve(curve)

	// Create prover
	hX, hY := curve.ScalarBaseMult(a.Bytes())
	prover, err = zk.NewBinaryProver(value, a, hX, hY, gkX, gkY)
	if err != nil {
		return nil, err
	}

	// Generate proof
	// data := sha256.Sum256(common.ConcatBytesTight(
	// a.PublicKey.X.Bytes(), a.PublicKey.Y.Bytes()))
	z := sha256.Sum256(data)
	proof, err = prover.Prove(z[:])
	if err != nil {
		return nil, err
	}

	return &BinaryBallot{
		hX, hY,
		yX, yY,
		proof,
	}, nil
}

// Verify verifies binary ballot
func (b *BinaryBallot) Verify() error {
	if !isOnCurve(b.hX, b.hY) {
		return errors.New("Invalid h = g^a")
	}

	if !isOnCurve(b.yX, b.yY) {
		return errors.New("Invalid y = g^{ak} * g^v")
	}

	res, err := b.zkp.Verify()
	if err != nil {
		return err
	}
	if !res {
		return errors.New("Failed to verify")
	}

	return nil
}

func (b *BinaryBallot) String() string {
	return fmt.Sprintf(`BinaryBallot:
h		= (%v, %v)
y		= (%v, %v)
%s`, b.hX, b.hY, b.yX, b.yY, b.zkp.String())
}
