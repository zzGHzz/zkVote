package vote

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"errors"
	"math/big"

	"github.com/zzGHzz/zkVote/common"
	"github.com/zzGHzz/zkVote/zk"
)

// BinaryBallot - ballot structure
type BinaryBallot struct {
	xX, xY, yX, yY *big.Int
	zkp            *zk.BinaryProof
}

// NewBinaryBallot generates a binary ballot
func NewBinaryBallot(value bool, a *ecdsa.PrivateKey, gk *ecdsa.PublicKey) (*BinaryBallot, error) {
	var (
		yX, yY *big.Int

		prover *zk.BinaryProver
		proof  *zk.BinaryProof
		err    error
	)

	if !isOnCurve(gk.X, gk.Y) || isOnCurve(a.PublicKey.X, a.PublicKey.Y) {
		return nil, ErrInvalidPubKey
	}

	if !isInRange(a.D) {
		return nil, ErrInvalidPrivKey
	}

	// y = g^{k*a}
	yX, yY = curve.ScalarMult(gk.X, gk.Y, a.D.Bytes())

	if value {
		// y = y * g^v
		yX, yY = curve.Add(yX, yY, curve.Params().Gx, curve.Params().Gy)
	}

	// Set global ECC var for zk package
	zk.SetEllipticCurve(curve)
	// Create prover
	prover, err = zk.NewBinaryProver(value, a.D, a.PublicKey.X, a.PublicKey.Y, gk.X, gk.Y)
	if err != nil {
		return nil, err
	}
	// Generate proof
	data := sha256.Sum256(common.ConcatBytesTight(
		a.PublicKey.X.Bytes(), a.PublicKey.Y.Bytes()))
	proof, err = prover.Prove(data[:])
	if err != nil {
		return nil, err
	}

	return &BinaryBallot{
		a.PublicKey.X, a.PublicKey.Y,
		yX, yY,
		proof,
	}, nil
}

// Verify verifies binary ballot
func (b *BinaryBallot) Verify() error {
	res, err := b.zkp.Verify()
	if err != nil {
		return err
	}
	if !res {
		return errors.New("Failed to verify")
	}

	return nil
}
