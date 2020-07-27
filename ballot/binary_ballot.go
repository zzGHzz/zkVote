package ballot

import (
	"crypto/ecdsa"
	"crypto/elliptic"
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

// var
var (
	ErrInvalidPubKey = errors.New("Invalid public key")
)

// NewBinaryBallot generates a binary ballot
func NewBinaryBallot(value bool, a *ecdsa.PrivateKey, gk *ecdsa.PublicKey) (*BinaryBallot, error) {
	var (
		curve  elliptic.Curve
		yX, yY *big.Int

		prover *zk.BinaryProver
		proof  *zk.BinaryProof
		err    error
	)

	// check curve
	if a.Curve != gk.Curve {
		return nil, zk.ErrCurveNotMatch
	}

	curve = a.Curve

	// check gk
	if !curve.IsOnCurve(gk.X, gk.Y) {
		return nil, ErrInvalidPubKey
	}

	// y = g^{k*a}
	yX, yY = curve.ScalarMult(gk.X, gk.Y, a.D.Bytes())

	if value {
		// y = y * g^v
		yX, yY = curve.Add(yX, yY, curve.Params().Gx, curve.Params().Gy)
	}

	// Set ECC
	zk.SetECC(curve)
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
func (b *BinaryBallot) Verify() (bool, error) {
	return b.zkp.Verify()
}
