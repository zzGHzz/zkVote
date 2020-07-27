package zk

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"math/big"
)

// zk related errors
var (
	ErrInvalidPub    = errors.New("Invalid pubilc key")
	ErrInvalidPriv   = errors.New("Invalid private key")
	ErrCurveNotMatch = errors.New("Ellipic curves not match")
	ErrOutOfRange    = errors.New("Out of range")
	ErrNotOnCurve    = errors.New("Not on curve")
)

func randq(q *big.Int) (*big.Int, error) {
	if q.Cmp(big.NewInt(0)) <= 0 {
		return nil, errors.New("Negative input")
	}

	for {
		r, err := rand.Int(rand.Reader, q)
		if err != nil {
			return nil, err
		}

		// >0
		if r.Cmp(big.NewInt(0)) == 1 {
			return r, nil
		}
	}
}

func ecrand(curve elliptic.Curve) (*big.Int, error) {
	k, err := ecdsa.GenerateKey(curve, rand.Reader)

	if err != nil {
		return nil, err
	}

	return new(big.Int).Set(k.D), nil
}
