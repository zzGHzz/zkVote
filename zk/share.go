package zk

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"math/big"
)

var (
	errNil           = errors.New("Nil input")
	errInvalidPub    = errors.New("Invalid pubilc key")
	errInvalidPriv   = errors.New("Invalid private key")
	errCurveNotMatch = errors.New("Ellipic curves not match")
	errOutOfRange    = errors.New("Out of range")
	errNotOnCurve    = errors.New("Not on curve")
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
