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
	curve elliptic.Curve = elliptic.P256()
	N     *big.Int       = new(big.Int).Set(curve.Params().N)
	Gx    *big.Int       = new(big.Int).Set(curve.Params().Gx)
	Gy    *big.Int       = new(big.Int).Set(curve.Params().Gy)

	ErrCurveNotMatch = errors.New("Ellipic curves not match")
	ErrOutOfRange    = errors.New("Out of range")
	ErrNotOnCurve    = errors.New("Not on curve")
)

// SetEllipticCurve sets elliptic curve
func SetEllipticCurve(c elliptic.Curve) {
	curve = c
	N = new(big.Int).Set(curve.Params().N)
	Gx = new(big.Int).Set(curve.Params().Gx)
	Gy = new(big.Int).Set(curve.Params().Gy)
}

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

func ecrand() (*big.Int, error) {
	k, err := ecdsa.GenerateKey(curve, rand.Reader)

	if err != nil {
		return nil, err
	}

	return new(big.Int).Set(k.D), nil
}

func isOnCurve(X, Y *big.Int) bool {
	return curve.IsOnCurve(X, Y)
}

func isInRange(x *big.Int) bool {
	return x.Cmp(big.NewInt(0)) > 0 && x.Cmp(N) < 0
}
