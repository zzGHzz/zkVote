package vote

import (
	"crypto/elliptic"
	"math/big"
)

// var
var (
	curve elliptic.Curve = elliptic.P256()
)

// SetEllipticCurve sets elliptic curve
func SetEllipticCurve(c elliptic.Curve) {
	curve = c
}

// Ballot interface
type Ballot interface {
	VerifyBallot() error
}

// Vote interface
type Vote interface {
	Cast(b Ballot, addr []byte) error
	Tally(k *big.Int) error
	VerifyTallyRes() error

	GetAuthPublicKey() (*big.Int, *big.Int)
}
