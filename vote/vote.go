package vote

import (
	"crypto/elliptic"
)

// var
var (
	curve elliptic.Curve = elliptic.P256()
)

// SetEllipticCurve sets elliptic curve
func SetEllipticCurve(c elliptic.Curve) {
	curve = c
}

// Vote interface
type Vote interface {
	Cast(b Ballot) error
	Tally() error
	VerifyTally() error
}

// Ballot interface
type Ballot interface {
	Verify() error
}
