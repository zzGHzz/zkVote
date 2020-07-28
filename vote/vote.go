package vote

import (
	"crypto/elliptic"
	"errors"
)

// var
var (
	curve elliptic.Curve = elliptic.P256()

	ErrInvalidPubKey   = errors.New("Invalid public key")
	ErrInvalidPrivKey  = errors.New("Invalid private key")
	ErrInvalidBallot   = errors.New("Invalid ballot")
	ErrInvalidTallyRes = errors.New("Invalid tally result")
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
