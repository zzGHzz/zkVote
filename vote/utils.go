package vote

import (
	"math/big"
)

func isOnCurve(X, Y *big.Int) bool {
	return curve.IsOnCurve(X, Y)
}

func isInRange(x *big.Int) bool {
	return x.Cmp(big.NewInt(0)) > 0 && x.Cmp(curve.Params().N) < 0
}

func ecinv(X, Y *big.Int) (*big.Int, *big.Int) {
	X1 := new(big.Int).Mod(X, curve.Params().P)
	Y1 := new(big.Int).Mod(Y, curve.Params().P)
	Y1 = Y1.Sub(curve.Params().P, Y1)

	return X1, Y1
}
