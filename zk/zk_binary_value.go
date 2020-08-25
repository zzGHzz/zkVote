// Prove v\in{0,1} given g^a, ((g^k)^a)(g^v)
// 	a 		- a known secret key
//	g^k 	- a known public key

package zk

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"

	"github.com/zzGHzz/zkVote/common"
)

// BinaryProver - structure
type BinaryProver struct {
	value    bool     // binary cast value
	a        *big.Int // secret
	gaX, gaY *big.Int // g^a
	gkX, gkY *big.Int // public key shared by authority
}

// BinaryProof - structure
type BinaryProof struct {
	data               *big.Int
	gaX, gaY, gkX, gkY *big.Int
	yX, yY             *big.Int // y = g^{ka}
	d1, r1             *big.Int
	d2, r2             *big.Int
	a1X, a1Y, b1X, b1Y *big.Int
	a2X, a2Y, b2X, b2Y *big.Int
}

// NewBinaryProver - new Prover
func NewBinaryProver(value bool, a, gaX, gaY, gkX, gkY *big.Int) (*BinaryProver, error) {
	if gkX == nil || gkY == nil {
		return nil, errors.New("gk cannot be nil")
	}

	if !isOnCurve(gkX, gkY) {
		return nil, ErrNotOnCurve
	}

	if a == nil {
		var err error
		a, err = ecrand()
		if err != nil {
			return nil, err
		}
	} else {
		if !isInRange(a) {
			return nil, ErrOutOfRange
		}
	}

	return &BinaryProver{value, a, gaX, gaY, gkX, gkY}, nil
}

// Prove generates the zk proof of a binary value
//
// data - used to identify the prover, e.g., his/her account address
func (p *BinaryProver) Prove(data *big.Int) (*BinaryProof, error) {
	var w, r1, r2, d1, d2 *big.Int
	var yX, yY *big.Int
	var a1X, a1Y, b1X, b1Y, a2X, a2Y, b2X, b2Y *big.Int

	var err error

	if w, err = ecrand(); err != nil {
		return nil, err
	}
	wX, wY := curve.ScalarBaseMult(w.Bytes())

	var X1, Y1, X2, Y2, X3, Y3 *big.Int
	if !p.value {
		if r2, err = ecrand(); err != nil {
			return nil, err
		}
		if d2, err = ecrand(); err != nil {
			return nil, err
		}

		// y = g^{k*a}
		yX, yY = curve.ScalarMult(p.gkX, p.gkY, p.a.Bytes())

		// a1 = g^w
		a1X, a1Y = wX, wY

		// b1 = g^{kw}
		b1X, b1Y = curve.ScalarMult(p.gkX, p.gkY, w.Bytes())

		// a2 = g^{r2 + d2*a}
		X1, Y1 = curve.ScalarBaseMult(r2.Bytes())
		X2, Y2 = curve.ScalarMult(p.gaX, p.gaY, d2.Bytes())
		a2X, a2Y = curve.Add(X1, Y1, X2, Y2)

		// g^{d2*k*a} = (g^{k*a})^{d2}
		X1, Y1 = curve.ScalarMult(yX, yY, d2.Bytes())
		// g^{k*r2} = (g^k)^r2
		X2, Y2 = curve.ScalarMult(p.gkX, p.gkY, r2.Bytes())
		// g^{-d2}
		X3, Y3 = curve.ScalarBaseMult(new(big.Int).Sub(N, d2).Bytes())
		// b2 = g^{d2*k*a + k*r2 - d2}
		b2X, b2Y = curve.Add(X1, Y1, X2, Y2)
		b2X, b2Y = curve.Add(b2X, b2Y, X3, Y3)

		// c = hash(data, g^a, y, a1, b1, a2, b2)
		c := sha256.Sum256(common.ConcatBytes(
			data.Bytes(),
			p.gaX.Bytes(), p.gaY.Bytes(),
			yX.Bytes(), yY.Bytes(),
			a1X.Bytes(), a1Y.Bytes(),
			b1X.Bytes(), b1Y.Bytes(),
			a2X.Bytes(), a2Y.Bytes(),
			b2X.Bytes(), b2Y.Bytes(),
		))
		// fmt.Printf("%x\n", c)

		// d1 = c - d2
		d1 = new(big.Int).SetBytes(c[:])
		d1 = d1.Sub(d1, d2)
		d1 = d1.Mod(d1, N)

		// r1 = w - d1*a
		r1 = new(big.Int).Mul(d1, p.a)
		r1 = r1.Sub(w, r1)
		r1 = r1.Mod(r1, N)
	} else {
		if r1, err = ecrand(); err != nil {
			return nil, err
		}
		if d1, err = ecrand(); err != nil {
			return nil, err
		}

		// y = g^{ka+1}
		yX, yY = curve.ScalarMult(p.gkX, p.gkY, p.a.Bytes())
		yX, yY = curve.Add(yX, yY, Gx, Gy)

		// a2 = g^w
		a2X, a2Y = wX, wY

		// b2 = g^{kw}
		b2X, b2Y = curve.ScalarMult(p.gkX, p.gkY, w.Bytes())

		// a1 = g^{r1 + d1*a}
		X1, Y1 = curve.ScalarBaseMult(r1.Bytes())
		X2, Y2 = curve.ScalarMult(p.gaX, p.gaY, d1.Bytes())
		a1X, a1Y = curve.Add(X1, Y1, X2, Y2)

		// g^{d1*k*a+d1} = y^d1
		X1, Y1 = curve.ScalarMult(yX, yY, d1.Bytes())
		// g^{k*r1} = (g^k)^r1
		X2, Y2 = curve.ScalarMult(p.gkX, p.gkY, r1.Bytes())
		// b1 = g^{d1*k*a + k*r1 + d1} = y^d1 g^{k*r1}
		b1X, b1Y = curve.Add(X1, Y1, X2, Y2)

		// c = hash(data, g^a, y, a1, b1, a2, b2)
		c := sha256.Sum256(common.ConcatBytes(
			data.Bytes(),
			p.gaX.Bytes(), p.gaY.Bytes(),
			yX.Bytes(), yY.Bytes(),
			a1X.Bytes(), a1Y.Bytes(),
			b1X.Bytes(), b1Y.Bytes(),
			a2X.Bytes(), a2Y.Bytes(),
			b2X.Bytes(), b2Y.Bytes(),
		))

		// d2 = c - d1
		d2 = new(big.Int).SetBytes(c[:])
		d2 = d2.Sub(d2, d1)
		d2 = d2.Mod(d2, N)

		// r2 = w - d2*a
		r2 = new(big.Int).Mul(d2, p.a)
		r2 = r2.Sub(w, r2)
		r2 = r2.Mod(r2, N)
	}

	return &BinaryProof{
		data,
		new(big.Int).Set(p.gaX), new(big.Int).Set(p.gaY),
		new(big.Int).Set(p.gkX), new(big.Int).Set(p.gkY),
		yX, yY,
		d1, r1, d2, r2,
		a1X, a1Y, b1X, b1Y,
		a2X, a2Y, b2X, b2Y}, nil
}

// Validate checks the validity of the zk proof
func (p *BinaryProof) validate() error {
	// r1, r2, d1, d2 \in [1, N-1]
	if !isInRange(p.r1) || !isInRange(p.r2) || !isInRange(p.d1) || !isInRange(p.d2) {
		return ErrOutOfRange
	}

	// a1, a2, b1, b2 must on curve
	if !isOnCurve(p.a1X, p.a1Y) ||
		!isOnCurve(p.a2X, p.a2Y) ||
		!isOnCurve(p.b1X, p.b1Y) ||
		!isOnCurve(p.b2X, p.b2Y) ||
		!isOnCurve(p.gaX, p.gaY) ||
		!isOnCurve(p.gkX, p.gkY) {
		return ErrNotOnCurve
	}

	return nil
}

// Verify verifies the zk proof of the binary value
func (p *BinaryProof) Verify() (bool, error) {
	if err := p.validate(); err != nil {
		return false, nil
	}

	// d1 + d2 == c mod N
	c := sha256.Sum256(common.ConcatBytes(
		p.data.Bytes(),
		p.gaX.Bytes(), p.gaY.Bytes(),
		p.yX.Bytes(), p.yY.Bytes(),
		p.a1X.Bytes(), p.a1Y.Bytes(),
		p.b1X.Bytes(), p.b1Y.Bytes(),
		p.a2X.Bytes(), p.a2Y.Bytes(),
		p.b2X.Bytes(), p.b2Y.Bytes(),
	))

	x := new(big.Int).Add(p.d1, p.d2)
	x = x.Mod(x, N)
	y := new(big.Int).SetBytes(c[:])
	y = y.Mod(y, N)
	if x.Cmp(y) != 0 {
		return false, nil
	}

	var X, Y, X1, Y1, X2, Y2 *big.Int

	// a1 = g^{r1 + d1*a}
	X1, Y1 = curve.ScalarBaseMult(p.r1.Bytes())
	X2, Y2 = curve.ScalarMult(p.gaX, p.gaY, p.d1.Bytes())
	X, Y = curve.Add(X1, Y1, X2, Y2)
	if p.a1X.Cmp(X) != 0 || p.a1Y.Cmp(Y) != 0 {
		return false, nil
	}

	// b1 = g^{k*r1} y^d1
	X1, Y1 = curve.ScalarMult(p.gkX, p.gkY, p.r1.Bytes())
	X2, Y2 = curve.ScalarMult(p.yX, p.yY, p.d1.Bytes())
	X, Y = curve.Add(X1, Y1, X2, Y2)
	if p.b1X.Cmp(X) != 0 || p.b1Y.Cmp(Y) != 0 {
		return false, nil
	}

	// a2 = g^{r2 + d2*a}
	X1, Y1 = curve.ScalarBaseMult(p.r2.Bytes())
	X2, Y2 = curve.ScalarMult(p.gaX, p.gaY, p.d2.Bytes())
	X, Y = curve.Add(X1, Y1, X2, Y2)
	if p.a2X.Cmp(X) != 0 || p.a2Y.Cmp(Y) != 0 {
		return false, nil
	}

	// b2 = g^{k*r2} (y/g)^d2
	X1, Y1 = curve.ScalarMult(p.gkX, p.gkY, p.r2.Bytes())
	X2, Y2 = curve.Add(p.yX, p.yY, Gx, new(big.Int).Sub(curve.Params().P, Gy))
	X2, Y2 = curve.ScalarMult(X2, Y2, p.d2.Bytes())
	X, Y = curve.Add(X1, Y1, X2, Y2)
	if p.b2X.Cmp(X) != 0 || p.b2Y.Cmp(Y) != 0 {
		return false, nil
	}

	return true, nil
}

func (p *BinaryProof) String() string {
	return fmt.Sprintf("a1 = (%x, %x); b1 = (%x, %x); (d1, r1) = (%x, %x); a2 = (%x, %x); b2 = (%x, %x); (d2, r2) = (%x, %x)",
		p.a1X, p.a1Y, p.b1X, p.b1Y, p.d1, p.r1, p.a2X, p.a2Y, p.b2X, p.b2Y, p.d2, p.r2)
}

// MarshalJSON implements MarshalJSON
func (p *BinaryProof) MarshalJSON() ([]byte, error) {
	return json.Marshal(p.BuildJSONBinaryProof())
}

// BuildJSONBinaryProof builds JSON object
func (p *BinaryProof) BuildJSONBinaryProof() *JSONBinaryProof {
	return &JSONBinaryProof{
		Data: common.BigIntToHexStr(p.data),
		GAX:  common.BigIntToHexStr(p.gaX),
		GAY:  common.BigIntToHexStr(p.gaY),
		GKX:  common.BigIntToHexStr(p.gkX),
		GKY:  common.BigIntToHexStr(p.gkY),
		YX:   common.BigIntToHexStr(p.yX),
		YY:   common.BigIntToHexStr(p.yY),
		A1X:  common.BigIntToHexStr(p.a1X),
		A1Y:  common.BigIntToHexStr(p.a1Y),
		B1X:  common.BigIntToHexStr(p.b1X),
		B1Y:  common.BigIntToHexStr(p.b1Y),
		A2X:  common.BigIntToHexStr(p.a2X),
		A2Y:  common.BigIntToHexStr(p.a2Y),
		B2X:  common.BigIntToHexStr(p.b2X),
		B2Y:  common.BigIntToHexStr(p.b2Y),
		R1:   common.BigIntToHexStr(p.r1),
		R2:   common.BigIntToHexStr(p.r2),
		D1:   common.BigIntToHexStr(p.d1),
		D2:   common.BigIntToHexStr(p.d2),
	}
}

// UnmarshalJSON implements UnmarshalJSON
func (p *BinaryProof) UnmarshalJSON(data []byte) error {
	var jsonproof JSONBinaryProof

	if err := json.Unmarshal(data, &jsonproof); err != nil {
		return err
	}

	return p.FromJSONBinaryProof(&jsonproof)
}

// FromJSONBinaryProof reconstructs from JSONBinaryProof
func (p *BinaryProof) FromJSONBinaryProof(jsonproof *JSONBinaryProof) error {
	var err error

	if p.data, err = common.HexStrToBigInt(jsonproof.Data); err != nil {
		return err
	}

	if p.gaX, err = common.HexStrToBigInt(jsonproof.GAX); err != nil {
		return err
	}
	if p.gaY, err = common.HexStrToBigInt(jsonproof.GAY); err != nil {
		return err
	}

	if p.gkX, err = common.HexStrToBigInt(jsonproof.GKX); err != nil {
		return err
	}
	if p.gkY, err = common.HexStrToBigInt(jsonproof.GKY); err != nil {
		return err
	}

	if p.yX, err = common.HexStrToBigInt(jsonproof.YX); err != nil {
		return err
	}
	if p.yY, err = common.HexStrToBigInt(jsonproof.YY); err != nil {
		return err
	}

	if p.a1X, err = common.HexStrToBigInt(jsonproof.A1X); err != nil {
		return err
	}
	if p.a1Y, err = common.HexStrToBigInt(jsonproof.A1Y); err != nil {
		return err
	}

	if p.b1X, err = common.HexStrToBigInt(jsonproof.B1X); err != nil {
		return err
	}
	if p.b1Y, err = common.HexStrToBigInt(jsonproof.B1Y); err != nil {
		return err
	}

	if p.a2X, err = common.HexStrToBigInt(jsonproof.A2X); err != nil {
		return err
	}
	if p.a2Y, err = common.HexStrToBigInt(jsonproof.A2Y); err != nil {
		return err
	}

	if p.b2X, err = common.HexStrToBigInt(jsonproof.B2X); err != nil {
		return err
	}
	if p.b2Y, err = common.HexStrToBigInt(jsonproof.B2Y); err != nil {
		return err
	}

	if p.r1, err = common.HexStrToBigInt(jsonproof.R1); err != nil {
		return err
	}
	if p.d1, err = common.HexStrToBigInt(jsonproof.D1); err != nil {
		return err
	}

	if p.r2, err = common.HexStrToBigInt(jsonproof.R2); err != nil {
		return err
	}
	if p.d2, err = common.HexStrToBigInt(jsonproof.D2); err != nil {
		return err
	}

	return nil
}
