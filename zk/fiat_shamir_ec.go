// Prove the knowledge of secrete x where y = g^x

package zk

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/zzGHzz/zkVote/common"
)

// ECFSProver - prover structure
type ECFSProver struct {
	x      *big.Int // secret
	hX, hY *big.Int // log base h = g^a where a is unknown
	yX, yY *big.Int // y = h^x
}

// ECFSProof - proof structure
type ECFSProof struct {
	data      *big.Int
	hX, hY    *big.Int
	yX, yY    *big.Int
	tX, tY, r *big.Int
}

// NewECFSProver news a prover
func NewECFSProver(x, hX, hY *big.Int) (*ECFSProver, error) {
	// check the range of x
	if !isInRange(x) {
		return nil, ErrOutOfRange
	}

	// y = h^k
	yX, yY := curve.ScalarMult(hX, hY, x.Bytes())

	// fmt.Println(curve.IsOnCurve(yX, yY))

	return &ECFSProver{
		new(big.Int).Set(x),
		new(big.Int).Set(hX), new(big.Int).Set(hY),
		yX, yY,
	}, nil
}

// Prove generates ECFSProof
func (p *ECFSProver) Prove(data *big.Int) (*ECFSProof, error) {
	// v <--r-- Z_q^*
	v, err := ecrand()
	if err != nil {
		return nil, err
	}

	// t = g^v
	tX, tY := curve.ScalarMult(p.hX, p.hY, v.Bytes())

	// c = H(data, g, y, t)
	c := sha256.Sum256(common.ConcatBytesTight(
		data.Bytes(),
		p.hX.Bytes(), p.hY.Bytes(),
		p.yX.Bytes(), p.yY.Bytes(),
		tX.Bytes(), tY.Bytes(),
	))
	// fmt.Printf("%x\n", c)

	// r = v - c*x
	r := new(big.Int).SetBytes(c[:])
	r = r.Mul(r, p.x)
	r = r.Sub(v, r)
	r = r.Mod(r, N)

	return &ECFSProof{
		data,
		new(big.Int).Set(p.hX), new(big.Int).Set(p.hY),
		new(big.Int).Set(p.yX), new(big.Int).Set(p.yY),
		tX, tY, r,
	}, nil
}

// Verify verifies ECFSProof
func (p *ECFSProof) Verify() (bool, error) {
	// y must be on curve
	if !isOnCurve(p.yX, p.yY) {
		return false, ErrNotOnCurve
	}

	// t must be on curve
	if !isOnCurve(p.tX, p.tY) {
		return false, ErrNotOnCurve
	}

	// h must be on curve
	if !isOnCurve(p.hX, p.hY) {
		return false, ErrNotOnCurve
	}

	// r must be in range
	if !isInRange(p.r) {
		return false, ErrOutOfRange
	}

	// c = hash(data, g, y, t)
	c := sha256.Sum256(common.ConcatBytesTight(
		p.data.Bytes(),
		p.hX.Bytes(), p.hY.Bytes(),
		p.yX.Bytes(), p.yY.Bytes(),
		p.tX.Bytes(), p.tY.Bytes(),
	))

	// check t = (g^r)(y^c)
	X1, Y1 := curve.ScalarMult(p.hX, p.hY, p.r.Bytes())
	X2, Y2 := curve.ScalarMult(p.yX, p.yY, new(big.Int).SetBytes(c[:]).Bytes())
	X1, Y1 = curve.Add(X1, Y1, X2, Y2)
	if X1.Cmp(p.tX) != 0 || Y1.Cmp(p.tY) != 0 {
		return false, nil
	}
	return true, nil
}

func (p *ECFSProof) String() string {
	return fmt.Sprintf("h = (%x, %x); y = (%x, %x); t = (%x, %x); r = %x",
		p.hX, p.hY, p.yX, p.yY, p.tX, p.tY, p.r)
}

// JSONECFSProof defines json object
type JSONECFSProof struct {
	Data string `json:"data"`
	HX   string `json:"hx"`
	HY   string `json:"hy"`
	YX   string `json:"yx"`
	YY   string `json:"yy"`
	TX   string `json:"tx"`
	TY   string `json:"ty"`
	R    string `json:"r"`
}

// BuildJSONJSONECFSProof returns json object
func (p *ECFSProof) BuildJSONJSONECFSProof() *JSONECFSProof {
	return &JSONECFSProof{
		Data: common.BigIntToHexStr(p.data),
		HX:   common.BigIntToHexStr(p.hX),
		HY:   common.BigIntToHexStr(p.hY),
		YX:   common.BigIntToHexStr(p.yX),
		YY:   common.BigIntToHexStr(p.yY),
		TX:   common.BigIntToHexStr(p.tX),
		TY:   common.BigIntToHexStr(p.tY),
		R:    common.BigIntToHexStr(p.r),
	}
}

// FromJSONECFSProof reconstructs proof from json object
func (p *ECFSProof) FromJSONECFSProof(obj *JSONECFSProof) error {
	var err error

	if p.data, err = common.HexStrToBigInt(obj.Data); err != nil {
		return err
	}

	if p.hX, err = common.HexStrToBigInt(obj.HX); err != nil {
		return err
	}
	if p.hY, err = common.HexStrToBigInt(obj.HY); err != nil {
		return err
	}

	if p.yX, err = common.HexStrToBigInt(obj.YX); err != nil {
		return err
	}
	if p.yY, err = common.HexStrToBigInt(obj.YY); err != nil {
		return err
	}

	if p.tX, err = common.HexStrToBigInt(obj.TX); err != nil {
		return err
	}
	if p.tY, err = common.HexStrToBigInt(obj.TY); err != nil {
		return err
	}

	if p.r, err = common.HexStrToBigInt(obj.R); err != nil {
		return err
	}

	return nil
}

// MarshalJSON implements json marshal
func (p *ECFSProof) MarshalJSON() ([]byte, error) {
	return json.Marshal(p.BuildJSONJSONECFSProof())
}

// UnmarshalJSON implements json unmarshal
func (p *ECFSProof) UnmarshalJSON(data []byte) error {
	var obj JSONECFSProof
	if err := json.Unmarshal(data, &obj); err != nil {
		return err
	}
	return p.FromJSONECFSProof(&obj)
}
