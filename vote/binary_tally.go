package vote

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/big"

	"github.com/zzGHzz/zkVote/common"

	"github.com/zzGHzz/zkVote/zk"
)

// BinaryTally structure
type BinaryTally struct {
	gkX, gkY *big.Int

	HX, HY   *big.Int // H = prod_i h_i = prod_i g^a_i
	YX, YY   *big.Int // Y = prod_i y_i = prod_i g^{a_i*k + v_i}
	nVoter   uint64   // number of ballots
	authData *big.Int
}

// BinaryTallyRes structure
type BinaryTallyRes struct {
	// gkX, gkY *big.Int

	V uint64 // V = sum_i v_i
	// HX, HY *big.Int // h = prod_i g^a_i
	XX, XY *big.Int // X = h^k
	YX, YY *big.Int // Y = X * g^v

	// hashedAuthAddr []byte
	proof *zk.ECFSProof // zkp proves the correctness of h^k
}

// Tally computes result and zk proof
func (t *BinaryTally) tally(k *big.Int) (*BinaryTallyRes, error) {
	if !isInRange(k) {
		return nil, errors.New("Invalid k")
	}

	x, y := curve.ScalarBaseMult(k.Bytes())
	if x.Cmp(t.gkX) != 0 || y.Cmp(t.gkY) != 0 {
		return nil, errors.New("k doesn't match saved g^k")
	}

	// X = h^k where h = prod_i g^a_i
	XX, XY := curve.ScalarMult(t.HX, t.HY, k.Bytes())

	// Get inv(X)
	iXX, iXY := new(big.Int).Set(XX), new(big.Int).Sub(curve.Params().P, XY)

	// g^v = Y/X
	gVX, gVY := curve.Add(t.YX, t.YY, iXX, iXY)

	// power break v
	X, Y := big.NewInt(0), big.NewInt(0)
	V := uint64(0)
	for {
		V = V + 1
		X, Y = curve.Add(X, Y, curve.Params().Gx, curve.Params().Gy)
		if X.Cmp(gVX) == 0 && Y.Cmp(gVY) == 0 {
			break
		}
		if V > t.nVoter {
			return nil, errors.New("Tally failed")
		}
	}

	// Generate zkp for proving the correctness of h^k
	prover, err := zk.NewECFSProver(k, t.HX, t.HY)
	if err != nil {
		return nil, err
	}
	proof, err := prover.Prove(t.authData)
	if err != nil {
		return nil, err
	}

	return &BinaryTallyRes{
		// new(big.Int).Set(t.gkX), new(big.Int).Set(t.gkY),
		V,
		// new(big.Int).Set(t.HX), new(big.Int).Set(t.HY),
		XX, XY,
		new(big.Int).Set(t.YX), new(big.Int).Set(t.YY),
		// append([]byte(nil), t.hashedAuthData...),
		proof,
	}, nil
}

// Verify verifies tally result
func (r *BinaryTallyRes) verify() error {
	// if !isOnCurve(r.gkX, r.gkY) {
	// 	return errors.New("Invalid g^k")
	// }

	// if !isOnCurve(r.HX, r.HY) {
	// 	return errors.New("Invalid h = prod_i g^a_i")
	// }

	if !isOnCurve(r.XX, r.XY) {
		return errors.New("Invalid X = h^k")
	}

	if !isOnCurve(r.YX, r.YY) {
		return errors.New("Invalid Y = X * g^V")
	}

	// Check the correctness of V
	gVX, gVY := curve.ScalarBaseMult(big.NewInt(int64(r.V)).Bytes())
	XgVX, XgVY := curve.Add(r.XX, r.XY, gVX, gVY)

	if XgVX.Cmp(r.YX) != 0 || XgVY.Cmp(r.YY) != 0 {
		return errors.New("Y != X * g^v")
	}

	// Verify zkp
	res, err := r.proof.Verify()
	if err != nil {
		return err
	}
	if !res {
		return errors.New("Invalid zkp")
	}

	return nil
}

func (r *BinaryTallyRes) String() (string, string) {
	return fmt.Sprintf("No. YES = %d", r.V), r.proof.String()
}

// JSONBinaryTallyRes defines json object
type JSONBinaryTallyRes struct {
	V     uint64            `json:"v"`
	XX    string            `json:"xx"`
	XY    string            `json:"xy"`
	YX    string            `json:"yx"`
	YY    string            `json:"yy"`
	Proof *zk.JSONECFSProof `json:"proof"`
}

// BuildJSONBinaryTallyRes builds json object
func (r *BinaryTallyRes) BuildJSONBinaryTallyRes() *JSONBinaryTallyRes {
	return &JSONBinaryTallyRes{
		V:     r.V,
		XX:    common.BigIntToHexStr(r.XX),
		XY:    common.BigIntToHexStr(r.XY),
		YX:    common.BigIntToHexStr(r.YX),
		YY:    common.BigIntToHexStr(r.YY),
		Proof: r.proof.BuildJSONJSONECFSProof(),
	}
}

// MarshalJSON implements json marshal
func (r *BinaryTallyRes) MarshalJSON() ([]byte, error) {
	return json.Marshal(r.BuildJSONBinaryTallyRes())
}

// FromJSONBinaryTallyRes reconstructs from json object
func (r *BinaryTallyRes) FromJSONBinaryTallyRes(obj *JSONBinaryTallyRes) error {
	var err error

	r.V = obj.V

	// if r.HX, err = common.HexStrToBigInt(obj.Proof.HX); err != nil {
	// 	return err
	// }
	// if r.HY, err = common.HexStrToBigInt(obj.Proof.HY); err != nil {
	// 	return err
	// }

	if r.XX, err = common.HexStrToBigInt(obj.XX); err != nil {
		return err
	}
	if r.XY, err = common.HexStrToBigInt(obj.XY); err != nil {
		return err
	}

	if r.YX, err = common.HexStrToBigInt(obj.YX); err != nil {
		return err
	}
	if r.YY, err = common.HexStrToBigInt(obj.YY); err != nil {
		return err
	}

	if r.proof == nil {
		r.proof = new(zk.ECFSProof)
	}
	if err := r.proof.FromJSONECFSProof(obj.Proof); err != nil {
		return err
	}

	return nil
}

// UnmarshalJSON implements json unmarshal
func (r *BinaryTallyRes) UnmarshalJSON(data []byte) error {
	var obj JSONBinaryTallyRes
	if err := json.Unmarshal(data, &obj); err != nil {
		return err
	}

	return r.FromJSONBinaryTallyRes(&obj)
}
