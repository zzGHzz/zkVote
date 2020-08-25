package vote

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/big"

	"github.com/zzGHzz/zkVote/common"

	"github.com/zzGHzz/zkVote/zk"
)

// BinaryBallot - ballot structure
type BinaryBallot struct {
	hX, hY *big.Int // h = g^a
	yX, yY *big.Int // y = g^{a*k} * g^v
	proof  *zk.BinaryProof
}

// NewBinaryBallot generates a binary ballot
//
// data contains the data (e.g., account address) that identifies the voter.
func NewBinaryBallot(value bool, a, gkX, gkY *big.Int, data *big.Int) (*BinaryBallot, error) {
	var (
		yX, yY *big.Int

		prover *zk.BinaryProver
		proof  *zk.BinaryProof
		err    error
	)

	if !isOnCurve(gkX, gkY) {
		return nil, errors.New("Invalid g^k")
	}

	if !isInRange(a) {
		return nil, errors.New("Invalid a")
	}

	// y = g^{k*a}
	yX, yY = curve.ScalarMult(gkX, gkY, a.Bytes())

	if value {
		// y = y * g^v
		yX, yY = curve.Add(yX, yY, curve.Params().Gx, curve.Params().Gy)
	}

	// Set global ECC var for zk package
	zk.SetEllipticCurve(curve)

	// Create prover
	hX, hY := curve.ScalarBaseMult(a.Bytes())
	prover, err = zk.NewBinaryProver(value, a, hX, hY, gkX, gkY)
	if err != nil {
		return nil, err
	}

	// Generate proof
	proof, err = prover.Prove(data)
	if err != nil {
		return nil, err
	}

	return &BinaryBallot{
		hX, hY,
		yX, yY,
		proof,
	}, nil
}

// VerifyBallot verifies binary ballot
func (b *BinaryBallot) VerifyBallot() error {
	if !isOnCurve(b.hX, b.hY) {
		return errors.New("Invalid h = g^a")
	}

	if !isOnCurve(b.yX, b.yY) {
		return errors.New("Invalid y = g^{ak} * g^v")
	}

	res, err := b.proof.Verify()
	if err != nil {
		return err
	}
	if !res {
		return errors.New("Failed to verify")
	}

	return nil
}

func (b *BinaryBallot) String() (string, string) {
	return fmt.Sprintf("h = (%x, %x); y = (%x, %x)", b.hX, b.hY, b.yX, b.yY), b.proof.String()
}

// BuildJSONBinaryBallot builds JSON object
func (b *BinaryBallot) BuildJSONBinaryBallot() *JSONBinaryBallot {
	_p := b.proof.BuildJSONBinaryProof()

	return &JSONBinaryBallot{
		HX: common.BigIntToHexStr(b.hX),
		HY: common.BigIntToHexStr(b.hY),
		YX: common.BigIntToHexStr(b.yX),
		YY: common.BigIntToHexStr(b.yY),
		Proof: &JSONCompressedBinaryProof{
			Data: _p.Data,
			GKX:  _p.GKX,
			GKY:  _p.GKY,
			D1:   _p.D1,
			D2:   _p.D2,
			R1:   _p.R1,
			R2:   _p.R2,
			A1X:  _p.A1X,
			A1Y:  _p.A1Y,
			B1X:  _p.B1X,
			B1Y:  _p.B1Y,
			A2X:  _p.A2X,
			A2Y:  _p.A2Y,
			B2X:  _p.B2X,
			B2Y:  _p.B2Y,
		},
	}
}

// MarshalJSON implements json marshal
func (b *BinaryBallot) MarshalJSON() ([]byte, error) {
	return json.Marshal(b.BuildJSONBinaryBallot())
}

// FromJSONBinaryBallot reconstructs from json object
func (b *BinaryBallot) FromJSONBinaryBallot(obj *JSONBinaryBallot) error {
	var err error

	if b.hX, err = common.HexStrToBigInt(obj.HX); err != nil {
		return err
	}
	if b.hY, err = common.HexStrToBigInt(obj.HY); err != nil {
		return err
	}

	if b.yX, err = common.HexStrToBigInt(obj.YX); err != nil {
		return err
	}
	if b.yY, err = common.HexStrToBigInt(obj.YY); err != nil {
		return err
	}

	if b.proof == nil {
		b.proof = new(zk.BinaryProof)
	}

	_p := obj.Proof
	p := &zk.JSONBinaryProof{
		Data: _p.Data,
		GKX:  _p.GKX,
		GKY:  _p.GKY,
		D1:   _p.D1,
		D2:   _p.D2,
		R1:   _p.R1,
		R2:   _p.R2,
		A1X:  _p.A1X,
		A1Y:  _p.A1Y,
		B1X:  _p.B1X,
		B1Y:  _p.B1Y,
		A2X:  _p.A2X,
		A2Y:  _p.A2Y,
		B2X:  _p.B2X,
		B2Y:  _p.B2Y,

		GAX: obj.HX,
		GAY: obj.HY,
		YX:  obj.YX,
		YY:  obj.YY,
	}

	if err = b.proof.FromJSONBinaryProof(p); err != nil {
		return err
	}

	return nil
}

// UnmarshalJSON implements json unmarshal
func (b *BinaryBallot) UnmarshalJSON(data []byte) error {
	var obj JSONBinaryBallot
	if err := json.Unmarshal(data, &obj); err != nil {
		return err
	}

	return b.FromJSONBinaryBallot(&obj)
}
