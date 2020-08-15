package vote

import (
	"crypto/sha256"
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
func NewBinaryBallot(value bool, a, gkX, gkY *big.Int, data []byte) (*BinaryBallot, error) {
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
	z := sha256.Sum256(data)
	proof, err = prover.Prove(new(big.Int).SetBytes(z[:]))
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

// JSONBinaryBallot JSON
type JSONBinaryBallot struct {
	HX    string              `json:"hx"`
	HY    string              `json:"hy"`
	YX    string              `json:"yx"`
	YY    string              `json:"yy"`
	Proof *zk.JSONBinaryProof `json:"proof"`
}

// BuildJSONBinaryBallot builds JSON object
func (b *BinaryBallot) BuildJSONBinaryBallot() *JSONBinaryBallot {
	return &JSONBinaryBallot{
		HX:    common.BigIntToHexStr(b.hX),
		HY:    common.BigIntToHexStr(b.hY),
		YX:    common.BigIntToHexStr(b.yX),
		YY:    common.BigIntToHexStr(b.yY),
		Proof: b.proof.BuildJSONBinaryProof(),
	}
}

// MarshalJSON implements json marshal
func (b *BinaryBallot) MarshalJSON() ([]byte, error) {
	return json.Marshal(b.BuildJSONBinaryBallot())
}

// UnmarshalJSON implements json unmarshal
func (b *BinaryBallot) UnmarshalJSON(data []byte) error {
	var (
		obj JSONBinaryBallot
		err error
	)
	if err := json.Unmarshal(data, &obj); err != nil {
		return err
	}

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
	if err = b.proof.FromJSONBinaryProof(obj.Proof); err != nil {
		return err
	}

	return nil
}
