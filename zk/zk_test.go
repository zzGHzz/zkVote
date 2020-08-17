package zk

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/zzGHzz/zkVote/common"
)

func TestBinaryValueZK(t *testing.T) {
	var (
		prover *BinaryProver
		proof  *BinaryProof

		err error
		res bool

		curve elliptic.Curve = elliptic.P256()
		a, k  *ecdsa.PrivateKey
	)

	// Generate private keys for voter and authority
	a, err = ecdsa.GenerateKey(curve, rand.Reader)
	assert.Nil(t, err)
	k, err = ecdsa.GenerateKey(curve, rand.Reader)
	assert.Nil(t, err)

	// Generate data (e.g., voter's account address)
	data := sha256.Sum256(common.ConcatBytes(a.PublicKey.X.Bytes(), a.PublicKey.Y.Bytes()))

	// Generate and verify zk proof for v = 1
	prover, err = NewBinaryProver(true, a.D, a.PublicKey.X, a.PublicKey.Y, k.PublicKey.X, k.PublicKey.Y)
	assert.Nil(t, err)
	proof, err = prover.Prove(new(big.Int).SetBytes(data[:]))
	res, err = proof.Verify()
	assert.Nil(t, err)
	assert.True(t, res)

	// Generate and verify zk proof for v = 1
	prover.value = false
	assert.Nil(t, err)
	proof, err = prover.Prove(new(big.Int).SetBytes(data[:]))
	res, err = proof.Verify()
	assert.Nil(t, err)
	assert.True(t, res)
}

func TestECFS(t *testing.T) {
	var (
		prover *ECFSProver
		proof  *ECFSProof

		err error
		res bool

		x, a *ecdsa.PrivateKey
	)

	// generate secret x
	x, err = ecdsa.GenerateKey(curve, rand.Reader)
	assert.Nil(t, err)

	// generate data
	data := sha256.Sum256(common.ConcatBytes(x.PublicKey.X.Bytes(), x.PublicKey.Y.Bytes()))

	a, err = ecdsa.GenerateKey(curve, rand.Reader)
	assert.Nil(t, err)

	// generate proof
	prover, err = NewECFSProver(x.D, a.PublicKey.X, a.PublicKey.Y)
	assert.Nil(t, err)

	// generate proof
	proof, err = prover.Prove(new(big.Int).SetBytes(data[:]))
	assert.Nil(t, err)

	// verification
	res, err = proof.Verify()
	assert.Nil(t, err)
	assert.True(t, res)
}

func TestBinaryProofJSON(t *testing.T) {
	var (
		prover *BinaryProver
		proof  *BinaryProof
		a, k   *ecdsa.PrivateKey
		err    error
		b      []byte
	)
	a, _ = ecdsa.GenerateKey(curve, rand.Reader)
	k, _ = ecdsa.GenerateKey(curve, rand.Reader)
	data := sha256.Sum256(common.ConcatBytes(a.PublicKey.X.Bytes(), a.PublicKey.Y.Bytes()))

	// Generate a random yes vote
	prover, err = NewBinaryProver(true, a.D, a.PublicKey.X, a.PublicKey.Y, k.PublicKey.X, k.PublicKey.Y)
	assert.Nil(t, err)
	proof, err = prover.Prove(new(big.Int).SetBytes(data[:]))
	assert.Nil(t, err)

	// json marshal
	b, err = json.Marshal(proof)
	assert.Nil(t, err)

	// json unmarshal
	var reconstruct BinaryProof
	err = json.Unmarshal(b, &reconstruct)
	assert.Nil(t, err)
	assert.Equal(t, *proof, reconstruct)
}

func TestECFSProofJSON(t *testing.T) {
	var (
		prover *ECFSProver
		proof  *ECFSProof
		err    error
		x, a   *ecdsa.PrivateKey
		b      []byte
	)

	// generate secret x
	x, err = ecdsa.GenerateKey(curve, rand.Reader)
	assert.Nil(t, err)

	// generate data
	data := sha256.Sum256(common.ConcatBytes(x.PublicKey.X.Bytes(), x.PublicKey.Y.Bytes()))

	a, err = ecdsa.GenerateKey(curve, rand.Reader)
	assert.Nil(t, err)

	// generate proof
	prover, err = NewECFSProver(x.D, a.PublicKey.X, a.PublicKey.Y)
	assert.Nil(t, err)

	// generate proof
	proof, err = prover.Prove(new(big.Int).SetBytes(data[:]))
	assert.Nil(t, err)

	// json marshal
	b, err = json.Marshal(proof)
	assert.Nil(t, err)

	// json unmarshal
	var reconstruct ECFSProof
	err = json.Unmarshal(b, &reconstruct)
	assert.Nil(t, err)
	assert.Equal(t, *proof, reconstruct)
}
