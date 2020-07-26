package zk

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/zzGHzz/zkVote/common"
)

func TestBinaryValueZK(t *testing.T) {
	var (
		prover *BinaryProver
		proof  *BinaryProof

		err error

		curve elliptic.Curve = elliptic.P256()
		a, k  *ecdsa.PrivateKey
	)

	// Generate private keys for voter and authority
	a, err = ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	k, err = ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// Generate data (e.g., voter's account address)
	data := sha256.Sum256(common.ConcatBytesTight(a.PublicKey.X.Bytes(), a.PublicKey.Y.Bytes()))

	// Generate and verify zk proof for v = 1
	prover, err = NewBinaryProver(true, a, &k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	proof, err = prover.Prove(data[:])
	res, err := proof.Verify(&a.PublicKey, &k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if !res {
		t.Fatal("Verification failed")
	}

	// Generate and verify zk proof for v = 1
	prover, err = NewBinaryProver(false, a, &k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	proof, err = prover.Prove(data[:])
	res, err = proof.Verify(&a.PublicKey, &k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if !res {
		t.Fatal("Verification failed")
	}
}
