package vote

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"testing"

	"math/big"
	rnd "math/rand"

	"github.com/stretchr/testify/assert"
)

func genBinaryBallot(value bool, addr *big.Int, gkX, gkY *big.Int, t *testing.T) *BinaryBallot {
	a, _ := ecdsa.GenerateKey(curve, rand.Reader)

	b, err := NewBinaryBallot(value, a.D, gkX, gkY, addr)
	assert.Nil(t, err)

	err = b.VerifyBallot()
	assert.Nil(t, err)

	return b
}

func getRandAddr() []byte {
	addr := make([]byte, 20)
	rand.Read(addr)
	return addr
}

func TestBinaryVoteCast(t *testing.T) {
	k, _ := ecdsa.GenerateKey(curve, rand.Reader)
	authAddr := new(big.Int).SetBytes(getRandAddr())

	// nVoter := uint(20)

	binaryVote, err := NewBinaryVote(k.PublicKey.X, k.PublicKey.Y, authAddr)
	assert.Nil(t, err)

	voterAddr := new(big.Int).SetBytes(getRandAddr())

	// Cast the first ballot
	ballot1 := genBinaryBallot(true, voterAddr, k.PublicKey.X, k.PublicKey.Y, t)
	err = binaryVote.Cast(ballot1, voterAddr)
	assert.Nil(t, err)
	savedBallot, ok := binaryVote.ballots[sha256.Sum256(voterAddr.Bytes())]
	assert.True(t, ok)
	assert.Equal(t, savedBallot, ballot1)
	assert.Equal(t, binaryVote.HX, ballot1.hX)
	assert.Equal(t, binaryVote.HY, ballot1.hY)

	// cast another ballot to replace the first one
	ballot2 := genBinaryBallot(false, voterAddr, k.PublicKey.X, k.PublicKey.Y, t)
	err = binaryVote.Cast(ballot2, voterAddr)
	assert.Nil(t, err)
	savedBallot, ok = binaryVote.ballots[sha256.Sum256(voterAddr.Bytes())]
	assert.True(t, ok)
	assert.Equal(t, savedBallot, ballot2)
	assert.Equal(t, binaryVote.HX, ballot2.hX)
	assert.Equal(t, binaryVote.HY, ballot2.hY)
}

func castRandBallots(binaryVote *BinaryVote, n int, t *testing.T) int {
	V := 0

	for i := 0; i < n; i++ {
		value := rnd.Intn(2) != 0

		if value {
			V = V + 1
		}

		b := genBinaryBallot(value, new(big.Int).SetBytes(getRandAddr()), binaryVote.gkX, binaryVote.gkY, t)

		err := binaryVote.Cast(b, new(big.Int).SetBytes(getRandAddr()))
		assert.Nil(t, err)
	}

	return V
}

func TestBinaryVoteTally(t *testing.T) {
	// no. of voters
	n := 20

	// generate authority secret key k
	k, _ := ecdsa.GenerateKey(curve, rand.Reader)
	// generate authority address
	addr := make([]byte, 20)
	rand.Read(addr)

	binaryVote, err := NewBinaryVote(k.PublicKey.X, k.PublicKey.Y, new(big.Int).SetBytes(addr))
	assert.Nil(t, err)

	// Cast ballots
	V := castRandBallots(binaryVote, n, t)

	// Tally
	err = binaryVote.Tally(k.D)
	assert.Nil(t, err)
	assert.Equal(t, binaryVote.res.V, V)
	err = binaryVote.VerifyTallyRes()
	assert.Nil(t, err)
}

func TestBinaryBallotJSON(t *testing.T) {
	a, _ := ecdsa.GenerateKey(curve, rand.Reader)
	k, _ := ecdsa.GenerateKey(curve, rand.Reader)
	data := append(a.PublicKey.X.Bytes(), a.PublicKey.Y.Bytes()...)
	ballot, err := NewBinaryBallot(true, a.D, k.PublicKey.X, k.PublicKey.Y, new(big.Int).SetBytes(data))
	assert.Nil(t, err)

	b, err := json.Marshal(ballot)
	assert.Nil(t, err)

	var reconstruct BinaryBallot
	err = json.Unmarshal(b, &reconstruct)
	assert.Nil(t, err)
	assert.Equal(t, *ballot, reconstruct)
}

func TestBinaryTallyResJSON(t *testing.T) {
	var (
		b   []byte
		err error
	)

	n := 20
	k, _ := ecdsa.GenerateKey(curve, rand.Reader)
	authAddr := make([]byte, 20)
	rand.Read(authAddr)

	binaryVote, err := NewBinaryVote(k.PublicKey.X, k.PublicKey.Y, new(big.Int).SetBytes(authAddr))
	assert.Nil(t, err)

	castRandBallots(binaryVote, n, t)
	err = binaryVote.Tally(k.D)
	assert.Nil(t, err)

	// json marshal
	res := binaryVote.GetTallyRes()
	b, err = json.Marshal(res)
	assert.Nil(t, err)

	// json unmarshal
	var reconstruct BinaryTallyRes
	err = json.Unmarshal(b, &reconstruct)
	assert.Nil(t, err)
	assert.Equal(t, *res, reconstruct)
}
