package vote

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBinaryBallotJSON(t *testing.T) {
	a, _ := ecdsa.GenerateKey(curve, rand.Reader)
	k, _ := ecdsa.GenerateKey(curve, rand.Reader)
	data := append(a.PublicKey.X.Bytes(), a.PublicKey.Y.Bytes()...)
	ballot, err := NewBinaryBallot(true, a.D, k.PublicKey.X, k.PublicKey.Y, data)
	assert.Nil(t, err)

	b, err := json.Marshal(ballot)
	assert.Nil(t, err)

	var reconstruct BinaryBallot
	err = json.Unmarshal(b, &reconstruct)
	assert.Nil(t, err)
	assert.Equal(t, *ballot, reconstruct)
}
