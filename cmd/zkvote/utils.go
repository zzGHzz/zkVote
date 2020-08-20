package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"math/big"
	rnd "math/rand"
	"reflect"

	"github.com/zzGHzz/zkVote/common"

	"github.com/zzGHzz/zkVote/vote"
)

var curve = elliptic.P256()

func randValidBinaryBallot() *vote.BinaryBallot {
	a, _ := ecdsa.GenerateKey(curve, rand.Reader)
	k, _ := ecdsa.GenerateKey(curve, rand.Reader)
	data := make([]byte, 20)
	rand.Read(data)
	v := rnd.Intn(2) != 0

	ballot, err := vote.NewBinaryBallot(v, a.D, k.PublicKey.X, k.PublicKey.Y, new(big.Int).SetBytes(data))

	if err != nil {
		return nil
	}

	return ballot
}

func invalidBinaryBallot() *vote.BinaryBallot {
	b := randValidBinaryBallot()
	if b == nil {
		return nil
	}
	bj := b.BuildJSONBinaryBallot()

	switch rnd.Intn(2) {
	case 0:
		r, _ := common.RandBytes(32)
		s := fmt.Sprintf("0x%x", r)
		id := rnd.Intn(4)
		reflect.ValueOf(bj).Elem().Field(id).SetString(s)
	case 1:
		r, _ := common.RandBytes(32)
		s := fmt.Sprintf("0x%x", r)
		id := rnd.Intn(19)
		switch id {
		case 0:
			r, _ = common.RandBytes(20)
			s = fmt.Sprintf("0x%x", r)
		default:
		}
		reflect.ValueOf(bj.Proof).Elem().Field(id).SetString(s)
	}

	if err := b.FromJSONBinaryBallot(bj); err != nil {
		return nil
	}

	return b
}

func randValidBinaryBallots(n int) []*vote.BinaryBallot {
	if n <= 0 {
		return []*vote.BinaryBallot{}
	}

	ballots := make([]*vote.BinaryBallot, n)
	for i := 0; i < n; i++ {
		ballots[i] = randValidBinaryBallot()
	}

	return ballots
}

func invalidBinaryBallots(n int) []*vote.BinaryBallot {
	if n <= 0 {
		return []*vote.BinaryBallot{}
	}

	ballots := make([]*vote.BinaryBallot, n)
	for i := 0; i < n; i++ {
		ballots[i] = invalidBinaryBallot()
	}

	return ballots
}
