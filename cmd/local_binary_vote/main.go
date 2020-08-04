package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/zzGHzz/zkVote/common"
	"github.com/zzGHzz/zkVote/vote"
)

func main() {
	auth, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	k := new(big.Int).Set(auth.D)
	gkX := new(big.Int).Set(auth.PublicKey.X)
	gkY := new(big.Int).Set(auth.PublicKey.Y)
	authAddr, _ := common.RandBytes(20)

	fmt.Printf("k = %x, g^k = (%x, %x)\n\n", k, gkX, gkY)

	nVote := uint(5)

	fmt.Printf("Init a vote for %d voters\n\n", nVote)
	v, _ := vote.NewBinaryVote(nVote, nVote, gkX, gkY, authAddr)

	printline()
	fmt.Println()

	fmt.Printf("Generate and cast encrypted ballots\n")
	values := []bool{true, true, false, false, true}
	nYes := 3

	for i := 0; i < 5; i++ {
		voter, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		a := new(big.Int).Set(voter.D)
		voterAddr, _ := common.RandBytes(20)

		b, _ := vote.NewBinaryBallot(values[i], a, gkX, gkY, voterAddr)

		ballotStr, zkpStr := b.String()
		valStr := "YES"
		if !values[i] {
			valStr = "NO"
		}
		fmt.Printf("\nBallot [%d]:\nVALUE: %v\nCONTENT: %s\nZKPROOF: %s\n", i+1, valStr, ballotStr, zkpStr)

		if err := b.VerifyBallot(); err != nil {
			panic("zkp verification failed")
		}

		fmt.Printf("\nZKProof verification: PASS\n")

		v.Cast(b, voterAddr)

		fmt.Println()
	}

	printline()
	fmt.Println()

	fmt.Printf("Tally voting result\n")
	if err := v.Tally(k); err != nil {
		panic(err)
	}

	res := v.GetTallyRes()
	resStr, zkpStr := res.String()
	fmt.Printf("\n%s\nZKPROOF: %s\n", resStr, zkpStr)

	if err := v.VerifyTallyRes(); err != nil {
		panic(err)
	}

	fmt.Printf("\nZKProof verification: PASS\n")

	if res.V != uint(nYes) {
		panic("Invalid number of Yes votes")
	}

	fmt.Printf("\nCorrect number of YES votes\n")

	return
}

func printline() {
	fmt.Println("-----------------------------")
}
