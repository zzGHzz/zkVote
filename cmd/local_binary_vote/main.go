package main

import (
	"crypto/elliptic"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/big"

	"github.com/zzGHzz/zkVote/common"
	"github.com/zzGHzz/zkVote/vote"
)

var accounts = [10]struct {
	k    string
	addr string
}{
	{"3e61996a0a49b26a5608a55a3e0669aff271959d2e43658766e3514a07a5ccf3", "0xCDFDFD58e986130445B560276f52CE7985809238"},
	{"fb36f708acfd7e220634c4f48228fc5640c55575e5b2824047e4fa740bc5b532", "0x17faD1428DC464187C33C5EfD281aE7E58937Fd8"},
	{"24c0f884abc45fc6013e38e0571c24fb0b2bcdd19493640a454d07ee57bf83dc", "0xF9a0c98Aa23Bf75D46384B839620Ec2E9926DE7d"},
	{"5d6de2a70d5c8bffabf5010926d98e45dd5d98db55ca739104a092f5bf152deb", "0xbd0A8dca41215d772b9cd6fB91696EcC9ac6a2D1"},
	{"ec6aca0c3d926317040cc4f4f40385f7e38714ea529c77129f2e5cf6f174d3ed", "0xbC985662CE20FD344Ea02dd92b208C2ab0eC78fd"},
	{"c052e95e1f99a601f0c39fdda813c74df50987dd4ef2b4fcb6a1b628edf6e61d", "0x72752eb265000AF3D16bAE4D9a6312Dc84c65D41"},
	{"67bc06c668f9dac4b9e4850b395f84d7d2bf88951f785e191a0ddc0e55b70c86", "0x9902a999FB8103B37bD11DB32a86E1ecf3FC12e6"},
	{"ed0115126799073ccbd4b757a410805c2785b3da699881f35689aa934c896d8f", "0xCA9d05b097cf7646ad641101bffE48022f842A2d"},
	{"82dbe83e281095d2011244f66e1f54a9c505ecb7036090390f909b5849cbcdee", "0x20bb4844D2DBEA13053ca43B60b07Eae1b56e964"},
	{"d8fb043dfc25bb5ea4621668a69f954b6e9810f9c3075eef463fc6b40e5d8189", "0x06Abf1999FC0E0A5C26784d8817Df99e7d13b2FC"},
}

var c = elliptic.P256()

func main() {
	// auth, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	// k := new(big.Int).Set(auth.D)
	// gkX := new(big.Int).Set(auth.PublicKey.X)
	// gkY := new(big.Int).Set(auth.PublicKey.Y)
	// authAddr, _ := common.RandBytes(20)

	var (
		k        *big.Int
		gkX, gkY *big.Int
		authAddr *big.Int

		ok bool
	)

	if k, ok = new(big.Int).SetString(accounts[0].k, 16); !ok {
		panic("Invalid privKey[0]")
	}
	gkX, gkY = c.ScalarBaseMult(k.Bytes())
	if authAddr, ok = new(big.Int).SetString(accounts[0].addr[2:], 16); !ok {
		panic("Invalid accounts[0]")
	}

	fmt.Printf("k = %x, g^k = (%x, %x)\n\n", k, gkX, gkY)

	if data, err := json.Marshal(struct {
		GKX string `json:"gkx"`
		GKY string `json:"gky"`
	}{
		common.BigIntToHexStr(gkX),
		common.BigIntToHexStr(gkY),
	}); err != nil {
		panic(err)
	} else {
		file := "./auth_public_key.json"
		if err := ioutil.WriteFile(file, data, 0664); err != nil {
			panic(err)
		}
	}

	nVote := uint(5)

	fmt.Printf("Init a vote for %d voters\n\n", nVote)
	v, _ := vote.NewBinaryVote(nVote, nVote, gkX, gkY, authAddr.Bytes())

	printline()
	fmt.Println()

	fmt.Printf("Generate and cast encrypted ballots\n")
	values := []bool{true, true, false, false, true}
	nYes := 3

	for i := 0; i < 5; i++ {
		// voter, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		// a := new(big.Int).Set(voter.D)
		// voterAddr, _ := common.RandBytes(20)

		var (
			a         *big.Int
			voterAddr *big.Int
			ok        bool
		)

		if a, ok = new(big.Int).SetString(accounts[i+1].k, 16); !ok {
			panic(fmt.Sprintf("Invalid privKey[%d]", i+1))
		}
		if voterAddr, ok = new(big.Int).SetString(accounts[i+1].addr[2:], 16); !ok {
			panic(fmt.Sprintf("Invalid accounts[%d]", i+1))
		}

		b, _ := vote.NewBinaryBallot(values[i], a, gkX, gkY, voterAddr.Bytes())

		ballotStr, zkpStr := b.String()
		valStr := "YES"
		if !values[i] {
			valStr = "NO"
		}
		fmt.Printf("\nBallot [%d]:\nVALUE: %v\nCONTENT: %s\nZKPROOF: %s\n", i+1, valStr, ballotStr, zkpStr)

		if data, err := json.Marshal(b); err != nil {
			panic(err)
		} else {
			file := fmt.Sprintf("./vote_%d.json", i)
			if err := ioutil.WriteFile(file, data, 0664); err != nil {
				panic(err)
			}
		}

		if err := b.VerifyBallot(); err != nil {
			panic("zkp verification failed")
		}

		fmt.Printf("\nZKProof verification: PASS\n")

		v.Cast(b, voterAddr.Bytes())

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

	if data, err := json.Marshal(res); err != nil {
		panic(err)
	} else {
		if err := ioutil.WriteFile("./tally.json", data, 0664); err != nil {
			panic(err)
		}
	}

	if err := v.VerifyTallyRes(); err != nil {
		panic(err)
	}

	fmt.Printf("\nZKProof verification: PASS\n")

	if res.V != uint64(nYes) {
		panic("Invalid number of Yes votes")
	}

	fmt.Printf("\nCorrect number of YES votes\n")

	return
}

func printline() {
	fmt.Println("-----------------------------")
}
