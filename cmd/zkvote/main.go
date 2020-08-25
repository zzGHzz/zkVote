package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"path/filepath"

	"github.com/zzGHzz/zkVote/common"

	"github.com/urfave/cli/v2"
	"github.com/zzGHzz/zkVote/vote"
)

var (
	inFlag *cli.StringSliceFlag = &cli.StringSliceFlag{
		Name:     "in",
		Aliases:  []string{"i"},
		Required: true,
	}
	outFlag *cli.StringFlag = &cli.StringFlag{
		Name:     "out",
		Aliases:  []string{"o"},
		Required: true,
	}
	// fileFlag *cli.StringFlag = &cli.StringFlag{
	// 	Name:    "file",
	// 	Aliases: []string{"f"},
	// }
	// numFlag *cli.IntFlag = &cli.IntFlag{
	// 	Name:     "number",
	// 	Aliases:  []string{"n"},
	// 	Required: true,
	// }
)

func main() {
	app := &cli.App{
		Commands: []*cli.Command{
			{
				Name:  "gen-priv-key",
				Usage: "Generate private key",
				Flags: []cli.Flag{
					outFlag,
				},
				Action: genPrivKey,
			},
			{
				Name:  "gen-bin-ballot",
				Usage: "Generate binary ballot(s)",
				Flags: []cli.Flag{
					inFlag,
					outFlag,
				},
				Action: genBinaryBallots,
			},
			{
				Name:  "ver-bin-ballot",
				Usage: "Verify yes/no ballots",
				Flags: []cli.Flag{
					inFlag,
					outFlag,
				},
				Action: verifyBinaryBallots,
			},
			{
				Name:  "tally",
				Usage: "Tally voting result",
				Flags: []cli.Flag{
					inFlag,
					outFlag,
				},
				Action: tally,
			},
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}

func genPrivKey(ctx *cli.Context) error {
	file := ctx.String(outFlag.Name)
	// if _, err := os.Stat(outDir); os.IsNotExist(err) {
	// 	return fmt.Errorf("Output dir [%s] does not exist", outDir)
	// }

	a, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}

	// file := ctx.String(fileFlag.Name)
	// if file == "" {
	// 	file = "./priv-key.json"
	// }
	data, err := json.Marshal(Key{
		K: "0x" + a.D.Text(16),
		X: "0x" + a.PublicKey.X.Text(16),
		Y: "0x" + a.PublicKey.Y.Text(16),
	})
	if err != nil {
		return err
	}
	if err := ioutil.WriteFile(file, data, 0700); err != nil {
		return err
	}

	return nil
}

func genBinaryBallots(ctx *cli.Context) error {
	var (
		a, gkX, gkY, addr *big.Int
		err               error

		data    []byte
		ballots []*vote.BinaryBallot
	)

	data, err = ioutil.ReadFile(ctx.StringSlice(inFlag.Name)[0])
	if err != nil {
		return err
	}

	// outDir := ctx.String(outFlag.Name)
	// if _, err := os.Stat(outDir); os.IsNotExist(err) {
	// 	return fmt.Errorf("Output dir [%s] does not exist", outDir)
	// }

	var input DataForGenBinaryBallots
	if err := json.Unmarshal(data, &input); err != nil {
		return err
	}

	// Convert g^k from string
	if gkX, err = common.HexStrToBigInt(input.GKX); err != nil {
		return err
	}
	if gkY, err = common.HexStrToBigInt(input.GKY); err != nil {
		return err
	}

	for _, d := range input.Data {
		// Convert string to big.Int
		if a, err = common.HexStrToBigInt(d.A); err != nil {
			return err
		}
		if addr, err = common.HexStrToBigInt(d.Address); err != nil {
			return err
		}

		// Generate binary ballot
		b, err := vote.NewBinaryBallot(d.V != 0, a, gkX, gkY, addr)
		if err != nil {
			return err
		}

		ballots = append(ballots, b)
	}

	file := ctx.String(outFlag.Name)
	// if file == "" {
	// 	file = "bin-ballot.json"
	// }
	if len(ballots) == 1 {
		data, err = json.Marshal(ballots[0])
	} else {
		data, err = json.Marshal(ballots)
	}
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(file, data, 0700)
	if err != nil {
		return err
	}

	// for i, b := range ballots {
	// 	fname := fmt.Sprintf("bin-ballot-%d.json", i)

	// 	// Write into file
	// 	data, err = json.Marshal(b)
	// 	if err != nil {
	// 		return err
	// 	}

	// 	err = ioutil.WriteFile(filepath.Join(outDir, fname), data, 0700)
	// 	if err != nil {
	// 		return err
	// 	}
	// }

	return nil
}

func verifyBinaryBallots(ctx *cli.Context) error {
	data, err := ioutil.ReadFile(ctx.StringSlice(inFlag.Name)[0])
	if err != nil {
		return err
	}

	outDir := ctx.String(outFlag.Name)
	if _, err := os.Stat(outDir); os.IsNotExist(err) {
		return errors.New("out_dir does not exist")
	}

	var ballots []*vote.BinaryBallot
	if err := json.Unmarshal(data, &ballots); err != nil {
		return err
	}

	var invalids []string
	var valids []*vote.BinaryBallot
	for _, ballot := range ballots {
		if err := ballot.VerifyBallot(); err != nil {
			obj := ballot.BuildJSONBinaryBallot()
			invalids = append(invalids, obj.Proof.Data)
		} else {
			valids = append(valids, ballot)
		}
	}

	data, err = json.Marshal(invalids)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(filepath.Join(outDir, "invalid-bin-addrs.json"), data, 0700)
	if err != nil {
		return err
	}

	data, err = json.Marshal(valids)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(filepath.Join(outDir, "valid-bin-ballot.json"), data, 0700)
	if err != nil {
		return err
	}

	return nil
}

func tally(ctx *cli.Context) error {
	outDir := ctx.String(outFlag.Name)
	if _, err := os.Stat(outDir); os.IsNotExist(err) {
		return errors.New("out_dir does not exist")
	}

	inFiles := ctx.StringSlice(inFlag.Name)
	if len(inFiles) < 2 {
		return errors.New("Not enough input files")
	}

	data1, err := ioutil.ReadFile(inFiles[0])
	if err != nil {
		return err
	}
	data2, err := ioutil.ReadFile(inFiles[1])
	if err != nil {
		return err
	}

	var (
		ballots  []*vote.BinaryBallot
		authData AuthDataForTally
	)

	if err := json.Unmarshal(data1, &authData); err != nil {
		if err := json.Unmarshal(data2, &authData); err != nil {
			return err
		}
		if err := json.Unmarshal(data1, &ballots); err != nil {
			return err
		}
	} else if err := json.Unmarshal(data2, &ballots); err != nil {
		return err
	}

	var invalids []string
	var valids []*vote.BinaryBallot
	for _, ballot := range ballots {
		if err := ballot.VerifyBallot(); err != nil {
			obj := ballot.BuildJSONBinaryBallot()
			invalids = append(invalids, obj.Proof.Data)
		} else {
			valids = append(valids, ballot)
		}
	}

	var (
		gkX, gkY, k, addr *big.Int
		tal               *vote.BinaryTally
		res               *vote.BinaryTallyRes
		data              []byte
	)

	if gkX, err = common.HexStrToBigInt(authData.GKX); err != nil {
		return err
	}
	if gkY, err = common.HexStrToBigInt(authData.GKY); err != nil {
		return err
	}
	if k, err = common.HexStrToBigInt(authData.K); err != nil {
		return err
	}
	if addr, err = common.HexStrToBigInt(authData.Address); err != nil {
		return err
	}

	if tal, err = vote.NewBinaryTally(gkX, gkY, addr, valids); err != nil {
		return err
	}

	if res, err = tal.Tally(k); err != nil {
		return err
	}

	// write tally result
	if data, err = json.Marshal(res); err != nil {
		return err
	}
	if err = ioutil.WriteFile(filepath.Join(outDir, "bin-tally-res.json"), data, 0700); err != nil {
		return err
	}

	// write addresses of the invalid ballots
	if data, err = json.Marshal(invalids); err != nil {
		return err
	}
	if err = ioutil.WriteFile(filepath.Join(outDir, "invalid-bin-addr.json"), data, 0700); err != nil {
		return err
	}

	return nil
}

// func genRandValidBallots(ctx *cli.Context) error {
// 	outDir := ctx.String(outFlag.Name)
// 	if _, err := os.Stat(outDir); os.IsNotExist(err) {
// 		return errors.New("out_dir does not exist")
// 	}

// 	n := ctx.Int(numFlag.Name)
// 	if n <= 0 {
// 		return errors.New("num must be larger than zero")
// 	}

// 	bs := randValidBinaryBallots(n)
// 	if len(bs) != n {
// 		return errors.New("errors in generating random yes/no ballots")
// 	}

// 	data, err := json.Marshal(bs)
// 	if err != nil {
// 		return err
// 	}
// 	if err := ioutil.WriteFile(filepath.Join(outDir, ctx.String(fileFlag.Name)), data, 0700); err != nil {
// 		return err
// 	}

// 	return nil
// }

// func genInvalidBallots(ctx *cli.Context) error {
// 	outDir := ctx.String(outFlag.Name)
// 	if _, err := os.Stat(outDir); os.IsNotExist(err) {
// 		return errors.New("out_dir does not exist")
// 	}

// 	n := ctx.Int(numFlag.Name)
// 	if n <= 0 {
// 		return errors.New("num must be larger than zero")
// 	}

// 	bs := invalidBinaryBallots(n)
// 	if len(bs) != n {
// 		return errors.New("errors in generating invalid yes/no ballots")
// 	}

// 	data, err := json.Marshal(bs)
// 	if err != nil {
// 		return err
// 	}
// 	file := ctx.String(fileFlag.Name)
// 	if file == "" {
// 		file = "invalid-bin-ballots.json"
// 	}
// 	if err := ioutil.WriteFile(filepath.Join(outDir, file), data, 0700); err != nil {
// 		return err
// 	}

// 	return nil
// }
