package main

import (
	"encoding/json"
	"errors"
	"fmt"
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
	inFileFlag *cli.StringFlag = &cli.StringFlag{
		Name:     "in_file",
		Aliases:  []string{"i"},
		Required: true,
	}
	outDirFlag *cli.StringFlag = &cli.StringFlag{
		Name:     "out_dir",
		Aliases:  []string{"o"},
		Required: true,
	}
	fileFlag *cli.StringFlag = &cli.StringFlag{
		Name:    "file",
		Aliases: []string{"f"},
	}
	numFlag *cli.IntFlag = &cli.IntFlag{
		Name:     "number",
		Aliases:  []string{"n"},
		Required: true,
	}
)

func main() {
	app := &cli.App{
		Commands: []*cli.Command{
			{
				Name:  "bat-ver-bin",
				Usage: "Batch verify yes/no ballots",
				Flags: []cli.Flag{
					inFileFlag,
					outDirFlag,
				},
				Action: batchVerifyBinaryBallots,
			},
			{
				Name:  "gen-bin",
				Usage: "Generate ballot",
				Flags: []cli.Flag{
					inFileFlag,
					outDirFlag,
					fileFlag,
				},
				Action: genBinaryBallot,
			},
			{
				Name:  "gen-rand-bin",
				Usage: "Generate random valid yes/no ballots",
				Flags: []cli.Flag{
					outDirFlag,
					fileFlag,
					numFlag,
				},
				Action: genRandValidBallots,
			},
			{
				Name:  "gen-invalid-bin",
				Usage: "Generate random valid yes/no ballots",
				Flags: []cli.Flag{
					outDirFlag,
					fileFlag,
					numFlag,
				},
				Action: genInvalidBallots,
			},
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}

func genBinaryBallot(ctx *cli.Context) error {
	var (
		a, gkX, gkY, addr *big.Int
		err               error

		data []byte
		b    *vote.BinaryBallot
	)

	data, err = ioutil.ReadFile(ctx.String(inFileFlag.Name))
	if err != nil {
		return err
	}

	outDir := ctx.String(outDirFlag.Name)
	if _, err := os.Stat(outDir); os.IsNotExist(err) {
		return fmt.Errorf("Output dir [%s] does not exist", outDir)
	}

	type LoadInfo struct {
		GKX  string `json:"gkx"`
		GKY  string `json:"gky"`
		A    string `json:"a"`
		Addr string `json:"address"`
		V    uint   `json:"v"`
	}

	var info LoadInfo
	if err := json.Unmarshal(data, &info); err != nil {
		return err
	}

	// Convert string to big.Int
	if a, err = common.HexStrToBigInt(info.A); err != nil {
		return err
	}
	if gkX, err = common.HexStrToBigInt(info.GKX); err != nil {
		return err
	}
	if gkY, err = common.HexStrToBigInt(info.GKY); err != nil {
		return err
	}
	if addr, err = common.HexStrToBigInt(info.Addr); err != nil {
		return err
	}

	// Generate binary ballot
	b, err = vote.NewBinaryBallot(info.V != 0, a, gkX, gkY, addr)
	if err != nil {
		return err
	}

	// Write into file
	data, err = json.Marshal(b)
	if err != nil {
		return err
	}
	file := ctx.String(fileFlag.Name)
	if file == "" {
		file = "ballot.json"
	}
	err = ioutil.WriteFile(filepath.Join(outDir, file), data, 0700)
	if err != nil {
		return err
	}

	return nil
}

func batchVerifyBinaryBallots(ctx *cli.Context) error {
	data, err := ioutil.ReadFile(ctx.String(inFileFlag.Name))
	if err != nil {
		return err
	}

	outDir := ctx.String(outDirFlag.Name)
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
	err = ioutil.WriteFile(filepath.Join(outDir, "invalid-addrs.json"), data, 0700)
	if err != nil {
		return err
	}

	data, err = json.Marshal(valids)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(filepath.Join(outDir, "valid-bin-ballots.json"), data, 0700)
	if err != nil {
		return err
	}

	return nil
}

func genRandValidBallots(ctx *cli.Context) error {
	outDir := ctx.String(outDirFlag.Name)
	if _, err := os.Stat(outDir); os.IsNotExist(err) {
		return errors.New("out_dir does not exist")
	}

	n := ctx.Int(numFlag.Name)
	if n <= 0 {
		return errors.New("num must be larger than zero")
	}

	bs := randValidBinaryBallots(n)
	if len(bs) != n {
		return errors.New("errors in generating random yes/no ballots")
	}

	data, err := json.Marshal(bs)
	if err != nil {
		return err
	}
	if err := ioutil.WriteFile(filepath.Join(outDir, ctx.String(fileFlag.Name)), data, 0700); err != nil {
		return err
	}

	return nil
}

func genInvalidBallots(ctx *cli.Context) error {
	outDir := ctx.String(outDirFlag.Name)
	if _, err := os.Stat(outDir); os.IsNotExist(err) {
		return errors.New("out_dir does not exist")
	}

	n := ctx.Int(numFlag.Name)
	if n <= 0 {
		return errors.New("num must be larger than zero")
	}

	bs := invalidBinaryBallots(n)
	if len(bs) != n {
		return errors.New("errors in generating invalid yes/no ballots")
	}

	data, err := json.Marshal(bs)
	if err != nil {
		return err
	}
	if err := ioutil.WriteFile(filepath.Join(outDir, ctx.String(fileFlag.Name)), data, 0700); err != nil {
		return err
	}

	return nil
}
