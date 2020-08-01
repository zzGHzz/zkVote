package vote

import (
	"crypto/sha256"
	"errors"
	"math/big"
)

// BinaryVote structure
type BinaryVote struct {
	gkX, gkY       *big.Int // authority's public key
	hashedAuthAddr []byte   // address of authorty

	minVoter, maxVoter uint // min and max number of votes

	ballots map[[32]byte]*BinaryBallot // binary ballots

	HX, HY *big.Int // H = prod_i g^a_i = prod_i x_i
	YX, YY *big.Int // Y = prod_i y_i

	res *BinaryTallyRes
}

// NewBinaryVote news a yes-or-no vote
func NewBinaryVote(minVoter, maxVoter uint, gkX, gkY *big.Int, authAddr []byte) (*BinaryVote, error) {
	if !isOnCurve(gkX, gkY) {
		return nil, errors.New("Invalid g^k")
	}

	vote := new(BinaryVote)

	if maxVoter == 0 || minVoter > maxVoter {
		return nil, errors.New("Invalid voter number setting")
	}
	vote.maxVoter = maxVoter
	vote.minVoter = minVoter

	vote.gkX = new(big.Int).Set(gkX)
	vote.gkY = new(big.Int).Set(gkY)
	z := sha256.Sum256(authAddr)
	vote.hashedAuthAddr = z[:]
	vote.ballots = make(map[[32]byte]*BinaryBallot)

	vote.HX = big.NewInt(0)
	vote.HY = big.NewInt(0)
	vote.YX = big.NewInt(0)
	vote.YY = big.NewInt(0)

	return vote, nil
}

// NewBinaryTally creates a tally
func (v *BinaryVote) newBinaryTally() *BinaryTally {
	return &BinaryTally{
		new(big.Int).Set(v.gkX), new(big.Int).Set(v.gkY),
		new(big.Int).Set(v.HX), new(big.Int).Set(v.HY),
		new(big.Int).Set(v.YX), new(big.Int).Set(v.YY),

		uint(len(v.ballots)),
		v.hashedAuthAddr,
	}
}

// Cast casts a ballot
func (v *BinaryVote) Cast(bt Ballot, addr []byte) error {
	b, ok := bt.(*BinaryBallot)
	if !ok {
		return errors.New("Invalid ballot type")
	}

	if err := b.VerifyBallot(); err != nil {
		return err
	}

	z := sha256.Sum256(addr)
	if old, ok := v.ballots[z]; ok {
		iOldhX, iOldhY := new(big.Int).Set(old.hX), new(big.Int).Sub(curve.Params().P, old.hY)
		v.HX, v.HY = curve.Add(v.HX, v.HY, iOldhX, iOldhY)

		iOldyX, iOldyY := new(big.Int).Set(old.yX), new(big.Int).Sub(curve.Params().P, old.yY)
		v.YX, v.YY = curve.Add(v.YX, v.YY, iOldyX, iOldyY)
	} else {
		if uint(len(v.ballots)) >= v.maxVoter {
			return errors.New("Max number of voters reached")
		}
	}

	v.HX, v.HY = curve.Add(v.HX, v.HY, b.hX, b.hY)
	v.YX, v.YY = curve.Add(v.YX, v.YY, b.yX, b.yY)

	v.ballots[sha256.Sum256(addr)] = b

	return nil
}

// Tally tallies the voting results
func (v *BinaryVote) Tally(k *big.Int) error {
	if !isInRange(k) {
		return errors.New("Invalid k")
	}

	if uint(len(v.ballots)) < v.minVoter {
		return errors.New("Min number of voters unreached")
	}

	t := v.newBinaryTally()

	res, err := t.tally(k)
	if err != nil {
		return err
	}
	v.res = res

	return nil
}

// VerifyTallyRes verifies the tally results
func (v *BinaryVote) VerifyTallyRes() error {
	if v.res == nil {
		return errors.New("No tally results")
	}

	if err := v.res.verify(); err != nil {
		return err
	}

	return nil
}

// GetAuthPublicKey returns authority public key
func (v *BinaryVote) GetAuthPublicKey() (*big.Int, *big.Int) {
	return new(big.Int).Set(v.gkX), new(big.Int).Set(v.gkY)
}
