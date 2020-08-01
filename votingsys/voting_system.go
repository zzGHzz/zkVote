package votingsys

import (
	"crypto/sha256"
	"errors"
	"math/big"
	"time"

	"github.com/zzGHzz/zkVote/vote"
)

// VotingSys structure
type VotingSys struct {
	StartTime map[[32]byte]uint64
	EndTime   map[[32]byte]uint64
	Votes     map[[32]byte]vote.Vote
}

// VoteType ...
type VoteType int

const (
	// Binary vote
	Binary VoteType = iota
)

// VoteOptions ...
type VoteOptions struct {
	gkX, gkY *big.Int
	voteType VoteType

	minVoter, maxVoter uint
	authAddr           []byte

	startTime, endTime uint64
}

// NewVotingSys news a voting system
func NewVotingSys() *VotingSys {
	return &VotingSys{
		StartTime: make(map[[32]byte]uint64),
		EndTime:   make(map[[32]byte]uint64),
		Votes:     make(map[[32]byte]vote.Vote),
	}
}

// id = H(now, g^k)
func getVoteID(opt *VoteOptions) [32]byte {
	now := big.NewInt(time.Now().Unix()).Bytes()
	data := append([]byte(nil), now...)
	data = append(data, opt.gkX.Bytes()...)
	data = append(data, opt.gkY.Bytes()...)
	return sha256.Sum256(data)
}

// Register creates a vote
func (sys *VotingSys) Register(opt *VoteOptions) ([32]byte, error) {
	now := uint64(time.Now().Unix())
	if now > opt.startTime {
		return [32]byte{}, errors.New("Starting time before now")
	}
	if opt.endTime <= opt.startTime {
		return [32]byte{}, errors.New("Ending time before starting time")
	}

	id := getVoteID(opt)
	sys.StartTime[id] = opt.startTime
	sys.EndTime[id] = opt.endTime

	switch opt.voteType {
	case Binary:
		v, err := vote.NewBinaryVote(
			opt.minVoter, opt.maxVoter,
			opt.gkX, opt.gkY,
			opt.authAddr,
		)
		if err != nil {
			return [32]byte{}, err
		}
		sys.Votes[id] = v
	}

	return id, nil
}

// Cast casts ballot
func (sys *VotingSys) Cast(voteID [32]byte, b vote.Ballot, addr []byte) error {
	v, ok := sys.Votes[voteID]
	if !ok {
		return errors.New("Vote not found")
	}

	now := uint64(time.Now().Unix())
	if now > sys.EndTime[voteID] {
		return errors.New("Vote has ended")
	}

	return v.Cast(b, addr)
}
