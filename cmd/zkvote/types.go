package main

// VoterDataForBinaryBallot contains data from voter for a binary ballot
type VoterDataForBinaryBallot struct {
	A       string `json:"a"`
	Address string `json:"address"`
	V       uint   `json:"v"`
}

// DataForGenBinaryBallots contains data to create binary ballots
type DataForGenBinaryBallots struct {
	GKX  string                      `json:"gkx"`
	GKY  string                      `json:"gky"`
	Data []*VoterDataForBinaryBallot `json:"data"`
}
