package main

// VoterData contains data from voter for a binary ballot
type VoterData struct {
	A       string `json:"a"`
	Address string `json:"address"`
	V       uint   `json:"v"`
}

// DataForGenBinaryBallots contains data to create binary ballots
type DataForGenBinaryBallots struct {
	GKX  string       `json:"gkx"`
	GKY  string       `json:"gky"`
	Data []*VoterData `json:"data"`
}

// Key contains a private key and its corresponding public key
type Key struct {
	K string `json:"k"`
	X string `json:"x"`
	Y string `json:"y"`
}

// AuthDataForTally contains data from authority to perform tally
type AuthDataForTally struct {
	K       string `json:"k"`
	Address string `json:"address"`
	GKX     string `json:"gkx"`
	GKY     string `json:"gky"`
}
