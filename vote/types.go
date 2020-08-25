package vote

// JSONBinaryBallot ...
type JSONBinaryBallot struct {
	HX    string                     `json:"hx"`
	HY    string                     `json:"hy"`
	YX    string                     `json:"yx"`
	YY    string                     `json:"yy"`
	Proof *JSONCompressedBinaryProof `json:"proof"`
}

// JSONCompressedBinaryProof ...
type JSONCompressedBinaryProof struct {
	Data string `json:"data"`
	GKX  string `json:"gkx"`
	GKY  string `json:"gky"`
	D1   string `json:"d1"`
	D2   string `json:"d2"`
	R1   string `json:"r1"`
	R2   string `json:"r2"`
	A1X  string `json:"a1x"`
	A1Y  string `json:"a1y"`
	B1X  string `json:"b1x"`
	B1Y  string `json:"b1y"`
	A2X  string `json:"a2x"`
	A2Y  string `json:"a2y"`
	B2X  string `json:"b2x"`
	B2Y  string `json:"b2y"`
}

// JSONCompressedECFSProof ...
type JSONCompressedECFSProof struct {
	Data string `json:"data"`
	HX   string `json:"hx"`
	HY   string `json:"hy"`
	TX   string `json:"tx"`
	TY   string `json:"ty"`
	R    string `json:"r"`
}

// JSONBinaryTallyRes defines json object
type JSONBinaryTallyRes struct {
	V     int                      `json:"v"`
	XX    string                   `json:"xx"`
	XY    string                   `json:"xy"`
	YX    string                   `json:"yx"`
	YY    string                   `json:"yy"`
	Proof *JSONCompressedECFSProof `json:"proof"`
}
