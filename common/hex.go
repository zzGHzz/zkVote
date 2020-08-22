package common

import (
	"errors"
	"math/big"
	"regexp"
)

// BigIntToHexStr converts big int to hex string
func BigIntToHexStr(i *big.Int) string {
	h := i.Text(16)
	if len(h)%2 == 1 {
		h = "0" + h // make sure that the length is even
	}
	return "0x" + h
}

// HexStrToBigInt converts hex string to big int
func HexStrToBigInt(s string) (*big.Int, error) {
	regstr := "^0[xX][0-9a-fA-F]+$"
	if matched, err := regexp.Match(regstr, []byte(s)); err != nil || !matched {
		return nil, errors.New("Invalid hex string")
	}

	i, b := new(big.Int).SetString(s[2:], 16)
	if !b {
		return nil, errors.New("Invalid hex string")
	}

	return i, nil
}
