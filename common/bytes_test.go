package common

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
)

// func TestConcatBytesTight(t *testing.T) {
// 	a := []byte{0x0, 0x10, 0x23}
// 	b := []byte{0x0, 0x0, 0x0, 0xff, 0xa0}
// 	c := []byte{0x99}
// 	e := []byte(nil)
// 	d := []byte{0x10, 0x23, 0xff, 0xa0, 0x99}

// 	assert.Equal(t, ConcatBytesTight(e, a, b, c), d)
// }

func TestBigIntToHexStr(t *testing.T) {
	i, _ := new(big.Int).SetString("12345", 16)
	h := BigIntToHexStr(i)
	assert.Equal(t, h, "0x012345")

	i, _ = new(big.Int).SetString("123456", 16)
	h = BigIntToHexStr(i)
	assert.Equal(t, h, "0x123456")
}
