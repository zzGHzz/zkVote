package common

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestConcatBytesTight(t *testing.T) {
	a := []byte{0x0, 0x10, 0x23}
	b := []byte{0x0, 0x0, 0x0, 0xff, 0xa0}
	c := []byte{0x99}
	d := []byte{0x10, 0x23, 0xff, 0xa0, 0x99}

	assert.Equal(t, ConcatBytesTight(a, b, c), d)
}
