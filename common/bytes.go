package common

import (
	"crypto/rand"
	"errors"
)

// ConcatBytesTight ...
func ConcatBytesTight(bs ...[]byte) []byte {
	var r []byte

	for _, b := range bs {
		if len(b) == 0 {
			continue
		}

		i := 0
		for {
			if b[i] != 0x0 {
				break
			}
			i = i + 1
		}
		r = append(r, b[i:]...)
	}

	return r
}

// RandBytes generates rand byte array
func RandBytes(n uint) ([]byte, error) {
	if n == 0 {
		return []byte(nil), errors.New("Zero length")
	}
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return []byte(nil), err
	}
	return b, nil
}
