package common

import (
	"crypto/rand"
	"errors"
)

// ConcatBytes concatenates byte arrays
func ConcatBytes(data ...[]byte) []byte {
	var concat []byte
	for _, b := range data {
		if len(b) == 0 {
			continue
		}

		concat = append(concat, b...)
	}

	return concat
}

// // ConcatBytesTight ...
// func ConcatBytesTight(bs ...[]byte) []byte {
// 	var r []byte

// 	for _, b := range bs {
// 		if len(b) == 0 {
// 			continue
// 		}

// 		i := 0
// 		for {
// 			if b[i] != 0x0 {
// 				break
// 			}
// 			i = i + 1
// 		}
// 		r = append(r, b[i:]...)
// 	}

// 	return r
// }

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
