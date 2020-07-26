package common

// ConcatBytesTight ...
func ConcatBytesTight(bs ...[]byte) []byte {
	var r []byte

	for _, b := range bs {
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
