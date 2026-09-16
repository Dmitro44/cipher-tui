package gost

// For gamma with feedback

func pad(data []byte) []byte {
	padLen := 8 - (len(data) % 8)
	padded := make([]byte, len(data)+padLen)
	copy(padded, data)
	for i := len(data); i < len(padded); i++ {
		padded[i] = byte(padLen)
	}
	return padded
}

func unpad(data []byte) []byte {
	padLen := int(data[len(data)-1])
	if padLen > 0 && padLen <= 8 {
		return data[:len(data)-padLen]
	}
	return data
}

// For mac gen
func zeroPad(data []byte) []byte {
	padded := make([]byte, len(data))
	if rem := len(data) % 8; rem != 0 {
		padded = make([]byte, len(data)+8-rem)
		copy(padded, data)
	}
	return padded
}
