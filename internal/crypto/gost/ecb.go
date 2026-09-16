package gost

func ECBEncrypt(data, key []byte) []byte {
	padded := pad(data)
	result := make([]byte, len(padded))
	for i := 0; i < len(padded); i += 8 {
		copy(result[i:i+8], BlockEncrypt32(padded[i:i+8], key))
	}

	return result
}

func ECBDecrypt(data, key []byte) []byte {
	result := make([]byte, len(data))
	for i := 0; i < len(result); i += 8 {
		copy(result[i:i+8], BlockDecrypt32(data[i:i+8], key))
	}

	return unpad(result)
}
