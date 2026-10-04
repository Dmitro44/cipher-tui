package belt

import "fmt"

func ECBEncrypt(data, key []byte) ([]byte, error) {
	if err := validateKey(key); err != nil {
		return nil, err
	}
	if len(data) < BlockSize {
		return nil, fmt.Errorf(
			"belt-ecb: message must contain at least one %d-byte block, got %d bytes",
			BlockSize, len(data),
		)
	}

	if len(data)%BlockSize == 0 {
		result := make([]byte, len(data))
		for i := 0; i < len(data); i += BlockSize {
			copy(result[i:i+BlockSize], BlockEncrypt(data[i:i+BlockSize], key))
		}
		return result, nil
	}

	return ecbEncryptLastPartial(data, key), nil
}

func ECBDecrypt(data, key []byte) ([]byte, error) {
	if err := validateKey(key); err != nil {
		return nil, err
	}
	if len(data) < BlockSize {
		return nil, fmt.Errorf(
			"belt-ecb: ciphertext must contain at least one %d-byte block, got %d bytes",
			BlockSize, len(data),
		)
	}

	if len(data)%BlockSize == 0 {
		result := make([]byte, len(data))
		for i := 0; i < len(data); i += BlockSize {
			copy(result[i:i+BlockSize], BlockDecrypt(data[i:i+BlockSize], key))
		}
		return result, nil
	}

	return ecbDecryptLastPartial(data, key), nil
}

func ecbEncryptLastPartial(data, key []byte) []byte {
	n := len(data) / BlockSize
	rem := len(data) % BlockSize
	result := make([]byte, len(data))

	for i := 0; i < n-1; i++ {
		copy(result[i*BlockSize:], BlockEncrypt(data[i*BlockSize:(i+1)*BlockSize], key))
	}

	lastCipher := BlockEncrypt(data[(n-1)*BlockSize:n*BlockSize], key)

	augmented := make([]byte, BlockSize)
	copy(augmented, data[n*BlockSize:])
	copy(augmented[rem:], lastCipher[rem:])

	copy(result[(n-1)*BlockSize:n*BlockSize], BlockEncrypt(augmented, key))
	copy(result[n*BlockSize:], lastCipher[:rem])

	return result
}

func ecbDecryptLastPartial(data, key []byte) []byte {
	n := len(data) / BlockSize
	rem := len(data) % BlockSize
	result := make([]byte, len(data))

	for i := 0; i < n-1; i++ {
		copy(result[i*BlockSize:], BlockDecrypt(data[i*BlockSize:(i+1)*BlockSize], key))
	}

	cAug := data[(n-1)*BlockSize : n*BlockSize]
	tail := data[n*BlockSize:]
	augmented := BlockDecrypt(cAug, key)

	lastCipher := make([]byte, BlockSize)
	copy(lastCipher, tail)
	copy(lastCipher[rem:], augmented[rem:])

	copy(result[(n-1)*BlockSize:n*BlockSize], BlockDecrypt(lastCipher, key))
	copy(result[n*BlockSize:], augmented[:rem])

	return result
}
