package belt

import (
	"crypto/rand"
	"errors"
	"fmt"
)

func GammaWithFeedbackEncrypt(data, key []byte) ([]byte, []byte, error) {
	if err := validateKey(key); err != nil {
		return nil, nil, err
	}
	if len(data) == 0 {
		return nil, nil, errors.New("belt-cfb: message is empty")
	}

	sync := make([]byte, BlockSize)
	if _, err := rand.Read(sync); err != nil {
		return nil, nil, fmt.Errorf("belt-cfb: generate sync: %w", err)
	}

	return gammaWithFeedbackEncrypt(data, key, sync), sync, nil
}

func gammaWithFeedbackEncrypt(data, key, sync []byte) []byte {
	cipherText := make([]byte, len(data))
	yPrev := sync

	for offset := 0; offset < len(data); offset += BlockSize {
		end := min(offset+BlockSize, len(data))

		yCurr := BlockEncrypt(yPrev, key)
		for i := offset; i < end; i++ {
			cipherText[i] = data[i] ^ yCurr[i-offset]
		}

		yPrev = cipherText[offset:end]
	}

	return cipherText
}

func GammaWithFeedbackDecrypt(data, key, sync []byte) ([]byte, error) {
	if err := validateKey(key); err != nil {
		return nil, err
	}
	if len(sync) != BlockSize {
		return nil, fmt.Errorf("belt-cfb: sync must be %d bytes, got %d", BlockSize, len(sync))
	}
	if len(data) == 0 {
		return nil, errors.New("belt-cfb: ciphertext is empty")
	}

	return gammaWithFeedbackDecrypt(data, key, sync), nil
}

func gammaWithFeedbackDecrypt(data, key, sync []byte) []byte {
	plainText := make([]byte, len(data))
	xPrev := sync

	for offset := 0; offset < len(data); offset += BlockSize {
		end := min(offset+BlockSize, len(data))

		xCurr := BlockEncrypt(xPrev, key)
		for i := offset; i < end; i++ {
			plainText[i] = data[i] ^ xCurr[i-offset]
		}

		xPrev = data[offset:end]
	}

	return plainText
}
