package gost

import (
	"crypto/rand"
	"encoding/binary"
)

func Gamma(iv []byte, key []byte, length int) []byte {
	if len(iv) != 8 {
		panic("iv must be 8 byte")
	}

	n3, n4 := BlockEncryptParts(iv, key, 32)

	gamma := make([]byte, 0, length)
	for len(gamma) < length {
		n3 = n3 + 0x1010101B // mod 2^32

		// mod 2^32-1
		n4 = n4 + 0x10101041
		if n4 < 0x10101041 { // overflow
			n4++
		}
		if n4 == 0xFFFFFFFF {
			n4 = 0
		}

		block := make([]byte, 8)
		binary.LittleEndian.PutUint32(block[0:4], n3)
		binary.LittleEndian.PutUint32(block[4:8], n4)

		enc := BlockEncrypt32(block, key)
		gamma = append(gamma, enc...)
	}

	return gamma[:length]
}

func GostGammaEncrypt(data, key []byte) ([]byte, []byte) {
	iv := make([]byte, 8)
	if _, err := rand.Read(iv); err != nil {
		panic(err)
	}

	gamma := Gamma(iv, key, len(data))

	cypherText := make([]byte, len(data))
	for i := range data {
		cypherText[i] = data[i] ^ gamma[i]
	}

	return cypherText, iv
}

func GostGammaDecrypt(data, key, iv []byte) []byte {
	gamma := Gamma(iv, key, len(data))

	result := make([]byte, len(data))
	for i := range data {
		result[i] = data[i] ^ gamma[i]
	}

	return result
}
