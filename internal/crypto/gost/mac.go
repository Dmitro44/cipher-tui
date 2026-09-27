package gost

import (
	"bytes"
	"encoding/binary"
)

func parts(block, key []byte, rounds int) (uint32, uint32) {
	second, first := BlockEncryptParts(block, key, rounds)
	return first, second
}

func MACProduce(data, key []byte, l int) []byte {
	if l <= 0 || l > 32 {
		panic("l can't be less than 1 or more than 32")
	}
	padded := zeroPad(data)

	n1, n2 := parts(padded, key, 16)

	for i := 8; i < len(padded); i += 8 {
		w1 := binary.LittleEndian.Uint32(padded[i : i+4])
		w2 := binary.LittleEndian.Uint32(padded[i+4 : i+8])

		n1 ^= w1
		n2 ^= w2

		combined := make([]byte, 8)
		binary.LittleEndian.PutUint32(combined[0:4], n1)
		binary.LittleEndian.PutUint32(combined[4:8], n2)

		n1, n2 = parts(combined, key, 16)
	}

	byteLen := (l + 7) / 8

	result := make([]byte, 4)
	binary.BigEndian.PutUint32(result, n1)
	return result[:byteLen]
}

func GammaEncryptWithMAC(data, key []byte) ([]byte, []byte, []byte) {
	cypherText, iv := GostGammaEncrypt(data, key)

	mac := MACProduce(data, key, 32)

	return cypherText, iv, mac
}

func GammaDecryptWithMAC(data, key, iv, mac []byte) []byte {
	decrypted := GostGammaDecrypt(data, key, iv)

	decryptedMac := MACProduce(decrypted, key, 32)

	if !bytes.Equal(mac, decryptedMac) {
		panic("cypherText was corrupted")
	}

	return decrypted
}
