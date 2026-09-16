package gost

import (
	"bytes"
	"encoding/binary"
)

func MACProduce(data, key []byte, l int) []byte {
	if l > 32 {
		panic("l can't be more than 32")
	}
	padded := zeroPad(data)

	n1, n2 := BlockEncryptParts(padded, key, 16)

	for i := 8; i < len(padded); i += 8 {
		w1 := binary.LittleEndian.Uint32(padded[i : i+4])
		w2 := binary.LittleEndian.Uint32(padded[i+4 : i+8])

		n1 ^= w1
		n2 ^= w2

		combined := make([]byte, 8)
		binary.LittleEndian.PutUint32(combined[0:4], n1)
		binary.LittleEndian.PutUint32(combined[4:8], n2)

		n1, n2 = BlockEncryptParts(combined, key, 16)
	}

	result := make([]byte, 8)
	binary.LittleEndian.PutUint32(result[0:4], n1)
	binary.LittleEndian.PutUint32(result[4:8], n2)

	byteLen := (l + 7) / 8
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
