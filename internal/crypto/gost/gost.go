package gost

import (
	"encoding/binary"
	"math/bits"
)

var sbox = [8][16]uint8{
	{4, 10, 9, 2, 13, 8, 0, 14, 6, 11, 1, 12, 7, 15, 5, 3},
	{14, 11, 4, 12, 6, 13, 15, 8, 1, 3, 10, 2, 7, 0, 9, 5},
	{5, 8, 1, 13, 10, 3, 4, 2, 14, 15, 12, 7, 6, 0, 9, 11},
	{7, 13, 10, 1, 0, 8, 9, 15, 14, 4, 6, 12, 11, 2, 5, 3},
	{6, 12, 7, 1, 15, 13, 9, 4, 11, 14, 2, 0, 5, 10, 3, 8},
	{0, 11, 14, 7, 9, 1, 13, 5, 8, 12, 15, 10, 3, 2, 4, 6},
	{8, 13, 14, 3, 11, 9, 6, 10, 12, 1, 7, 2, 15, 0, 4, 5},
	{12, 9, 6, 13, 1, 2, 8, 0, 15, 4, 10, 3, 11, 7, 5, 14},
}

func KeysForRoundEncrypt(key []byte, rounds int) []uint32 {
	subkeys := make([]uint32, 8)
	for i := range 8 {
		subkeys[i] = binary.LittleEndian.Uint32(key[i*4 : i*4+4])
	}

	result := make([]uint32, rounds)
	for i := range rounds {
		if i < rounds-8 {
			result[i] = subkeys[i%8]
		} else {
			result[i] = subkeys[7-i%8]
		}
	}

	return result
}

func KeysForRoundDecrypt(key []byte, rounds int) []uint32 {
	subkeys := make([]uint32, 8)
	for i := range 8 {
		subkeys[i] = binary.LittleEndian.Uint32(key[i*4 : i*4+4])
	}

	result := make([]uint32, rounds)
	for i := range rounds {
		if i < 8 {
			result[i] = subkeys[i]
		} else {
			result[i] = subkeys[7-i%8]
		}
	}

	return result
}

func f(left uint32, subkey uint32) uint32 {
	s := left + subkey

	var result uint32
	for i := range 8 {
		// 4 bits
		x := uint8((s >> (4 * i)) & 0xF)

		replaced := sbox[i][x]

		result |= uint32(replaced) << (4 * i)
	}

	result = bits.RotateLeft32(result, 11)

	return result
}

func BlockEncryptParts(input []byte, key []byte, rounds int) (uint32, uint32) {
	left := binary.LittleEndian.Uint32(input[0:4])
	right := binary.LittleEndian.Uint32(input[4:8])

	subkeys := KeysForRoundEncrypt(key, rounds)

	for i := range rounds {
		left, right = right^f(left, subkeys[i]), left
	}

	return right, left
}

func BlockDecryptParts(input []byte, key []byte, rounds int) (uint32, uint32) {
	left := binary.LittleEndian.Uint32(input[0:4])
	right := binary.LittleEndian.Uint32(input[4:8])

	subkeys := KeysForRoundDecrypt(key, rounds)

	for i := range rounds {
		left, right = right^f(left, subkeys[i]), left
	}

	return right, left
}

func BlockEncrypt32(input []byte, key []byte) []byte {
	left, right := BlockEncryptParts(input, key, 32)

	combined := make([]byte, 8)
	binary.LittleEndian.PutUint32(combined[0:4], left)
	binary.LittleEndian.PutUint32(combined[4:8], right)
	return combined
}

func BlockDecrypt32(input []byte, key []byte) []byte {
	left, right := BlockDecryptParts(input, key, 32)

	combined := make([]byte, 8)
	binary.LittleEndian.PutUint32(combined[0:4], left)
	binary.LittleEndian.PutUint32(combined[4:8], right)
	return combined
}
