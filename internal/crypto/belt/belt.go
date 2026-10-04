package belt

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/bits"
)

const (
	BlockSize = 16
	KeySize   = 32
)

// H substitution
var hTable = mustDecodeH(
	"b194bac80a08f53b366d008e584a5de4" +
		"8504fa9d1bb6c7ac252e72c202fdce0d" +
		"5be3d61217b96181fe6786ad716b890b" +
		"5cb0c0ff33c356b835c405aed8e07f99" +
		"e12bdc1ae28257ec703fccf095ee8df1" +
		"c1ab76389fe678caf7c6f860d5bb9c4f" +
		"f33c657b637c306add4ea7799eb23d31" +
		"3e98b56e27d3bccf591e181f4c5ab793" +
		"e9dee72c8f0c0fa62ddb49f46f739647" +
		"06075316ed247a3739cba38303a98bf6" +
		"92bd9b1ce5d141015445fbc95e4d0ef2" +
		"682080aa227d642f2687f93490405511" +
		"be32971343fc9a48a02a885f194b09a1" +
		"7ecda4d01544af8ca58450bf66d2e88a" +
		"a2d7465242a8dfb36974c551eb232921" +
		"d4efd9b43a622875911410ea776cda1d",
)

func mustDecodeH(s string) [256]byte {
	var table [256]byte

	raw, err := hex.DecodeString(s)
	if err != nil {
		panic("belt: invalid H table: " + err.Error())
	}
	copy(table[:], raw)

	return table
}

// hWord applies H substitution to each byte of 32-bits word
func hWord(u uint32) uint32 {
	return uint32(hTable[byte(u)]) |
		uint32(hTable[byte(u>>8)])<<8 |
		uint32(hTable[byte(u>>16)])<<16 |
		uint32(hTable[byte(u>>24)])<<24
}

func g(u uint32, r int) uint32 {
	return bits.RotateLeft32(hWord(u), r)
}

// keyWords divides key into 8 32-bit words
func keyWords(key []byte) [8]uint32 {
	var theta [8]uint32
	for i := range theta {
		theta[i] = binary.LittleEndian.Uint32(key[i*4 : i*4+4])
	}

	return theta
}

// K[j] = theta[(j-1) mod 8].
func subkeysForRound(theta [8]uint32, i int, encrypt bool) [7]uint32 {
	var subkeys [7]uint32
	for j := range subkeys {
		if encrypt {
			subkeys[j] = theta[(7*i-7+j)%8]
		} else {
			subkeys[j] = theta[(7*i-1-j)%8]
		}
	}

	return subkeys
}

// beltRound выполняет один такт шифрования/расшифрования над словами
// a, b, c, d. Формулы такта одинаковы для обоих направлений и различаются
// только порядком тактовых ключей.
func beltRound(a, b, c, d uint32, i uint32, k [7]uint32) (uint32, uint32, uint32, uint32) {
	b ^= g(a+k[0], 5)
	c ^= g(d+k[1], 21)
	a -= g(b+k[2], 13)

	e := g(b+c+k[3], 21) ^ i

	b += e
	c -= e
	d += g(c+k[4], 13)
	b ^= g(a+k[5], 21)
	c ^= g(d+k[6], 5)

	return a, b, c, d
}

func BlockEncrypt(src, key []byte) []byte {
	theta := keyWords(key)

	a := binary.LittleEndian.Uint32(src[0:4])
	b := binary.LittleEndian.Uint32(src[4:8])
	c := binary.LittleEndian.Uint32(src[8:12])
	d := binary.LittleEndian.Uint32(src[12:16])

	// Такты с циклической перестановкой регистров abcd -> bdac -> dcba -> cadb.
	a, b, c, d = beltRound(a, b, c, d, 1, subkeysForRound(theta, 1, true))
	b, d, a, c = beltRound(b, d, a, c, 2, subkeysForRound(theta, 2, true))
	d, c, b, a = beltRound(d, c, b, a, 3, subkeysForRound(theta, 3, true))
	c, a, d, b = beltRound(c, a, d, b, 4, subkeysForRound(theta, 4, true))
	a, b, c, d = beltRound(a, b, c, d, 5, subkeysForRound(theta, 5, true))
	b, d, a, c = beltRound(b, d, a, c, 6, subkeysForRound(theta, 6, true))
	d, c, b, a = beltRound(d, c, b, a, 7, subkeysForRound(theta, 7, true))
	c, a, d, b = beltRound(c, a, d, b, 8, subkeysForRound(theta, 8, true))

	// abcd -> bdac (a<->b, c<->d, b<->c).
	a, b = b, a
	c, d = d, c
	b, c = c, b

	dst := make([]byte, BlockSize)
	binary.LittleEndian.PutUint32(dst[0:4], a)
	binary.LittleEndian.PutUint32(dst[4:8], b)
	binary.LittleEndian.PutUint32(dst[8:12], c)
	binary.LittleEndian.PutUint32(dst[12:16], d)

	return dst
}

func BlockDecrypt(src, key []byte) []byte {
	theta := keyWords(key)

	a := binary.LittleEndian.Uint32(src[0:4])
	b := binary.LittleEndian.Uint32(src[4:8])
	c := binary.LittleEndian.Uint32(src[8:12])
	d := binary.LittleEndian.Uint32(src[12:16])

	a, b, c, d = beltRound(a, b, c, d, 8, subkeysForRound(theta, 8, false))
	c, a, d, b = beltRound(c, a, d, b, 7, subkeysForRound(theta, 7, false))
	d, c, b, a = beltRound(d, c, b, a, 6, subkeysForRound(theta, 6, false))
	b, d, a, c = beltRound(b, d, a, c, 5, subkeysForRound(theta, 5, false))
	a, b, c, d = beltRound(a, b, c, d, 4, subkeysForRound(theta, 4, false))
	c, a, d, b = beltRound(c, a, d, b, 3, subkeysForRound(theta, 3, false))
	d, c, b, a = beltRound(d, c, b, a, 2, subkeysForRound(theta, 2, false))
	b, d, a, c = beltRound(b, d, a, c, 1, subkeysForRound(theta, 1, false))

	// abcd -> cadb (инверсии a<->b, c<->d, a<->d).
	a, b = b, a
	c, d = d, c
	a, d = d, a

	dst := make([]byte, BlockSize)
	binary.LittleEndian.PutUint32(dst[0:4], a)
	binary.LittleEndian.PutUint32(dst[4:8], b)
	binary.LittleEndian.PutUint32(dst[8:12], c)
	binary.LittleEndian.PutUint32(dst[12:16], d)

	return dst
}

func validateKey(key []byte) error {
	if len(key) != KeySize {
		return fmt.Errorf("belt: key must be %d bytes, got %d", KeySize, len(key))
	}

	return nil
}
