package belt

import (
	"bytes"
	"encoding/hex"
	"testing"
)

const (
	keyEnc = "e9dee72c8f0c0fa62ddb49f46f739647" + "06075316ed247a3739cba38303a98bf6"
	keyDec = "92bd9b1ce5d141015445fbc95e4d0ef2" + "682080aa227d642f2687f93490405511"

	msg48 = "b194bac80a08f53b366d008e584a5de4" +
		"8504fa9d1bb6c7ac252e72c202fdce0d" +
		"5be3d61217b96181fe6786ad716b890b"
	msg47 = "b194bac80a08f53b366d008e584a5de4" +
		"8504fa9d1bb6c7ac252e72c202fdce0d" +
		"5be3d61217b96181fe6786ad716b89"
	msg48Dec = "e12bdc1ae28257ec703fccf095ee8df1" +
		"c1ab76389fe678caf7c6f860d5bb9c4f" +
		"f33c657b637c306add4ea7799eb23d31"

	syncCFB    = "be32971343fc9a48a02a885f194b09a1"
	syncCFBDec = "7ecda4d01544af8ca58450bf66d2e88a"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()

	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("invalid hex %q: %v", s, err)
	}

	return b
}

func TestBlockEncryptOfficialVector(t *testing.T) {
	input := mustHex(t, "b194bac80a08f53b366d008e584a5de4")
	key := mustHex(t, keyEnc)
	want := mustHex(t, "69cca1c93557c9e3d66bc3e0fa88fa6e")

	if got := BlockEncrypt(input, key); !bytes.Equal(got, want) {
		t.Errorf("BlockEncrypt = %x, want %x", got, want)
	}
}

func TestBlockDecryptOfficialVector(t *testing.T) {
	input := mustHex(t, "e12bdc1ae28257ec703fccf095ee8df1")
	key := mustHex(t, keyDec)
	want := mustHex(t, "0dc5300600cab840b38448e5e993f421")

	if got := BlockDecrypt(input, key); !bytes.Equal(got, want) {
		t.Errorf("BlockDecrypt = %x, want %x", got, want)
	}
}

func TestBlockRoundTrip(t *testing.T) {
	key := mustHex(t, keyEnc)
	block := mustHex(t, "00112233445566778899aabbccddeeff")

	encrypted := BlockEncrypt(block, key)
	if got := BlockDecrypt(encrypted, key); !bytes.Equal(got, block) {
		t.Errorf("BlockDecrypt(BlockEncrypt(x)) = %x, want %x", got, block)
	}
}

func TestECBEncryptOfficialVector(t *testing.T) {
	key := mustHex(t, keyEnc)
	want := mustHex(t,
		"69cca1c93557c9e3d66bc3e0fa88fa6e"+
			"5f23102ef109710775017f73806da9dc"+
			"46fb2ed2ce771f26dcb5e5d1569f9ab0")

	got, err := ECBEncrypt(mustHex(t, msg48), key)
	if err != nil {
		t.Fatalf("ECBEncrypt: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("ECBEncrypt = %x, want %x", got, want)
	}
}

func TestECBDecryptOfficialVector(t *testing.T) {
	input := mustHex(t, msg48Dec)
	key := mustHex(t, keyDec)
	want := mustHex(t,
		"0dc5300600cab840b38448e5e993f421"+
			"e55a239f2ab5c5d5fdb6e81b40938e2a"+
			"54120ca3e6e19c7ad750fc3531daeab7")

	got, err := ECBDecrypt(input, key)
	if err != nil {
		t.Fatalf("ECBDecrypt: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("ECBDecrypt = %x, want %x", got, want)
	}
}

// 47-bytes msg check
func TestECBEncryptPartialOfficialVector(t *testing.T) {
	key := mustHex(t, keyEnc)
	want := mustHex(t,
		"69cca1c93557c9e3d66bc3e0fa88fa6e"+
			"36f00cfed6d1ca1498c12798f4beb207"+
			"5f23102ef109710775017f73806da9")

	encrypted, err := ECBEncrypt(mustHex(t, msg47), key)
	if err != nil {
		t.Fatalf("ECBEncrypt: %v", err)
	}
	if !bytes.Equal(encrypted, want) {
		t.Fatalf("ECBEncrypt = %x, want %x", encrypted, want)
	}
}

func TestECBDecryptPartialOfficialVector(t *testing.T) {
	input := mustHex(t, msg48Dec[:72])
	key := mustHex(t, keyDec)
	want := mustHex(t,
		"0dc5300600cab840b38448e5e993f421"+
			"5780a6e2b69eafbb258726d7b6718523"+
			"e55a239f")

	decrypted, err := ECBDecrypt(input, key)
	if err != nil {
		t.Fatalf("ECBDecrypt: %v", err)
	}
	if !bytes.Equal(decrypted, want) {
		t.Fatalf("ECBDecrypt = %x, want %x", decrypted, want)
	}
}

func TestECBRoundTrip(t *testing.T) {
	key := mustHex(t, keyEnc)
	data := mustHex(t, msg48)

	for length := BlockSize; length <= 3*BlockSize; length++ {
		src := data[:length]

		encrypted, err := ECBEncrypt(src, key)
		if err != nil {
			t.Fatalf("ECBEncrypt(%d bytes): %v", length, err)
		}
		if len(encrypted) != length {
			t.Fatalf("ECBEncrypt(%d bytes) produced %d bytes", length, len(encrypted))
		}

		decrypted, err := ECBDecrypt(encrypted, key)
		if err != nil {
			t.Fatalf("ECBDecrypt(%d bytes): %v", length, err)
		}
		if !bytes.Equal(decrypted, src) {
			t.Errorf("ECB round trip failed for length %d: got %x, want %x", length, decrypted, src)
		}
	}
}

func TestECBRejectsShortAndBadKey(t *testing.T) {
	if _, err := ECBEncrypt([]byte("short"), mustHex(t, keyEnc)); err == nil {
		t.Error("ECBEncrypt accepted a message shorter than one block")
	}
	if _, err := ECBEncrypt(mustHex(t, msg48), []byte("too-short-key")); err == nil {
		t.Error("ECBEncrypt accepted a key of invalid length")
	}
}

func TestCFBEncryptOfficialVector(t *testing.T) {
	key := mustHex(t, keyEnc)
	sync := mustHex(t, syncCFB)
	want := mustHex(t,
		"c31e490a90efa374626cc99e4b7b8540"+
			"a6e48685464a5a06849c9ca769a1b0ae"+
			"55c2cc5939303ec832dd2fe16c8e5a1b")

	if got := gammaWithFeedbackEncrypt(mustHex(t, msg48), key, sync); !bytes.Equal(got, want) {
		t.Errorf("belt-cfb encrypt = %x, want %x", got, want)
	}

	plainText, err := GammaWithFeedbackDecrypt(want, key, sync)
	if err != nil {
		t.Fatalf("GammaWithFeedbackDecrypt: %v", err)
	}
	if !bytes.Equal(plainText, mustHex(t, msg48)) {
		t.Errorf("belt-cfb decrypt = %x, want %x", plainText, mustHex(t, msg48))
	}
}

func TestCFBDecryptOfficialVector(t *testing.T) {
	input := mustHex(t, msg48Dec)
	key := mustHex(t, keyDec)
	sync := mustHex(t, syncCFBDec)
	want := mustHex(t,
		"fa9d107a86f375ee65cd1db881224bd0"+
			"16aff814938ed39b3361abb0bf0851b6"+
			"52244eb06842dd4c94aa4500774e40bb")

	if got := gammaWithFeedbackDecrypt(input, key, sync); !bytes.Equal(got, want) {
		t.Errorf("belt-cfb encrypt = %x, want %x", got, want)
	}
}

func TestCFBRoundTrip(t *testing.T) {
	key := mustHex(t, keyEnc)
	data := mustHex(t, msg48)

	for length := 1; length <= 3*BlockSize; length++ {
		src := data[:length]

		encrypted, sync, err := GammaWithFeedbackEncrypt(src, key)
		if err != nil {
			t.Fatalf("GammaWithFeedbackEncrypt(%d bytes): %v", length, err)
		}
		if len(encrypted) != length {
			t.Fatalf("GammaWithFeedbackEncrypt(%d bytes) produced %d bytes", length, len(encrypted))
		}
		if len(sync) != BlockSize {
			t.Fatalf("sync length = %d, want %d", len(sync), BlockSize)
		}

		decrypted, err := GammaWithFeedbackDecrypt(encrypted, key, sync)
		if err != nil {
			t.Fatalf("GammaWithFeedbackDecrypt(%d bytes): %v", length, err)
		}
		if !bytes.Equal(decrypted, src) {
			t.Errorf("belt-cfb round trip failed for length %d: got %x, want %x", length, decrypted, src)
		}
	}
}
