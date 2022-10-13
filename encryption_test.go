package lukstool

import (
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ripemd160"
)

func Test_AFroundtrip(t *testing.T) {
	type hashmaker func() hash.Hash
	hashes := map[string]hashmaker{
		"sha1":      sha1.New,
		"sha256":    sha256.New,
		"sha512":    sha512.New,
		"ripemd160": ripemd160.New,
	}
	for _, stripes := range []int{2, 4, 1000, 4000} {
		for hashName, hashMaker := range hashes {
			t.Run(fmt.Sprintf("%s:%d", hashName, stripes), func(t *testing.T) {
				h := hashMaker
				key := make([]byte, 32)
				n, err := rand.Read(key)
				require.Nil(t, err, "unexpected error reading random data")
				require.Equal(t, len(key), n, "short read while reading random data")

				split, err := afSplit(key, h(), 4000)
				require.Nil(t, err, "unexpected error splitting key")

				recovered, err := afMerge(split, h(), len(key), 4000)
				require.Nil(t, err, "unexpected error merging key")

				assert.Equal(t, key, recovered, "data was changed")
			})
		}
	}
}

func Test_enc_roundtrip(t *testing.T) {
	type testCases struct {
		cipher, mode string
		keysize      int
		datasize     int
	}
	for _, testCase := range []testCases{
		{"aes", "ecb", 16, 16},
		{"aes", "ecb", 16, 256},
		{"aes", "ecb", 16, 2048},
		{"aes", "ecb", 16, 65536},
		{"aes", "ecb", 32, 16},
		{"aes", "ecb", 32, 256},
		{"aes", "ecb", 32, 2048},
		{"aes", "ecb", 32, 65536},
		{"aes", "cbc-plain", 16, 256},
		{"aes", "cbc-plain", 16, 2048},
		{"aes", "cbc-plain", 16, 65536},
		{"aes", "cbc-plain64", 16, 256},
		{"aes", "cbc-plain64", 16, 2048},
		{"aes", "cbc-plain64", 16, 65536},
		{"aes", "cbc-plain", 32, 256},
		{"aes", "cbc-plain", 32, 2048},
		{"aes", "cbc-plain", 32, 65536},
		{"aes", "cbc-plain64", 32, 256},
		{"aes", "cbc-plain64", 32, 2048},
		{"aes", "cbc-plain64", 32, 65536},
		{"aes", "cbc-essiv:sha256", 32, 256},
		{"aes", "cbc-essiv:sha256", 32, 2048},
		{"aes", "cbc-essiv:sha256", 32, 65536},
		{"aes", "xts-plain", 64, 256},
		{"aes", "xts-plain", 64, 2048},
		{"aes", "xts-plain", 64, 65536},
		{"aes", "xts-plain64", 64, 256},
		{"aes", "xts-plain64", 64, 2048},
		{"aes", "xts-plain64", 64, 65536},
	} {
		t.Run(fmt.Sprintf("%s-%s-%d:%d", testCase.cipher, testCase.mode, testCase.keysize, testCase.datasize), func(t *testing.T) {
			key := make([]byte, testCase.keysize)
			n, err := rand.Read(key)
			require.Nil(t, err, "unexpected error reading random data")
			require.Equalf(t, len(key), n, "short read while reading random data: %d < %d", n, len(key))
			data := make([]byte, testCase.datasize)
			for i := 0; i < len(data); i++ {
				data[i] = uint8(i & 0xff)
			}
			encrypted, err := v1encrypt(testCase.cipher, testCase.mode, 0, key, data, 0, false)
			require.Nil(t, err, "unexpected error encrypting data")
			decrypted, err := v1decrypt(testCase.cipher, testCase.mode, 0, key, encrypted, 0, false)
			require.Nil(t, err, "unexpected error decrypting data")
			assert.Equal(t, data, decrypted, "data was altered somewhere")
		})
	}
}

func Test_roundUpToMultiple(t *testing.T) {
	type testCases struct {
		input, factor, result int
	}
	for _, testCase := range []testCases{
		{1, 2048, 2048},
		{2048, 2048, 2048},
		{4095, 2048, 4096},
		{4097, 2048, 6144},
	} {
		t.Run(fmt.Sprintf("%d:%d", testCase.input, testCase.factor), func(t *testing.T) {
			assert.Equal(t, testCase.result, roundUpToMultiple(testCase.input, testCase.factor))
		})
	}
}
