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
