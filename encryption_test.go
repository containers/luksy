package luksy

import (
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ripemd160"
)

var (
	_ io.Writer = &wrapper{}
	_ io.Reader = &wrapper{}
)

func Test_HeaderSizes(t *testing.T) {
	assert.Equal(t, 592, v1HeaderStructSize, "BUG: v1 header size is off")
	assert.Equal(t, 4096, v2HeaderStructSize, "BUG: v2 header size is off")
}

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
		{"aes", "ecb", 24, 16},
		{"aes", "ecb", 24, 256},
		{"aes", "ecb", 24, 2048},
		{"aes", "ecb", 24, 65536},
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
		{"serpent", "xts-plain", 64, 256},
		{"serpent", "xts-plain", 64, 2048},
		{"serpent", "xts-plain", 64, 65536},
		{"serpent", "xts-plain64", 64, 256},
		{"serpent", "xts-plain64", 64, 2048},
		{"serpent", "xts-plain64", 64, 65536},
		{"twofish", "xts-plain", 64, 256},
		{"twofish", "xts-plain", 64, 2048},
		{"twofish", "xts-plain", 64, 65536},
		{"twofish", "xts-plain64", 64, 256},
		{"twofish", "xts-plain64", 64, 2048},
		{"twofish", "xts-plain64", 64, 65536},
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
		{4096, 2048, 4096},
		{4097, 2048, 6144},
	} {
		t.Run(fmt.Sprintf("%d~^~%d", testCase.input, testCase.factor), func(t *testing.T) {
			assert.Equal(t, testCase.result, roundUpToMultiple(testCase.input, testCase.factor))
		})
	}
}

func Test_roundDownToMultiple(t *testing.T) {
	type testCases struct {
		input, factor, result int
	}
	for _, testCase := range []testCases{
		{1, 2048, 0},
		{2048, 2048, 2048},
		{4095, 2048, 2048},
		{4096, 2048, 4096},
		{4097, 2048, 4096},
	} {
		t.Run(fmt.Sprintf("%d~v~%d", testCase.input, testCase.factor), func(t *testing.T) {
			assert.Equal(t, testCase.result, roundDownToMultiple(testCase.input, testCase.factor))
		})
	}
}

func TestWrappers(t *testing.T) {
	for _, sectorSize := range []int{0, 512, 4096} {
		var version string
		switch sectorSize {
		case 0:
			version = "v1"
		default:
			version = fmt.Sprintf("v2,sector=%d", sectorSize)
		}
		for payloadIndex, payloadLength := range []int{0x80, 0x100, 0x1000, 0x4000, 0x10000, 0x100000} {
			for _, trailerLength := range []int{0, 1, 0x1ff, 0x201, 0x1001} {
				for _, chunkSize := range []int{0x123, 0x1234, 0x12345} {
					if payloadIndex > 0 && chunkSize > payloadLength+trailerLength+sectorSize+512 {
						continue
					}
					t.Run(fmt.Sprintf("%s,payload=%d,trailer=%d,chunk=%d", version, payloadLength, trailerLength, chunkSize), func(t *testing.T) {
						password := t.Name()
						buf := make([]byte, payloadLength)
						n, err := rand.Read(buf)
						require.NoError(t, err)
						require.Equal(t, len(buf), n)

						var header []byte
						var encrypt func([]byte) ([]byte, error)
						var blockSize int
						switch sectorSize {
						case 0:
							header, encrypt, blockSize, err = EncryptV1([]string{password}, "")
						default:
							header, encrypt, blockSize, err = EncryptV2([]string{password}, "", sectorSize)
						}
						require.NoError(t, err)
						require.NotNil(t, header)
						require.NotZero(t, blockSize)

						tempdir := t.TempDir()
						encryptedFile := filepath.Join(tempdir, "encrypted")

						f, err := os.Create(encryptedFile)
						require.NoError(t, err)
						writeCloser := io.WriteCloser(f)
						n, err = writeCloser.Write(header)
						require.NoError(t, err)
						require.Equal(t, len(header), n)
						encrypter := EncryptWriter(encrypt, writeCloser, blockSize)
						var nWritten int
						for offset := 0; offset < len(buf); offset += chunkSize {
							chunkLength := chunkSize
							if offset+chunkLength > len(buf) {
								chunkLength = len(buf) - offset
							}
							written, err := encrypter.Write(buf[offset : offset+chunkLength])
							require.NoError(t, err)
							nWritten += written
						}
						require.Equal(t, len(buf), nWritten)
						err = encrypter.Close()
						require.NoError(t, err)
						trailer := make([]byte, trailerLength)
						copy(trailer, "TEST")
						nWritten, err = writeCloser.Write(trailer)
						require.NoError(t, err)
						require.Equal(t, len(trailer), nWritten)

						f, err = os.Open(encryptedFile)
						require.NoError(t, err)
						v1header, v2headerA, v2headerB, v2json, err := ReadHeaders(f, ReadHeaderOptions{})
						require.NoError(t, err)

						var decrypt func([]byte) ([]byte, error)
						var payloadOffset int64
						var payloadLength int64
						switch sectorSize {
						case 0:
							require.NotNil(t, v1header)
							_, _, _, _, err = v1header.Decrypt("", f)
							assert.Error(t, err)

							decrypt, blockSize, payloadOffset, payloadLength, err = v1header.Decrypt(password, f)
							require.NoError(t, err)
							require.NotZero(t, blockSize)
							require.NotZero(t, payloadOffset)
							require.NotZero(t, payloadLength)
							assert.GreaterOrEqual(t, payloadLength, int64(len(buf)))
						default:
							require.NotNil(t, v2headerA)
							require.NotNil(t, v2headerB)
							require.NotNil(t, v2json)
							_, _, _, _, err = v2headerA.Decrypt("", f, *v2json)
							assert.Error(t, err)
							_, _, _, _, err = v2headerB.Decrypt("", f, *v2json)
							assert.Error(t, err)

							decrypt, blockSize, payloadOffset, payloadLength, err = v2headerA.Decrypt(password, f, *v2json)
							require.NoError(t, err)
							require.NotZero(t, blockSize)
							require.NotZero(t, payloadOffset)
							require.NotZero(t, payloadLength)
							assert.GreaterOrEqual(t, payloadLength, int64(len(buf)))
						}

						_, err = f.Seek(payloadOffset, io.SeekStart)
						require.NoError(t, err)

						decrypter := DecryptReader(decrypt, f, blockSize)
						otherBuf := make([]byte, payloadLength)

						var nRead int
						var sawEOF bool
						for offset := 0; offset < len(otherBuf); offset += chunkSize {
							chunkLength := chunkSize
							if offset+chunkLength > len(otherBuf) {
								chunkLength = len(otherBuf) - offset
							}
							read, err := decrypter.Read(otherBuf[offset : offset+chunkLength])
							if err != nil {
								if !errors.Is(err, io.EOF) {
									require.NoError(t, err)
								}
								sawEOF = true
							}
							nRead += read
							if nRead == 0 && sawEOF {
								break
							}
						}
						err = decrypter.Close()
						require.NoError(t, err)
						require.Equal(t, roundDownToMultiple(int(payloadLength), blockSize), nRead)
						require.Equal(t, buf, otherBuf[:len(buf)])

						_, err = f.Seek(-int64(len(trailer)), io.SeekEnd)
						require.NoError(t, err)

						otherTrailer := make([]byte, len(trailer))
						nRead, err = f.Read(otherTrailer)
						require.NoError(t, err)
						require.Equal(t, len(trailer), nRead)
						require.Equal(t, trailer, otherTrailer)
					})
				}
			}
		}
	}
}
